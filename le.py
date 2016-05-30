#!/usr/bin/env python3

#
# letsencrypt-woju -- ACME client done right
# Copyright (C) 2015  Wojtek Porczyk <wojciech@porczyk.eu>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#


import argparse
import base64
import binascii
import copy
import json
import logging
import os
import posixpath
import sys
import time
import urllib.error
import urllib.request

import cryptography.hazmat.backends
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.serialization
import cryptography.x509
import cryptography.x509.oid
import yaml

_backend = cryptography.hazmat.backends.default_backend()

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')


def b64e(d):
    logging.log(5, 'b64e({!r})'.format(d))
    if isinstance(d, dict):
        d = json.dumps(d, sort_keys=True).encode('ascii')
    return base64.urlsafe_b64encode(d).rstrip(b'=')


def b64d(d):
    return base64.urlsafe_b64decode(d + b'=' * ((-len(d)) % 4))


def ensure_directory(dirname):
    if os.path.exists(dirname):
        return

    old_umask = os.umask(0o077)
    try:
        os.makedirs(dirname)
    finally:
        os.umask(old_umask)


def make_or_load_key(key_file, key_size):
    if os.path.exists(key_file):
        # pylint: disable=line-too-long
        return cryptography.hazmat.primitives.serialization.load_pem_private_key(
            open(key_file, 'rb').read(),
            password=None,
            backend=_backend)

    else:
        ensure_directory(os.path.dirname(key_file))

        # pylint: disable=line-too-long
        key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
            public_exponent=0x10001,
            key_size=key_size,
            backend=_backend)

        old_umask = os.umask(0o077)
        try:
            # pylint: disable=line-too-long
            open(key_file, 'wb').write(key.private_bytes(
                encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
                format=cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=cryptography.hazmat.primitives.serialization.NoEncryption(),
                ))
        except:
            os.unlink(key_file)
            raise
        finally:
            os.umask(old_umask)

        return key


class Cert(object):
    RDN = {
        'c':    cryptography.x509.oid.NameOID.COUNTRY_NAME,
        'l':    cryptography.x509.oid.NameOID.LOCALITY_NAME,
        'st':   cryptography.x509.oid.NameOID.STATE_OR_PROVINCE_NAME,
        'o':    cryptography.x509.oid.NameOID.ORGANIZATION_NAME,
        'ou':   cryptography.x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME,
    }

    def __init__(self, app, name, config):
        self.app = app
        self.name = name
        self.domains = config['domains']
        self.subject = [tuple(rdn.items())[0] for rdn in config['subject']]
        self.key = make_or_load_key(self.key_file, app.config['key_size'])

    def __repr__(self):
        return '<{} subject={} domains={!r}>'.format(
            self.__class__.__name__,
            ''.join('/{}={}'.format(attr, value)
                for attr, value in self.subject),
            self.domains)


    @property
    def crt_file(self):
        return os.path.join(self.app.config['crt_path'], self.name + '.crt')

    @property
    def csr_file(self):
        return os.path.join(self.app.config['csr_path'], self.name + '.csr')

    @property
    def key_file(self):
        return os.path.join(self.app.config['key_path'], self.name + '.key')

    @property
    def uri_file(self):
        return os.path.join(self.app.config['crt_path'], self.name + '.uri')


    def get_uri(self):
        try:
            return open(self.uri_file).read().strip()
        except OSError:
            return None

    def set_uri(self, uri):
        open(self.uri_file, 'w').write(uri.strip() + '\n')

    uri = property(get_uri, set_uri)


    def make_csr(self):
        # CRYPTO
        name = [cryptography.x509.NameAttribute(self.RDN[attr], value)
            for attr, value in self.subject]
        name.append(cryptography.x509.NameAttribute(
            cryptography.x509.oid.NameOID.COMMON_NAME,
            self.domains[0]))

        csr = cryptography.x509.CertificateSigningRequestBuilder().subject_name(
                cryptography.x509.Name(name))

        if len(self.domains) > 1:
            csr = csr.add_extension(
                cryptography.x509.SubjectAlternativeName([
                    cryptography.x509.DNSName(domain)
                    for domain in self.domains[1:]]),
                critical=False)

        csr = csr.sign(
                self.key,
                cryptography.hazmat.primitives.hashes.SHA256(),
                _backend)

        data = csr.public_bytes(
            cryptography.hazmat.primitives.serialization.Encoding.DER)
        open(self.csr_file, 'wb').write(data)
        return data


    def write_http_01_challenge(self, token, key_authorization):
        filepath = os.path.join(self.app.config['challenge_path'], self.name, token)
        ensure_directory(os.path.dirname(filepath))
        open(filepath, 'w').write(key_authorization)


    def write_certificate(self, data):
        ensure_directory(os.path.dirname(self.crt_file))
        open(self.crt_file, 'wb').write(data)


class ACME(object):
    MAX_TIMEOUT = 300 # s
    def __init__(self, app):
        self.log = logging.getLogger('ACME')
        self.app = app
        self.key = make_or_load_key(
            self.app.config['key'],
            self.app.config['key_size'])
        numbers = self.key.public_key().public_numbers()
        self.header = {
            'alg': 'RS256',
            'jwk': {
                'e': self.jwk_number(numbers.e),
                'n': self.jwk_number(numbers.n),
                'kty': 'RSA',
            },
        }

        self.log.debug('header={!r}'.format(self.header))


    def sign(self, data):
        '''Sign the data with JWS.'''
        # CRYPTO
        self.log.debug('sign(data={!r})'.format(data))
        protected = b64e(self.copy_with_nonce(self.header))
        payload = b64e(data)

        signer = self.key.signer(
            cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
            cryptography.hazmat.primitives.hashes.SHA256())
        signer.update(protected)
        signer.update(b'.')
        signer.update(payload)
        signature = b64e(signer.finalize()).decode('ascii')

        return {
            'header': self.header,
            'protected': protected.decode('ascii'),
            'payload': payload.decode('ascii'),
            'signature': signature,
        }


    def get_jwk_thumbprint(self):
        '''Get JWK thumbprint of the underlying key.'''
        # CRYPTO
        digest = cryptography.hazmat.primitives.hashes.Hash(
            cryptography.hazmat.primitives.hashes.SHA256(),
            backend=_backend)
        digest.update(json.dumps(
            self.header['jwk'], sort_keys=True, separators=(',', ':')
        ).encode('ascii'))
        return b64e(digest.finalize()).decode('ascii')

    def key_authorization(self, token):
        return '{}.{}'.format(token, self.get_jwk_thumbprint())


    def get_nonce(self):
        self.log.debug('get_nonce()')
        nonce = urllib.request.urlopen(
            urllib.request.Request(
                posixpath.join(self.app.config['api'], 'directory'),
                method='HEAD')
        ).headers['Replay-Nonce']
        self.log.debug('nonce={!r}'.format(nonce))
        return nonce


    def copy_with_nonce(self, data):
        data = copy.deepcopy(data)
        data['nonce'] = self.get_nonce()
        return data


    def request(self, endpoint, data):
        self.log.debug(
            'request(endpoint={!r}, data={!r})'.format(endpoint, data))

        if not endpoint.startswith(self.app.config['api']):
            endpoint = posixpath.join(self.app.config['api'], endpoint)
        data = self.sign(data)

        self.log.debug('endpoint={!r}, data={!r}'.format(endpoint, data))
        request = urllib.request.Request(
            endpoint,
            json.dumps(data, sort_keys=True).encode('ascii'),
            method='POST')

        try:
            response = urllib.request.urlopen(request)
        except urllib.error.HTTPError as err:
            errdata = json.loads(err.readall().decode('ascii'))
            logging.critical(
                'ACME error ({errdata[type]}): {errdata[detail]}'.format(
                    errdata=errdata))
            raise

        return response


    def new_reg(self):
        self.log.debug('new_reg()')

        data = {
            'resource': 'new-reg',
            'contact': self.app.config['contact'],
        }
        if 'agreement' in self.app.config:
            data['agreement'] = self.app.config['agreement']

        response = self.request('acme/new-reg', data)
        self.app.uri = response.headers['Location']
        return response


    def reg(self):
        self.log.debug('reg()')
        if self.app.uri is None:
            raise TypeError('not registered yet')
        return self.request(self.app.uri, {
            'resource': 'reg',
        })


    def new_authz(self, cert, domain):
        self.log.debug('new_authz(domain={!r})'.format(domain))
        if not domain in cert.domains:
            raise TypeError('domain {!r} not in cert {!r}'.format(domain, cert))

        response = self.request('acme/new-authz', {
            'resource': 'new-authz',
            'identifier': {
                'type': 'dns',
                'value': domain},
        })

        data = json.loads(response.readall().decode('ascii'))
        for challenge in data['challenges']:
            if challenge['type'] == 'http-01':
                return self.challenge_http_01(cert, challenge)

        raise TypeError('no suitable challenge')


    def challenge_http_01(self, cert, challenge):
        assert challenge['type'] == 'http-01', \
            'wrong kind of challenge: {!r}'.format(challenge['type'])

        # draft-ietf-acme-01 says default value is 'pending'
        if challenge.get('status', 'pending') != 'pending':
            raise TypeError('cannot respond to non-pending challenge')

        if '/' in challenge['token']:
            raise ValueError(
                "'/' in token, attempted directory traversal by server")

        key_authorization = self.key_authorization(challenge['token'])
        cert.write_http_01_challenge(challenge['token'], key_authorization)

        return self.request(challenge['uri'], {
            'resource': 'challenge',
            'keyAuthorization': key_authorization})


    def new_cert(self, cert):
        self.log.info('requesting new certificate')
        response = self.request('acme/new-cert', {
            'resource': 'new-cert',
            'csr': b64e(cert.make_csr()).decode('ascii')})
        location = response.headers['Location']
        self.log.info('got location {!r}'.format(location))
        cert.uri = location

        while True:
            response = urllib.request.urlopen(location)
            if response.code == 202:
                timeout = int(response.headers['Retry-After'])
                if timeout > self.MAX_TIMEOUT:
                    self.log.warning(
                        'server told us to retry after {}s, wating {}s'.format(
                            timeout, self.MAX_TIMEOUT))
                    timeout = self.MAX_TIMEOUT
                time.sleep(timeout)
                continue
            break

        data = response.read()
        data = cryptography.x509.load_der_x509_certificate(data,
            backend=_backend)
        data = b''.join(c.public_bytes(
                cryptography.hazmat.primitives.serialization.Encoding.PEM)
            for c in self.app.download_chain(data))
        cert.write_certificate(data)
        return data


    @staticmethod
    def jwk_number(number):
        '''Format key material for use with JSON.'''
        h = '{:x}'.format(number)
        h = '0' * (len(h) % 2) + h
        return b64e(binascii.unhexlify(h)).decode('ascii')



class LetsEncrypt(object):
    def __init__(self, conffile):
        self.log = logging.getLogger('LetsEncrypt')
        self.config = yaml.load(open(conffile))
        self.certs = {name: Cert(self, name, config)
            for name, config in self.config['certs'].items()}
        self.acme = ACME(self)

    def get_uri(self):
        try:
            return open(self.config['account_uri']).read().strip()
        except OSError:
            return None

    def set_uri(self, uri):
        open(self.config['account_uri'], 'w').write(uri.strip() + '\n')

    uri = property(get_uri, set_uri)

    def download_chain(self, cert):
        self.log.debug('download_chain(cert={!r})'.format(cert))
        yield cert

        try:
            extension = cert.extensions.get_extension_for_oid(
                cryptography.x509.extensions.AuthorityInformationAccess.oid)
        except cryptography.x509.extensions.ExtensionNotFound:
            self.log.debug('download_chain extension not found, return')
            return

        aia = extension.value
        for description in aia:
            if description.access_method != \
                 cryptography.x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                continue

            uri = description.access_location.value
            self.log.debug('download_chain fetching uri={!r}'.format(uri))
            response = urllib.request.urlopen(uri)
            data = response.read()

            parent = None
            for loader in (
                    cryptography.x509.load_der_x509_certificate,
                    cryptography.x509.load_pem_x509_certificate,
                    ):
                try:
                    parent = loader(data, backend=_backend)
                except ValueError:
                    continue

            if parent is None:
                self.log.debug('download_chain not a certificate')
                continue

            if parent.subject == parent.issuer:
                self.log.debug('download_chain got self-signed'.format(uri))
                return
                # XXX shouldn't this be "continue"?
                # that way it would get all paths

            yield from self.download_chain(parent)
            return


CONFFILE = '/etc/ssl/le.conf'

parser_new_reg = argparse.ArgumentParser(
    description='register new account')
parser_new_reg.add_argument('--config', '-f', metavar='CONFFILE',
    default=CONFFILE,
    help='config file (default: %(default)s)')

parser_new_authz = argparse.ArgumentParser(
    description='request new certificate for a cluster of domains')
parser_new_authz.add_argument('--config', '-f', metavar='CONFFILE',
    default=CONFFILE,
    help='config file (default: %(default)s)')
parser_new_authz.add_argument('cert', metavar='CERT',
    help='certificate ID from config')
parser_new_authz.add_argument('domain', metavar='DOMAIN',
    help='domain for which to request authorization')

parser_new_cert = argparse.ArgumentParser(
    description='request authorization of a domain')
parser_new_cert.add_argument('--config', '-f', metavar='CONFFILE',
    default=CONFFILE,
    help='config file (default: %(default)s)')
parser_new_cert.add_argument('cert', metavar='CERT',
    help='certificate ID from config')


def new_reg():
    args = parser_new_reg.parse_args()
    app = LetsEncrypt(args.config)
    app.acme.new_reg()
    print(app.uri)


def new_authz():
    args = parser_new_authz.parse_args()
    app = LetsEncrypt(args.config)
    try:
        cert = app.certs[args.cert]
    except KeyError:
        parser_new_authz.error('no such cert: {!r}; available: {}'.format(
            args.cert, ', '.join(app.certs)))

    try:
        app.acme.new_authz(cert, sys.argv[2])
    except TypeError as e:
        parser_new_authz.error(str(e))


def new_cert():
    args = parser_new_cert.parse_args()
    app = LetsEncrypt(args.config)
    try:
        cert = app.certs[args.cert]
    except KeyError:
        parser_new_cert.error('no such cert: {!r}; available: {}'.format(
            args.cert, ', '.join(app.certs)))
    app.acme.new_cert(cert)


console_scripts = {
    'new-reg': new_reg,
    'new-authz': new_authz,
    'new-cert': new_cert,
}

if __name__ == '__main__':
    try:
        main = console_scripts[sys.argv[0]]
    except KeyError:
        sys.stderr.write('no such tool: {!r}\n'.format(sys.argv[0]))
    main()


# vim: ts=4 sts=4 sw=4 et
