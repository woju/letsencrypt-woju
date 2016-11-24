# le-woju: Let's Encrypt Client Done Right

The recent development in the CA infrastructure is a free CA called „Let's
Encrypt” that will automagically issue a DV certificate to anyone who proves
ownership of his domain name. Now anyone can encrypt any web server traffic
without paying protection money to commercial CA that are basically
unaccountable to anyone and deemed too big to fail.

That's a pretty big achievement for humankind, given how botched the situation
were before. I'd like to publicly acknowledge the important work of ISRG in this
area.

However, the default `letsencrypt` client is a shame. It's a big pile of goo,
which requires superuser rights, not only because it runs its own HTTP server to
complete the handhake, but also to clobber your server configuration. It
shouldn't be this way: you already have pretty decent HTTP server anyway and why
should you need special priviledges just to download a file from the Internet?

I'd like to present my solution to the problem: single script under 500 lines of
Python 3 code. There are two dependencies: [cryptography][cryptography] and
[PyYAML][pyyaml]. No root required.


## HOWTO

1. Install package, and its config file.

    git clone https://github.com/woju/letsencrypt-woju.git
    cd letsencrypt-woju
    python3 setup.py install

1. In config file (`/etc/ssl/le.conf`), adjust:
  a. your contact information:

    contact:
      - mailto:root@example.org
    # - tel:+48000000000

  a. agree to the agreement (uncomment the apropriate line); sorry for this
     step, but I thought this should be done manually

  a. certificate definition(s)

    certs:
      example:
        subject:
	  - c: PL
	  - l: Warsaw
	# do not put "- cn:" here
	domains:
	  - example.org
	  - example.net # if more than one domain, there will be subjectAltNames

1. Run `le-new-reg`. You need to run this only once in your lifetime.

1. Set up your favourite HTTP server (see nginx example below). The critical
   point is that you have to alias the location `/.well-known/acme-challenge` to
   `/etc/ssl/acme-challenge` in your filesystem. The client will put a cookie in
   there to prove the domain ownership.

   Reload your server.

1. Run `le-new-authz example example.org` and `le-new-authz example example.net`
   (once per domain). `example` is name of the section.

1. Run `le-new-cert example` (as before, `example` is the name of the section).
   This will actually obtain the certificate.

1. Uncomment the SSL server section in httpd config. Reload the server.

   At this point, you should have a working setup. Congratulations!

1. Remember to periodically refresh your certificate (Let's Encrypt will issue
   certificates valid for 90 days). It is a good idea to employ cron, for
   example once a month:

     useradd luser # adjust for your own needs
     chown luser:root /etc/ssl/example.crt
     cat <<EOF >/etc/cron.monthly/letsencrypt
     #!/bin/sh

     sudo -u luser le-new-cert example
     EOF


## nginx configuration
    
    server {
        listen 80;
        server_name example.org;
    
        location /.well-known/acme-challenge {
            alias /etc/ssl/acme-challenges/example;
        }
    
        location / {
            return 301 https://$server_name$request_uri;
        }
    }
    
    # the following section should be uncommented after getting first
    # certificate, since nginx will fail to load without certificate
    #server {
    #    listen 443 ssl;
    #    server_name example.org;
    #
    #    ssl_certificate /etc/ssl/example.crt;
    #    ssl_certificate_key /etc/ssl/private/example.key;
    #
    #    add_header Strict-Transport-Security 'max-age=2592000; includeSubdomains'; # 30 days
    #    add_header Public-Key-Pins 'pin-sha256="FIXME"; max-age=604800; includeSubdomains'; # 7 days
    #
    #    # the rest of your precious nginx.conf
    #}

## Apache HTTP configuration

TBD

[cryptography]: https://cryptography.io/
[pyyaml]: http://pyyaml.org/wiki/PyYAML
