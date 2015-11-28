#!/usr/bin/env python3

import setuptools
import le

if __name__ == '__main__':
    setuptools.setup(
        name='le-woju',
        version='0.1',
        author='Wojtek Porczyk',
        author_email='wojciech@porczyk.eu',
        description='Let\'s Encrypt client done right',
        license='GPL3+',
        url='https://github.com/woju/le-woju',

        requires=['cryptography', 'yaml'],

        py_modules=['le'],
        entry_points={
            'console_scripts': ['le-{} = le:{}'.format(name, main.__name__)
                for name, main in le.console_scripts.items()]
        },
        data_files=[
            ('/etc/ssl', ['le.conf']),
        ],
    )

# vim: ts=4 sts=4 sw=4 et
