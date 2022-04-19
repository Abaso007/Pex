#!/usr/bin/env python3

#
# MIT License
#
# Copyright (c) 2020-2022 EntySec
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

import ssl
import OpenSSL


class SSLTools:
    def wrap_client(self, client, keyfile='hatsploit.key', certfile='hatsploit.crt', protocol=ssl.PROTOCOL_TLS,
                    expire=365, nodename='HatSploit', country='US', state='HatSploit', location='HatSploit',
                    organization='HatSploit', unit='HatSploit'):
        key = self.generate_key()
        cert = self.generate_cert(
            key,
            expire=expire,
            nodename=nodename,
            country=country,
            state=state,
            location=location,
            organization=organization,
            unit=unit
        )

        self.write_key(key, keyfile)
        self.write_cert(cert, certfile)

        return ssl.wrap_socket(
            client,
            server_side=True,
            certfile=certfile,
            keyfile=keyfile,
            ssl_version=protocol
        )

    def write_key(self, key, filename):
        with open(filename, 'wb') as f:
            f.write(self.dump_key(key))

    def write_cert(self, cert, filename):
        with open(filename, 'wb') as f:
            f.write(self.dump_cert(cert))

    @staticmethod
    def dump_key(key):
        TYPE_PEM = OpenSSL.crypto.FILETYPE_PEM
        return OpenSSL.crypto.dump_privatekey(TYPE_PEM, key)

    @staticmethod
    def dump_cert(cert):
        TYPE_PEM = OpenSSL.crypto.FILETYPE_PEM
        return OpenSSL.crypto.dump_certificate(TYPE_PEM, cert)

    @staticmethod
    def generate_key():
        TYPE_RSA = OpenSSL.crypto.TYPE_RSA

        key = OpenSSL.crypto.PKey()
        key.generate_key(TYPE_RSA, 2048)

        return key

    @staticmethod
    def generate_cert(key, expire=365, nodename='HatSploit', country='US', state='HatSploit',
                      location='HatSploit', organization='HatSploit', unit='HatSploit'):
        cert = OpenSSL.crypto.X509()
        cert.get_subject().CN = nodename
        cert.get_subject().C = country
        cert.get_subject().ST = state
        cert.get_subject().L = location
        cert.get_subject().O = organization
        cert.get_subject().OU = unit

        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(expire * 24 * 60 * 60)

        cert.set_serial_number(0)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)

        cert.sign(key, "sha512")

        return cert
