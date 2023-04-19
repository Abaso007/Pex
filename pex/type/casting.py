"""
MIT License

Copyright (c) 2020-2022 EntySec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import re


class Casting(object):
    """ Subclass of pex.type module.

    This subclass of pex.type module is intended for providing
    implementations of some type casting methods.
    """

    def __init__(self) -> None:
        super().__init__()

    @staticmethod
    def is_mac(mac: str) -> bool:
        """ Check if string is a MAC address.

        :param str mac: string to check
        :return bool: True if string is a MAC address
        """

        regexp = (
            r"^[a-f\d]{1,2}"
            r":[a-f\d]{1,2}"
            r":[a-f\d]{1,2}"
            r":[a-f\d]{1,2}"
            r":[a-f\d]{1,2}"
            r":[a-f\d]{1,2}$"
        )

        return bool(re.match(regexp, mac.lower()))

    @staticmethod
    def is_ipv4(ipv4: str) -> bool:
        """ Check if string is an IPv4 address.

        :param str ipv4: string to check
        :return bool: True if string is an IPv4 address
        """

        regexp = (
            "^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.)"
            "{3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        )

        return bool(re.match(regexp, ipv4))

    @staticmethod
    def is_ipv6(ipv6: str) -> bool:
        """ Check if string is an IPv6 address.

        :param str ipv6: string to check
        :return bool: True if string is an IPv6 address
        """

        regexp = (
            "^(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)%.*$"
        )

        return bool(re.match(regexp, ipv6))

    def is_ip(self, ip: str) -> bool:
        """ Check if string is an IPv4 or an IPv6 address.

        :param str ip: string to check
        :return bool: True if string is an IPv4 or an IPv6 address
        """

        return bool(self.is_ipv4(ip) or self.is_ipv6(ip))

    def is_ipv4_cidr(self, ipv4_cidr: str) -> bool:
        """ Check if string is an IPv4 cidr.

        :param str ipv4_cidr: string to check
        :return bool: True if string is an IPv4 cidr
        """

        cidr = ipv4_cidr.split('/')

        return bool(
            len(cidr) == 2
            and self.is_ipv4(cidr[0])
            and int(cidr[1]) in range(32 + 1)
        )

    def is_ipv6_cidr(self, ipv6_cidr: str) -> bool:
        """ Check if string is an IPv6 cidr.

        :param str ipv6_cidr: string to check
        :return bool: True if string is an IPv6 cidr
        """

        cidr = ipv6_cidr.split('/')

        return bool(
            len(cidr) == 2
            and self.is_ipv6(cidr[0])
            and int(cidr[1]) in range(64 + 1)
        )

    def is_port(self, port: int) -> bool:
        """ Check if integer is a port.

        :param int port: integer to check
        :return bool: True if integer is a port
        """

        return bool(self.is_integer(port) and 0 < port <= 65535)

    def is_port_range(self, port_range: str) -> bool:
        """ Check if string is a port range.

        :param str port_range: string to check
        :return bool: True if string is a port range
        """

        value = port_range.split('-')

        return bool(
            len(value) == 2
            and int(value[0]) <= int(value[1])
            and self.is_port(value[0])
            and self.is_port(value[1])
        )

    @staticmethod
    def is_integer(value: str) -> bool:
        """ Check if string is an integer.

        :param str value: string to check
        :return bool: True if string is an integer else False
        """

        value = value

        return value.isdigit()

    @staticmethod
    def is_float(value: str) -> bool:
        """ Check if string is a float.

        :param str value: string to check
        :return bool: True if string is a float else False
        """

        value = value
        return bool(re.match(r'^-?\d+(?:\.\d+)$', value))

    def is_number(self, value: str) -> bool:
        """ Check if string is a number (float/int).

        :param str value: string to check
        :return bool: True if string is a number else False
        """

        return bool(self.is_integer(value) or self.is_float(value))

    @staticmethod
    def is_boolean(value: str) -> bool:
        """ Check if string is a boolean (yes/no/y/n).

        :param str value: string to check
        :return bool: True if string is a boolean else False
        """

        value = value.lower()
        return value in {'yes', 'no', 'y', 'n'}
