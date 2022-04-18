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

import requests
import socket
import urllib3

from pex.tools.http import HTTPTools

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HTTPClient:
    http_tools = HTTPTools()

    def http_request(self, method, host, port, path='/', ssl=False, timeout=10, output=True, session=requests,
                     **kwargs):
        if not output:
            timeout = 0
        kwargs.setdefault("timeout", timeout)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", True)

        if not ssl:
            ssl = int(port) in [443]
        url = self.http_tools.normalize_url(host, port, path, ssl)

        try:
            return getattr(session, method.lower())(url, **kwargs)
        except (requests.exceptions.MissingSchema, requests.exceptions.InvalidSchema):
            raise RuntimeError(f"Invalid URL schema in {url}!")
        except requests.exceptions.ConnectionError:
            raise RuntimeError(f"Connection failed for {url}!")
        except requests.RequestException as e:
            raise RuntimeError(str(e) + '!')
        except socket.error as e:
            raise RuntimeError(str(e) + '!')
