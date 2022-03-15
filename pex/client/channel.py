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

import re
import selectors
import sys
import telnetlib
import time


class ChannelSocket:
    def __init__(self, client):
        self.sock = telnetlib.Telnet()
        self.sock.sock = client

        self.read_size = 1024 ** 2
        self.read_delay = 1

        self.stashed = b""

        self.terminated = False
        self.badges = Badges()

    def stash(self):
        stashed_data = self.stashed
        self.stashed = b""

        return stashed_data

    def disconnect(self):
        try:
            self.sock.close()
            return True
        except Exception:
            return False

    def send(self, data):
        if self.sock.sock:
            self.sock.write(data)
            return True
        return False

    def read(self, size):
        if self.sock.sock:
            return self.sock.sock.recv(size)
        return b""

    def readall(self):
        if self.sock.sock:
            result = self.stash()
            self.sock.sock.setblocking(False)

            while True:
                try:
                    data = self.read(self.read_size)
                except Exception:
                    if result:
                        break
                    continue

                result += data
                time.sleep(self.read_delay)

            self.sock.sock.setblocking(True)
            return result
        return None

    def print_until(self, token):
        if self.sock.sock:
            token = token.encode()
            print(self.stash().decode(errors='ignore'), end='')

            while True:
                data = self.read(self.read_size)

                if token in data:
                    token_index = data.index(token)
                    token_size = len(token)

                    self.badges.print_empty(data[:token_index].decode(errors='ignore'), start='', end='')
                    self.stashed = data[token_index+token_size:]

                    break

                print(data.decode(errors='ignore'), end='')
            return True
        return False

    def read_until(self, token):
        if self.sock.sock:
            token = token.encode()
            result = self.stash()

            while True:
                data = self.read(self.read_size)

                if token in data:
                    token_index = data.index(token)
                    token_size = len(token)

                    result += data[:token_index]
                    self.stashed = data[token_index+token_size:]

                    break

                result += data

            return result
        return None

    def send_command(self, command, output=True, decode=True):
        if self.sock.sock:
            try:
                buffer = command.encode()
                self.send(buffer)
 
                if output:
                    data = self.readall()

                    if decode:
                        data = data.decode(errors='ignore')

                    return data
            except Exception:
                self.terminated = True
            return None
        return None

    def send_token_command(self, command, token, output=True, decode=True, display=False):
        if self.sock.sock:
            try:
                buffer = command.encode()
                self.send(buffer)
 
                if display:
                    self.print_until(token)
                else:
                    data = self.read_until(token)

                    if output:
                        if decode:
                            data = data.decode(errors='ignore')

                        return data
            except Exception:
                self.terminated = True
            return None
        return None

    def interact(self, terminator='\n'):
        if self.sock.sock:
            selector = selectors.SelectSelector()

            selector.register(self.sock, selectors.EVENT_READ)
            selector.register(sys.stdin, selectors.EVENT_READ)

            while True:
                for key, events in selector.select():
                    if key.fileobj is self.sock:
                        try:
                            response = self.stash() + self.sock.read_eager()
                        except Exception:
                            self.terminated = True
                            return False
                        if response:
                            self.badges.print_empty(response.decode(errors='ignore'), start='', end='')
                    elif key.fileobj is sys.stdin:
                        line = sys.stdin.readline().strip()
                        if not line:
                            pass
                        if line == "quit":
                            return True
                        self.sock.write((line + terminator).encode())
        else:
            return False


class ChannelClient:
    @staticmethod
    def open_channel(client):
        return ChannelSocket(client)
