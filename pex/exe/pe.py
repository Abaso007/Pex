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

class Pe:
    magic = [
        b"\x4d\x5a"
    ]

    headers = {
        'x86': (
            b'\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00'
            b'\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x0e\x1f\xba\x0e\x00\xb4\x09\xcd'
            b'\x21\xb8\x01\x4c\xcd\x21\x54\x68\x69\x73\x20\x70\x72\x6f\x67\x72\x61\x6d\x20\x63\x61\x6e\x6e\x6f'
            b'\x74\x20\x62\x65\x20\x72\x75\x6e\x20\x69\x6e\x20\x44\x4f\x53\x20\x6d\x6f\x64\x65\x2e\x0d\x0d\x0a'
            b'\x24\x00\x00\x00\x00\x00\x00\x00\x50\x45\x00\x00\x4c\x01\x02\x00\xd3\x7c\xb5\x58\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\xe0\x00\x0f\x03\x0b\x01\x02\x1b\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00'
            b'\x00\x10\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x10\x00\x00\x00\x02\x00\x00'
            b'\x04\x00\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x30\x00\x00\x00\x02\x00\x00'
            b'\x1a\x89\x00\x00\x03\x00\x00\x00\x00\x00\x20\x00\x00\x10\x00\x00\x00\x00\x10\x00\x00\x10\x00\x00'
            b'\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x14\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2e\x74\x65\x78\x74\x00\x00\x00'
            b'\x63\x01\x00\x00\x00\x10\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x20\x00\x50\x60\x2e\x69\x64\x61\x74\x61\x00\x00\x14\x00\x00\x00\x00\x20\x00\x00'
            b'\x00\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x30\xc0'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
        ),
        'x64': (
            b'\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00'
            b'\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x0e\x1f\xba\x0e\x00\xb4\x09\xcd'
            b'\x21\xb8\x01\x4c\xcd\x21\x54\x68\x69\x73\x20\x70\x72\x6f\x67\x72\x61\x6d\x20\x63\x61\x6e\x6e\x6f'
            b'\x74\x20\x62\x65\x20\x72\x75\x6e\x20\x69\x6e\x20\x44\x4f\x53\x20\x6d\x6f\x64\x65\x2e\x0d\x0d\x0a'
            b'\x24\x00\x00\x00\x00\x00\x00\x00\x50\x45\x00\x00\x64\x86\x02\x00\xe8\x5d\xb6\x58\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\xf0\x00\x2f\x02\x0b\x02\x02\x1b\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00'
            b'\x00\x10\x00\x00\x00\x10\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x02\x00\x00'
            b'\x04\x00\x00\x00\x00\x00\x00\x00\x05\x00\x02\x00\x00\x00\x00\x00\x00\x30\x00\x00\x00\x02\x00\x00'
            b'\x9a\x9e\x00\x00\x03\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x10\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x2e\x74\x65\x78\x74\x00\x00\x00\x20\x02\x00\x00\x00\x10\x00\x00'
            b'\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x50\x60'
            b'\x2e\x69\x64\x61\x74\x61\x00\x00\x14\x00\x00\x00\x00\x20\x00\x00\x00\x02\x00\x00\x00\x06\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x30\xc0\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
        )
    }

    def pack_pe(self, arch, data):
        if arch in self.headers.keys():
            pe = self.headers[arch] + data

            if arch == 'x86':
                pe += b'\xff' * 4 + b'\x00' * 4 + b'\xff' * 4
                content = pe.ljust(1536, b'\x00')
            elif arch == 'x64':
                pe += b'\x00' * 7 + b'\xff' * 8 + b'\x00' * 8 + b'\xff' * 8
                content = pe.ljust(2048, b'\x00')
            else:
                raise RuntimeError("PE header corrupted!")
            return content

        raise RuntimeError("Failed to find compatible PE header!")
