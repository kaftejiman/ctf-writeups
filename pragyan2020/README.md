# AskTheOracle - Crypto 150 points
> Mr Robot has worked all night to find the Cipher "TIe8CkeWpqPFBmFcIqZG0JoGqBIWZ9dHbDqqfdx2hPlqHvwH/+tbAXDSyzyrn1Wf" then he faints of Overdose. You are left with a challenge to get the key to the database before EVIL CORP starts backing up the data.
> `nc ctf.pragyan.org 8500`
> P.S- After solving you will get a flag in the format of pctf{code}, change it to p_ctf{code} and submit it.

Straightforward [Oracle Padding Attack(https://en.wikipedia.org/wiki/Padding_oracle_attack)]

Used [mwielgoszewski POA API(https://github.com/mwielgoszewski/python-paddingoracle)]

```python
from paddingoracle import BadPaddingException, PaddingOracle
from base64 import b64encode, b64decode
from pwn import *
import requests
import time

iv = 'This is an IV456'

class PadBuster(PaddingOracle):
    def __init__(self, **kwargs):
        super(PadBuster, self).__init__(**kwargs)

    def oracle(self, data, **kwargs):
        while 1:
            try:             
                r = remote('ctf.pragyan.org',8500)
                r.recvuntil('\n')
                r.sendline(b64encode(data) + '|' + b64encode(iv))
                res = r.recvallS()
                break
            except (PwnlibException):
                continue

        if res.find("Padding Error!") == -1 or res.find("padding error") == -1:
            return
        else:
            raise BadPaddingException()

if __name__ == '__main__':
    import logging
    import sys

    #logging.basicConfig(level=logging.DEBUG)
    cipher = 'TIe8CkeWpqPFBmFcIqZG0JoGqBIWZ9dHbDqqfdx2hPlqHvwH/+tbAXDSyzyrn1Wf'
    padbuster = PadBuster()
    plain = padbuster.decrypt(b64decode(cipher), block_size=16, iv=iv)

    print('Decrypted: %s => %r' % (cipher, plain))

```
