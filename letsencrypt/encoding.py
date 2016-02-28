from base64 import b64encode, b64decode, urlsafe_b64encode
from textwrap import wrap
from binascii import unhexlify

def toPem(data):
    enc = b64encode(data)
    return "\n".join(wrap(enc, 64)) + "\n"

def fromPem(fp, begin, end):
    rcTxt = ""
    for line in fp.readlines():
        line = line.strip()
        if line == begin:
            rcTxt = ""
            continue
        if line == end:
            return b64decode(rcTxt)
        rcTxt += line

def dataToJwsBase64(data):
    return urlsafe_b64encode(data).replace("=", "")

def numberToBase64(number):
    n = "%x" % (number)
    n = "0%s" % (n) if len(n) % 2 == 1 else n
    return dataToJwsBase64(unhexlify(n))
