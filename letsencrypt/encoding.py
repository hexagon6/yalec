from base64 import b64encode, b64decode, urlsafe_b64encode
from textwrap import wrap
from binascii import unhexlify

def consoleCleanBinary(data):
    """
    Walks over the data-buffer given and writes it to a new buffer replacing
    characters that should not be presented on a console by dots.
    
    @param data: The data to be replaced.
    @return: Console safe string.
    """
    return ''.join([i if ord(i) < 127 and ord(i) > 31 else '.' for i in data])
    
def toPem(data):
    """
    Converts the given data object to a base64 encoded string that is wrapped
    every 64 characters and ends with a line-break.
    
    This is normally the format of the data-blocks as you find them within a
    PEM file. This method can be used to convert binary ASN.1 data (so called
    DER format) into PEM.
    
    @param data: The data to be encoded.
    @return: String of PEM data.
    """
    enc = b64encode(data)
    return "\n".join(wrap(enc, 64)) + "\n"

def fromPem(fp, begin, end):
    """
    Converts the given data from PEM to binary data using the given begin and
    end-markers.
    
    @param fp: A pointer to a data-input-stream.
    @param begin: The begin marker of the structure. Normally something like
        "-----BEGIN CERTIFICATE-----". The marker must represent a whole line.
    @param end: Then end marker of the structure. Normally something like
        "-----END CERTIFICATE-----". The marker mus represent a whole line.
    @return: Buffer of binary data.
    """
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
    """
    Converts the given data to urlsafe base64 and removes tailing = characters.
    
    This is the format of data delivered during JWS signed transfers.
    
    @param data: The data that should be converted.
    @return: The converted data buffer.
    """
    return urlsafe_b64encode(data).replace("=", "")

def numberToBase64(number):
    """
    Converts a number to a urlsafe base64-string.
    
    @param number: The number to be converted.
    @return: Base64 encoded variant of the number. 
    """
    n = "%x" % (number)
    n = "0%s" % (n) if len(n) % 2 == 1 else n
    return dataToJwsBase64(unhexlify(n))
