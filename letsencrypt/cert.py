from hashlib import sha256
import json
import jws

import encoding

from Crypto.PublicKey import RSA

class X509Base(object):
    """
    Base class for certificates and x509 objects. This provides import and
    export functions.
    """
    def __init__(self):
        """
        Constructor.
        """
        self.__data = None
    
    def _setBeginEnd(self, begin, end):
        """
        Setter for the begin and end markers in PEM structures.
        
        @param begin: The begin marker.
        @param end: The end marker.
        """
        self.__begin = begin
        self.__end = end
        
    def getData(self):
        """
        Getter for the data object.
        
        @return: The data object.
        """
        return self.__data

    def valid(self):
        """
        Returns true, if CSR has data loaded. This actually does not check
        really for structural validity but it checks, if there is data within
        the objects buffer.
        
        @return: True, if valid.
        """
        return self.__data is not None and len(self.__data) > 0

    def load(self, fp, fmt = "PEM"):
        """
        Loads a CSR from file or a stream.
        
        @param fp: Input stream that allows reading data.
        @param fmt: Type of the file ("PEM" or "DER"). Default "PEM".
        @raise Exception: If data cannot be read, an exception is raised.
        """
        if fmt == "PEM":
            self.__data = encoding.fromPem(fp, self.__begin, self.__end)
            if len(self.__data) == 0:
                raise Exception("failed to import data as PEM")
            return True
        if fmt == "DER":
            self.__data = fp.read()
            return True
        raise Exception("unknown format %s" % (fmt))

    def getJwsFormat(self):
        """
        Returns the data as special JWS encoded base64.
        
        @return: Data encoded as JWS encoded base64.
        """
        if self.__data is None or len(self.__data) == 0:
            return ""
        return encoding.dataToJwsBase64(self.__data)

    def toPem(self, fp):
        """
        Writes the CSR as PEM.
        
        @param fp: The file to write to.
        """
        fp.write("%s\n" % (self.__begin))
        fp.write(encoding.toPem(self.__data))
        fp.write("%s\n" % (self.__end))

class CertificateSigningRequest(X509Base):
    """
    This object represents a CSR.
    """
    def __init__(self):
        """
        Constructor.
        
        The constructor just creates an empty object.
        """
        self.__data = None
        self._setBeginEnd("-----BEGIN CERTIFICATE REQUEST-----", "-----END CERTIFICATE REQUEST-----")

class Certificate(X509Base):
    """
    Object represents a x509 certificate.
    """
    def __init__(self):
        """
        Constructor.
        """
        self.__data = None
        self._setBeginEnd("-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----")

class RsaKeyPair(object):
    """
    Object representing a RSA keypair.
    """
    def __init__(self):
        """
        Constructor.
        """
        self.__key = None
    
    def load(self, fp):
        """
        Loads the key from the given stream.
        
        @param fp: Input stream providing the key data.
        """
        self.__key = RSA.importKey(fp)
    
    def getJwk(self):
        """
        Returns the JWK structure representing the public-key.
        
        @return: JWK structure representing the key.
        """
        pub = self.__key.publickey()
        e = encoding.numberToBase64(pub.e)
        n = encoding.numberToBase64(pub.n)
        return { 'e' : e, 'kty' : 'RSA', 'n' : n }

    def getJwkThumbprint(self):
        """
        Returns the JWK thumbprint of the key.
        
        @return: JWK thumbprint of the key as string.
        """
        condensed = json.dumps(self.getJwk(), sort_keys = True, separators=(',', ':'))
        return encoding.dataToJwsBase64(sha256(condensed).digest())

    def signJsonArray(self, postArr, nonce = None):
        """
        Signs the given array of post data with this key. It additionally can
        add some nonce to the jwsHeader, if nonce parameter is different from
        None.
        
        The returned value is a urlsafe base64 encoded string, containing
        the JWK header, the content and the JWS.
        
        @param postArr: The post array to be signed.
        @param nonce: An additional nonce to be added to the JWS header.
        @return: Base64 enconded JSON including JWS.
        """
        jwsHeader = { 'typ' : 'JWT', 'alg': 'RS256', 'jwk' : self.getJwk() }
        if nonce is not None:
            jwsHeader['nonce'] = nonce
        postList = [jws.utils.encode(jwsHeader),
                    jws.utils.encode(postArr),
                    jws.sign(jwsHeader, postArr, self.__key)]
        postData = "%s.%s.%s" % tuple(postList)
        return postData
