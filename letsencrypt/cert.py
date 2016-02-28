from hashlib import sha256
import json
import jws

import encoding

from Crypto.PublicKey import RSA

class CertificateSigningRequest(object):
    '''
    This object represents a CSR.
    '''
    def __init__(self):
        self.__data = None
    
    def valid(self):
        '''
        Returns true, if CSR has data loaded.
        '''
        return self.__data is not None and len(self.__data) > 0
    
    def load(self, fp, fmt = "PEM"):
        '''
        Loads a CSR from file.
        
        @param fp: Input stream that allows reading data.
        @param fmt: Type of the file. Default "PEM"
        '''
        if fmt == "PEM":
            self.__data = encoding.fromPem(fp, "-----BEGIN CERTIFICATE REQUEST-----", "-----END CERTIFICATE REQUEST-----")
            return True
        if fmt == "DER":
            self.__data = fp.read()
            return True
        raise Exception("unknown format %s" % (fmt))
    
    def getJwsFormat(self):
        '''
        Returns the data as special JWS encoded base64.
        '''
        if self.__data is None or len(self.__data) == 0:
            return ""
        return encoding.dataToJwsBase64(self.__data)

    def toPem(self, fp):
        '''
        Writes the CSR as PEM.
        
        @param fp: The file to write to.
        '''
        fp.write("-----BEGIN CERTIFICATE REQUEST-----\n")
        fp.write(encoding.toPem(self.__data))
        fp.write("-----END CERTIFICATE REQUEST-----\n")

class Certificate(object):
    '''
    Object represents a x509 certificate.
    '''
    def __init__(self):
        self.__data = None
        
    def load(self, fp, fmt = "PEM"):
        '''
        Loads a certificate from file.
        
        @param fp: Input stream that allows reading data.
        @param fmt: Type of the file. Default "PEM".
        '''
        if fmt == "PEM":
            self.__data = encoding.fromPem(fp, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----")
            if len(self.__data) == 0:
                raise Exception("failed to import data as PEM")
            return True
        if fmt == "DER":
            self.__data = fp.read()
            return True
        raise Exception("unknown format %s" % (fmt))

    def toPem(self, fp):
        '''
        Writes the certificate as PEM.
        
        @param fp: The file to write to.
        '''
        fp.write("-----BEGIN CERTIFICATE-----\n")
        fp.write(encoding.toPem(self.__data))
        fp.write("-----END CERTIFICATE-----\n")

class RsaKeyPair(object):
    '''
    Object representing a RSA keypair.
    '''
    def __init__(self):
        self.__key = None
    
    def load(self, fp):
        '''
        Loads the key from the given stream.
        
        @param fp: Input stream providing the key data.
        '''
        self.__key = RSA.importKey(fp)
    
    def getJwk(self):
        '''
        Returns the JWK structure representing the public-key.
        '''
        pub = self.__key.publickey()
        e = encoding.numberToBase64(pub.e)
        n = encoding.numberToBase64(pub.n)
        return { 'e' : e, 'kty' : 'RSA', 'n' : n }

    def getJwkThumbprint(self):
        '''
        Returns the JWK thumbprint of the key.
        '''
        condensed = json.dumps(self.getJwk(), sort_keys = True, separators=(',', ':'))
        return encoding.dataToJwsBase64(sha256(condensed).digest())

    def signJsonArray(self, postArr, nonce):
        '''
        Signs the given array of post data with this key. It additionally can
        add some nonce to the jwsHeader, if nonce parameter is different from
        None.
        
        The returned value is a urlsafe base64 encoded string, containing
        the JWK header, the content and the JWS.
        '''
        jwsHeader = { 'typ' : 'JWT', 'alg': 'RS256', 'jwk' : self.getJwk() }
        if nonce is not None:
            jwsHeader['nonce'] = nonce
        postList = [jws.utils.encode(jwsHeader),
                    jws.utils.encode(postArr),
                    jws.sign(jwsHeader, postArr, self.__key)]
        postData = "%s.%s.%s" % tuple(postList)
        return postData
