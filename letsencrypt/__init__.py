from pycurl import Curl
from cStringIO import StringIO
import json
from OpenSSL import crypto
from OpenSSL.crypto import PKey

from time import sleep

import logging

class LeService(object):
    NEW_AUTHZ   = u'new-authz'
    NEW_REG     = u'new-reg'
    NEW_CERT    = u'new-cert'
    REVOKE_CERT = u'revoke-cert'
    DIR_MIN = [NEW_AUTHZ, NEW_REG, NEW_CERT, REVOKE_CERT]

    def __init__(self, baseUrl, HttpProvider, Authenticators, Certificate):
        """
        Constructor.
        
        @param baseUrl: Base url providing the service directory.
        @param HttpProvider: Class to be used for HTTP requests.
        @param Authenticators: List of authenticator classes.
        """
        self.__baseUrl = baseUrl
        self.__HttpProvider = HttpProvider
        self.__Authenticators = Authenticators
        self.__Certificate = Certificate
    
    def updateDirectory(self):
        """
        Updates the directory information.
        """
        logging.debug("request directory for %s", self.__baseUrl)
        http = self.__HttpProvider(self.__baseUrl)
        http.prepareGet()
        resp = http.perform()
        if resp <> 200:
            raise Exception('invalid server response %d' % resp) 
        data = http.getData()
        self.__directory = json.load(data)
        for e in self.DIR_MIN:
            if not e in self.__directory:
                raise Exception("%s not found in directory" % (e))
        self.__keepNonce(http)
    
    def newReg(self, userKey, contact, agreement):
        """
        Tries to perform a registration for a new user key.
        """
        logging.info("perform new registration for contact: %s" % (", ".join(contact)))
        postArr = {"resource" : "new-reg", "contact" : contact, "agreement" : agreement }
        postData = userKey.signJsonArray(postArr, self.__nonce)
        http = self.__HttpProvider(self.__directory["new-reg"])
        http.preparePost(postData, ["Nonce: %s" % (self.__nonce),])
        resp = http.perform()
        data = http.getData()
        structure = json.load(data)
        self.__keepNonce(http)
        if resp == 201:
            logging.info("registration has been successful")
            return True, structure
        return False, structure

    def simpleAuthz(self, userKey, identifier):
        '''
        Performs an authentication for the given identifier.
        '''
        rc, structure = self.newAuthz(userKey, identifier)
        if not rc:
            return rc, structure
        challenges = self.selectChallenges(structure["challenges"], structure["combinations"])
        if len(challenges) == 0:
            return False, {"type":"urn:acme:error:noauthenticator","detail":"No authenticator for service","status":404}
        for challenge in challenges:
            keyAuthorization = ".".join([challenge["token"], userKey.getJwkThumbprint()])
            auth = self.prepareChallenge(userKey, challenge, keyAuthorization)
            rc, structure = self.triggerChallenge(userKey, challenge, keyAuthorization)
            if rc:
                rc, structure = self.waitAuthzDone(structure["uri"])
            self.cleanupChallenge(auth)
            if not rc:
                return False
        return True
        
    def newAuthz(self, userKey, identifier):
        '''
        Perform to call for new-authz.
        '''
        postArr = {"resource" : "new-authz", "identifier" : identifier}
        postData = userKey.signJsonArray(postArr, self.__nonce)
        http = self.__HttpProvider(self.__directory["new-authz"])
        http.preparePost(postData, ["Nonce: %s" % (self.__nonce),])
        resp = http.perform()
        data = http.getData()
        structure = json.load(data)
        self.__keepNonce(http)
        if not resp == 201:
            return False, structure
        return True, structure

    def selectChallenges(self, challenges, combinations):
        '''
        Select a set of challenges out of a defined set of possible combinations
        that is supported by the authenticators. An empty list is returned,
        if no possible combination has been detected.
        '''
        for combination in combinations:
            auth = []
            logging.debug("check combination: %s" % (", ".join(str(x) for x in combination)))
            found = True
            for entry in combination:
                auth.append(challenges[entry])
                type = challenges[entry]["type"]
                if not self.__Authenticators.has_key(type):
                    logging.debug("no autenticator for %s" % (type))
                    found = False
                    break
                logging.debug("authenticator for %s found" % (type))
            if found:
                return auth
        return []
    
    def prepareChallenge(self, userKey, challenge, keyAuthorization):
        '''
        Prepares all challenges given.
        '''
        auth = self.__Authenticators[challenge["type"]]()
        auth.prepare(userKey, challenge, keyAuthorization)
        return auth
    
    def triggerChallenge(self, userKey, challenge, keyAuthorization):
        '''
        Triggers the challenge to tell the remote side to start the challenge.
        '''
        token = challenge["token"]
        postArr = {"resource" : "challenge", "type" : challenge["type"], "keyAuthorization" : keyAuthorization }
        postData = userKey.signJsonArray(postArr, self.__nonce)
        http = self.__HttpProvider(challenge["uri"])
        http.preparePost(postData, ["Nonce: %s" % (self.__nonce),])
        resp = http.perform()
        data = http.getData()
        structure = json.load(data)
        self.__keepNonce(http)
        if not resp == 202:
            return False, structure
        return True, structure
        
    def cleanupChallenge(self, auth):
        '''
        Prepares all challenges given.
        '''
        auth.cleanup()

    def waitAuthzDone(self, uri, block = True):
        '''
        Keep polling for authorization result until done.
        '''
        for I in range(20 if block else 1):
            http = self.__HttpProvider(uri)
            http.prepareGet(["Nonce: %s" % (self.__nonce),])
            resp = http.perform()
            data = http.getData()
            structure = json.load(data)
            if not structure["status"] == "pending":
                break
            if block:
                sleep(1)
        return structure["status"] == "valid", structure

    def newCert(self, userKey, csr):
        '''
        Deliver a CSR and request a new certificate to be issed.
        '''
        logging.info("request csr")
        postArr = {"resource" : "new-cert", "csr": csr.getJwsFormat()}
        postData = userKey.signJsonArray(postArr, self.__nonce)
        http = self.__HttpProvider(self.__directory["new-cert"])
        http.preparePost(postData, ["Nonce: %s" % (self.__nonce),])
        resp = http.perform()
        data = http.getData()
        self.__keepNonce(http)
        if not resp == 201:
            return False, json.loads(data)
        
        logging.info("wait for certificate")
        location = http.getHeader("Location")[0]
        for I in range(4):
            http = self.__HttpProvider(location)
            http.prepareGet(["Nonce: %s" % (self.__nonce),])
            resp = http.perform()
            data = http.getData()
            if not resp == 202:
                break
            timeout = int(http.getHeader("Retry-After"))
            sleep(timeout)
        if resp == 200:
            logging.info("got certificate. create certificate object.")
            cert = self.__Certificate()
            cert.load(data, fmt = "DER")
            return True, cert
        else:
            logging.info("could not retrieve certificate")
            return False, None
            
        
    def createMailContact(self, mail):
        '''
        Creates a new mail contact to be used during account registration.
        
        @param mail: A valid mail address.
        '''
        return ["mailto:%s" % (mail),]
    
    def createDnsAuth(self, domain):
        '''
        Creates a new DNS auth for the given domain.
        
        @param domain: The domain to create the auth for.
        '''
        return { "type" : "dns", "value" : domain }
        
    def __keepNonce(self, http):
        '''
        Extracts the nonce from the header of the HTTP response and keeps it
        internally.
        
        @param http: The http object that carried out the request.
        '''
        nonce = http.getHeader("Replay-Nonce")
        if len(nonce) == 0:
            logging.warning("server did not provide nonce")
        else:
            logging.debug("keep nonce: %s" % nonce[0])
            self.__nonce = nonce[0]

