from pycurl import Curl
from cStringIO import StringIO
import json
import re
from urlparse import urlparse
from time import sleep

import logging

class LeException(Exception):
    """
    Specialized exception for the LeService actions.
    """
    def __init__(self, msg, data = {}):
        """
        Constructor.
        
        @param msg: Message string of the exception.
        @param data: Additional data. Optional.
        """
        self.msg = msg
        self.data = data
        
class NewRegResponse(object):
    """
    Response object containing data received during a new-reg execution.
    """
    def __init__(self, success, location, status, structure):
        """
        Constructor.
        
        @param success: Result status of the registration. True, if a new
            account has been created.
        @param location: Location of the user registration.
        @param status: The HTTP status-code.
        @param structure: The response structure received during the request.
        """
        self.success = success
        self.location = location
        self.status = status
        self.status = structure

class NewAuthzResponse(object):
    """
    Response object containing data received during a new-autz execution.
    """
    def __init__(self, status, structure):
        """
        Constructor.
        
        @param status: The HTTP status-code.
        @param structure: The response structure received during the request.
        """
        self.status = status
        self.structure = structure
        self.challanges = structure["challenges"]
        self.combinations = structure["combinations"]

class ChallengeResponse(object):
    """
    Response object containing data received during a challenge execution.
    """
    def __init__(self, status, structure):
        """
        Constructor.
        
        @param status: The HTTP status-code.
        @param structure: The response structure received during the request.
        """
        self.status = status
        self.structure = structure
        self.uri = structure["uri"]

class WaitAuthzResponse(object):
    """
    Response to a polling request on the authz result containing data received
    during the execution.
    """
    def __init__(self, status, structure):
        """
        Constructor.
        
        @param status: The HTTP status-code.
        @param structure: The response structure received during the request.
        """
        self.status = status
        self.structure = structure
        self.authzStatus = structure["status"]
        self.valid = (self.authzStatus == "valid")
        self.error = None
        if not self.valid and structure.has_key("error"):
            self.error = structure["error"]
    
# specification at https://ietf-wg-acme.github.io/acme/
# TODO: 6.4, 6.5
# TODO: handle responses, raise exceptions on error
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
        self.__userKey = None
        self.__config = {}
    
    def setUserKey(self, userKey):
        """
        Sets the user-key to be used for all transactions.
        
        The key is used during each communication with the ACME services and
        may not be equal to a server-key used for x509 certificates.
        
        The user-key must be set before any transaction with the ACME server.
        
        The user-key must be the same for all transactions executed regarding
        a registration. So this value is normally set before the authentication
        transactions and will not be replaced by another key until the
        certificate actions have been finalized.
        
        @param userKey: The new user-key to be set.
        """
        self.__userKey = userKey
    
    def setConfigEntry(self, name, value):
        """
        Sets a config-entry that is delivered to the authentifactors used.
        """
        self.__config[name] = value
        
    def updateDirectory(self):
        """
        Updates the directory information.
        
        This method retrieves the base-url of the service. As defined by the
        ACME specification, this URL provides a directory naming all services
        that can be accessed by the client.
        
        As the directory information is used by this class to find the proper
        services to query, this method must be called everytime the base-url
        has been altered.
        
        @raise Exception: This method raises an exception on any error.
        """
        logging.debug("request directory for %s", self.__baseUrl)
        self.__urlOk(self.__baseUrl)
        http = self.__newHttp(self.__baseUrl)
        http.prepareGet()
        resp = http.perform()
        if resp <> 200:
            raise LeException("invalid server response %d" % resp) 
        data = http.getData()
        self.__directory = json.load(data)
        for e in self.DIR_MIN:
            if not e in self.__directory:
                raise LeException("%s not found in directory" % (e))
        self.__keepNonce(http)
    
    def newReg(self, contact, agreement):
        """
        Tries to perform a registration for a new user key.
        
        @rtype: NewRegResponse
        @return: Returns an object containing the registration result, the JSON
            object retrieved and the location, where the registration as been
            placed.
        """
        logging.info("perform new registration for contact: %s" % (", ".join(contact)))
        postArr = {"resource" : "new-reg", "contact" : contact, "agreement" : agreement }
        postData = self.__userKey.signJsonArray(postArr, self.__nonce)
        http = self.__newHttp(self.__directory["new-reg"])
        http.preparePost(postData, ["Nonce: %s" % (self.__nonce),])
        resp = http.perform()
        data = http.getData()
        structure = json.load(data)
        self.__keepNonce(http)
        # TODO: add function to update/read registation (seet 6.3.)
        if resp not in [201, 409]:
            message = self.__errorFromStructure("%d: error during new-reg" % (resp), structure)
            raise LeException(message, structure)
        logging.info("registration was: %d - %s" % (resp, ("registered" if resp == 201 else "account exists")))
        location = self.__getLocation(http)
        return NewRegResponse(resp == 201, location, resp, structure)

    def simpleAuthz(self, identifier):
        """
        This method allows a simple way to perform a full authz for the given
        identifier. It will request a challenge, select appropriate algorithms,
        trigger the AuthProviders and request the authentication result.
        
        @param identifier: The identifier to perform the new-authz procedure.
        @raise Exception: A exception is raised on all errors.
        """
        authz = self.newAuthz(identifier)
        challenges = self.selectChallenges(authz.challanges, authz.combinations)
        if len(challenges) == 0:
            raise LeException("no valid combination of challenges found")
        for challenge in challenges:
            self.__checkToken(challenge["token"])
            keyAuthorization = ".".join([challenge["token"], self.__userKey.getJwkThumbprint()])
            auth = self.prepareChallenge(challenge, keyAuthorization)
            triggerResp = self.triggerChallenge(challenge, keyAuthorization)
            waitResp = self.waitAuthzDone(triggerResp.uri)
            # TODO: cleanup skipped on errors
            self.cleanupChallenge(auth)

            if waitResp.authzStatus == "invalid":
                message = self.__errorFromStructure("error during authentication", waitResp.error)
                raise LeException(message, waitResp.error)

            if not waitResp.valid:
                message = self.__errorFromStructure("unknown error during authentication", waitResp.error)
                raise LeException(message, waitResp.error)
        
    def newAuthz(self, identifier):
        """
        Perform to call for new-authz.
        
        This requests possible challenges for the given identifier from the ACME
        provider.
        
        @param identifier: The identifier to request the challenges for.
        @return: Response information object.
        @rtype: NewAuthzResponse
        @raise Exception: Raises an exception on every error.
        """
        postArr = {"resource" : "new-authz", "identifier" : identifier}
        postData = self.__userKey.signJsonArray(postArr, self.__nonce)
        http = self.__newHttp(self.__directory["new-authz"])
        http.preparePost(postData, ["Nonce: %s" % (self.__nonce),])
        resp = http.perform()
        data = http.getData()
        structure = json.load(data)
        self.__keepNonce(http)
        if not resp == 201:
            message = self.__errorFromStructure("%d: error during new-authz" % (resp), structure)
            raise LeException(message, structure)
        return NewAuthzResponse(resp, structure)

    def selectChallenges(self, challenges, combinations):
        """
        Select a set of challenges out of a defined set of possible combinations
        that is supported by the authenticators. An empty list is returned,
        if no possible combination has been detected.
        
        This method just expexts the "challenges" and "combinations" lists from
        a new-authz query as parameters.
        
        @param challenges: A set of challenges.
        @param combination: A set of combinations on challenges.
        @return: A list of selected challenges to perform.
        """
        for combination in combinations:
            auth = []
            logging.debug("check combination: %s" % (", ".join(str(x) for x in combination)))
            found = True
            for entry in combination:
                auth.append(challenges[entry])
                chllType = challenges[entry]["type"]
                if not self.__Authenticators.has_key(chllType):
                    logging.debug("no autenticator for %s" % (chllType))
                    found = False
                    break
                logging.debug("authenticator for %s found" % (chllType))
            if found:
                return auth
        return []
    
    def prepareChallenge(self, challenge, keyAuthorization):
        """
        Prepares the given challenge.
        
        Each challenge implies actions to be carried out in beforehand calling
        the ACME provider to perform the checks on the challenge. This method
        triggers the authenticator defined for the given challenge and ensures,
        that the challenge is prepared.
        
        @param challenge: The challenge to be performed. This object must
            contain the information on the challenge to be executed as provided
            by the ACME provider via JSON.
        @param keyAuthorization: JWK thumbprint of the user-key as string.
        @return: Returns the authentication provider triggered. This need to be
            triggered again for cleanup.
        """
        auth = self.__Authenticators[challenge["type"]]()
        auth.prepare(self.__userKey, challenge, keyAuthorization, self.__config)
        return auth
    
    def triggerChallenge(self, challenge, keyAuthorization):
        """
        Triggers the challenge to tell the remote side to start the challenge.
        
        This calls the URI defined within the challenge structure of the ACME
        party to ensure that the challenge starts.
        
        @param challenge: JSON structure of the challenge to be started as
            it as been provided by the ACME provider.
        @param keyAuthorization: The JWK thumbprint representing the user-key
            as string.
        @return: Response to the trigger on the challenge.
        @rtype: ChallengeResponse
        @raise Exception: Raises an exception on errors.
        """
        postArr = {"resource" : "challenge", "type" : challenge["type"], "keyAuthorization" : keyAuthorization }
        postData = self.__userKey.signJsonArray(postArr, self.__nonce)
        http = self.__newHttp(challenge["uri"])
        http.preparePost(postData, ["Nonce: %s" % (self.__nonce),])
        resp = http.perform()
        data = http.getData()
        structure = json.load(data)
        self.__keepNonce(http)
        if resp not in [200, 202]:
            message = self.__errorFromStructure("%d: error during triggering challenge" % (resp), structure)
            raise LeException(message, structure)
        return ChallengeResponse(resp, structure)
        
    def cleanupChallenge(self, auth):
        """
        Prepares all challenges given.
        
        @param auth: The authenticator instance that need to be cleaned.
        """
        auth.cleanup()

    def waitAuthzDone(self, uri):
        """
        Keep polling for authorization result until done.
        
        The method blocks until the authentication has been succeeded or finally
        failed.
        
        @param uri: The uri to tech for authentication done.
        """
        for I in range(5):
            http = self.__newHttp(uri)
            http.prepareGet(["Nonce: %s" % (self.__nonce),])
            resp = http.perform()
            data = http.getData()
            structure = json.load(data)
            if not structure["status"] == "pending":
                break
            sleep(self.__getRetryAfter(http, 1))
        return WaitAuthzResponse(resp, structure)

    def newCert(self, csr):
        """
        Issues a new certificate base on a CSR given.
        
        This can only be called after properly authenticating the current
        registration via a successful authentication for all targets as
        defined within the CSR.
        
        @param csr: The CSR to be signed.
        @return: New certificate signed as a result of the delivery of the CSR.
        @raise Exception: Raises an exception on each error.
        """
        logging.info("request cert")
        postArr = {"resource" : "new-cert", "csr": csr.getJwsFormat()}
        postData = self.__userKey.signJsonArray(postArr, self.__nonce)
        http = self.__newHttp(self.__directory["new-cert"])
        http.preparePost(postData, ["Nonce: %s" % (self.__nonce),])
        resp = http.perform()
        data = http.getData()
        self.__keepNonce(http)
        if not resp == 201:
            structure = None
            try:
                structure = json.load(data)
            except:
                pass
            message = self.__errorFromStructure("%d: error during certificate request" % (resp), structure)
            raise LeException(message, structure)
        
        logging.info("wait for certificate")
        location = self.__getLocation(http)
        for I in range(4):
            http = self.__newHttp(location)
            http.prepareGet(["Nonce: %s" % (self.__nonce),])
            resp = http.perform()
            data = http.getData()
            if not resp == 202:
                break
            timeout = int(http.getHeader("Retry-After"))
            sleep(timeout)

        if not resp == 200:
            logging.info("could not retrieve certificate")
            structure = None
            try:
                structure = json.load(data)
            except:
                pass
            message = self.__errorFromStructure("%d: error while waiting for certificate" % (resp), structure)
            raise LeException(message, structure)

        logging.info("got certificate. create certificate object.")
        cert = self.__Certificate()
        cert.load(data, fmt = "DER")
        return cert
    
    def revokeCert(self, cert):
        """
        Revokey the certificate provided.
        
        @param cert: The certificate to be revoked.
        @raise Exception: Raises an exception if revocation has failed.
        """
        logging.info("revoke cert")
        postArr = {"resource" : "revoke-cert", "certificate": cert.getJwsFormat()}
        postData = self.__userKey.signJsonArray(postArr, self.__nonce)
        http = self.__newHttp(self.__directory["revoke-cert"])
        http.preparePost(postData, ["Nonce: %s" % (self.__nonce),])
        resp = http.perform()
        data = http.getData()
        self.__keepNonce(http)
        if resp == 200:
            logging.info("revokation has been successful")
            return
        structure = json.load(data)
        message = self.__errorFromStructure("%d: error during revocation" % (resp), structure)
        raise LeException(message, structure)
        
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

    def __getLocation(self, http):
        """
        Extracts the first Location header entry from the http object given.
        
        @param http: The object to extract the header from.
        @return: String of the content of the location header or empty, if no
            location header found.
        """
        location = http.getHeader("Location")
        if len(location) == 0:
            return ""
        return location[0]

    def __getLinks(self, http):
        """
        Extracts and parses the Link header from the http object given.
        
        @param http: The object to extract the headers from.
        @return: List of Link headers found within the header. All links are
            returned as a tuple where the first field matches the links location
            and the second field matches the relations name.
        """
        rex = re.compile('Link=<([^>]*)>;rel="([^"]*)"')
        links = http.getHeader("Link")
        rc = []
        for link in links:
            m = rex.match(link)
            if not m:
                continue
            rc.append((m.group(1), m.group(2)))
        logging.debug("extracted links from header: ", rc)
        return rc

    def __getRetryAfter(self, http, default = -1):
        """
        Extracts the retry-after header and returns the value as int.
        
        @param http The http object to extract the data from.
        @param default The default value, if header is absent.
        @return: Value of the retry-after header or the default value, if
            absent.
        """
        retry = http.getHeader("Retry-After")
        if len(retry) == 0:
            return default
        return int(retry[0])

    def __errorFromStructure(self, prefix, structure):
        """
        Tries to create a useful message from the given JSON structure.
        
        @param prefix: The base-message. This is used as a prefix.
        @param structure: The JSON structure provided by the ACME server.
        """
        message = prefix
        if structure is not None and structure.has_key("detail"):
            message += " (%s)" % (structure["detail"])
        return message
    
    def __urlOk(self, url):
        """
        Checks, if the given URL is within the domain of the BASE url.
        
        @param url: The url to be checked.
        @raise Exception: If URL is not within the services domain, an
            exception is caused.
        """
        base = urlparse(self.__baseUrl)
        site = urlparse(url)
        if not site.hostname == base.hostname:
            raise LeException("hostname mismatch: base=%s, url=%s" % (base.hostname, site.hostname))
    
    def __newHttp(self, url):
        """
        Creates a new instance of the HTTP provider for the given URL.
        
        @param url: The url to request.
        @return: HTTP provider to access the URL.
        """
        self.__urlOk(url)
        return self.__HttpProvider(url)

    def __checkToken(self, token):
        """
        Checks, if the token only contains valid characters.
        
        @param token: The token to be checked.
        @raise Exception: An exception is raised, if token contains invalid
            characters.
        """
        rex = re.compile("^[a-zA-Z0-9-_]*$")
        if rex.match(token) is None:
            raise LeException("ACME service provided invalid token")

