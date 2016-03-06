from os import makedirs, path, remove
from config import CHALLENGE_PREFIX
from letsencrypt import LeException

import logging

class HttpAuthenticator(object):
    """
    Definition of a simple HTTP authenticator. That class reflects the
    authentication for http-01 protocol.
    
    A http-01 authenticator basically places a file into a specific directory
    that is reached via HTTP on the domain to be authenticated. The
    specification requires that a file with the name of a token provided as
    response on the new-auth is available at 
    http://<dnsname>/.well-known/acme-challenge/
    that contains the token and the JWK thumbprint of the user-key separated
    by ".".
    """
    def __init__(self):
        """
        Just the default constructor.
        """
        pass

    def prepare(self, userKey, challenge, keyAuthorization, config = {}):
        """
        Creates the challenge file. It will also create the necessary directory
        structure, if it does not exist.
        
        This method needs proper permissions on the location of the auth-file.
        
        @param userKey: The userKey that is used during the challenge.
        @param challenge: The definition of the challenge as provided by the
            remote server. This is just the structure loaded from JSON. This
            structure has to contain the "token" index.
        @param keyAuthorization: The JWK thubmprint of the user-key. This will
            be written to the file.
        """
        if not config.has_key("WEBDIR"):
            raise LeException("WEBDIR not found in config")
        self.__chllDir = path.join(config["WEBDIR"], CHALLENGE_PREFIX)
        chllFile = path.join(self.__chllDir, challenge["token"])
        logging.info("try to create authorization file %s" % (chllFile))
        if not path.exists(self.__chllDir):
            makedirs(self.__chllDir)
        
        fp = open(chllFile, "w")
        fp.write(keyAuthorization)
        fp.close()
        
        self.__chllFile = chllFile
    
    def cleanup(self):
        """
        Deletes the challenge file.
        """
        logging.info("remove authorization file")
        if self.__chllFile is not None:
            remove(self.__chllFile)
