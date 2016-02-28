from os import makedirs, path, remove
from config import WEBDIR, CHALLENGE_PREFIX

import logging

class HttpAuthenticator(object):
    def __init__(self):
        pass

    def prepare(self, userKey, challenge, keyAuthorization):
        self.__chllDir = path.join(WEBDIR, CHALLENGE_PREFIX)
        chllFile = path.join(self.__chllDir, challenge["token"])
        logging.info("try to create authorization file %s" % (chllFile))
        if not path.exists(self.__chllDir):
            makedirs(self.__chllDir)
        
        fp = open(chllFile, "w")
        fp.write(keyAuthorization)
        fp.close()
        
        self.__chllFile = chllFile
    
    def cleanup(self):
        logging.info("remove authorization file")
        if self.__chllFile is not None:
            remove(self.__chllFile)
