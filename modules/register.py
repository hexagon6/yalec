from modules import getOpts
import config
from os import path

from config import KeyPair, HttpProvider, Authenticators, Certificate
from letsencrypt import LeService

class RegisterModule(object):
    """
    This module performs a registration of a user-key on the let's encrypt
    ACME service.
    """
    def __init__(self, argv):
        """
        Constructor.
        """
        if len(argv) < 1:
            raise Exception("No module defined.")
        self.__name = argv[0]
        self.__argv = argv[1:]

        if self.__name != "register":
            raise Exception("unknown module name %s" % (self.__name))

        shortopts = ["h"]
        longopts = ["help", "userkey=", "mail=", "base=", "terms="]
        mandatory = ["--userkey", "--mail"]
        defaults = {"--base" : [config.BASE], "--terms" : [config.TERMS]}
        self.__valid, self.__optsMap = getOpts(argv[1:], shortopts, longopts, mandatory, defaults)

    def execute(self):
        """
        Executes the module.
        """
        if not self.__valid or any(x[0] in ["h", "help"] for x in self.__optsMap.keys()):
            RegisterModule.printHelp(self.__name)
            return 1
        
        userKeyFile = self.__optsMap["--userkey"][:1][0]
        if not path.exists(userKeyFile) or not path.isfile(userKeyFile):
            print "cannot open %s for reading" % (userKeyFile)
            RegisterModule.printHelp(self.__name)
            return 1
        
        base = self.__optsMap["--base"][:1][0]
        terms = self.__optsMap["--terms"]
        mail = self.__optsMap["--mail"]
        
        userKey = KeyPair()
        userKey.load(open(userKeyFile, "r"))
        le = LeService(base, HttpProvider, Authenticators, Certificate)
        le.setUserKey(userKey)
        le.updateDirectory()
        regResp = le.newReg(le.createMailContact(mail), terms)
        if not regResp.success:
            print "user seems already been known to the ACME service"
        else:
            print "registered now user to ACME service"
        print "profile address: %s" % (regResp.location)

        
    @staticmethod
    def describe(name):
        """
        Returns a short description of the module.
        """
        if name == "register":
            return "registers a new user-key on the ACME service"
        raise Exception("unknown module name %s" % (name))

    @staticmethod
    def printHelp(name):
        """
        Shows the modules help.
        """
        print """module {0}
parameters:
    --help           - show help and exit
    --userkey=<file> - the key to be registered for ACME [mandatory]
    --mail=<mail>    - mailaddress to associate with the key [mandatory]
    --base=<base>    - base address of the let's encrypt service [optional
                       Note: default value taken from config.py
    --terms=<terms>  - url of the terms and conditions to agree [optional]
                       Note: default value taken from config.py""".format(name)
