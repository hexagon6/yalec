# yalec - Yet Another Let's Encrypt Client
# Copyright (C) 2016 Falk Garbsch
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#

from modules import getOpts
import config
from os import path

from config import KeyPair, HttpProvider, Authenticators, Certificate, CertificateSigningRequest
from letsencrypt import LeService

class RevokeModule(object):
    """
    This module allows revoking certificates issued by ACME provider.
    """
    def __init__(self, argv):
        """
        Constructor.
        """
        if len(argv) < 1:
            raise Exception("No module defined.")
        self.__name = argv[0]
        self.__argv = argv[1:]

        if self.__name != "revoke":
            raise Exception("unknown module name %s" % (self.__name))

        shortopts = ["h"]
        longopts = ["help", "userkey=", "cert=", "base="]
        mandatory = ["--userkey", "--cert"]
        defaults = {"--base" : [config.BASE]}
        self.__valid, self.__optsMap = getOpts(argv[1:], shortopts, longopts, mandatory, defaults)

    def execute(self):
        """
        Executes the module.
        """
        if not self.__valid or any(x[0] in ["h", "help"] for x in self.__optsMap.keys()):
            RevokeModule.printHelp(self.__name)
            return 1

        userKeyFile = self.__optsMap["--userkey"][:1][0]
        if not path.exists(userKeyFile) or not path.isfile(userKeyFile):
            print "cannot open %s for reading" % (userKeyFile)
            RevokeModule.printHelp(self.__name)
            return 1

        certFile = self.__optsMap["--cert"][:1][0]
        if not path.exists(certFile) or not path.isfile(certFile):
            print "cannot open %s for reading" % (certFile)
            RevokeModule.printHelp(self.__name)
            return 1
        
        base = self.__optsMap["--base"][:1][0]
        
        userKey = KeyPair()
        userKey.load(open(userKeyFile, "r"))
        cert = Certificate()
        cert.load(open(certFile, "r"))

        print "revoke certificate"
        le = LeService(base, HttpProvider, Authenticators, Certificate)
        le.setUserKey(userKey)
        le.updateDirectory()
        le.revokeCert(cert)
        print "done"

    @staticmethod
    def describe(name):
        """
        Returns a short description of the module.
        """
        if name == "revoke":
            return "module for revoking certs issued by an ACME provider"
        raise Exception("unknown module name %s" % (name))

    @staticmethod
    def printHelp(name):
        """
        Shows the modules help.
        """
        print """module {0}
parameters:
    --help           - show help and exit
    --userkey=<file> - the key of a user registered for ACME actions [mandatory]
    --cert=<file>    - file containing cert to be revoked [mandatory]
    --base=<base>    - base address of the let's encrypt service [optional
                       Note: default value taken from config.py""".format(name)
