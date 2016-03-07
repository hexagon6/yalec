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

class SignModule(object):
    """
    This module allows signing CSRs to receive new certificates. This includes
    performing the ACME challenge for the certificates.
    """
    def __init__(self, argv):
        """
        Constructor.
        """
        # TODO: add reading all domains from the CSR instead of manual definition
        if len(argv) < 1:
            raise Exception("No module defined.")
        self.__name = argv[0]
        self.__argv = argv[1:]

        if self.__name != "sign":
            raise Exception("unknown module name %s" % (self.__name))

        shortopts = ["h"]
        longopts = ["help", "userkey=", "csr=", "base=", "domain=", "certout=", "webdir="]
        mandatory = ["--userkey", "--csr", "--domain", "--certout"]
        defaults = {"--base" : [config.BASE], "--webdir" : [config.WEBDIR]}
        self.__valid, self.__optsMap = getOpts(argv[1:], shortopts, longopts, mandatory, defaults)

    def execute(self):
        """
        Executes the module.
        """
        if not self.__valid or any(x[0] in ["h", "help"] for x in self.__optsMap.keys()):
            SignModule.printHelp(self.__name)
            return 1

        userKeyFile = self.__optsMap["--userkey"][:1][0]
        if not path.exists(userKeyFile) or not path.isfile(userKeyFile):
            print "cannot open %s for reading" % (userKeyFile)
            SignModule.printHelp(self.__name)
            return 1

        csrFile = self.__optsMap["--csr"][:1][0]
        if not path.exists(csrFile) or not path.isfile(csrFile):
            print "cannot open %s for reading" % (csrFile)
            SignModule.printHelp(self.__name)
            return 1
        
        base = self.__optsMap["--base"][:1][0]
        certout = self.__optsMap["--certout"][:1][0]
        webdir = self.__optsMap["--webdir"][:1][0]
        fp = open(certout, "w")
        
        userKey = KeyPair()
        userKey.load(open(userKeyFile, "r"))
        csr = CertificateSigningRequest()
        csr.load(open(csrFile, "r"))

        le = LeService(base, HttpProvider, Authenticators, Certificate)
        le.setUserKey(userKey)
        le.setConfigEntry("WEBDIR", webdir)
        le.updateDirectory()
        
        for domain in self.__optsMap["--domain"]:
            print "perform authentication for domain %s" % (domain)
            le.simpleAuthz(le.createDnsAuth(domain))
        print "request certificate for csr"
        cert = le.newCert(csr)
        
        print "save certificate to %s" % (certout)
        cert.toPem(fp)
        fp.flush()
        fp.close()
        print "done"
        
    @staticmethod
    def describe(name):
        """
        Returns a short description of the module.
        """
        if name == "sign":
            return "module for signing CSRs via ACME"
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
    --csr=<file>     - file containing the CSR to be signed [mandatory]
    --certout=<file> - output file to write certificate to [mandatory]
    --domain=<domain>- domain to be included for signing [mandatory]
                       Note: to get this working, there must be one definition
                       for each domain listed as CN or SAN. 
    --webdir=<dir>   - directory for http-based challenge [optional]
                       Note: default value taken from config.py
    --base=<base>    - base address of the let's encrypt service [optional
                       Note: default value taken from config.py""".format(name)
