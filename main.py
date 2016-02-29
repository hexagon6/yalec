import config
from config import Certificate, CertificateSigningRequest, KeyPair, HttpProvider, Authenticators
import json
from cStringIO import StringIO
from pycurl import Curl
from letsencrypt import LeService
from letsencrypt import cert

import logging

from sys import exit

if __name__ == '__main__':
    logging.basicConfig(level = logging.DEBUG)
    
    # 1.) load CSR from file
    csr = CertificateSigningRequest()
    csr.load(open(config.CSR, "r"))
    
    # 2.) load user-key from file
    userKey = KeyPair()
    userKey.load(open(config.KEY, "r"))
    
    # 3.) setup the LeService instance
    le = LeService(config.BASE, HttpProvider, Authenticators, Certificate)
    le.setUserKey(userKey)  # sets the user-key to be used for account
    
    # 4.) initially fetch directory
    #     (need to be done before communication with the ACME provider)
    le.updateDirectory()

    # 5.) try to perform a new registration.
    regResp = le.newReg(le.createMailContact(config.EMAIL), config.TERMS)
    #     if regResp.success is false, the user already existed. otherwise
    #     there would have been an exception
    if not regResp.success:
        print "user already registered"
    
    # 6.) perform authentication for the domain. this will raise an exception,
    #     if it fails
    le.simpleAuthz(le.createDnsAuth(config.DOMAIN))
    
    # 7.) we should now be ready to receive our certificate. let's try.
    #     if not, an exception will be raised.
    cert = le.newCert(csr)
    
    # 8.) print out the certificate on the console.
    buffer = StringIO()
    cert.toPem(buffer)
    print buffer.getvalue()

