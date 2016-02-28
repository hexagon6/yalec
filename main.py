'''
Created on 15.02.2016

@author: falk
'''

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
    csr = CertificateSigningRequest()
    csr.load(open(config.CSR, "r"))
    userKey = KeyPair()
    userKey.load(open(config.KEY, "r"))
    le = LeService(config.BASE, HttpProvider, Authenticators, Certificate)
    le.updateDirectory()
    rc, s = le.newReg(userKey, le.createMailContact(config.EMAIL), config.TERMS)
    if not rc:
        print "user creation failed. ignore."
    rc = le.simpleAuthz(userKey, le.createDnsAuth(config.DOMAIN))
    if not rc:
        print "auth failed"
        exit(1)
    rc, s = le.newCert(userKey, csr)
    if not rc:
        print "certificate request failed"
        exit(1)
    buffer = StringIO()
    s.toPem(buffer)
    print buffer.getvalue()
    
    
#    service = LeService(config.BASE)
#    service.queryBase()
