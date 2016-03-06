BASE="https://acme-staging.api.letsencrypt.org/directory"
TERMS="https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"
WEBDIR="/tmp/acme"
CHALLENGE_PREFIX=".well-known/acme-challenge/"

from letsencrypt import http
HttpProvider = http.HttpProviderCurl

from letsencrypt import cert
Certificate = cert.Certificate
CertificateSigningRequest = cert.CertificateSigningRequest
KeyPair = cert.RsaKeyPair

from letsencrypt import auth
Authenticators = {"http-01" : auth.HttpAuthenticator}
