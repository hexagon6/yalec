BASE="https://acme-staging.api.letsencrypt.org/directory"
KEY="certs/user-privkey.pem"
CSR="certs/csr.pem"
TERMS="https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"
EMAIL="test@example.com"
DOMAIN="example.com"
WEBDIR="/var/www/acme"
CHALLENGE_PREFIX=".well-known/acme-challenge/"

from letsencrypt import http
HttpProvider = http.HttpProviderCurl

from letsencrypt import cert
Certificate = cert.Certificate
CertificateSigningRequest = cert.CertificateSigningRequest
KeyPair = cert.RsaKeyPair

from letsencrypt import auth
Authenticators = {"http-01" : auth.HttpAuthenticator}
