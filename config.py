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
