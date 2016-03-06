# yalec is Yet Another Let's Encrypt Client #

Note: This is yet work in progress. While signing a CSR will basically work,
using the client is not yet very convenient, as it still lacks documentation
and all input can only be provided by the config.py file for now.

The aim of this project is to provide a client that does not need root
permissions like the original let's encrypt client, does not need a whole
bunch of external dependencies, and is well structured in an object oriented
matter, so it can be understood and modified easily.

## Dependencies ##

The client itself is coded in python, so if you do not want a client depending
on python, just use it as a reference to build your own.

For now, the client depends on tree packages:
* python-jws
* pycurl
* pycrypto

### Installing dependencies ###

pycurl and pycrypto need to be installed on the executing system via:
  pip install pycurl
  pip install pycropto

There is no need to install python-jws as yalec uses a modified version of it
provided as a part of this repository.

### Use of dependencies ###

The pycrypto module is needed to load and parse RSA keys. The ACME protocol
requires the client to perform fancy stuff with the RSA keys used like signing
JSON and splitting keys of into their modulo and exponent. This tasks are
performed using the pycrypto module. It is also a dependency for the
python-jws module.

pycurl is used to carry out the requests via HTTP. While all things might also
be done using urllib2, I tend to use pycurl as it has a lot more options to
perform more complicated tasks. If you do not like the idea to use pycurl, feel
free to provide a pull request providing an additional HttpProvider using
something else.

## Using the yalec ##

The ACME protocol defines some basic processes that need to be done in order to
receive a new certificate. Some of the steps only need to be done before you
are able to receive your first certificate. Other need to be done before you
can renew an already issued certificate.

### Testing ###

Let's Encrypt restricts the number of certificates that can be requested for a
specific domain by a specific user per month. So before starting your production
setup, use the staging-environment provided by Let's Encrypt to test it. For
this, you should use https://acme-staging.api.letsencrypt.org/directory as
base address. This is also the default, if you leave out the --base definition
in the commands below.

### Registering a user ###

Before you can receive a certificate, you need to register a user. A
registration basically consists of a user-key and some contact-information.
During the registration you also accept the terms of service. This is only
needed once before requesting your first certificate.

So, we need to create a new user-key and then register it via yalec. Yalec does
not yet allow to create user-keys internally but provides a function that shows
you a command that allows to create a key via openssl:

```bash
python2 yalec.py userkey --keyout=certs/user.key --bits=4096 --cmd
```

This will output you something like this:
```bash
# create key with the following commands:
openssl genrsa -out certs/user.key 4096 ; chmod 600 certs/user.key
```

If you execute the openssl-command, it will create a new key file within the
certs directory that contains your user-key.

__Note: You need to keep the key-file written private, as this is your private key.__

Now you can register that user by calling:

```bash
python2 yalec.py register --userkey=certs/user.key --mail="me@example.com" --base="https://acme-v01.api.letsencrypt.org"
```

__Note: If you have the guts, you can pipe this directly into bash. If you try this, please check first, if command outputs sane commands.__

### Creating a CSR for your domain ###

Like creating user-keys you can use yalec to provide a basic command that allows
creating a CSR for your domain or domains. This implies to create a new private
key for the server as well.

```bash
python2 yalec.py serverkey --keyout=certs/server.key --csrout=certs/server.csr --domain=example.com --domain=www.example.com --domain=mail.example.com --cmd
```

This will output something like this:
```bash
# create key with the following commands:
openssl genrsa -out certs/server.key 4096 ; chmod 600 certs/server.key
# create csr with the following commands:
TMPFILE=$(mktemp); tee $TMPFILE <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1=example.com
DNS.2=www.example.com
DNS.3=mail.example.com
EOF
openssl req -new -key "certs/server.key" -out "certs/server.csr" -subj "/CN=example.com/" -config $TMPFILE
rm $TMPFILE
```

__Note: You need to keep the key-file written private, as this is your private key. If you key gets compromised, create a new one instantly as your encryption is insecure from that point of time. If you already have requested a certificate for the key, revoke it.__

If you execute the bunch of commands outputed by yalec, you should have a new
server.key file and a server.csr file that allows creating a proper csr.

You can always reuse the CSR created for certificate renewal but it might be
wise to create a new private key and a new CSR from time to time.

__Note: If you have the guts, you can pipe this directly into bash. If you try this, please check first, if command outputs sane commands.__

### Retrieving your certificate ###

As you have registered your user and created a CSR you should be able to request
your certificate now.

```bash
python2 yalec.py sign --userkey=certs/user.key --certout=certs/server.crt --csr=certs/server.csr --domain=example.com --domain=www.example.com --domain=mail.example.com webdir=/tmp/acme --base="https://acme-v01.api.letsencrypt.org"
```

You can just reuse this command everytime you want to renew your certificate.
This will be like every 2 Month (or 30 days before the certificate validity
ends).

During this request, you have to name all domains of the CSR again and tell
the script, where it finds your webroot by the webdir option.

The user acutally executing the command needs access to the webdir (or at least
to the subfolder .well-known/acme-challenge and needs proper permissions to add
files there.

For each domain named, this folder must be accessible via
http://<domain>/.well-known/acme-challenge.

So what the command does is:
For each domain in the list of domains, it requests a challenge from the ACME
server. The ACME server tells yalec a name of a file to be placed at
http://domain/.well-known/acme-challenge/<filename>. After the file has been
placed there, yalec tells the server to retrieve the file which then allows
the creation of certificates of the domain for the given user.

### Installing the certificate ###

To configure your webserver use the server-key created as private key and the
server-certiticate as certificate file (server.key and server.crt in the example
above).

You also need to provide a full certificate chain. For some servers, the chain
must be placed into the server-certificate file. If this is the case, you can
just do it by downloading the issuing certificate from Let's Encrypt and attach
it to your certificate file:

```bash
(cat server.crt ; curl "https://letsencrypt.org/certs/letsencryptauthorityx1.pem") > server.chain.crt
```

### Revokation of certificated ###

TBD.: This is not yet available via commandline but will be added soon.

## License ##

TBD

