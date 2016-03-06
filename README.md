# yalec
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

### Registering a user ###

Before you can receive a certificate, you need to register a user. A
registration basically consists of a user-key and some contact-information.
During the registration you also accept the terms of service.

So, we need to create a new user-key and then register it via yalec. Yalec does
not yet allow to create user-keys internally but provides a function that shows
you a command that allows to create a key via openssl:

`python2 yalec.py userkey --keyout certs/user.key --bits 4096 --cmd`

This will output you something like this:
```bash
  # create key with the following commands:
  openssl genrsa -out certs/user.key 4096 ; chmod 600 certs/user.key
```

If you execute the openssl-command, it will create a new file within the certs
directory that contains your user-key.

Now you can register that user by calling:

code(
python2 yalec.py register --userkey certs/user.key --mail "me@example.com"
)


