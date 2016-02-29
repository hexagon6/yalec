# yalec
yalec is Yet Another Let's Encrypt Client

Note: This is yet work in progress. While signing a CSR will basically work,
using the client is not yet very convenient, as it still lacks documentation
and all input can only be provided by the config.py file for now.

The aim of this project is to provide a client that does not need root
permissions like the original let's encrypt client, does not need a whole
bunch of external dependencies, and is well structured in an object oriented
matter, so it can be understood and modified easily.

The client itself is coded in python, so if you do not want a client depending
on python, just use it as a reference to build your own.

For now, the client depends on tree packages:
* python-jws
* pycurl
* pycrypto

pycurl and pycrypto need to be installed on the executing system via:
  pip install pycurl
  pip install pycropto

There is no need to install python-jws as yalec uses a modified version of it
provided as a part of this repository.

The pycrypto module is needed to load and parse RSA keys. This is also used by
the python-jws module. The pycurl module is used for HTTP requests.

The structure of the code allows getting rid of dependencies by just replacing
their implementation within the config.py file. I am personally a friend of
pycurl as it has a rich set of features when communicating with HTTP servers.
Buf if you dislike the idea, feel free to provide a HttpProvider implementaion
based on whatever library you like (maybe urllib2) and feel free to provide
a pull-request, so that I can include this.

The same goes for pycrypto.



