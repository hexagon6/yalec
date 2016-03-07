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

# the key-creation is still work in progress. for not we only printout commands
# that should help to create keys using openssl on commandline. 
class KeyModule(object):
    """
    This module helps to create new keys. For now, it just helps by printing
    out openssl commands that can be used to create appropriate keys.
    """
    def __init__(self, argv):
        """
        Constructor.
        """
        if len(argv) < 1:
            raise Exception("No module defined.")
        self.__name = argv[0]
        self.__argv = argv[1:]

        if self.__name not in ["userkey", "serverkey"]:
            raise Exception("unknown module name %s" % (self.__name))

        shortopts = ["h"]
        longopts = ["help", "cmd", "bits=", "keyout="]
        defaults = {"--bits": ["4096",]}
        mandatory = ["--keyout"]
        try:
            self.__openssl = __import__("OpenSSL")
        except:
            mandatory.append("--cmd")
        
        if self.__name == "serverkey":
            longopts += ["domain=", "csrout="]
            mandatory += ["--csrout", "--domain"]

        self.__valid, self.__optsMap = getOpts(argv[1:], shortopts, longopts, mandatory, defaults)
        bits = int(self.__optsMap["--bits"][:1][0])
        if bits < 2048 or bits > 4096:
            self.__valid = False

    def execute(self):
        """
        Executes the module.
        """
        if not self.__valid or any(x[0] in ["h", "help"] for x in self.__optsMap.keys()):
            KeyModule.printHelp(self.__name)
            return 1
        if self.__optsMap.has_key("--cmd"):
            return self.__executeCmd()
        return self.__executeInternal()
        
    def __executeInternal(self):
        """
        Executes the internal key creation using pyopenssl.
        """
        bits = int(self.__optsMap["--bits"][:1][0])
        keyout = self.__optsMap["--keyout"][:1][0]
        fp = open(keyout, "w")
        print "generating key."
        crypto = self.__openssl.crypto
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, bits)
        print "write key to file."
        fp.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        fp.flush()
        fp.close()
        print "done"
        
    def __executeCmd(self):
        """
        Executes the command output module.
        """
        bits = self.__optsMap["--bits"][:1][0]
        keyout = self.__optsMap["--keyout"][:1][0]
        command = ""
        command += "# create key with the following commands:\n"
        command += "openssl genrsa -out {0} {1} ; chmod 600 {0}\n".format(keyout, bits)
        if self.__name == "serverkey":
            csrout = self.__optsMap["--csrout"][:1][0]
            command += "# create csr with the following commands:\n"
            
            domains = self.__optsMap["--domain"]
            firstDomain = domains[0]
            sanConfig = ""
            sanUse = ""
            sanClear = ""
            if len(domains) > 1:
                sanConfig = "TMPFILE=$(mktemp); "
                sanConfig += """tee $TMPFILE <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_req]
subjectAltName = @alt_names

[alt_names]
"""
                for n, v in enumerate(domains):
                    sanConfig += "DNS.%d=%s\n" % (n + 1, v)
                sanConfig += "EOF\n"
                command += sanConfig
                sanUse = " -config $TMPFILE"
                sanClear = "rm $TMPFILE"
            
            command += "openssl req -new -key \"{0}\" -out \"{1}\" -subj \"/CN={2}/\"{3}\n".format(keyout, csrout, firstDomain, sanUse)
            command += sanClear
        print command
        
    @staticmethod
    def describe(name):
        """
        Returns a short description of the module.
        """
        if name == "userkey":
            return "creates user-keys used registrations"
        if name == "serverkey":
            return "creates server-keys used for certificates"
        raise Exception("unknown module name %s" % (name))

    @staticmethod
    def printHelp(name):
        """
        Shows the modules help.
        """
        print """module {0}
parameters:
    --help          - show help and exit
    --keyout=<file> - file to write the private key to [mandatory]
    --bits=<bits>   - bitsize of RSA key (range: 2048-4096) [optional]
    --cmd           - shows openssl command that can be used to create the key
                      instead of creating the key internally
                      Note: mandatory, if pyopenssl not installed""".format(name)
        if name == "serverkey":
            print """    --csrout        - file to write the CSR to [mandatory]
    --domain=<dom>  - the domain listed in the CSR [mandatory]
                      Note: multiple domains can be added repeating the command.
                      if so, the first domain will be stored within subject and
                      following domains
                      within SAN fields."""
