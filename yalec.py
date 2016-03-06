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

from sys import argv, exit

from modules.key import KeyModule
from modules.register import RegisterModule
from modules.sign import SignModule
from modules.revoke import RevokeModule
from letsencrypt import LeException

modules = {"userkey" : KeyModule, "serverkey": KeyModule, "register" : RegisterModule, "sign" : SignModule, "revoke" : RevokeModule }

def printHelp(argv):
    global modules
    print """usage: {0} <module> [param1 [param2 [...]]]

available modules:""".format(argv[0])
    for name, module in modules.items():
        print "    %s - %s" % (name, module.describe(name))
    print """
Each module provides own module paramaters modparam1 ... modparamN. Please
reffer to the modules help page for further information.
""" 

def main(argv):
    global modules
    if len(argv) < 2 or argv[1] == "--help" or not modules.has_key(argv[1]):
        printHelp(argv)
        exit(1)
    module = modules[argv[1]](argv[1:])
    try:
        module.execute()
    except LeException as e:
        print "error: %s" % (e.msg)

if __name__ == '__main__':
    main(argv)