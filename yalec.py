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