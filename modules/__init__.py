import getopt

def getOpts(argv, shortopts, longopts, mandatory = [], optsMap = {}):
    """
    Helper function to class commandline arguments.
    
    @param argv: The commandline arguments excluding the application and module
      names
    @param shortopts: The short-options allowed.
    @param longopts: The long-options allowed.
    @param mandatory: An optional set of mandatory arguments.
    @param optsMap: An optional dict defining default values. This dict must
      contain the option and a list of default values.
    @return: Pair of values. The first value indicates, if the options list can
      be seen as valid. The second contains a dict of decoded values.
    """
    valid = True
    try:
        opts, args = getopt.getopt(argv, shortopts, longopts)
        valid = True
        for c, a in opts:
            if not optsMap.has_key(c):
                optsMap[c] = []
            optsMap[c].append(a)
        for m in mandatory:
            if m not in optsMap.keys():
                print "option %s missing" % (m)
                valid = False
    except getopt.GetoptError as e:
        print "error: %s" % (e.msg)
        valid = False
    return valid, optsMap
