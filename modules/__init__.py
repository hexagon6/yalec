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
