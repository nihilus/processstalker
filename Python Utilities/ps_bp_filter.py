#!/usr/bin/python
#!c:\python\python.exe

#
# Process Stalker - Python Utility
# Copyright (C) 2005 Pedram Amini <pamini@idefense.com,pedram.amini@gmail.com>
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
# notes:
#
# this utility is provided as a means to filter generated breakpoint lists. breakpoint lists can be filtered in one of
# two ways:
#
#     function      - filter breakpoints that aren't on a function.
#     function list - filter breakpoints that belong to any function as defined by a user-supplied function list.
#
# the "in/out" modifier specifies whether or not the functions in the function list are to be filtered into the output
# list or out of the input list. example usage:
#
#     ps_bp_filter input.bpl filtered.bpl functions
#     ps_bp_filter input.bpl filtered.bpl 00001234:deadbeef in
#

import sys
sys.path.append(sys.argv[0].rsplit('/', 1)[0] + "/ps_api")

from ps_parsers import *
from psx        import *

# usage function.
def usage():
    msg = "usage: ps_bp_filter <input bpl> <output bpl> <functions | <func1>:[func2]:[...] <in | out>>"
    sys.stderr.write(msg)
    sys.exit(1)

# command line argument sanity checking.
try:
    input_file    = sys.argv[1]
    output_file   = sys.argv[2]
    filter_method = sys.argv[3]
except:
    usage()

# function list argument sanity checking.
if filter_method != "functions":
    try:
        function_list = filter_method.rstrip(":").split(":")
        in_or_out     = sys.argv[4]

        if in_or_out != "in" and in_or_out != "out":
            raise Exception
    except:
        usage()

# create input/output bpl parsers.
input_bpl_parser  = bpl_parser()
output_bpl_parser = bpl_parser()

# parse the input bpl.
try:
    input_bpl_parser.parse(input_file)
except psx, x:
    sys.stderr.write(x.__str__())
    sys.exit(1)

# step through the loaded breakpoints filtering appropriately.
for i in xrange(input_bpl_parser.num_entries()):
    (module, function, node) = input_bpl_parser.get_bp_entry(i)

    # if the filter method is function-only, add only function-level nodes.
    if (filter_method == "functions"):
        if function == node:
            output_bpl_parser.add_bp_entry(module, function, node)

    # otherwise a custom filter was specified, filter in/out the nodes within the defined function list.
    else:
        found = False
        for func in function_list:
            if long(func, 16) == function:
                found = True
                break

        # if we are filtering "in" and the current function exists within the specified list, add it.
        if in_or_out == "in" and found:
            output_bpl_parser.add_bp_entry(module, function, node)

        # if we are filtering "out" and the current function was not found within the specified list, add it.
        if in_or_out == "out" and not found:
            output_bpl_parser.add_bp_entry(module, function, node)

# save the filtered list to disk.
output_bpl_parser.save(output_file)