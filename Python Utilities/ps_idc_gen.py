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
# this utility will parse a GML file enumerating the following information:
#
#    - function names
#    - comments
#
# an IDC script will be generated that can be used to import changes made from within the graph editor back to the
# IDA database. example usage:
#
#     ps_idc_gen.py *.gml > import_changes.idc
#

import sys
sys.path.append(sys.argv[0].rsplit('/', 1)[0] + "/ps_api")

from gml import *
from psx import *

if len(sys.argv) < 2:
    sys.stderr.write("usage: ps_idc_gen <file 1> [file 2] [...] > import_changes.idc")
    sys.exit(1)

# create the IDC script header.

print "// Process Stalker - IDC Generator"
print "#include <idc.idc>"
print "static main("
print "{"

# step through the input files.
for input_file in sys.argv[1:]:
    graph_parser = gml_graph()

    try:
        graph_parser.parse_file(input_file)
    except psx, x:
        sys.stderr.write(x.__str__())
        sys.exit(1)

    # step through each node in the graph.
    for i in xrange(graph_parser.num_nodes()):
        node  = graph_parser.get_node(i)
        label = node.get_label_stripped()

        #
        # extract information from this node label (HTML stripped).
        #

        # if this node is a function, extract the function name.
        if node.get_block() == node.get_function():
            function_name = node.get_name()
            if not function_name.startswith("sub_"):
                "    MakeName(0x%s, \"%s\");" % (node.get_function(), function_name)

        # extract comments.
        for line in label.split("\n"):
            if line.count(";"):
                matches = re.search("^([a-fA-f0-9]+).*;\s*(.*)", line)

                if matches:
                    (addr, comment) = matches.groups()
                    print"    MakeComm(0x%s, \"%s\");" % (addr, comment)

print "}"