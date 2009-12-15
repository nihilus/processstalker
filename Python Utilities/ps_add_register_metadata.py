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
# this utility will add captured register metadata to the specified graph. example usage:
#
#     ps_add_register_metadata 2360-regs.0 in.gml > out.gml
#

import sys
sys.path.append(sys.argv[0].rsplit('/', 1)[0] + "/ps_api")

from ps_parsers import *
from gml        import *
from psx        import *

# globals
metadata_cache = {}

if len(sys.argv) < 3:
    sys.stderr.write("usage: ps_add_register_metadata <recording-regs> <GML file> [rebase address] > out.gml")
    sys.exit(1)

recording = sys.argv[1]
gml_file  = sys.argv[2]

if len(sys.argv) == 4:
    rebase_address = long(sys.argv[3], 16)
else:
    rebase_address = 0

# open and parse the register metadata recording file.
register_metadata = register_metadata_parser(rebase_address)

try:
    register_metadata.parse(recording)
except psx, x:
    sys.stderr.write(x.__str__())
    sys.exit(1)

# open and parse the input graph.
gml_graph = gml_graph()

try:
    gml_graph.parse_file(gml_file)
except psx, x:
    sys.stderr.write(x.__str__())
    sys.exit(1)

# step through each node in the graph adding register metadata.
for i in xrange(gml_graph.num_nodes()):
    node = gml_graph.get_node(i)

    for reg in ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI"]:
        register = register_metadata.retrieve_register_metadata(reg, node.get_block())

        if register:
            node.set_register(reg, register["value"], register["single_location"], register["single_data"])

    # replace the node.
    gml_graph.replace_node(i, node)

# render the modified graph.
print gml_graph.render()