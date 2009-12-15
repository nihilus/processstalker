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
# this utility will highlight interesting graph nodes defined as the following:
#
#    - instruction level loops (rep movs, etc.)
#    - call to string manipulation API (wstrcpy, strcat, sprintf, etc.)
#    - call to memory allocation and manipulation API (malloc, LocalAlloc, etc.)
#
# command line options are made available to:
#
#    - specify if "all" nodes, "hit" nodes or missed should be highlighted.
#    - specify what cases for highlighting should be activated (default all).
#
# example usage:
#
#     ps_graph_highlight --nodes all --reps --str in.gml > graph-highlighted.gml
#

import getopt
import sys
sys.path.append(sys.argv[0].rsplit('/', 1)[0] + "/ps_api")

from gml import *
from psx import *

# globals.
highlight_nodes    = "all"
h_switches         = {}

h_switches["reps"] = False
h_switches["ints"] = False
h_switches["str"]  = False
h_switches["mem"]  = False
h_switches["all"]  = True       # default to highlighting for all cases.

# parse command line options.
try:
    opts, args = getopt.getopt(sys.argv[1:], "n:rism", ["nodes=", "reps", "ints", "str", "mem"])

    if not len(args):
        raise getopt.error("no args")
except getopt.GetoptError:
    msg = "usage: ps_graph_highlight [--nodes hit, missed, all] [--reps, --ints, --str, --mem] <GML file> > out.gml"
    sys.stderr.write(msg)
    sys.exit(1)

for o, a in opts:
    if o in ("-n", "--nodes") : highlight_nodes    = a
    if o in ("-r", "--reps")  : h_switches["reps"] = True
    if o in ("-i", "--ints")  : h_switches["ints"] = True
    if o in ("-s", "--str")   : h_switches["str"]  = True
    if o in ("-m", "--mem")   : h_switches["mem"]  = True

# if the node filter was customized, disable "all" highlighting.
if h_switches["reps"] or h_switches["ints"] or h_switches["str"] or h_switches["mem"]:
    h_switches["all"] = False

# sanity checking.
if highlight_nodes not in ("hit", "missed", "all"):
    highlight_nodes = "all"

# open and parse the input graph.
gml_graph = gml_graph()

try:
    gml_graph.parse_file(args[0])
except psx, x:
    sys.stderr.write(x.__str__())
    sys.exit(1)

# step through each node in the graph.
for i in xrange(gml_graph.num_nodes()):
    highlight = False
    node      = gml_graph.get_node(i)

    # retrieve the HTML stripped disassembly.
    label = node.get_label_stripped()

    #
    # determine if this node needs to be highlighted.
    #

    # REP XXX instructions.
    if h_switches["reps"] or h_switches["all"]:
        if re.search("rep ins",  label, re.I): highlight = True
        if re.search("rep lods", label, re.I): highlight = True
        if re.search("rep movs", label, re.I): highlight = True
        if re.search("rep outs", label, re.I): highlight = True
        if re.search("rep stos", label, re.I): highlight = True

    # INT XXX instructions.
    if h_switches["ints"] or h_switches["all"]:
        if re.search(" int [^;]*\n", label, re.I): highlight = True

    # string manipulation routines.
    if h_switches["str"] or h_switches["all"]:
        if re.search("call[^;]*str[^;]*\n",     label, re.I): highlight = True
        if re.search("call[^;]*wcs[^;]*\n",     label, re.I): highlight = True
        if re.search("call[^;]*mbs[^;]*\n",     label, re.I): highlight = True
        if re.search("call[^;]*scanf[^;]*\n",   label, re.I): highlight = True
        if re.search("call[^;]*sprintf[^;]*\n", label, re.I): highlight = True

    # memory manipulation routines.
    if h_switches["mem"] or h_switches["all"]:
        if re.search("call[^;]*mem[^;]*\n",   label, re.I): highlight = True
        if re.search("call[^;]*alloc[^;]*\n", label, re.I): highlight = True

    # re-define the fill color if this node needs to be highlighted.
    if highlight:
        if highlight_nodes == "all":
            node.set_g_fill("#9933CC")

        elif highlight_nodes == "hit" and node.get_g_fill() == "#FBB5B5":
            node.set_g_fill("#9933CC")

        elif highlight_nodes == "missed" and node.get_g_fill() == "#FBB5B5":
            node.set_g_fill("#9933CC")

        # replace the node.
        gml_graph.replace_node(i, node)

# render the highlighted graph.
print gml_graph.render()