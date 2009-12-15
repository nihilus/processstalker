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
# this utility is provided as a means to visualize each function that was "hit" within a recording. every basic block
# will be dispayed, basic blocks that were "hit" will be highlighted.
#
# note: this utility expects the .gml function graphs to exist in the current
#       directory.
#
# example usage:
#
#     ps_view_recording_funcs recording.0.processed             > out.gml
#     ps_view_recording_funcs recording.0.processed -f deadbeef > out.gml
#

import getopt
import random
import sys
sys.path.append(sys.argv[0].rsplit('/', 1)[0] + "/ps_api")

from ps_parsers import *
from gml        import *
from psx        import *

# globals.
function_list   = []
block_list      = []
graph_cat       = gml_graph()
uid_start       = 0
cluster_id      = 0
function_filter = False
xref_file       = False
base_address    = 0

# parse command line options.
try:
    opts, args = getopt.getopt(sys.argv[1:], "x:b:f:", ["xref=", "base=", "function="])

    if not len(args):
        raise getopt.error("no args")
except getopt.GetoptError:
    msg = "usage: ps_view_recording_funcs [-f function] [-x <xrefs file> -b <base addr>] <recording> > out.gml"
    sys.stderr.write(msg)
    sys.exit(1)

for o, a in opts:
    if o in ("-x", "--xref")     : xref_file       = a
    if o in ("-b", "--base")     : base_address    = long(a, 16)
    if o in ("-f", "--function") : function_filter = long(a, 16)

recording_file = args[0]

# instantiate a recorder object and parse the specified file.
recording = recording_parser()

try:
    recording.parse(recording_file)
except psx, x:
    sys.stderr.write(x.__str__())
    sys.exit(1)

# step through the entries in the recording.
for i in xrange(recording.num_entries()):
    (time, thread, module, base, function, offset) = recording.get_recording_entry(i)

    if base_address:
        base = base_address

    function = base + function
    block    = base + offset

    # if a function filter argument was provided and the current function does not match then continue.
    if function_filter and function_filter != function:
        continue

    # add this block to the block list if it doesn't already exist.
    if not block_list.count((module, block)):
        block_list.append((module, block))

    # add this module/function pair to the function list if it doesn't already exist.
    if not function_list.count((module, function)):
        function_list.append((module, function))

###
### the rest of this code was basically ripped from ps_graph_cat
###

# parse each function graph, highlighting visited blocks.
for (module, function) in function_list:
    graph_parser = gml_graph(uid_start)

    try:
        graph_parser.parse_file("%s-%08x.gml" % (module, function))
    except psx, x:
        sys.stderr.write(x.__str__())
        sys.exit(1)

    # for the next graph, increment the uid start by the number of nodes in this graph.
    uid_start = uid_start + graph_parser.num_nodes()

    # step through the nodes in the current graph, highlighting the "hit" ones.
    for i in xrange(graph_parser.num_nodes()):
        node = graph_parser.get_node(i)

        # if the current node exists in the block hit list, highlight it.
        if block_list.count((module, node.get_block())):
            node.set_g_fill("#FBB5B5")

    # create a cluster for the nodes in this graph.
    cluster = gml_cluster()

    # add the nodes from this graph to the output graph.
    for i in xrange(graph_parser.num_nodes()):
        node = graph_parser.get_node(i)
        graph_cat.add_node(node)

        # if this node has the function name, set the cluster label.
        name = node.get_name()
        if name:
            cluster.set_label(name)

        # add the node as a vertex to the cluster.
        cluster.add_vertex(node.get_uid())

    # add the edges from this graph to the output graph.
    for i in xrange(graph_parser.num_edges()):
        edge = graph_parser.get_edge(i)
        graph_cat.add_edge(edge)

    # generate a random color for this cluster.
    cluster_color = "#%02x%02x%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
    cluster.set_g_fill(cluster_color)

    # set the cluster id and label.
    cluster.set_id(cluster_id)
    cluster_id = cluster_id + 1

    # add the cluster to the output graph.
    graph_cat.add_cluster(cluster)

# if a xref-file and base address were specified, then parse edges into the graph from it.
if xref_file and base_address:
    xrefs = xrefs_parser(base_address)

    try:
        xrefs.parse(xref_file)
    except psx, x:
        sys.stderr.write(x.__str__())
        sys.exit(1)

    # enumerate the loaded cross-reference data points.
    for i in xrange(xrefs.num_entries()):
        (function, source, destination) = xrefs.get_xref_entry(i)

        # locate the nodes.
        src_node = graph_cat.find_node_by_address(source)
        dst_node = graph_cat.find_node_by_address(destination)

        if src_node and dst_node:
            # add the edge.
            edge = gml_edge()

            edge.set_src_id(src_node.get_id())
            edge.set_dst_id(dst_node.get_id())

            edge.set_src_uid(src_node.get_uid())
            edge.set_dst_uid(dst_node.get_uid())

            graph_cat.add_edge(edge)

# render the constructed graph.
print graph_cat.render()