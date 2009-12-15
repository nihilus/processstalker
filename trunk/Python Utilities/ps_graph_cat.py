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
# this utility is provided to combine multiple function graphs into one larger and optionally interconnected (slow to
# render) graph. functions are clustered together. example usage:
#
#   ps_graph_cat.py -x irc.dll.xrefs -b 46001000 irc.dll-460089b0.gml irc.dll-460096f0.gml > out.gml
#

import getopt
import random
import sys
sys.path.append(sys.argv[0].rsplit('/', 1)[0] + "/ps_api")

from ps_parsers import *
from gml        import *
from psx        import *

uid_start    = 0
graph_cat    = gml_graph()
cluster_id   = 0
xref_file    = False
base_address = 0

# parse command line options.
try:
    opts, args = getopt.getopt(sys.argv[1:], "x:b:", ["xref=", "base="])

    if not len(args):
        raise getopt.error("no args")
except getopt.GetoptError:
    sys.stderr.write("usage: ps_graph_cat [-x <xrefs file> -b <base addr>] <file_1> [file_2] ...")
    sys.exit(1)

for o, a in opts:
    if o in ("-x", "--xref"): xref_file    = a
    if o in ("-b", "--base"): base_address = long(a, 16)

for input_file in args:
    graph_parser = gml_graph(uid_start)

    try:
        graph_parser.parse_file(input_file)
    except psx, x:
        sys.stderr.write(x.__str__())
        sys.exit(1)

    # for the next graph, increment the uid start by the number of nodes in this graph.
    uid_start = uid_start + graph_parser.num_nodes()

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