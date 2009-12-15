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
# this utility constructs a "state mapping" from multiple recorder files. the visualization is function-level and
# clusters nodes together by recorder state. example usage:
#
#     ps_state_mapper module.xrefs DEADBEEF recorder.0 recorder.1 > out.gml
#

import os
import random
import sys
sys.path.append(sys.argv[0].rsplit('/', 1)[0] + "/ps_api")

from ps_parsers import *
from gml        import *
from psx        import *

# globals.
graph      = gml_graph()
clusters   = {}
node_id    = 0
cluster_id = 0

# command line sanity checking.
try:
    if len(sys.argv) < 4:
        raise Exception

    xrefs_file   = sys.argv[1]
    base_address = long(sys.argv[2], 16)
    xref_module  = os.path.basename(sys.argv[1]).replace(".xrefs", "")
except:
    sys.stderr.write("ps_state_mapper <xrefs file> <base address> <recorder0 recorder1 [...]> > out.gml")
    sys.exit(1)

# open the cross-references file and load it into memory, rebased.
xrefs = xrefs_parser(base_address)

try:
    xrefs.parse(xrefs_file)
except psx, x:
    sys.stderr.write(x.__str__())
    sys.exit(1)

# open and parse the specified recorder files.
for arg in xrange(3, len(sys.argv)):
    recording_file = sys.argv[arg]
    recording      = recording_parser()

    try:
        recording.parse(recording_file)
    except psx, x:
        sys.stderr.write(x.__str__())
        continue

    # step through the recording entries.
    for i in xrange(recording.num_entries()):
        (null, null, module, base, function, null) = recording.get_recording_entry(i)

        # rebase the function.
        function = base + function

        # we only care about recording lines for the xrefs module specified.
        if module.lower() == xref_module.lower():
            # create a cluster for this recording file if it doesn't already exist.
            if not clusters.has_key(recording_file):
                clusters[recording_file] = gml_cluster()
                clusters[recording_file].set_id(cluster_id)
                clusters[recording_file].set_label(recording_file)

                cluster_id = cluster_id + 1

            # if this node doesn't already exist within the graph/cluster, add it.
            node = graph.find_node_by_address(function)

            if not node:
                node = gml_node()
                node.set_function(function)
                node.set_block(function)
                node.set_name("0x%08x" % function)
                node.set_label("0x%08x" % function)
                node.set_g_fill("#FFFF00")
                node.set_id(node_id)
                node.set_uid(node_id)
                node.set_g_width(300)
                node.set_g_height(300)

                graph.add_node(node)

                node_id = node_id + 1

            # add the node to the cluster.
            clusters[recording_file].add_vertex(node.get_id())

# add the edges to the graph.
for i in xrange(xrefs.num_entries()):
    (source, null, destination) = xrefs.get_xref_entry(i)

    # prevent self loops.
    if source != destination:
        src_node = graph.find_node_by_address(source)
        dst_node = graph.find_node_by_address(destination)

        # if both the source and destination nodes exist in the graph, create an edge.
        if src_node and dst_node:
            edge = gml_edge()
            edge.set_src_id(src_node.get_id())
            edge.set_dst_id(dst_node.get_id())
            edge.set_src_uid(src_node.get_uid())
            edge.set_dst_uid(dst_node.get_uid())
            graph.add_edge(edge)

# add the clusters to the graph
for cluster in clusters:
    cluster_color = "#%02x%02x%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
    clusters[cluster].set_g_fill(cluster_color)

    graph.add_cluster(clusters[cluster])

# render the constructed graph.
print graph.render()