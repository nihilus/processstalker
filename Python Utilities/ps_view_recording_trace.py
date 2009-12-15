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
# this utility is provided as a means to visualize the results of a recorder file in sequential order. it will "fold"
# repeat sequences and cluster them together with a repeat count.
#
# note: this utility expects the .gml function graphs to exist in the current
#       directory.
#
# example usage:
#
#     ps_view_recording_trace recording.0.processed > recording.0.gml
#

import random
import sys
sys.path.append(sys.argv[0].rsplit('/', 1)[0] + "/ps_api")

from ps_parsers import *
from gml        import *
from psx        import *

# globals.
sequence   = []
edges      = []
output     = []
clusters   = []
node_cache = {}
uid_start  = 0

# command line argument sanity checking.
if len(sys.argv) < 2:
    sys.stderr.write("usage: ps_view_recording_trace <recording> > out.gml")
    sys.exit(1)

recording_file = sys.argv[1]

# open and parse the specified recorder file.
recording = recording_parser()

try:
    recording.parse(recording_file)
except psx, x:
    sys.stderr.write(x.__str__())
    sys.exit(1)

for i in xrange(recording.num_entries()):
    (time, thread, module, base, function, offset) = recording.get_recording_entry(i)

    function   = base + function
    offset     = base + offset
    graph_file = "%s-%08x.gml" % (module, function)

    # if this module doesn't have a key in the node cache, create it.
    if not node_cache.has_key(module):
        node_cache[module] = {}

    # if this node doesn't have an entry in the node cache, parse the function and load the underlying nodes.
    if not node_cache[module].has_key(offset):
        try:
            tmp_graph = gml_graph(uid_start)
            tmp_graph.parse_file(graph_file)

            # for the next graph, increment the uid start by the number of nodes in this graph.
            uid_start = uid_start + tmp_graph.num_nodes()
        except psx, x:
            sys.stderr.write(x.__str__())
            sys.exit(1)

        # add the nodes from this graph to the node cache.
        for i in xrange(tmp_graph.num_nodes()):
            node = tmp_graph.get_node(i)
            node_cache[module][node.get_block()] = node

    # add each module/offset pair to the output sequence.
    sequence.append((module, offset, node_cache[module][offset].get_uid()))

#
#                      F O L D I N G   A L G O R I T H M
#
# we use a sliding window, opened by 'pos' and closed by 'idx', to step through
# the input sequence while identifying clusters and filtering nodes into the
# output data structure. while stepping through the input sequence we look for
# one of the following three states:
#
#     - idx = pos, check for repeat sequence.
#     - current element not found in sliding window, add it to output.
#     - current element found in sliding window, look for new sequence.
#

pos = 0
idx = 0

# if folding is disabled, skip this loop.
while idx < len(sequence):
    #
    # if the current position 'idx' is the same as the position 'pos' then
    # check for a repeat sequence.
    #

    if idx == pos and len(clusters) > 0:
        (last_cluster, count) = clusters[len(clusters) - 1]

        # assume repeat sequence exists and disprove later.
        repeat_sequence = True

        # disprove above.
        for i in xrange(len(last_cluster)):
            (c_module, c_address, null) = last_cluster[i]
            (s_module, s_address, null) = sequence[idx + i]

            if c_module != s_module or c_address != s_address:
                repeat_sequence = False
                break

        # if a repeat sequence was found, then update the count and slide
        # positions 'idx' and 'pos', and continue with the next element.
        if repeat_sequence:
            count += 1
            clusters[len(clusters) - 1] = (last_cluster, count)
            idx = pos = idx + len(last_cluster)
            continue

    #
    # if the current element does not exist between position 'pos' and the
    # current position 'idx'. then add it to the output queue, increment 'idx'
    # and continue with the next element.
    #

    # assume not found and disprove later.
    found = False

    # disprove above.
    (idx_module, idx_address, idx_id) = sequence[idx]

    for i in xrange(pos, idx):
        (module, address, null) = sequence[i]
        if module == idx_module and address == idx_address:
            found = True

    if not found:
        output.append((idx_module, idx_address, idx_id))
        idx += 1
        continue

    #
    # no possibility exists for a repeat cluster, but a match for the current
    # sequence element was found. determine if a new cluster should be created.
    #

    (idx_module, idx_address, idx_id) = sequence[idx]

    for i in xrange(pos, idx):
        (module, address, null) = sequence[i]

        if module == idx_module and address == idx_address:
            # assume a sequence was found and disprove later.
            sequence_found  = True
            sequence_length = idx - i
            cluster         = []

            # ensure we have enough left in the sequence for a match to exist,
            # otherwise the current match is too far away and must be ignored.
            if idx + sequence_length > len(sequence):
                sequence_found = False
                break

            # disprove above.
            for j in xrange(i, idx):
                (t_module, t_address, t_id) = sequence[j]
                (n_module, n_address, n_id) = sequence[j + sequence_length]

                # determine the node id from the output list.
                found = False

                # search through the output list backwards.
                i = len(output) - 1

                while i >= 0:
                    (out_module, out_address, out_id) = output[i]

                    if out_module == t_module and out_address == t_address:
                        node_id = out_id
                        break

                    i -= 1

                cluster.append((t_module, t_address, node_id))

                if t_module != n_module or t_address != n_address:
                    sequence_found = False
                    break

    # if a sequence was found, then create a cluster for it.
    if sequence_found:
        clusters.append((cluster, 2))
        idx += len(cluster)
        pos = idx
    # otherwise add the element to the output queue, increment 'idx' and
    # continue with the next element.
    else:
        output.append((idx_module, idx_address, idx_id))
        idx += 1

#
# construct the output graph
#

output_graph = gml_graph()

# node.
for (module, offset, node_id) in output:
        # retrieve the node from the node cache
        node = node_cache[module][offset]

        # add the node to the output graph.
        output_graph.add_node(node)

        # add this node id to the edge list.
        edges.append(node_id)

# edges.
for i in xrange(len(edges) - 1):
    # create edge.
    edge = gml_edge()
    edge.set_src_id(edges[i])
    edge.set_dst_id(edges[i+1])
    edge.set_src_uid(edges[i])
    edge.set_dst_uid(edges[i+1])

    # add the edge to the output graph.
    output_graph.add_edge(edge)


# clusters.
cluster_id = 0
for (vertices, count) in clusters:
    cluster = gml_cluster()

    cluster_color = "#%02x%02x%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
    cluster.set_g_fill(cluster_color)
    cluster.set_id(cluster_id)

    # list the vertices in this cluster.
    for (null, null, vertex) in vertices:
        cluster.add_vertex(vertex)

    output_graph.add_cluster(cluster)

    cluster_id += 1

print output_graph.render()