#!/usr/bin/python
#!c:\python\python.exe

#
# Process Stalker - Python API
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

'''
@author:  Pedram Amini
@license: GNU General Public License 2.0 or later
@contact: pedram.amini@gmail.com
'''

import re
import sys

from pyparsing import __version__ as pyparsing_version
from pyparsing import *

from psx import *

########################################################################################################################

class gml_cluster:
    '''
    Clusters contain a number of attributes that describe the size, color, label, nodes etc. of the displayable groups
    nodes. Relevant getters and setters exist for manipulating cluster attributes. The render() routine should be used
    for returning a cluster description suitable for inclusion in a GML file.
    '''

    ####################################################################################################################
    def __init__ (self):
        '''
        Set the default attributes for the newly created cluster. See the source if you want to modify the default
        creation values.
        '''

        self.id           = 0
        self.label        = ""
        self.g_x          = 0
        self.g_y          = 0
        self.g_width      = 0
        self.g_height     = 0
        self.g_fill       = "#900fd0"
        self.g_pattern    = 1
        self.g_line_fill  = "#999999"
        self.g_line_width = 2.0
        self.g_stipple    = 1
        self.g_style      = "rectangle"
        self.vertices     = []

    ####################################################################################################################
    def add_vertex (self, node_id):
        '''
        Add a node ID as a vertex in the cluster, ignores duplicates.

        @type  node_id: Integer
        @param node_id: Node identifier to add
        '''

        if self.vertices.count(node_id) == 0:
            self.vertices.append(node_id)

    ####################################################################################################################
    def del_vertex (self, node_id):
        '''
        Delete a node ID as a vertex from the cluster.

        @type  node_id: Integer
        @param node_id: Node identifier
        '''

        self.vertices.remove(node_id)

    ####################################################################################################################
    def get_g_fill (self):
        '''
        Get the fill color of the cluster from the graphics sub-header.

        @rtype:  HTML RGB string (ex: #CCFFCC)
        @return: Color
        '''

        return self.g_fill

    ####################################################################################################################
    def get_g_height (self):
        '''
        Get the height of the cluster from the graphics sub-header.

        @rtype:  Integer
        @return: Cluster height in pixels
        '''

        return self.g_height

    ####################################################################################################################
    def get_g_line_fill (self):
        '''
        Get the fill color of the border line from the graphics sub-header.

        @rtype:  HTML RGB string (ex: #CCFFCC)
        @return: Color
        '''

        return self.g_line_fill

    ####################################################################################################################
    def get_g_line_width (self):
        '''
        Get the width of the border line for the cluster from the graphics sub-header.

        @rtype:  Float
        @return: Line width in pixels
        '''

        return self.g_line_width

    ####################################################################################################################
    def get_g_pattern (self):
        '''
        Get the pattern value for the cluster from the graphics sub-header.

        @rtype:  Integer
        @return: Pattern value
        '''

        return self.g_pattern

    ####################################################################################################################
    def get_g_stipple (self):
        '''
        Get the stipple value for the cluster from the graphics sub-header.

        @rtype:  Integer
        @return: Stipple value
        '''

        return self.g_stipple

    ####################################################################################################################
    def get_g_style (self):
        '''
        Get the style for the cluster from the graphics sub-header. For the purposes of Process
        Stalker this value will always be "rectangle".

        @rtype:  String
        @return: Style
        '''

        return self.g_style

    ####################################################################################################################
    def get_g_width (self):
        '''
        Get the width of the cluster from the graphics sub-header.

        @rtype:  Integer
        @return: Line width in pixels
        '''

        return self.g_width

    ####################################################################################################################
    def get_g_x (self):
        '''
        Get the x coordinate of the top left corner of the cluster in the graphics sub-header.

        @rtype:  Integer
        @return: X-Coordinate in pixels
        '''

        return self.g_x

    ####################################################################################################################
    def get_g_y (self):
        '''
        Get the y coordinate of the top left corner of the cluster in the graphics sub-header.

        @rtype:  Integer
        @return: Y-Coordinate in pixels
        '''

        return self.g_y

    ####################################################################################################################
    def get_id (self):
        '''
        Get the identifier for the cluster.

        @rtype:  Integer
        @return: Identifier
        '''

        return self.id

    ####################################################################################################################
    def get_label (self):
        '''
        Get the label (if any) of the cluster.

        @rtype:  String
        @return: Cluster label
        '''

        return self.label

    ####################################################################################################################
    def get_vertices (self):
        '''
        Return the list of vertices in the cluster.

        @rtype:  List
        @return: Sorted list of vertices
        '''

        self.vertices.sort()
        return self.vertices

    ####################################################################################################################
    def render (self):
        '''
        Render a cluster description suitable for use in a GML file using the set internal attributes.

        @rtype:  String
        @return: GML cluster description
        '''

        cluster  = "  cluster [\n"
        cluster += "    id %d\n"              % self.id
        cluster += "    label \"%s\"\n"       % self.label
        cluster += "    graphics [\n"
        cluster += "      x %d.000\n"         % self.g_x
        cluster += "      y %d.000\n"         % self.g_y
        cluster += "      width %d.000\n"     % self.g_width
        cluster += "      height %d.000\n"    % self.g_height
        cluster += "      fill \"%s\"\n"      % self.g_fill
        cluster += "      pattern %d\n"       % self.g_pattern
        cluster += "      color \"%s\"\n"     % self.g_line_fill
        cluster += "      lineWidth %f\n"     % self.g_line_width
        cluster += "      stipple %d\n"       % self.g_stipple
        cluster += "      style \"%s\"\n"     % self.g_style
        cluster += "    ]\n"

        # ensure the vertex list is sorted prior to enumerating it.
        self.vertices.sort()

        for v in self.vertices:
            cluster += "    vertex \"%d\"\n"  % v

        cluster += "  ]\n"

        return cluster

    ####################################################################################################################
    def set_g_fill (self, color):
        '''
        Set the fill color of the cluster in the graphics sub-header.

        @type  color: HTML RGB string (ex: #CCFFCC)
        @param color: Color
        '''

        self.g_fill = color

    ####################################################################################################################
    def set_g_height (self, pixels):
        '''
        Set the height of the cluster in the graphics sub-header.

        @type  pixels: Integer
        @param pixels: Cluster height in pixels
        '''

        self.g_height = pixels

    ####################################################################################################################
    def set_g_line_fill (self, color):
        '''
        Set the fill color of the border line in the graphics sub-header.

        @type  color: HTML RGB string (ex: #CCFFCC)
        @param color: Color
        '''

        self.g_line_fill = color

    ####################################################################################################################
    def set_g_line_width (self, pixels):
        '''
        Set the width of the border line for the cluster in the graphics sub-header.

        @type  pixels: Float
        @param pixels: Line width in pixels
        '''

        self.g_line_width = pixels

    ####################################################################################################################
    def set_g_pattern (self, pattern):
        '''
        Set the pattern type for the cluster in the graphics sub-header.

        @type  pattern: Integer
        @param pattern: Pattern value
        '''

        self.g_pattern = pattern

    ####################################################################################################################
    def set_g_stipple (self, stipple):
        '''
        Set the stipple type for the cluster in the graphics sub-header.

        @type  stipple: Integer
        @param stipple: Stipple value
        '''

        self.g_stipple = stipple

    ####################################################################################################################
    def set_g_style (self, style):
        '''
        Set the style for the cluster from the graphics sub-header. For the purposes of Process Stalker this value will
        always be "rectangle".

        @type  style: String
        @param style: Style
        '''

        self.g_style = style

    ####################################################################################################################
    def set_g_width (self, pixels):
        '''
        Set the width of the cluster in the graphics sub-header.

        @type  pixels: Integer
        @param pixels: Cluster width in pixels
        '''

        self.g_width = pixels

    ####################################################################################################################
    def set_g_x (self, x):
        '''
        Set the x coordinate of the top left corner of the cluster in the graphics sub-header.

        @type  x: Integer
        @param x: X-Coordinate in pixels
        '''

        self.g_x = x

    ####################################################################################################################
    def set_g_y (self, y):
        '''
        Set the y coordinate of the top left corner of the cluster in the graphics sub-header.

        @type  y: Integer
        @param y: Y-Coordinate in pixels
        '''

        self.g_y = y

    ####################################################################################################################
    def set_id (self, id):
        '''
        Set the identifier for the cluster.

        @type  id: Integer
        @param id: Identifier
        '''

        self.id = id

    ####################################################################################################################
    def set_label (self, label):
        '''
        Set the label of this cluster.

        @type  label: String
        @param label: Cluster label
        '''

        self.label = label

    ####################################################################################################################
    def __module_test__ (self):
        '''
            Run a few basic tests to ensure the class is working.
        '''

        self.set_id(1)
        self.set_label("test label")
        self.set_g_fill("#123456")
        self.set_g_width(100)
        self.set_g_height(200)
        self.set_g_line_fill("#aabbcc")
        self.set_g_line_width(2.0)
        self.set_g_x(1000)
        self.set_g_y(2000)
        self.add_vertex(5)
        self.add_vertex(100)
        self.add_vertex(50)
        self.add_vertex(50)
        self.del_vertex(5)
        self.add_vertex(15)

        print self.render()

########################################################################################################################

class gml_edge:
    '''
    Edges contain a number of attributes that describe the source, destination, color, shape etc. of displayable lines.
    Relevant getters and setters exist for manipulating edge attributes. The render() routine should be used for
    returning an edge description suitable for inclusion in a GML file.
    '''

    ####################################################################################################################
    def __init__ (self):
        '''
        Set the default attributes for the newly created edge. See the source if you want to modify the default creation
        values.
        '''

        self.src_id         = 0
        self.dst_id         = 0
        self.src_uid        = 0
        self.dst_uid        = 0
        self.generalization = 0
        self.g_type         = "line"
        self.g_arrow        = "none"
        self.g_stipple      = 1
        self.g_line_width   = 1.0
        self.g_fill         = "#0000FF"

    ####################################################################################################################
    def get_dst_id (self):
        '''
        Get the identifier for the edges destination. This identifier can *not* be assumed to be unique. See
        get_dst_uid().

        @rtype:  Integer
        @return: Identifier
        '''

        return self.dst_id

    ####################################################################################################################
    def get_dst_uid (self):
        '''
        Get the unique identifier for the edges destination. The dst_id member variable stores the original value from
        the GML file. The purpose of the UID is to uniquely identify the edge destination among a list of loaded edges
        that may potentially have overlapping IDs. The parser class will automatically assign an incremented value.

        @rtype:  Integer
        @return: Unique identifier
        '''

        return self.dst_uid

    ####################################################################################################################
    def get_g_arrow (self):
        '''
        Get the arrow type for the edge from the graphics sub-header.

        @rtype:  String
        @return: Arrow type
        '''

        return self.g_arrow

    ####################################################################################################################
    def get_g_fill (self):
        '''
        Get the fill color of the edge from the graphics sub-header.

        @rtype:  HTML RGB string (ex: #CCFFCC)
        @return: Color
        '''

        return self.g_fill

    ####################################################################################################################
    def get_g_line_width (self):
        '''
        Get the line width for the edge from the graphics sub-header.

        @rtype:  Float
        @return: Line width in pixels
        '''

        return self.g_line_width

    ####################################################################################################################
    def get_g_stipple (self):
        '''
        Get the stipple value for the edge from the graphics sub-header.

        @rtype:  Integer
        @return: Stipple value
        '''

        return self.g_stipple

    ####################################################################################################################
    def get_g_type (self):
        '''
        Get the shape for the edge from the graphics sub-header. For the purposes of Process Stalker this value will be
        "line".

        @rtype:  String
        @return: Line type
        '''

        return self.g_type

    ####################################################################################################################
    def get_generalization (self):
        '''
        Get the generalization value for this edge.

        @rtype:  Integer
        @return: Generalization
        '''

        return self.generalization

    ####################################################################################################################
    def get_src_id (self):
        '''
        Get the identifier for the edges source. This identifier can *not* be assumed to be unique. See get_src_uid().

        @rtype:  Integer
        @return: Identifier
        '''

        return self.src_id

    ####################################################################################################################
    def get_src_uid (self):
        '''
        Get the unique identifier for the edges source. The src_id member variable stores the original value from the
        GML file. The purpose of the UID is to uniquely identify the edge source among a list of loaded edges that may
        potentially have overlapping IDs. The parser class will automatically assign an incremented value.

        @rtype:  Integer
        @return: Unique identifier
        '''

        return self.src_uid

    ####################################################################################################################
    def render (self):
        '''
        Render an edge description suitable for use in a GML file using the set internal attributes.

        @rtype:  String
        @return: GML edge description
        '''

        edge  = "  edge [\n"
        edge += "    source %d\n"          % self.src_uid
        edge += "    target %d\n"          % self.dst_uid
        edge += "    generalization %d\n"  % self.generalization
        edge += "    graphics [\n"
        edge += "      type \"%s\"\n"      % self.g_type
        edge += "      arrow \"%s\"\n"     % self.g_arrow
        edge += "      stipple %d\n"       % self.g_stipple
        edge += "      lineWidth %f\n"     % self.g_line_width
        edge += "      fill \"%s\"\n"      % self.g_fill
        edge += "    ]\n"
        edge += "  ]\n"

        return edge

    ####################################################################################################################
    def set_dst_id (self, id):
        '''
        Set the identifier for the edges destination. This identifier can *not* be assumed to be unique. See
        set_dst_uid().

        @type  id: Integer
        @param id: Identifier
        '''

        self.dst_id = id

    ####################################################################################################################
    def set_dst_uid (self, uid):
        '''
        Set the unique identifier for the edges destination. The dst_id member variable stores the original value from
        the GML file. The purpose of the UID is to uniquely identify the edge destination among a list of loaded edges
        that may potentially have overlapping IDs. The parser class will automatically assign an incremented value.

        @type  uid: Integer
        @param uid: Unique identifier
        '''

        self.dst_uid = uid

    ####################################################################################################################
    def set_g_arrow (self, arrow):
        '''
        Set the arrow type for the edge in the graphics sub-header.

        @type  arrow: String
        @param arrow: Arrow type
        '''

        self.g_arrow = arrow

    ####################################################################################################################
    def set_g_fill (self, color):
        '''
        Set the fill color of the edge in the graphics sub-header.

        @type  color: HTML RGB string (ex: #CCFFCC)
        @param color: Color
        '''

        self.g_fill = color

    ####################################################################################################################
    def set_generalization (self, generalization):
        '''
        Set the generalization value for the edge.

        @type  generalization: Integer
        @param generalization: Generalization value
        '''

        self.generalization = generalization

    ####################################################################################################################
    def set_g_line_width (self, pixels):
        '''
        Set the line width for the edge in the graphics sub-header.

        @type  pixels: Float
        @param pixels: Line width in pixels
        '''

        self.g_line_width = pixels

    ####################################################################################################################
    def set_g_stipple (self, stipple):
        '''
        Set the stipple value for the edge in the graphics sub-header.

        @type  stipple: Integer
        @param stipple: Stipple value
        '''

        self.g_stipple = stipple

    ####################################################################################################################
    def set_g_type (self, type):
        '''
        Set the shape for the edge in the graphics sub-header. For the purposes of Process Stalker this value will be
        "line".

        @type  type: String
        @param type: Line type
        '''

        self.g_type = type

    ####################################################################################################################
    def set_src_id (self, id):
        '''
        Set the identifier for the edges source. This identifier can *not* be assumed to be unique. See get_src_uid().

        @type  id: Integer
        @param id: Identifier
        '''

        self.src_id = id

    ####################################################################################################################
    def set_src_uid (self, uid):
        '''
        Set the unique identifier for the edges source. The src_id member variable stores the original value from the
        GML file. The purpose of the UID is to uniquely identify the edge source among a list of loaded edges that may
        potentially have overlapping IDs. The parser class will automatically assign an incremented value.

        @type  uid: Integer
        @param uid: Unique identifier
        '''

        self.src_uid = uid

    ####################################################################################################################
    def __module_test__ (self):
        '''
            Run a few basic tests to ensure the class is working.
        '''

        self.set_src_id(10)
        self.set_dst_id(20)
        self.set_src_uid(100)
        self.set_dst_uid(200)
        self.set_g_fill("#123456")

        print self.render()

########################################################################################################################

class gml_graph:
    '''
    This class ties together the node, edge and cluster classes into an abstracted graph object. The class is also
    capable of parsing a GML file into the relevant components and storing them within internal lists. The render()
    routine should be used for returning a graph description suitable for writing into a GML file. The render_to_file(),
    routine is a convenience function that should be used for saving a graph description rendering to disk.
    '''

    ####################################################################################################################
    def __init__ (self, uid_start=0):
        '''
        Initialize internal member variables.

        @type  uid_start: Integer
        @param uid_start: Optional number to start generating unique node ID's from.
        '''

        self.nodes     = []
        self.edges     = []
        self.clusters  = []

        self.uid_count = uid_start

        # quick search mappings.
        self.node_id_to_index      = {}
        self.node_address_to_index = {}

        # create the internal GML parser.
        self.gml_parser = None
        self.parser_define()

    ####################################################################################################################
    def add_cluster (self, cluster):
        '''
        Adds a cluster object to internal cluster list.

        @type  cluster: gml_cluster
        @param cluster: Cluster object

        @rtype:  Bool
        @return: True on success, False otherwise.
        '''

        if not isinstance(cluster, gml_cluster):
            return False

        self.clusters.append(cluster)
        return True

    ####################################################################################################################
    def add_edge (self, edge):
        '''
        Adds an edge object to internal edges list.

        @type  edge: gml_edge
        @param edge: Edge object

        @rtype:  Bool
        @return: True on success, False otherwise.
        '''

        if not isinstance(edge, gml_edge):
            return False

        self.edges.append(edge)
        return True

    ####################################################################################################################
    def add_node (self, node):
        '''
        Adds a node object to internal nodes list.

        @type  node: gml_node
        @param node: Node object

        @rtype:  Bool
        @return: True on success, False otherwise.
        '''

        if not isinstance(node, gml_node):
            return False

        self.nodes.append(node)

        # create data points in the quick search mappings.
        self.node_id_to_index      [node.get_id()]    = len(self.nodes) - 1
        self.node_address_to_index [node.get_block()] = len(self.nodes) - 1

        return True

    ####################################################################################################################
    def del_cluster (self, index):
        '''
        Delete a cluster from the internal list by it's index.

        @type  index: Integer
        @param index: Cluster index
        '''

        self.clusters.pop(index)

    ####################################################################################################################
    def del_edge (self, index):
        '''
        Delete an edge from the internal list by it's index.

        @type  index: Integer
        @param index: Edge index
        '''

        self.edges.pop(index)

    ####################################################################################################################
    def del_node (self, index):
        '''
        Delete a node from the internal list by it's index.

        @type  index: Integer
        @param index: Node index
        '''

        self.nodes.pop(index)

    ####################################################################################################################
    def find_cluster_by_node_id (self, node_id):
        '''
        Locate the cluster that contains the specified node ID.

        @type  node_id: Integer
        @param node_id: Node ID to search the cluster list for.

        @rtype:  gml_cluster
        @return: Found cluster or 'False' if not found
        '''

        for cluster in self.clusters:
            vertices = cluster.get_vertices()
            for vertex in vertices:
                if vertex == node_id:
                    return cluster

        return False

    ####################################################################################################################
    def find_node_by_address (self, node_address):
        '''
        Locate the node with the specified node address within in the internal list.

        @type  node_id: DWORD
        @param node_id: Node address to search for

        @rtype:  gml_node
        @return: Found node or 'False' if not found
        '''

        for node in self.nodes:
            if node.get_block() == node_address:
                return node

        return False

    ####################################################################################################################
    def find_node_by_id (self, node_id):
        '''
        Locate the node with the specified node ID within in the internal list.

        @type  node_id: Integer
        @param node_id: Node ID to search for

        @rtype:  gml_node
        @return: Found node or 'False' if not found
        '''

        # instead of iterating through the list here, we use the quick map.
        if self.node_id_to_index.has_key(node_id):
            return self.get_node(self.node_id_to_index[node_id])

        return False

    ####################################################################################################################
    def get_cluster (self, index):
        '''
        Return the cluster at the specified index.

        @type  index: Integer
        @param index: Index of cluster to return.

        @rtype:  gml_cluster
        @return: Cluster at specified index.

        @raise psx: An exception is raisd if the requested index is out of range.
        '''

        # ensure the requested index is within range.
        if index >= self.num_clusters():
            raise psx("Requested index is out of range.")

        return self.clusters[index]

    ####################################################################################################################
    def get_edge (self, index):
        '''
        Return the edge at the specified index.

        @type  index: Integer
        @param index: Index of edge to return.

        @rtype:  gml_edge
        @return: Edge at specified index.

        @raise psx: An exception is raisd if the requested index is out of range.
        '''

        # ensure the requested index is within range.
        if index >= self.num_edges():
            raise psx("Requested index is out of range.")

        return self.edges[index]

    ####################################################################################################################
    def get_node (self, index):
        '''
        Return the node at the specified index.

        @type  index: Integer
        @param index: Index of node to return.

        @rtype:  gml_node
        @return: Node at specified index.

        @raise psx: An exception is raisd if the requested index is out of range.
        '''

        # ensure the requested index is within range.
        if index >= self.num_nodes():
            raise psx("Requested index is out of range.")

        return self.nodes[index]

    ####################################################################################################################
    def num_clusters (self):
        '''
        Return the cluster count for the graph.

        @rtype:  Integer
        @return: Number of defined clusters in this graph.
        '''

        return len(self.clusters)

    ####################################################################################################################
    def num_edges (self):
        '''
        Return the edge count for the graph.

        @rtype:  Integer
        @return: Number of defined edges in this graph.
        '''

        return len(self.edges)

    ####################################################################################################################
    def num_nodes (self):
        '''
        Return the node count for the graph.

        @rtype:  Integer
        @return: Number of defined nodes in this graph.
        '''

        return len(self.nodes)

    ####################################################################################################################
    def parse_file (self, filename):
        '''
        Open the specified GML file and parse out the node, edge and cluster components.

        @type  filename: String
        @param filename: GML file to parse

        @raise psx: An exception is raised if parsing fails for any reason.
        '''

        # open the file, read-only.
        try:
            gml = open(filename, "r")
        except:
            raise psx("Unable to open '%s' for reading." % filename)

        gml_definition = ""

        # step through each line in the file and concatenate them into the string 'gml_definition'.
        for line in gml.readlines():
            line            = line.rstrip("\\\r\n")
            gml_definition += line

        self.parse(gml_definition)

    ####################################################################################################################
    def parse (self, gml_definition):
        '''
        Open the specified GML file and parse out the node, edge and cluster components.

        @type  gml_definition: String
        @param gml_definition: GML description to parse

        @raise psx: An exception is raised if parsing fails for any reason.
        '''

        try:
            if pyparsing_version >= '1.2':
                self.gml_parser.parseWithTabs()

            self.gml_parser.parseString(gml_definition)
        except ParseException, err:
            msg  = "*" * 80 + "\n"
            msg += "GML parsing error encountered. Please send the following error report and offending file to:\n\n"
            msg += "\tpedram.amini@gmail.com\n\n"
            msg += "*" * 80 + "\n\n"
            msg += err.line + "\n"
            msg += " " * (err.column-1) + "^" + "\n"
            msg += err.msg + "\n"
            sys.stderr.write(msg)

    ####################################################################################################################
    def parser_define(self):
        '''
        Define the pyparsing GML parser definition. This is my first experience with the pyparsing module,
        improvements are welcome.

        @todo: Modify parser definition such that attribute order is not important.
        '''

        # define punctuation
        lbrack = Literal("[").suppress()
        rbrack = Literal("]").suppress()

        # define what a floating point number looks like.
        float_number = OneOrMore(Word(nums + ".")).setName("float_number")

        # define attributes.
        arrow     = Group(CaselessLiteral("arrow")          + dblQuotedString.setParseAction(self.parser_strip_quotes))
        color     = Group(CaselessLiteral("color")          + dblQuotedString.setParseAction(self.parser_strip_quotes))
        creator   = Group(CaselessLiteral("creator")        + dblQuotedString.setParseAction(self.parser_strip_quotes))
        directed  = Group(CaselessLiteral("directed")       + Word(nums))
        fill      = Group(CaselessLiteral("fill")           + dblQuotedString.setParseAction(self.parser_strip_quotes))
        gen       = Group(CaselessLiteral("generalization") + Word(nums))
        h         = Group(CaselessLiteral("h")              + float_number)
        height    = Group(CaselessLiteral("height")         + float_number)
        id        = Group(CaselessLiteral("id")             + Word(nums))
        label     = Group(CaselessLiteral("label")          + dblQuotedString.setParseAction(self.parser_strip_quotes))
        line      = Group(CaselessLiteral("line")           + dblQuotedString.setParseAction(self.parser_strip_quotes))
        linewidth = Group(CaselessLiteral("linewidth")      + float_number)
        pattern   = Group(CaselessLiteral("pattern")        + (dblQuotedString.setParseAction(self.parser_strip_quotes)\
                                                            | Word(nums)))
        source    = Group(CaselessLiteral("source")         + Word(nums))
        stipple   = Group(CaselessLiteral("stipple")        + Word(nums))
        style     = Group(CaselessLiteral("style")          + dblQuotedString.setParseAction(self.parser_strip_quotes))
        target    = Group(CaselessLiteral("target")         + Word(nums))
        template  = Group(CaselessLiteral("template")       + dblQuotedString.setParseAction(self.parser_strip_quotes))
        type      = Group(CaselessLiteral("type")           + dblQuotedString.setParseAction(self.parser_strip_quotes))
        vertex    = Group(CaselessLiteral("vertex")         + dblQuotedString.setParseAction(self.parser_strip_quotes))
        w         = Group(CaselessLiteral("w")              + float_number)
        width     = Group(CaselessLiteral("width")          + float_number)
        x         = Group(CaselessLiteral("x")              + float_number)
        y         = Group(CaselessLiteral("y")              + float_number)

        ###
        ### define nodes.
        ###

        attributes    = Optional(x) + Optional(y) + w + h + fill + line + pattern + stipple + linewidth + type + width
        node_graphics = Group(CaselessLiteral("graphics") + lbrack + attributes + rbrack)

        attributes = id + template + label + node_graphics
        node       = CaselessLiteral("node") + lbrack + attributes + rbrack

        ###
        ### define edges.
        ###

        line_point = CaselessLiteral("point") + lbrack + x + y + rbrack
        edge_line  = CaselessLiteral("line")  + lbrack + OneOrMore(line_point) + rbrack

        attributes    = type + arrow + stipple + linewidth + Optional(edge_line) + fill
        edge_graphics = Group(CaselessLiteral("graphics") + lbrack + attributes + rbrack)

        attributes = source + target + gen + edge_graphics
        edge       = CaselessLiteral("edge") + lbrack + attributes + rbrack

        ###
        ### define graphs.
        ###

        attributes = ZeroOrMore(node) + ZeroOrMore(edge)
        graph      = CaselessLiteral("graph") + lbrack + attributes + rbrack

        ###
        ### define clusters.
        ###

        attributes       = Optional(x) + Optional(y) + Optional(width) + Optional(height) + fill + pattern + color + \
                           linewidth + stipple + style
        cluster_graphics = Group(CaselessLiteral("graphics") + lbrack + attributes + rbrack)

        attributes = id + label + cluster_graphics + ZeroOrMore(vertex)
        cluster    = CaselessLiteral("cluster") + lbrack + attributes + rbrack

        ###
        ### define rootclusters.
        ###

        rootcluster = CaselessLiteral("rootcluster") + lbrack + OneOrMore(cluster) + ZeroOrMore(vertex) + rbrack

        ###
        ### set parse actions.
        ###

        node.setParseAction(self.process_node)
        edge.setParseAction(self.process_edge)
        cluster.setParseAction(self.process_cluster)

        ###
        ### create the final GML definition.
        ###

        self.gml_parser = creator + directed + graph + Optional(rootcluster)

    ####################################################################################################################
    def parser_strip_quotes(self, original_string, location, tokens):
        '''
        This routine is used to strip quotes from matched GML element strings.

        @type  original_string: String
        @param original_string: The original parse string
        @type  location:        Integer
        @param location:        The location in the string where matching started
        @type  tokens:          ParseResults Object
        @param tokens:          The list of matched tokens
        '''

        return [ tokens[0].strip('"') ]

    ####################################################################################################################
    def process_cluster (self, original_string, location, tokens):
        '''
        This routine is called upon successful matching of cluster elements and is protyped as per the pyparsing
        specification.

        @type  original_string: String
        @param original_string: The original parse string
        @type  location:        Integer
        @param location:        The location in the string where matching started
        @type  tokens:          ParseResults Object
        @param tokens:          The list of matched tokens
        '''

        # insantiate a new cluster object.
        cluster = gml_cluster()

        # step through the list of cluster tokens, ignoring the first token ('cluster').
        for token in tokens[1:]:
            # 'graphics' tokens contain their own list of sub-tokens.
            if token[0] == "graphics":
                # step through the list of graphics tokens, ignoring the first token ('graphics').
                for (key, val) in token[1:]:
                    # determine the key type and set the relevant cluster-graphic attribute.
                    if key.lower() == "arrow":     cluster.set_g_arrow(val)
                    if key.lower() == "fill":      cluster.set_g_fill(val)
                    if key.lower() == "color":     cluster.set_g_line_fill(val)
                    if key.lower() == "linewidth": cluster.set_g_line_width(float(val))
                    if key.lower() == "stipple":   cluster.set_g_stipple(int(val))
                    if key.lower() == "style":     cluster.set_g_style(val)
            # standard token.
            else:
                # extract the key/val pair from the current token.
                (key, val) = token

                # determine the key type and set the relevant cluster attribute.
                if key.lower() == "id":     cluster.set_id(int(val))
                if key.lower() == "label":  cluster.set_label(val)
                if key.lower() == "vertex": cluster.add_vertex(int(val))

        # add the cluster object to the graph description.
        self.add_cluster(cluster)

    ####################################################################################################################
    def process_edge (self, original_string, location, tokens):
        '''
        This routine is called upon successful matching of edge elements and is protyped as per the pyparsing
        specification.

        @type  original_string: String
        @param original_string: The original parse string
        @type  location:        Integer
        @param location:        The location in the string where matching started
        @type  tokens:          ParseResults Object
        @param tokens:          The list of matched tokens
        '''

        # insantiate a new edge object.
        edge = gml_edge()

        # step through the list of edge tokens, ignoring the first token ('edge').
        for token in tokens[1:]:
            # 'graphics' tokens contain their own list of sub-tokens.
            if token[0] == "graphics":
                # step through the list of graphics tokens, ignoring the first token ('graphics').
                try:
                    for (key, val) in token[1:]:
                        # determine the key type and set the relevant edge-graphic attribute.
                        if key.lower() == "fill":      edge.set_g_fill(val)
                        if key.lower() == "pattern":   node.set_g_pattern(val)
                        if key.lower() == "stipple":   edge.set_g_stipple(int(val))
                        if key.lower() == "linewidth": edge.set_g_line_width(float(val))
                        if key.lower() == "type":      edge.set_g_type(val)
                except:
                    continue
            # standard token.
            else:
                # extract the key/val pair from the current token.
                (key, val) = token

                ### determine the key type and set the relevant edge attribute.
                if key.lower() == "generalization":
                    edge.set_generalization(int(val))

                # determine the source id of the edge
                if key.lower() == "source":
                    edge.set_src_id(int(val))

                    # determine the uid for the source node or default to using the id.
                    node = self.find_node_by_id(int(val))

                    if node:
                        edge.set_src_uid(node.get_uid())
                    else:
                        edge.set_src_uid(int(val))

                # determine the destination id of the edge
                if key.lower() == "target":
                    edge.set_dst_id(int(val))

                    # determine the uid for the target node or default to using the id.
                    node = self.find_node_by_id(int(val))

                    if node:
                        edge.set_dst_uid(node.get_uid())
                    else:
                        edge.set_dst_uid(int(val))

        # add the edge object to the graph description.
        self.add_edge(edge)

    ####################################################################################################################
    def process_node (self, original_string, location, tokens):
        '''
        This routine is called upon successful matching of node elements and is protyped as per the pyparsing
        specification.

        @type  original_string: String
        @param original_string: The original parse string
        @type  location:        Integer
        @param location:        The location in the string where matching started
        @type  tokens:          ParseResults Object
        @param tokens:          The list of matched tokens
        '''

        # insantiate a new node object.
        node = gml_node()

        # step through the list of node tokens, ignoring the first token ('node').
        for token in tokens[1:]:
            # 'graphics' tokens contain their own list of sub-tokens.
            if token[0] == "graphics":
                # step through the list of graphics tokens, ignoring the first token ('graphics').
                for (key, val) in token[1:]:
                    # determine the key type and set the relevant node-graphic attribute.
                    if key.lower() == "w":         node.set_g_width(float(val))
                    if key.lower() == "h":         node.set_g_height(float(val))
                    if key.lower() == "fill":      node.set_g_fill(val)
                    if key.lower() == "line":      node.set_g_line_fill(val)
                    if key.lower() == "pattern":   node.set_g_pattern(val)
                    if key.lower() == "stipple":   node.set_g_stipple(int(val))
                    if key.lower() == "linewidth": node.set_g_line_width(float(val))
                    if key.lower() == "type":      node.set_g_type(val)
                    if key.lower() == "width":     node.set_g_width_shape(float(val))
            # standard token.
            else:
                # extract the key/val pair from the current token.
                (key, val) = token

                ### determine the key type and set the relevant node attribute.
                if key.lower() == "template":
                    node.set_template(val)

                # uid = id
                if key.lower() == "id":
                    node.set_id(int(val))

                    # set this node's unique ID and increment the uid count.
                    node.set_uid(self.uid_count)
                    self.uid_count = self.uid_count + 1

                if key.lower() == "label":
                    # extract the id / offset mapping values, if available.
                    # example format: label "<!--node id:function offset:block offset-->

                    regex   = "<!--(\d+):([a-f0-9]+):([a-f0-9]+)-->(.*)"
                    matches = re.search(regex, val)

                    if matches:
                        (id, function, block, label) = matches.groups()

                        node.set_function(long(function, 16))
                        node.set_block(long(block, 16))
                        node.set_label(label)
                    else:
                        node.set_label(val)

                    # if this node is the start of a function, extract the function name.
                    if function == block:
                        # exmaple format: <font color=#004080><b>00401e80 sub_401E80</b></font>
                        regex   = "<font color=#004080><b>[a-f0-9]+ (\w+)</b></font>"
                        matches = re.search(regex, label)

                        if matches:
                            node.set_name(matches.groups()[0])

        # add the node object to the graph description.
        self.add_node(node)

    ####################################################################################################################
    def render (self):
        '''
        Render the GML graph description.

        @rtype:  String
        @return: GML graph description
        '''

        gml  = "Creator \"process stalker - pedram amini\"\n"
        gml += "directed 1\n"

        # open the graph tag.
        gml += "graph [\n"

        # add the nodes to the GML definition.
        for node in self.nodes:
            gml += node.render()

        # add the edges to the GML definition.
        for edge in self.edges:
            gml += edge.render()

        # close the graph tag.
        gml += "]\n"

        # if clusters exist.
        if len(self.clusters):
            # open the rootcluster tag.
            gml += "rootcluster [\n"

            # add the clusters to the GML definition.
            for cluster in self.clusters:
                gml += cluster.render()

            # add the clusterless nodes to the GML definition.
            for node in self.nodes:
                if not self.find_cluster_by_node_id(node.get_uid()):
                    gml += "    vertex \"%d\"\n" % node.get_uid()

            # close the rootcluster tag.
            gml += "]\n"

        return gml

    ####################################################################################################################
    def render_to_file (self, filename):
        '''
        Render the entire GML graph description.

        @type  filename: String
        @param filename: Filename to stored rendered GML definition to.

        @raise psx: An exception is raised if the specified file can not be opened for writing.
        '''

        # open the file in write mode, create it if it does exist, overwrite it if it does.
        try:
            file = open(filename, "w+")
        except:
            raise psx("Unable to open file '%s' for writing." % filename)

        # write the graph definition to file and close it.
        file.write(self.render())

        file.close()


    ####################################################################################################################
    def replace_node (self, index, node):
        '''
        Adds a node object to internal nodes list.

        @type  index: Integer
        @param index: Node index
        @type  node:  gml_node
        @param node:  Node object

        @rtype:  Bool
        @return: True on success, False otherwise.
        '''

        if not isinstance(node, gml_node):
            return False

        self.nodes[index] = node

        # get the node at the current index and remove it from the quick search mapping cache.
        old_node = self.get_node(index)

        del self.node_id_to_index      [old_node.get_id()]
        del self.node_address_to_index [old_node.get_block()]

        # create data points in the quick search mappings.
        self.node_id_to_index      [node.get_id()]    = index
        self.node_address_to_index [node.get_block()] = index

        return True

    ####################################################################################################################
    def __module_test__ (self):
        '''
            Run a few basic tests to ensure the class is working.
        '''

        data = """
            Creator "process stalker - pedram amini"
            directed 1
            graph [
              node [
                id 241
                template "oreas:std:rect"
                label "<!--10:deadbeef:c0cac01a-->stuff in node label"
                graphics [
                  w 432.0000000
                  h 520.0000000
                  fill "#CCFFCC"
                  line "#999999"
                  pattern "1"
                  stipple 1
                  lineWidth 1.0000000
                  type "rectangle"
                  width 1.0
                ]
              ]
              edge [
                source 241
                target 242
                generalization 0
                graphics [
                  type "line"
                  arrow "none"
                  stipple 1
                  lineWidth 1.0000000
                  fill "#FF0000"
                ]
              ]
            ]
            rootcluster [
              cluster [
                  id 1
                  label "004098e0 __WSAFDIsSet"
                  graphics [
                      fill "#d08429"
                      pattern 1
                      color "#999999"
                      lineWidth 2.000000000
                      stipple 1
                      style "rectangle"
                  ]
                  vertex "1413"
              ]
              cluster [
                  id 64
                  label "004108ca __ftbuf"
                  graphics [
                      fill "#bdf1de"
                      pattern 1
                      color "#999999"
                      lineWidth 2.000000000
                      stipple 1
                      style "rectangle"
                  ]
                  vertex "2073"
              ]
            ]
"""

        self.parse(data)
        print self.render()

########################################################################################################################

class gml_node:
    '''
    Nodes contain a number of attributes that describe the size, shape, color, label etc. of the displayable blocks.
    Relevant getters and setters exist for manipulating node attributes. The render() routine should be used for
    returning a node description suitable for inclusion in a GML file.
    '''

    ####################################################################################################################
    def __init__ (self):
        '''
        Set the default attributes for the newly created node. See the source if you want to modify the default creation
        values.
        '''

        self.uid           = 0
        self.id            = 0
        self.template      = "oreas:std:rect"
        self.function      = 0x00000000
        self.block         = 0x00000000
        self.name          = ""
        self.label         = ""
        self.g_width       = 0.0
        self.g_height      = 0.0
        self.g_fill        = "#CCFFCC"
        self.g_line_fill   = "#999999"
        self.g_pattern     = "1"
        self.g_stipple     = 1
        self.g_line_width  = 1.0
        self.g_type        = "rectangle"
        self.g_width_shape = 1.0
        self.registers     = {}

    ####################################################################################################################
    def get_block (self):
        '''
        Get the block address for the node.

        @rtype:  DWORD
        @return: Block address
        '''

        return self.block

    ####################################################################################################################
    def get_label (self):
        '''
        Get the label (disassembly) of the node.

        @rtype:  String
        @return: Node label (disassembly)
        '''

        return self.label

    ####################################################################################################################
    def get_label_stripped (self):
        '''
        Get the label (disassembly) of the node with all HTML entities stripped.

        @rtype:  String
        @return: Node label (disassembly) stripped

        @todo: There may be some Python routines that can do some of this work for us.
        '''

        stripped = self.label

        stripped = stripped.replace("&nbsp;", " ")
        stripped = stripped.replace("<br>", "\n")
        stripped = stripped.replace("<br />", "\n")
        stripped = stripped.replace("</p>", "\n")
        stripped = re.sub("^\s*label \"", "", stripped)
        stripped = re.sub("<.*?>", "", stripped)
        stripped = stripped.replace("&amp;", "&")
        stripped = stripped.replace("&lt;", "<")
        stripped = stripped.replace("&gt;", ">")
        stripped = stripped.replace("\xa0", " ")

        return stripped

    ####################################################################################################################
    def get_function (self):
        '''
        Get the address of the function the node belongs to.

        @rtype:  DWORD
        @return: Function address
        '''

        return self.function

    ####################################################################################################################
    def get_g_fill (self):
        '''
        Get the fill color of the node from the graphics sub-header.

        @rtype:  HTML RGB string (ex: #CCFFCC)
        @return: Color
        '''

        return self.g_fill

    ####################################################################################################################
    def get_g_height (self):
        '''
        Get the height of the node from the graphics sub-header.

        @rtype:  Float
        @return: Node height in pixels
        '''

        return self.g_height

    ####################################################################################################################
    def get_g_line_fill (self):
        '''
        Get the fill color of this line from the graphics sub-header.

        @rtype:  HTML RGB string (ex: #CCFFCC)
        @return: Color
        '''

        return self.g_line_fill

    ####################################################################################################################
    def get_g_line_width (self):
        '''
        Get the width of the border line for the node from the graphics sub-header.

        @rtype:  Float
        @return: Line width in pixels
        '''

        return self.g_line_width

    ####################################################################################################################
    def get_g_pattern (self):
        '''
        Get the pattern type for the node from the graphics sub-header.

        @rtype:  String
        @return: Pattern type
        '''

        return self.g_pattern

    ####################################################################################################################
    def get_g_stipple (self):
        '''
        Get the stipple value for the node from the graphics sub-header.

        @rtype:  Integer
        @return: Stipple value
        '''

        return self.g_stipple

    ####################################################################################################################
    def get_g_type (self):
        '''
        Get the shape for the node from the graphics sub-header. For the purposes of Process
        Stalker this value will be "rectangle".

        @rtype:  String
        @return: Shape type
        '''

        return self.g_type

    ####################################################################################################################
    def get_g_width (self):
        '''
        Get the width of the node from the graphics sub-header.

        @rtype:  Float
        @return: Node width in pixels
        '''

        return self.g_width

    ####################################################################################################################
    def get_g_width_shape (self):
        '''
        Get the shape width value for the node from the graphics sub-header. I'm actually unsure as to what exactly this
        attribute affects. For the purposes of Process Stalker this value will always be 1.

        @rtype:  Integer
        @return: Shape width
        '''

        return self.g_width_shape

    ####################################################################################################################
    def get_id (self):
        '''
        Get the identifier for the node. This identifier can *not* be assumed to be unique. See get_uid().

        @rtype:  Integer
        @return: Identifier
        '''

        return self.id

    ####################################################################################################################
    def get_name (self):
        '''
        Get the name (if any) of the node.

        @rtype:  String
        @return: Node name
        '''

        return self.name

    ####################################################################################################################
    def get_register (self, register):
        '''
        Get the values associated with the specified register for this node. Values are returned in the following list::

            (value, single_location, single_data, double_location, double_data)

        @type  register: String
        @param register: One of EAX, EBX, ECX, EDX, ESI, EDI, EBP
        @rtype:          Tuple
        @return:         Data for specified register or 'False' on error.
        '''

        register = register.upper()

        if register not in ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP"]:
            return False

        return ( \
            self.registers[register]["value"], \
            self.registers[register]["single_location"], self.registers[register]["single_data"], \
            self.registers[register]["double_location"], self.registers[register]["double_data"])

    ####################################################################################################################
    def get_template (self):
        '''
        Get the template for the node. For the purposes of Process Stalker this value will always be "oreas:std:rect".

        @rtype:  String
        @return: Template
        '''

        return self.template

    ####################################################################################################################
    def get_uid (self):
        '''
        Get the unique identifier for the node. The ID member variable stores the original value from the GML file. The
        purpose of the UID is to uniquely identify the node among a list of loaded nodes that may potentially have
        overlapping IDs. The parser class will automatically assign an incremented value.

        @rtype:  Integer
        @return: Unique identifier
        '''

        return self.uid

    ####################################################################################################################
    def render (self):
        '''
        Render a node description suitable for use in a GML file using the set internal attributes.

        @rtype:  String
        @return: GML node description
        '''

        # add available register values to the node label.
        register_header = ""
        regs_printed    = 0
        max_chars_wide  = 0

        # create a sorted list of register keys to iterate over.
        registers = self.registers.keys()
        registers.sort()

        for reg_name in registers:
            register = self.registers[reg_name]

            if regs_printed and regs_printed % 3 == 0:
                register_header += "<br>"

            register_header += "%s: <font color=#FF6600>%08x</font> " % (reg_name, register["value"])
            regs_printed    += 1

        # add available dereferenced register data to the node label.
        if register_header:
            register_header += "<br><br>"

        for reg_name in registers:
            register = self.registers[reg_name]

            for (location, data) in [("single_location", "single_data"), ("double_location", "double_data")]:
                if register[location]:
                    if len(register[data]) > max_chars_wide:
                        max_chars_wide = len(register[data])

                    # sanitize register header.
                    register[data] = register[data].replace("<",  "&lt;")
                    register[data] = register[data].replace(">",  "&gt;")
                    register[data] = register[data].replace("\\", "\\\\")
                    register[data] = register[data].replace("\"", "\\\"")

                    if register[location] == "heap":
                        location = "[<font color=#3399CC>%s</font>]&nbsp;" % register[location]
                    else:
                        location = "[<font color=#3399CC>%s</font>]" % register[location]

                    register_header += "&nbsp;*%s %s %s<br>" % (reg_name, location, register[data])

        if register_header:
            register_header += "<hr>"

            # add the register header to the label.
            matches = re.search("(<span .*?>)(<p><font color=#004080><b>.*?</b></font></p>)(.*)", self.label)

            if matches:
                (span, title, rest) = matches.groups()

            self.label = span + title + register_header + rest

            # expand the node width to accomodate the added data.
            required_width = (max_chars_wide + 15) * 8
            if self.get_g_width() < required_width:
                self.set_g_width(required_width)

            # expand the node height to accomodate the added data.
            added_height = (register_header.count("<br>") + 3) * 15
            self.set_g_height(self.get_g_height() + added_height)

        # GDE does not like lines longer then approx 250 bytes. within their their own GML files you won't find lines
        # longer then approx 210 bytes. wo we are forced to break long lines into chunks.
        chunked_label = ""
        cursor        = 0

        while cursor < len(self.label):
            amount = 200

            # if the end of the current chunk contains a backslash or double-quote, back off some.
            if cursor + amount < len(self.label):
                while self.label[cursor+amount] == '\\' or self.label[cursor+amount] == '"':
                    amount -= 1

            chunked_label += self.label[cursor:cursor+amount] + "\\\n"
            cursor        += amount

        # construct the node definition.
        node  = "  node [\n"
        node += "    id %d\n"              % self.uid
        node += "    template \"%s\"\n"    % self.template
        node += "    label \""
        node += "<!--%d:%08x:%08x-->\\\n"  % (self.uid, self.function, self.block)
        node += chunked_label + "\"\n"
        node += "    graphics [\n"
        node += "      w %f\n"             % self.g_width
        node += "      h %f\n"             % self.g_height
        node += "      fill \"%s\"\n"      % self.g_fill
        node += "      line \"%s\"\n"      % self.g_line_fill
        node += "      pattern \"%s\"\n"   % self.g_pattern
        node += "      stipple %d\n"       % self.g_stipple
        node += "      lineWidth %f\n"     % self.g_line_width
        node += "      type \"%s\"\n"      % self.g_type
        node += "      width %f\n"         % self.g_width_shape
        node += "    ]\n"
        node += "  ]\n"

        return node

    ####################################################################################################################
    def set_block (self, address):
        '''
        Set the block address for the node.

        @type  address: DWORD
        @param address: Block address
        '''

        self.block = address

    ####################################################################################################################
    def set_label (self, data):
        '''
        Set the label (disassembly) of the node.

        @type  data: String
        @param data: Node label (disassembly)
        '''

        self.label = data

    ####################################################################################################################
    def set_function (self, address):
        '''
        Set the address of the function the node belongs to.

        @type  address: DWORD
        @param address: Function address
        '''

        self.function = address

    ####################################################################################################################
    def set_g_fill (self, color):
        '''
        Set the fill color of the node in the graphics sub-header.

        @type  color: HTML RGB string (ex: #CCFFCC)
        @param color: Color
        '''

        self.g_fill = color

    ####################################################################################################################
    def set_g_height (self, pixels):
        '''
        Set the height of the node in the graphics sub-header.

        @type  pixels: Float
        @param pixels: Node height in pixels
        '''

        self.g_height = pixels

    ####################################################################################################################
    def set_g_line_fill (self, color):
        '''
        Set the fill color of this line in the graphics sub-header.

        @type  color: HTML RGB string (ex: #CCFFCC)
        @param color: Color
        '''

        self.g_line_fill = color

    ####################################################################################################################
    def set_g_line_width (self, pixels):
        '''
        Set the width of the border line for the node in the graphics sub-header.

        @type  pixels: Float
        @param pixels: Line width in pixels
        '''

        self.g_line_width = pixels

    ####################################################################################################################
    def set_g_pattern (self, pattern):
        '''
        Set the pattern type for the node in the graphics sub-header.

        @type  pattern: String
        @param pattern: Pattern type
        '''

        self.g_pattern = pattern

    ####################################################################################################################
    def set_g_stipple (self, stipple):
        '''
        Set the stipple value for the node in the graphics sub-header.

        @type  stipple: Integer
        @param stipple: Stipple value
        '''

        self.g_stipple = stipple

    ####################################################################################################################
    def set_g_type (self, type):
        '''
        Set the shape for the node in the graphics sub-header. For the purposes of Process Stalker this value will be
        "rectangle".

        @type  type: String
        @param type: Shape type
        '''

        self.g_type = type

    ####################################################################################################################
    def set_g_width (self, pixels):
        '''
        Set the width of the node in the graphics sub-header.

        @type  pixels: Float
        @param pixels: Node width in pixels
        '''

        self.g_width = pixels

    ####################################################################################################################
    def set_g_width_shape (self, pixels):
        '''
        Set the shape width value for the node in the graphics sub-header. I'm actually unsure as to what exactly this
        attribute affects. For the purposes of Process Stalker this value will always be 1.

        @type  pixels: Float
        @param pixels: Shape width
        '''

        self.g_width_shape = pixels

    ####################################################################################################################
    def set_id (self, id):
        '''
        Set the identifier for the node. This identifier can *not* be assumed to be unique. See set_uid().

        @type  id: Integer
        @param id: Identifier
        '''

        self.id = id

    ####################################################################################################################
    def set_name (self, name):
        '''
        Set the name of the node.

        @type  name: String
        @param name: Node name
        '''

        self.name = name

    ####################################################################################################################
    def set_register (self, register, value, single_location="", single_data="", double_location="", double_data=""):
        '''
        Set a register value for this node.

        @type  register:        String
        @param register:        One of EAX, EBX, ECX, EDX, ESI, EDI, EBP
        @type  value:           DWORD
        @param value:           32-bit register value
        @type  single_location: String
        @param single_location: Optional string specifying the location ("HEAP" or "STACK") *register "points" to.
        @type  single_data:     String
        @param single_data:     Optional string containing the data stored at *register.
        @type  double_location: String
        @param double_location: Optional string specifying the location ("HEAP" or "STACK") **register "points" to.
        @type  double_data:     String
        @param double_data:     Optional string containing the data stored at **register.
        '''

        register = register.upper()

        if register not in ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP"]:
            return

        self.registers[register]                    = {}
        self.registers[register]["value"]           = value
        self.registers[register]["single_location"] = single_location
        self.registers[register]["single_data"]     = single_data
        self.registers[register]["double_location"] = double_location
        self.registers[register]["double_data"]     = double_data


    ####################################################################################################################
    def set_template (self, template):
        '''
        Set the template for the node. For the purposes of Process Stalker this value will always be "oreas:std:rect".

        @type  template: String
        @param template: Template
        '''

        self.template = template

    ####################################################################################################################
    def set_uid (self, uid):
        '''
        Set the unique identifier for the node. The ID member variable stores the original value from the GML file. The
        purpose of the UID is to uniquely identify the node among a list of loaded nodes that may potentially have
        overlapping IDs. The parser class will automatically assign an incremented value.

        @type  uid: Integer
        @param uid: Unique identifier
        '''

        self.uid = uid

    ####################################################################################################################
    def __module_test__ (self):
        '''
            Run a few basic tests to ensure the class is working.
        '''

        self.set_id(10)
        self.set_uid(200)
        self.set_block(0xdeadbeef)
        self.set_label("test data")
        self.set_function(0xc0cac01a)
        self.set_g_fill("#123456")
        self.set_g_height(100.0)
        self.set_g_line_fill("#aabbcc")
        self.set_g_line_width(1.0)
        self.set_g_width(200.0)

        print self.render()