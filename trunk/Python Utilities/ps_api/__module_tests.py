#!/usr/bin/python

from ps_parsers import *
from gml        import *

print "*" * 80
print "BPL Module Test\n"

try:
    b = bpl_parser()
    b.__module_test__()
except:
    pass

print "\n" + "*" * 80
print "Recording Module Test\n"

try:
    r = recording_parser()
    r.__module_test__()
except:
    pass

print "\n" + "*" * 80
print "XREFS Module Test\n"

try:
    x = xrefs_parser()
    x.__module_test__()
except:
    pass

print "\n" + "*" * 80
print "GML Cluster Module Test\n"

try:
    c = gml_cluster()
    c.__module_test__()
except:
    pass

print "\n" + "*" * 80
print "GML Edge Module Test\n"

try:
    e = gml_edge()
    e.__module_test__()
except:
    pass

print "\n" + "*" * 80
print "GML Graph Module Test\n"

try:
    g = gml_graph()
    g.__module_test__()
except:
    pass

print "\n" + "*" * 80
print "GML Node Module Test\n"

try:
    n = gml_node()
    n.__module_test__()
except:
    pass