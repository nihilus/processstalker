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
# this utility will generate basic statistics on a recording including:
#
#    - per function hit count.
#    - function to function transition time.
#
# example usage:
#
#     ps_view_recording_stats recording.0.processed sort
#

import sys
sys.path.append(sys.argv[0].rsplit('/', 1)[0] + "/ps_api")

from ps_parsers import *
from psx        import *

# globals.
function_list  = {}
function_times = {}
last_module    = ""
last_function  = 0
last_time      = 0

# command line argument sanity checking.
if len(sys.argv) < 2:
    sys.stderr.write("usage: ps_view_recording_stats <recording> [sort]")
    sys.exit(1)

recording_file = sys.argv[1]

# determine if the second (optional) 'sort' argument was given.
if len(sys.argv) == 3:
    sort = True
else:
    sort = False

# open and parse the specified recorder file.
recording = recording_parser()

try:
    recording.parse(recording_file)
except psx, x:
    sys.stderr.write(x.__str__())
    sys.exit(1)

for i in xrange(recording.num_entries()):
    (time, thread, module, base, function, offset) = recording.get_recording_entry(i)

    function = base + function
    offset   = base + offset

    # initial 'last' variables.
    if not last_module:   last_module   = module
    if not last_function: last_function = function
    if not last_time:     last_time     = time

    # function transition.
    if function != last_function:
        function_time = time - last_time

        if not function_times.has_key(module):
            function_times[module] = []

        function_times[module].append((function_time, last_function))

        # update the 'last' variables.
        last_module   = module
        last_function = function
        last_time     = time

    # record a hit for this function in our function list.
    if not function_list.has_key(module):
        function_list[module] = {}

    if not function_list[module].has_key(function):
        function_list[module][function] = 1
    else:
        function_list[module][function] += 1

# record a transition for the last function.
function_time = time - last_time

if not function_times.has_key(module):
    function_times[module] = []

function_times[module].append((function_time, last_function))

#
# print the function hit-count list.
#

for module in function_list:
    print "\n\nfunction block hit counts for module %s\n" % module

    # convert dictionary to sortable list.
    sorted_list = []

    for function in function_list[module]:
        sorted_list.append((function_list[module][function], function))

    if sort:
        sorted_list.sort()

    i = 1
    for (count, function) in sorted_list:
        print "\t %08x\t%6d" % (function, count),

        if i % 3 == 0: print
        i += 1

#
# print the function transition time list.
#

for module in function_times:
    print "\n\nfunction transition times (milliseconds) for module %s\n" % module

    if sort:
        function_times[module].sort()

    i = 1
    for (time, function) in function_times[module]:
        print "\t %08x\t%6d" % (function, time),

        if i % 3 == 0: print
        i += 1