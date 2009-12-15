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
# this utility is provided to convert a recording into a function list that can be later utilized in a call to the
# breakpoint filter utility. example usage:
#
#     ps_recording_to_list recording.0.processed
#

import sys
sys.path.append(sys.argv[0].rsplit('/', 1)[0] + "/ps_api")

from ps_parsers import *
from psx        import *

# global.
modules = {}

if len(sys.argv) < 2:
    sys.stderr.write("usage: ps_recording_to_list <processed recording> [module]")
    sys.exit(1)

recording = sys.argv[1]

# instantiate a recorder object and parse the specified file.
parser = recording_parser()

try:
    parser.parse(recording)
except psx, x:
    sys.stderr.write(x.__str__())
    sys.exit(1)

# step through the entires in this recording.
for i in xrange(parser.num_entries()):
    (time, thread, module, base, function, offset) = parser.get_recording_entry(i)

    # ensure a key exists for the module the current entry resides in.
    if not modules.has_key(module):
        modules[module] = []

    # add the function to the global data struct.
    if not modules[module].count(function):
        modules[module].append(function)

# if a module was specified on the command line then only output the function list for that module.
if len(sys.argv) == 3:
    modules[sys.argv[2]].sort()
    for function in modules[sys.argv[2]]:
        sys.stdout.write("%08x:" % function)
# otherwise output the function list for all modules.
else:
    for module in modules:
        print "module " + module
        print "\t",

        modules[module].sort()
        for function in modules[module]:
            print "%08x" % function,