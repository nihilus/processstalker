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
# silly GDE will actually save GML files that it cannot parse. the issue occurs when node label lines end with:
#
#     font color=\
#
# the solution is to remove the leading '#' from the next line and append it to the "broken" line. example usage:
#
#     ps_gde_fixup in.gml
#

import sys

output = []

# command line argument sanity checking.
try:
    fixme = open(sys.argv[1])
except:
    sys.stderr.write("usage: ps_gde_fixup <in.gml>")
    sys.exit(1)

# step through the input file, fix each line and add it to the output queue.
for line in fixme.readlines():
    line = line.rstrip("\n")
    line = line.rstrip("\r")

    if line.endswith("color=\\"):
        line  = line.rstrip("\\")
        line += "#\\"

    if line.startswith("#"):
        line = line.lstrip("#")

    output.append(line)

# close the file and re-open it in write mode.
fixme.close()
fixme = open(sys.argv[1], "w")

# write the output queue to the file.
for line in output:
    fixme.write(line + "\n")

fixme.close()