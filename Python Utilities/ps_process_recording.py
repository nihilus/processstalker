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
# this utility is provided to process a recording to add function offsets to breakpoint addresses and optionally rebase
# the recording addresses. this utility must be applied to a recording before it can be visualized with
# ps_view_recording or ps_view_states.
#
# note: this utility expects the .bpl breakpoint lists to exist in the current
#       directory.
#
# example usage:
#
#     ps_process_recording recording.0
#

import sys
sys.path.append(sys.argv[0].rsplit('/', 1)[0] + "/ps_api")

from ps_parsers import *
from psx        import *

if len(sys.argv) < 2:
    sys.stderr.write("usage: ps_process_recording <recording> [base address]")
    sys.exit(1)

recording = sys.argv[1]

if len(sys.argv) == 3:
    base_address = long(sys.argv[2], 16)
else:
    base_address = 0

# instantiate a recorder object and pre-process the specified file.
parser = recording_parser()

try:
    parser.pre_process(recording, base_address)
except psx, x:
    sys.stderr.write(x.__str__())
    sys.exit(1)

# command line argument sanity checking.
try:
    # attempt to open the recording.
    recording = open(sys.argv[1])
except:
    msg = "usage: ps_process_recording <recording> [base address]"
    sys.stderr.write(msg)
    sys.exit(1)
