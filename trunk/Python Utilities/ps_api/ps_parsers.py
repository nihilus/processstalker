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

from psx import *

########################################################################################################################

class bpl_parser:
    '''
    Breakpoint lists contain module names, function offset addresses and node offset addresses. Breakpoint lists are
    the main "technology" behind Process Stalker functionality. As such, breakpoint manipulation and filtering are
    important concepts which this class attempts to abstract.
    '''

    ####################################################################################################################
    def __init__ (self):
        '''
        Initialize internal member variables.
        '''

        self.functions = []
        self.modules   = []
        self.nodes     = []

    ####################################################################################################################
    def add_bp_entry (self, module, function, node, dupe_check=False):
        '''
        Add a breakpoint entry to the internal lists.

        @type  module:     String
        @param module:     Module name
        @type  function:   DWORD
        @param function:   Function offset address
        @type  node:       DWORD
        @param node:       Node offset address
        @type  dupe_check: Boolean
        @param dupe_check: Optional flag specifying whether or not to check for duplicates before adding entry (slow).

        @raise psx: An exception is raised if the entry to add already exists.
        '''

        if dupe_check:
            for i in xrange(self.num_entries()):
                if self.modules[i] == module and self.functions[i] == function and self.nodes[i] == node:
                    raise psx("Breakpoint entry already exists.")

        self.functions.append(function)
        self.modules.append(module)
        self.nodes.append(node)

    ####################################################################################################################
    def del_bp_entry (self, index):
        '''
        Delete the breakpoint entry at the specified index.

        @type  index: Integer
        @param index: Breakpoint index

        @raise psx: An exception is raisd if the requested index is out of range.
        '''

        # ensure the requested index is within range.
        if index >= self.num_entries():
            raise psx("Requested index is out of range.")

        # remove the data at index from the internal lists.
        self.functions.pop(index)
        self.modules.pop(index)
        self.nodes.pop(index)

    ####################################################################################################################
    def get_bp_entry (self, index):
        '''
        Get the breakpoint entry at the specified index.

        @type  index: Integer
        @param index: Breakpoint index

        @rtype:  Tuple
        @return: BP module name, BP function offset address, BP node offset address

        @raise psx: An exception is raised if the requested index is out of range.
        '''

        # ensure the requested index is within range.
        if index >= self.num_entries():
            raise psx("Requested index is out of range.")

        return (self.modules[index], self.functions[index], self.nodes[index])

    ####################################################################################################################
    def num_entries (self):
        '''
        Get the entry count for this breakpoint list.

        @rtype:  Integer
        @return: Breakpoint count
        '''

        # we can return the len() on any of the internal lists.
        return len(self.functions)

    ####################################################################################################################
    def parse (self, filename):
        '''
        Open the specified breakpoint list filename and process the data into the internal lists. Breakpoint list
        format::

            module:function offset address:node offset address
            irc.dll:00000000:00000000

        @type  filename: String
        @param filename: Filename

        @raise psx: An exception is raised if requested breakpoint list can not be opened.
        '''

        # open the file, read-only.
        try:
            file = open(filename, "r")
        except:
            raise psx("Unable to open file '%s' for reading." % filename)

        # clear the internal lists.
        self.functions = []
        self.modules   = []
        self.nodes     = []

        # process the file line by line.
        for line in file.readlines():
            line = line.rstrip(" \r\n")

            # parse out the line fields, ignore on error.
            try:
                (module, function, node) = line.split(":")

                function = long(function, 16)
                node     = long(node,     16)
                module   = module.lower()
            except:
                continue

            # add the successfully extracted fields to the internal lists.
            self.functions.append(function)
            self.modules.append(module)
            self.nodes.append(node)

    ####################################################################################################################
    def save (self, filename):
        '''
        Save a breakpoint list to the specified file. The contents of the breakpoint list are generated from our
        internal variables in sorted order. Breakpoint list format::

            module:function offset address:node offset address
            irc.dll:00000000:00000000

        @type  filename: String
        @param filename: Filename

        @raise psx: An exception is raised if the specified file can not be opened for writing.
        '''

        # open the file in write mode, create it if it does exist, overwrite it if it does.
        try:
            file = open(filename, "w+")
        except:
            raise psx("Unable to open file '%s' for writing." % filename)

        # initialize a list for storing the in-memory breakpoint list.
        bpl = []

        # construct an in-memory list from the internal lists.
        for i in xrange(self.num_entries()):
            bpl.append("%s:%08x:%08x" % (self.modules[i], self.functions[i], self.nodes[i]))

        # sort the breakpoint list.
        bpl.sort()

        # write data to disk.
        for entry in bpl:
            file.write(entry + "\n")

    ####################################################################################################################
    def __module_test__ (self):
        '''
            Run a few basic tests to ensure the class is working.
        '''

        try:
            self.add_bp_entry("mod", 0xdeadbeef, 0x01010101)
            self.add_bp_entry("mod", 0xdeadbeef, 0x01010101)
        except psx, e:
            print e

        try:
            self.del_bp_entry(10)
        except psx, e:
            print e

        self.add_bp_entry("mod", 0xdeadbeef, 0x01010109)
        self.add_bp_entry("mod", 0xdeadbeef, 0x01010108)
        self.add_bp_entry("mod", 0xdeadbeef, 0x01010105)
        self.add_bp_entry("mod", 0xffffffff, 0x12345678)
        self.add_bp_entry("aaa", 0xffffffff, 0x12345678)

        try:
            self.save("__test.bpl")
        except psx, e:
            print e

        self.parse("__test.bpl")

        for i in xrange(self.num_entries()):
            print self.get_bp_entry(i)

        import os
        os.unlink("__test.bpl")

########################################################################################################################

class recording_parser:
    '''
    Process Stalker stores generated trace meta-data in recording files. These recordings serve as the starting point
    for generating "live" visualizations and must be processed prior to use. The purpose of this class is to alleviate
    the burden of handling recordings by providing an abstraction layer.

    Pre-processed recordings are stored in the following format::

        hit time:thread id:module name:module base address:breakpoint offset address
        002d97d0:00000a28:irc.dll:00401000:000092d1

    Post-processed recordings add the function offset address as as the second to last field::

        hit time: thread id:module name:module base address:breakpoint function offset address:breakpoint offset address
        002d97d0:00000a28:irc.dll:00401000:00009160:000092d1

    @todo: Implement routines to set individual recording entries. I currently have no use for this.
    '''

    ####################################################################################################################
    def __init__ (self):
        '''
        Initialize internal member variables.
        '''

        self.times     = []
        self.threads   = []
        self.modules   = []
        self.bases     = []
        self.functions = []
        self.nodes     = []

        # internal dictionaries used in recording processing.
        self.bp_lists    = {}   # breakpoint module/node pair to function mapping
        self.thread_fhs  = {}   # thread file handles list

    ####################################################################################################################
    def get_recording_entry (self, index):
        '''
        Get the recording entry at the specified index.

        @type  index: Integer
        @param index: Recording index

        @rtype:  Tuple
        @return: Time, thread ID, module name, module base address, function offset address, node offset address

        @raise psx: An exception is raised if the requested index is out of range.
        '''

        # ensure the requested index is within range.
        if index >= self.num_entries():
            raise psx("Requested index is out of range.")

        return (self.times[index], self.threads[index],   self.modules[index], \
                self.bases[index], self.functions[index], self.nodes[index])

    ####################################################################################################################
    def num_entries (self):
        '''
        Get the entry count for this recording.

        @rtype:  Integer
        @return: Recording count
        '''

        # we can return the len() on any of the internal lists.
        return len(self.times)

    ####################################################################################################################
    def parse (self, filename):
        '''
        Open the specified *processed* recording and process the data into the internal lists. File format::

            hit time:thread id:module name:mode base addr.:breakpoint function offset addr.:breakpoint offset addr.
            002d97d0:00000a28:irc.dll:00401000:00009160:000092d1

        @type  filename: String
        @param filename: Filename

        @raise psx: An exception is raised if requested recording file can not be opened.
        '''

        # open the file, read-only.
        try:
            file = open(filename, "r")
        except:
            raise psx("Unable to open file '%s' for reading." % filename)

        # clear the internal lists.
        self.times     = []
        self.threads   = []
        self.modules   = []
        self.bases     = []
        self.functions = []
        self.nodes     = []

        # process the file line by line.
        for line in file.readlines():
            line = line.rstrip(" \r\n")

            # parse out the line fields, ignore on error.
            try:
                (time, thread, module, base, function, node) = line.split(":")

                time     = long(time,     16)
                thread   = long(thread,   16)
                base     = long(base,     16)
                function = long(function, 16)
                node     = long(node,     16)
                module   = module.lower()
            except:
                continue

            # add the successfully extracted fields to the internal lists.
            self.times.append(time)
            self.threads.append(thread)
            self.modules.append(module)
            self.bases.append(base)
            self.functions.append(function)
            self.nodes.append(node)

    ####################################################################################################################
    def pre_process (self, filename, rebase=0):
        '''
        Open the specified recording and process the data into the internal lists. File format::

            hit time:thread id:module name:mode base addr.:breakpoint function offset addr.:breakpoint offset addr.
            002d97d0:00000a28:irc.dll:00401000:00009160:000092d1

        The second to final field, 'function offset address, is added in the processed output. Processed recorder files
        will be generated for each thread found within the pre-processed recording.

        @type  filename: String
        @param filename: Filename
        @type  rebase:   DWORD
        @param rebase:   Optional module rebase address

        @raise psx: An exception is raised if requested recording file can not be opened.
        '''

        # open the file, read-only.
        try:
            file = open(filename, "r")
        except:
            raise psx("Unable to open file '%s' for reading." % filename)

        # process the file line by line.
        for line in file.readlines():
            line = line.rstrip(" \r\n")

            # parse out the line fields, ignore on error.
            try:
                (time, thread, module, base, node) = line.split(":")

                time   = long(time,   16)
                thread = long(thread, 16)
                base   = long(base,   16)
                node   = long(node,   16)
                module = module.lower()

                # override the read-in base if the rebase option is specified.
                if rebase:
                    base = rebase
            except:
                continue

            # if the breakpoint list dictionary doesn't contain this module, then load it.
            if not self.bp_lists.has_key(module):
                self.bp_lists[module] = {}

                try:
                    bpl = open(module + ".bpl")
                except:
                    raise psx("Breakpoint list for module %s not found." % module)

                # process each line in this breakpoint list into the internal dictionary.
                for bp in bpl.readlines():
                    bp = bp.rstrip(" \r\n")

                    # parse out the line fields, ignore on error.
                    try:
                        (_module, _function, _node) = bp.split(":")

                        _function = long(_function, 16)
                        _node     = long(_node,     16)
                        _module   = _module.lower()
                    except:
                        continue

                    self.bp_lists[_module][_node] = _function

            # load the function address for the current recording address from the breakpoint list dictionary.
            function = self.bp_lists[module][node]

            # create an output file for the current thread if it doesn't exist.
            if not self.thread_fhs.has_key(thread):
                self.thread_fhs[thread] = open(filename + ".%08x-processed" % thread, "w+")

            # output the processed line to the thread file.
            self.thread_fhs[thread].write("%08x:%08x:%s:%08x:%08x:%08x\n" % (time, thread,   module, \
                                                                             base, function, node))

        # close the output file handles.
        for thread_fh in self.thread_fhs:
            self.thread_fhs[thread_fh].close()

        # close the input file handle.
        file.close()

    ####################################################################################################################
    def save (self, filename):
        '''
        Save a recording to the specified file. The contents of the recording are generated from our internal variables
        in sorted order. File format::

            hit time:thread id:module name:mode base addr.:breakpoint function offset addr.:breakpoint offset addr.
            002d97d0:00000a28:irc.dll:00401000:00009160:000092d1

        @type  filename: String
        @param filename: Filename

        @raise psx: An exception is raised if the specified file can not be opened for writing.
        '''

        # open the file in write mode, create it if it does exist, overwrite it if it does.
        try:
            file = open(filename, "w+")
        except:
            raise psx("Unable to open file '%s' for writing." % filename)

        # initialize a list for storing the in-memory recording.
        recording = []

        # construct an in-memory list from the internal lists.
        for i in xrange(self.num_entries()):
            recording.append("%08x:%08x:%s:%08x:%08x:%08x" % (self.times[i], self.threads[i],   self.modules[i], \
                                                              self.bases[i], self.functions[i], self.nodes[i]))

        # sort the cross-reference list.
        recording.sort()

        # write data to disk.
        for entry in recording:
            file.write(entry + "\n")

    ####################################################################################################################
    def __module_test__ (self):
        '''
            Run a few basic tests to ensure the class is working.
        '''

        self.pre_process("test.0")

        self.parse("test.0.000005cc-processed")
        print self.num_entries()
        print self.get_recording_entry(0)

########################################################################################################################

class register_metadata_parser:
    '''
    Process Stalker can store per-node register meta-data. The purpose of this class is to alleviate the burden of
    handling register recordings by providing an abstraction layer.

    Register recordings are stored in the following format::

        hit time:module name:breakpoint offset address:register name:register data location:register data
        0096e63c:msn.dll:022ede10:EAX::DEADBEEF
        0096e63c:msn.dll:022ede10:*EAX:heap:8405 0000 0000 0000 0000 0000 0100 0000
    '''

    ####################################################################################################################
    def __init__ (self, base_address=0):
        '''
        Initialize internal member variables.

        @type  base_address: DWORD
        @param base_address: Optional address to re-base parsed xref offsets to.
        '''

        self.times          = []
        self.modules        = []
        self.bases          = []
        self.addresses      = []
        self.registers      = []
        self.data_locations = []
        self.data           = []

        self.base_address = base_address

        # internal address to list index mapping. (dictionary of lists)
        self.address_map = {}

    ####################################################################################################################
    def get_recording_entry (self, index):
        '''
        Get the recording entry at the specified index.

        @type  index: Integer
        @param index: Recording index

        @rtype:  Tuple
        @return: Time, module name, base, breakpoint offset address, register, register data location, register data

        @raise psx: An exception is raised if the requested index is out of range.
        '''

        # ensure the requested index is within range.
        if index >= self.num_entries():
            raise psx("Requested index is out of range.")

        return (self.times[index],     self.modules[index],   self.bases[index],
                self.addresses[index], self.registers[index], self.data_locations[index], self.data[index])

    ####################################################################################################################
    def num_entries (self):
        '''
        Get the entry count for this recording.

        @rtype:  Integer
        @return: Recording count
        '''

        # we can return the len() on any of the internal lists.
        return len(self.times)

    ####################################################################################################################
    def parse (self, filename):
        '''
        Open and parse the specified register recording file. Register recordings are stored in the following format::

            hit time:module name:base addr:breakpoint offset address:register name:register data location:register data
            0096e63c:msn.dll:0001000:022ede10:EAX::DEADBEEF
            0096e63c:msn.dll:0001000:022ede10:*EAX:heap:8405 0000 0000 0000 0000 0000 0100 0000

        @type  filename: String
        @param filename: Filename

        @raise psx: An exception is raised if requested recording file can not be opened.
        '''

        # open the file, read-only.
        try:
            file = open(filename, "r")
        except:
            raise psx("Unable to open file '%s' for reading." % filename)

        # clear the internal lists.
        self.times          = []
        self.modules        = []
        self.bases          = []
        self.addresses      = []
        self.registers      = []
        self.data_locations = []
        self.data           = []

        # process the file line by line.
        for line in file.readlines():
            line = line.rstrip(" \r\n")

            # parse out the line fields, ignore on error.
            try:
                (time, module, base, address, register, data_location, data) = line.split(":")

                time     = long(time,    16)
                base     = long(base,    16)
                address  = long(address, 16)
                module   = module.lower()

                # if a data location wasn't specified, then this line specifies a direct register value.
                if not data_location:
                    data = long(data, 16)

                # if a rebase address was provided, then over ride the read-in base address.
                if self.base_address:
                    base = self.base_address
            except:
                continue

            # add the successfully extracted fields to the internal lists.
            self.times.append(time)
            self.modules.append(module)
            self.bases.append(base)
            self.addresses.append(address)
            self.registers.append(register)
            self.data_locations.append(data_location)
            self.data.append(data)

            # add this address->index map to the cache.
            key = "%08x" % (base + address)

            if not self.address_map.has_key(key):
                self.address_map[key] = []

            self.address_map[key].append(len(self.bases) - 1)

    ####################################################################################################################
    def retrieve_register_metadata (self, register, address, module=0):
        '''
        Get the recording entry at the specified index.

        @type  register:       String
        @param register:       One of EAX, EBX, ECX, EDX, ESI, EDI, EBP
        @type  address:        DWORD
        @param address:        Node address to retrieve register metadata for.
        @type  module:         String
        @param module:         Module name

        @rtype:  Dictionary
        @return: register{value, single_location, single_data, double_location, double_data} or 'False' if not found.

        @todo: Uncomment check for 'double_data' when double derefencing support is added to process stalker.
        '''

        data = {}
        key  = "%08x" % address

        # ensure the requested address exists in the cache.
        if not self.address_map.has_key(key):
            return False

        # step through each index for the requested key.
        for i in self.address_map[key]:
            # if we've completed filled the data structure, then stop looping to increase speed.
            # XXX - i currently don't use double derefencing so the below check for 'double data' is commented out.
            if data.has_key("value") and data.has_key("single_data"): # and data.has_key("double_data"):
                break

            # ignore entries that don't match the specified address.
            if self.bases[i] + self.addresses[i] != address:
                continue

            # ignore entries that don't match the specified register/module.
            if module and self.modules[i] != module:
                continue

            if self.registers[i].find(register) == -1:
                continue

            # register value
            if self.registers[i] == register:
                data["value"] = self.data[i]

            # *register
            elif self.registers[i] == "*" + register:
                data["single_location"] = self.data_locations[i]
                data["single_data"]     = self.data[i]

            # **register
            elif self.registers[i] == "**" + register:
                data["double_location"] = self.data_locations[i]
                data["double_data"]     = self.data[i]

        # if no register match was found, return 'False'.
        if not data.has_key("value"):
            return False

        # if derefencing data was not found, fill the data structure with empty fields.
        if not data.has_key("single_data"):
            data["single_data"]     = ""
            data["single_location"] = ""

        if not data.has_key("double_data"):
            data["double_data"]     = ""
            data["double_location"] = ""

        return data

    ####################################################################################################################
    def __module_test__ (self):
        '''
            Run a few basic tests to ensure the class is working.
        '''

        self.parse("test.0-regs")
        print self.num_entries()
        print self.get_recording_entry(0)

########################################################################################################################

class xrefs_parser:
    '''
    Cross-reference lists contain function offset addresses, source node offset addresses and destination node offset
    addresses. The cross-reference list contains the enumeration of all intra-modular calls and is used to create
    connected graphs and recursive graph views. Cross-reference list file format::

        function offset address:source node offset address:destination node offset address
        000000e0:0000011e:00015edc
    '''

    ####################################################################################################################
    def __init__ (self, base_address=0):
        '''
        Initialize internal member variables.

        @type  base_address: DWORD
        @param base_address: Optional address to re-base parsed xref offsets to.
        '''

        self.functions    = []
        self.sources      = []
        self.destinations = []

        self.base_address = base_address

    ####################################################################################################################
    def add_xref_entry (self, function, source, destination, dupe_check=False):
        '''
        Add a cross-reference entry to the internal lists.

        @type  function:    DWORD
        @param function:    Source function offset address
        @type  source:      DWORD
        @param source:      Source node offset address
        @type  destination: DWORD
        @param destination: Destination node offset address
        @type  dupe_check: Boolean
        @param dupe_check: Optional flag specifying whether or not to check for duplicates before adding entry (slow).

        @raise psx: An exception is raised if the entry to add already exists.
        '''

        if dupe_check:
            for i in xrange(self.num_entries()):
                if self.functions[i] == function and self.sources[i] == source and self.destinations[i] == destination:
                    raise psx("Cross-reference entry already exists.")

        self.functions.append(function)
        self.sources.append(source)
        self.destinations.append(destination)

    ####################################################################################################################
    def del_xref_entry (self, index):
        '''
        Delete the cross-reference entry at the specified index.

        @type  index: Integer
        @param index: Cross-reference index

        @raise psx: An exception is raised if the requested index is out of range.
        '''

        # ensure the requested index is within range.
        if index >= self.num_entries():
            raise psx("Requested index is out of range.")

        # remove the data at index from the internal lists.
        self.functions.pop(index)
        self.sources.pop(index)
        self.destinations.pop(index)

    ####################################################################################################################
    def get_xref_entry (self, index):
        '''
        Get the cross-reference entry at the specified index.

        @type  index: Integer
        @param index: Cross-reference index

        @rtype:  Tuple
        @return: Function offset address, source node offset address, destination node offset address

        @raise psx: An exception is raised if the requested index is out of range.
        '''

        # ensure the requested index is within range.
        if index >= self.num_entries():
            raise psx("Requested index is out of range.")

        return (self.functions[index], self.sources[index], self.destinations[index])

    ####################################################################################################################
    def get_xrefs_from (self, function):
        '''
        Return a list of all intra-modular cross-references from the specified function.

        @type  index: DWORD
        @param index: Address of function to return originating cross-references list from

        @rtype:  List
        @return: List of functions cross-referenced from the specified origin.
        '''

        xrefs = []

        # step through the loaded xref entries.
        for i in xrange(self.num_entries()):
            (source, source_node, destination) = self.get_xref_entry(i)

            if source + self.base_address == function:
                xrefs.append(destination)

        return xrefs

    ####################################################################################################################
    def num_entries (self):
        '''
        Get the entry count for this cross-reference list.

        @rtype:  Integer
        @return: Cross-reference count
        '''

        # we can return the len() on any of the internal lists.
        return len(self.functions)

    ####################################################################################################################
    def parse (self, filename):
        '''
        Open the specified Cross-reference list filename and process the data into the internal lists. File format::

            function offset address:source node offset address:destination node offset address
            000000e0:0000011e:00015edc

        @type  filename: String
        @param filename: Filename

        @raise psx: An exception is raised if requested cross-reference file can not be opened.
        '''

        # open the file, read-only.
        try:
            file = open(filename, "r")
        except:
            raise psx("Unable to open file '%s' for reading." % filename)

        # clear the internal lists.
        self.functions    = []
        self.sources      = []
        self.destinations = []

        # process the file line by line.
        for line in file.readlines():
            line = line.rstrip(" \r\n")

            # parse out the line fields, ignore on error.
            try:
                (function, source, destination) = line.split(":")

                function    = long(function,    16)
                source      = long(source,      16)
                destination = long(destination, 16)
            except:
                continue

            # re-base if required.
            if self.base_address:
                function    = self.base_address + function
                source      = self.base_address + source
                destination = self.base_address + destination

            # add the successfully extracted fields to the internal lists.
            self.functions.append(function)
            self.sources.append(source)
            self.destinations.append(destination)

    ####################################################################################################################
    def save (self, filename):
        '''
        Save a cross-reference list to the specified file. The contents of the cross-reference are generated from our
        internal variables in sorted order. File format::

            function offset address:source node offset address:destination node offset address
            000000e0:0000011e:00015edc

        @type  filename: String
        @param filename: Filename

        @raise psx: An exception is raised if the specified file can not be opened for writing.
        '''

        # open the file in write mode, create it if it does exist, overwrite it if it does.
        try:
            file = open(filename, "w+")
        except:
            raise psx("Unable to open file '%s' for writing." % filename)

        # initialize a list for storing the in-memory cross-reference list.
        xrefs = []

        # construct an in-memory list from the internal lists.
        for i in xrange(self.num_entries()):
            xrefs.append("%08x:%08x:%08x" % (self.functions[i], self.sources[i], self.destinations[i]))

        # sort the cross-reference list.
        xrefs.sort()

        # write data to disk.
        for entry in xrefs:
            file.write(entry + "\n")

    ####################################################################################################################
    def __module_test__ (self):
        '''
            Run a few basic tests to ensure the class is working.
        '''

        try:
            self.add_xref_entry(0x11111111, 0xdeadbeef, 0x01010101)
            self.add_xref_entry(0x11111111, 0xdeadbeef, 0x01010101)
        except psx, e:
            print e

        try:
            self.del_xref_entry(10)
        except psx, e:
            print e

        self.add_xref_entry(0x11111111, 0xdeadbeef, 0x01010109)
        self.add_xref_entry(0x11111111, 0xdeadbeef, 0x01010108)
        self.add_xref_entry(0x11111111, 0xdeadbeef, 0x01010105)
        self.add_xref_entry(0x11111111, 0xffffffff, 0x12345678)

        try:
            self.save("__test.xrefs")
        except psx, e:
            print e

        self.parse("__test.xrefs")

        for i in xrange(self.num_entries()):
            print self.get_xref_entry(i)

        import os
        os.unlink("__test.xrefs")
