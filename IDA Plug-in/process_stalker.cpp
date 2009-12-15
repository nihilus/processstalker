/*
    Process Stalker IDA Plug-in
    Copyright (C) 2005 Pedram Amini <pamini@idefense.com,pedram.amini@gmail.com>

    This program is free software; you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by the Free
    Software Foundation; either version 2 of the License, or (at your option)
    any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
    more details.

    You should have received a copy of the GNU General Public License along with
    this program; if not, write to the Free Software Foundation, Inc., 59 Temple
    Place, Suite 330, Boston, MA 02111-1307 USA
*/

#include <windows.h>
#include <math.h>

#include <ida.hpp>
#include <idp.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <expr.hpp>
#include <fpro.h>
#include <frame.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <nalt.hpp>
#include <name.hpp>

#pragma warning (disable:4273)

#include "function_analyzer.h"

/////////////////////////////////////////////////////////////////////////////////////////
// _ida_init()
//
// IDA will call this function only once.
// If this function returns PLUGIN_SKIP, IDA will never load it again.
// If this function returns PLUGIN_OK, IDA will unload the plugin but
// remember that the plugin agreed to work with the database.
// The plugin will be loaded again if the user invokes it by
// pressing the hot key or by selecting it from the menu.
// After the second load, the plugin will stay in memory.
// If this function returns PLUGIN_KEEP, IDA will keep the plugin
// in memory.
//
// arguments: none.
// returns:   plugin status.
//

int _ida_init (void)
{
    // this plug-in only works with metapc (x86) CPU types.
    if(strcmp(inf.procName, "metapc") != 0)
    {
        msg("[!] Detected an incompatible non-metapc CPU type: %s\n", inf.procName);
        return PLUGIN_SKIP;
    }

    msg("[*] pStalker> Process Stalker - Profiler\n"
        "[*] pStalker> Pedram Amini <pedram.amini@gmail.com>\n"
        "[*] pStalker> Compiled on "__DATE__"\n");

    return PLUGIN_OK;
}


/////////////////////////////////////////////////////////////////////////////////////////
// _ida_run()
//
// the run function is called when the user activates the plugin. this is the main
// function of the plugin.
//
// arguments: arg - the input argument. it can be specified in the
//                  plugins.cfg file. the default is zero.
// returns:   none.
//

void _ida_run (int arg)
{
    int   num_functions;
    int   function_id      = 0;
    int   base_node_id     = 0;
    float current_percent  = 0.0;
    float percent_complete = 0.0;
    char  *file_path;
    char  *tmp;
    char  path[1024];
    FILE  *bpl;
    function_analyzer *fa;

    const short COLORS   = 0x0001;
    const short COMMENTS = 0x0002;
    const short LOOPS    = 0x0004;
    short options;

    const char dialog_format [] =
        "STARTITEM 0\n"
        "Process Stalker\n"
        "<Enable Instruction Colors:C>\n"
        "<Enable Comments:C>\n"
        "<Allow Self Loops:C>>\n\n";

    /*
    // determine the imagebase of the loaded module. this snippet is from Ilfak
    // and allows us to get the "true" module image base (PE files only)

    netnode n("$ PE header");
    ea_t imagebase = n.altval(-2);

    msg("imagebase: %08x", imagebase);
    */

    // we can only run the program once the auto-analysis has been completed.
    if (!autoIsOk())
    {
        warning("Can not run Process Stalker until auto-analysis is complete.");
        msg("[!] pStalker> Can not run profiler until auto-analysis is complete.");
        return;
    }

    options = COLORS | COMMENTS;

    if (!AskUsingForm_c(dialog_format, &options))
        return;

    // ask the user for a file path to output breakpoint list and function graphs to.
    // XXX - we actually only want the output directory from the user but IDA doesn't have
    //       an SDK routine for that.
    file_path = askfile_c(1, "*.bpl", "Select a file/directory to store the generated files.");

    if (file_path == NULL)
    {
        msg("[!] pStalker> File name not provided.\n");
        return;
    }

    // strip off the filename from the file path, this is later passed to fa->gml_export().
    if ((tmp = strrchr(file_path, '\\')) != NULL)
        *tmp = '\0';

    // construct the breakpoint list file name as "file path + get_root_filename() + .bpl".
    _snprintf(path, sizeof(path), "%s\\%s.bpl", file_path, get_root_filename());

    // open/create the outfile.
    bpl = qfopen(path, "w+");

    num_functions = get_func_qty();

    // enumerate all functions.
    for (int i = 0; i < num_functions; i++, function_id++)
    {
        // print percent complete on intervals of 25.
        current_percent = floor((float)i / num_functions * 100);

        if (((int)current_percent % 25 == 0) && current_percent > percent_complete)
        {
            percent_complete = current_percent;
            msg("[*] pStalker> Profile analysis %d%% complete.\n", (int)percent_complete);
        }

        // create a new analyzer object to process this function.
        fa = new function_analyzer(i);

        if (!fa->is_ready())
            continue;

        fa->run_analysis();

        // disabling instruction level multi-colors saves a lot of space in the output .gml graph.
        if (options & COLORS)
            fa->set_gml_ins_color(TRUE);
        else
            fa->set_gml_ins_color(FALSE);

        // enable / disable comments in output graph.
        if (options & COMMENTS)
                fa->set_strip_comments(FALSE);
        else
            fa->set_strip_comments(TRUE);

        // orthogonal view is not possible if self-loops exist within the graph.
        if (options & LOOPS)
            fa->set_gml_ignore_self_loops(FALSE);
        else
            fa->set_gml_ignore_self_loops(TRUE);

        fa->gml_export(file_path, base_node_id);

        // increase the base node id by the number of nodes in the current routine.
        base_node_id += fa->get_num_nodes();

        // enumerate the function's basic blocks.
        for (int n = 1; n <= fa->get_num_nodes(); n++)
        {
            // output the breakpoint entry.
            // format: module name:function offset:offset
            qfprintf(bpl, "%s:%08x:%08x\n", get_root_filename(),
                                            fa->first_ea()  - inf.minEA,
                                            fa->get_node(n) - inf.minEA);
        }

        // done with the current analyzer object.
        delete fa;
    }

    // flush / close the outfile.
    qflush(bpl);
    qfclose(bpl);

    msg("[*] pStalker> Profile analysis 100%% complete.\n");
}


/////////////////////////////////////////////////////////////////////////////////////////
// _ida_term()
//
// IDA will call this function when the user asks to exit. this function will not be
// called in the case of emergency exists. usually this callback is empty.
//
// arguments: none.
// returns:   none.
//

void _ida_term (void)
{
    return;
}


// include the data structures that describe the plugin to IDA.
#include "plugin_info.h"