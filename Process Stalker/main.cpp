/*
    Process Stalker Tracer
    Portions Copyright (C) 2005 Pedram Amini <pamini@idefense.com,pedram.amini@gmail.com>

    This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
    version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
    warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
    Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

    Notes:
        - I originally developed function-recording utilizing splay trees but later modified my method as the project
          specs changed too. I left the splay code lingering however in case I decide to use it again.
*/

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <conio.h>
#include <time.h>
#include <Tlhelp32.h>

#include <map>
#include <vector>
using namespace std;

#include "debugger.hpp"
#include "log.hpp"
#include "pecoff.hpp"
#include "tracer.hpp"
#include "parser/tracedefs.hpp"
#include "process_stalker.hpp"
#include "splay.hpp"

//
// global variables.
//

Tracer             dbg;
vector <Debugger*> Children;

// lots of globals ... not the most elegant solution.
char    target[32];                             // current target. pid or filename.
bool    main_terminate       = false;           // main loop control flag.
stree   *function_list       = NULL;            // function list splay tree.
int     recorder_mode        = NOT_RECORDING;   // current recorder mode.
FILE    *bpl                 = NULL;            // break point list file handle.
FILE    *recorder            = NULL;            // current recorder file handle.
FILE    *recorder_regs       = NULL;            // current reg value recorder file handle.
bool    disassemble_flag     = true;            // toggle whether or not per breakpoint disassembly is done.
bool    reg_enum_flag        = true;            // toggle whether or not registers are followed on breakpoint handling.       
node    *bp_modules          = NULL;            // breakpoint modules linked list.
int     num_bp_modules       = 0;               // number of breakpoint modules.
char    *breakpoint_list     = NULL;            // initial breakpoint list.

int main (int argc, char **argv)
{
    unsigned int cit;
    int          option;
    char         filename[MAX_PATH];
    char         command_line[MAX_PATH];            // win2k max = MAX_PATH, otherwise could be 32k.
    map <DWORD,t_Debugger_memory*>::const_iterator  it;

    // init target char buf.
    memset(target, 0, sizeof(target));

    // Set the debugger's log level. (disable logging)
    dbg.log.set(LOG_SHUTUP);
    dbg.SetGlobalLoglevel(LOG_SHUTUP);

    //
    // do the command line argument thing.
    //

    for (int i = 1; i < argc; i++)
    {
        //
        // attach to a pid.
        //

        if (stricmp(argv[i], "-a") == 0 && i + 1 < argc)
        {
            if (!dbg.attach(atoi(argv[i+1])))
            {
                printf("[ERROR] No process with the ID %u\n", atoi(argv[i+1]));
                return 1;
            }

            // update the target name.
            strncpy(target, argv[i+1], sizeof(target) - 1);

            i++;
        }

        //
        // load a file. (no arguments)
        //

        else if (stricmp(argv[i], "-l") == 0 && i + 1 < argc)
        {
            if (!dbg.load(argv[i+1]))
            {
                printf("[ERROR] Could not load %s\n", argv[i+1]);
                return 1;
            }

            // update the target name.
            strncpy(target, argv[i+1], sizeof(target) - 1);
            
            // cut off the target name at the first dot.
            //char *dot = strchr(target, '.');
            //*dot = 0;

            i++;
        }

        //
        // load a file with arguments.
        //

        else if (stricmp(argv[i], "-la") == 0 && i + 1 < argc)
        {
            _snprintf(command_line, sizeof(command_line), "%s %s", argv[i+1], argv[i+2]);

            if (!dbg.load(argv[i+1], command_line))
            {
                printf("[ERROR] Could not load %s %s\n", argv[i+1], argv[i+2]);
                return 1;
            }

            // update the target name.
            _snprintf(target, sizeof(target), command_line);

            i += 2;
        }

        //
        // select a breakpoint list.
        //

        else if (stricmp(argv[i], "-b") == 0 && i + 1 < argc)
        {
            breakpoint_list = argv[i+1];

            // we open the file now with a global file handle and set the breakpoints after all
            // the modules have been loaded and parsed in the initial breakpoint handler.
            if ((bpl = fopen(breakpoint_list, "r+")) == NULL)
            {
                printf("\n[ERROR] Failed opening breakpoing list: %s\n", breakpoint_list);
                return 1;
            }

            i++;
        }

        //
        // select a starting recorder mode.
        //

        else if (stricmp(argv[i], "-r") == 0 && *target != NULL && i + 1 < argc)
        {
            recorder_mode = atoi(argv[i+1]);

            // create / open recorder file.
            sprintf(filename, "%s.%d", target, recorder_mode);
            recorder = fopen(filename, "a+");

            // create / open the register recorder file if register enumeration hasn't been disabled.
            if (reg_enum_flag)
            {
                sprintf(filename, "%s-regs.%d", target, recorder_mode);
                recorder_regs = fopen(filename, "a+");
            }

            i++;
        }

        //
        // set "one-time" mode. ie: do not restore breakpoints.
        //

        else if (stricmp(argv[i], "--one-time") == 0)
        {
            dbg.one_time = true;
        }

        //
        // disable register enumeration / dereferencing.
        //

        else if (stricmp(argv[i], "--no-regs") == 0)
        {
            reg_enum_flag = false;
        }

        //
        // invalid option.
        //

        else
            ps_usage();
    }

    //
    // command line sanity checking.
    //

    if (*target == NULL)
        ps_usage();

    //
    // print banner and start working.
    //

    printf("\nprocess stalker\n"
           "pedram amini <pedram.amini@gmail.com>\n"
           "compiled on "__DATE__"\n"
           "target: %s\n\n", target);

    // assign functions to handle breakpoints.
    dbg.set_inital_breakpoint_handler(&initial_break);
    dbg.set_breakpoint_handler(&normal_break);
    dbg.SetCloseRecordFunction(&closer);
    dbg.set_load_dll_handler(&ps_load_dll_callback);

    // assign a function to handle exit event.
    dbg.set_exit_handler(&itsdone);

    dbg.Analysis.StackDelta  = true;
    dbg.Analysis.StackDeltaV = 2048;

    // 
    // application main loop.
    //

    while (!main_terminate)
    {
        dbg.run(1000);

        for (cit = 0; cit < Children.size(); cit++)
                Children[cit]->run(1000);

        if (_kbhit())
        {
            option = getch();

            switch(option)
            {
                // activate a recorder.
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    // convert character option into integer option for recorder mode.
                    option -= 48;
                    
                    // close any previously open recorder file.
                    if (recorder_mode != NOT_RECORDING)
                    {
                        fclose(recorder);

                        if (reg_enum_flag)
                            fclose(recorder_regs);
                    }

                    printf("entering recorder mode %d, register enumeration is %s.\n", option, (reg_enum_flag ? "enabled" : "disabled"));
                    recorder_mode = option;

                    // create/open recorder file.
                    sprintf(filename, "%s.%d", target, option);
                    recorder = fopen(filename, "a+");

                    // create/open the register recording file if the register enumeration flag is raised.
                    if (reg_enum_flag)
                    {
                        sprintf(filename, "%s-regs.%d", target, option);
                        recorder_regs = fopen(filename, "a+");
                    }
                    break;

                // detach from debuggee.
                case 'd':
                    if (!dbg.pDebugActiveProcessStop || !dbg.pDebugSetProcessKillOnExit)
                    {
                        printf("\ndetaching is not possible on the current os ... request ignored.\n");
                        break;
                    }

                    main_terminate = true;
                    printf("\nclosing any open recorder and detaching ...\n");

                    if (recorder_mode != NOT_RECORDING)
                    {
                        fclose(recorder);

                        if (reg_enum_flag)
                            fclose(recorder_regs);
                    }

                    dbg.detach();

                    break;

                // display available options.
                case 'h':
                    ps_commands();
                    break;
                
                // display memory map for executable sections of each module.
                case 'm':
                    dbg.ReBuildMemoryMap();

                    printf("\n---------- MODULE LIST ----------\n");

                    for (it = dbg.MemoryMap.begin(); it != dbg.MemoryMap.end(); ++it)
                    {
                        // determine the correct section)
                        if ((it->second->basics.Protect & PAGE_EXECUTE)           ||
                            (it->second->basics.Protect & PAGE_EXECUTE_READ)      ||
                            (it->second->basics.Protect & PAGE_EXECUTE_READWRITE) ||
                            (it->second->basics.Protect & PAGE_EXECUTE_WRITECOPY))
                        {
                            // module executable section found.
                            printf("module %08x %s\n", it->second->address, it->second->Name.c_str());
                        }
                    }

                    printf("\nstalking:\n");

                    for (node *cursor = bp_modules; cursor != NULL; cursor = cursor->next)
                        printf("%08x - %08x [%08x] %s\n", cursor->base, cursor->base + cursor->size, cursor->size, cursor->name);

                    printf("---------- MODULE LIST ----------\n\n");

                    break;

                // quit program.
                case 'q':   
                    main_terminate = true;
                    printf("\nclosing any open recorder and quiting ...\n");

                    if (recorder_mode != NOT_RECORDING)
                    {
                        fclose(recorder);

                        if (reg_enum_flag)
                            fclose(recorder_regs);
                    }

                    break;
                
                // toggle verbosity. ie: display per breakpoint disassembly.
                case 'v':
                    disassemble_flag = !disassemble_flag;

                    printf("turning breakpoint disassembly: %s\n", (disassemble_flag) ? "ON" : "OFF");
                    break;

                // close active recorder mode.
                case 'x':
                    if (recorder_mode == NOT_RECORDING)
                        break;
                    
                    fclose(recorder);

                    if (reg_enum_flag)
                        fclose(recorder_regs);

                    printf("closing recorder mode %d\n", recorder_mode);
                    recorder_mode = NOT_RECORDING;
                    break;
                
                default:
                    ps_commands();
            }   // switch
        }       // _kbhit
    }           // while

    // Debugger class will handle it's own cleanup.
    // XXX - we don't free the bp_module list.
    return 0;
};


//////////////////////////////////////////////////////////////////////////////////////////////////////////
// ps_analyze_register()
//
// this routine is called for each register that we want to capture data from. it should only be called
// when recording is enabled.
//
// XXX - this routine needs to be as fast as possible. instead of attempting to detect the string type,
//       converting unicode strings, strcpy()-ing into recorder_buf etc ... it may be wise to simply
//       print X hex-bytes and loop through those bytes printing isprint() chars.
//
void ps_analyze_register (HANDLE process, DWORD tick_count, DWORD bp_address, node *bp_node, DWORD stack_top, DWORD stack_bottom, DWORD reg_value, char *reg_name)
{
    //DWORD         double_pointer;
    unsigned char explorer_buf[PS_EXPLORER_BUF_SIZE];
    char          recorder_buf[128];
    char          *ptr;
    int           i;

    fprintf(recorder_regs, "%08x:%s:%08x:%08x:%s::%08x\n", tick_count, bp_node->name, bp_node->base, bp_address - bp_node->base, reg_name, reg_value);

    if (!bp_node)
        return;

    // ensure the register points to a stack or heap address.
    // XXX - there are writable pages above 0x70000000 that aren't going to be stack/heap related, so we ignore them.
    if (reg_value > 0x70000000 || ps_get_page_type(process, reg_value) != PS_PAGE_WRITABLE)
        return;

    // single pointer dereference.
    ReadProcessMemory(process, (void *)(reg_value), &explorer_buf, PS_EXPLORER_BUF_SIZE - 1, NULL);

    // if the explored data is a unicode or ascii string then record the string. otherwise, record PS_RECORD_NUM_BYTES bytes.
    if (ps_is_printable_unicode((unsigned short *)explorer_buf, PS_EXPLORER_BUF_SIZE))
    {
        // convert the unicode string being held in explorer buf to an ascii string.
        WideCharToMultiByte(CP_ACP, 0, (unsigned short *)explorer_buf, PS_EXPLORER_BUF_SIZE, recorder_buf, lstrlenW((unsigned short *)explorer_buf) + 2, NULL, NULL);
    }
    else if (ps_is_printable_ascii(explorer_buf, PS_EXPLORER_BUF_SIZE))
    {
        strncpy(recorder_buf, (char *)explorer_buf, PS_EXPLORER_BUF_SIZE);
    }
    else
    {
        ptr = recorder_buf;
        for (i = 0; i < PS_RECORD_NUM_BYTES; i++)
            // print spaces appropriately to show memory alignment.
            ptr += sprintf(ptr, "%02x%s", explorer_buf[i], ((reg_value + i) & 3) ? "" : " ");
    }

    fprintf(recorder_regs, "%08x:%s:%08x:%08x:*%s:%s:%s\n", tick_count, bp_node->name, bp_node->base, bp_address - bp_node->base, reg_name, (reg_value >= stack_bottom && reg_value <= stack_top) ? "stack" : "heap", recorder_buf);

    /* XXX - not implemented.
    // double pointer dereference.
    double_pointer = (explorer_buf[0] << 24) + (explorer_buf[1] << 16) + (explorer_buf[2] << 8) + explorer_buf[3];
    printf("**%s -> %08x\n", reg_name, double_pointer);

    if (ps_get_page_type(process, double_pointer) == PS_PAGE_WRITABLE)
    {
        ReadProcessMemory(process, (void *)(double_pointer), &explorer_buf, PS_EXPLORER_BUF_SIZE - 1, NULL);

        printf("**%s [%s]-> ", reg_name, (double_pointer >= stack_bottom && double_pointer <= stack_top) ? "stack" : "heap");

        if (ps_is_printable_unicode((unsigned short *)explorer_buf, PS_EXPLORER_BUF_SIZE))
            wprintf(L"\nUNICODE: %s\n", explorer_buf);
        else if (ps_is_printable_ascii(explorer_buf, PS_EXPLORER_BUF_SIZE))
            printf("\nASCII: %s\n", explorer_buf);
        else
            for (i = 0; i < PS_EXPLORER_BUF_SIZE; i += 2)
                printf("%02X%02X ", explorer_buf[i], explorer_buf[i+1]);

        printf("\n");
    }
    */
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////
// ps_base_address()
//
// search through all loaded modules for a string match and return it's base address.
//
bool ps_base_address (char *module, DWORD *address, DWORD *size)
{
    map <DWORD,t_Debugger_memory*>::const_iterator  it;
    
    dbg.ReBuildMemoryMap();

    // determine the base address of the executable section for the loaded module.
    for (it = dbg.MemoryMap.begin(); it != dbg.MemoryMap.end(); ++it)
    {
        // match the module name.
        if (stricmp(it->second->Name.c_str(), module) != 0)
            continue;

        // ensure we found the correct section.
        if ((it->second->basics.Protect & PAGE_EXECUTE)           ||
            (it->second->basics.Protect & PAGE_EXECUTE_READ)      ||
            (it->second->basics.Protect & PAGE_EXECUTE_READWRITE) ||
            (it->second->basics.Protect & PAGE_EXECUTE_WRITECOPY))
        {
            // module executable section found.
            *address = it->second->address;
            *size    = it->second->basics.RegionSize;
            return true;
        }
    }

    return false;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////
// ps_commands()
//
// display the options.
//
void ps_commands (void)
{
    printf("\n");
    printf("commands: [h]   this screen                     [m] module list\n");
    printf("          [0-9] enter recorder modes            [x] stop recording\n");
    printf("          [v]   toggle verbosity\n");
    printf("          [d]   detach (XP/2003 only)           [q] quit/close\n");
    printf("\n");
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////
// ps_get_page_type()
//
// determine if the the page permissions at the specified address within the debuggee.
//
int ps_get_page_type (HANDLE process, DWORD address)
{
    MEMORY_BASIC_INFORMATION mbi;

    // pull the memory page permissions of the address in question.
    if (VirtualQueryEx(process, (void *)address, &mbi, sizeof(mbi)) < sizeof(mbi))
        return PS_PAGE_NOACCESS;

    // mbi.Protect can be one of:
    //
    //      PAGE_READONLY           [*] PAGE_EXECUTE
    //      PAGE_READWRITE          [*] PAGE_EXECUTE_READ
    //      PAGE_NOACCESS           [*] PAGE_EXECUTE_READWRITE
    //      PAGE_WRITECOPY          [*] PAGE_EXECUTE_WRITECOPY
    //      PAGE_GUARD
    //      PAGE_NOCACHE
    //
    // those marked with a [*] are legitimate excutable pages.

    // writable memory page.
    if (mbi.Protect & PAGE_READWRITE)
        return PS_PAGE_WRITABLE;

    // executable memory page.
    if (mbi.Protect & PAGE_EXECUTE           ||
        mbi.Protect & PAGE_EXECUTE_READ      ||
        mbi.Protect & PAGE_EXECUTE_READWRITE ||
        mbi.Protect & PAGE_EXECUTE_WRITECOPY)
    {
        return PS_PAGE_EXECUTABLE;
    }

    // invalid memory page.
    if (mbi.Protect & PAGE_NOACCESS)
        return PS_PAGE_NOACCESS;

    // other memory page.
    return PS_PAGE_OTHER;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////
// ps_is_printable_ascii()
//
// determine if the target string is ascii and printable within the specified max length.
//
bool ps_is_printable_ascii (unsigned char *string, int max_length)
{
    int i;

    // step through each character in the string.
    for (i = 0; *string && i < max_length; i++)
    {
        // if the current character is not ascii-printable, return false.
        if (!isprint(*string))
            return false;

        // next character.
        string++;
    }

    // ensure the minimum string length amount was exceeded.
    if (i < PS_MINUMUM_STRING_LENGTH)
        return false;

    return true;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////
// ps_is_printable_unicode()
//
// determine if the target string is unicode and printable within the specified max length.
//
bool ps_is_printable_unicode (unsigned short *string, int max_length)
{
    int i;

    // step through each character in the string.
    for (i = 0; *string && i < max_length; i++)
    {
        // if the current character is not unicode-printable, return false.
        if (!iswprint(*string))
            return false;

        // next character.
        string++;
    }

    // ensure the minimum string length amount was exceeded.
    if (i < PS_MINUMUM_STRING_LENGTH)
        return false;

    return true;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////
// ps_load_dll_callback()
//
// callback function for when a new dll is loaded into the target process.
//
void ps_load_dll_callback (PEfile *pe)
{
    FILE *fp;
    char filename[MAX_PATH];
    char  line[256], module[128];
    DWORD f_offset, offset, base, size;
    int loaded = 0;
    node *bp_node;
    map <DWORD,t_Debugger_memory*>::const_iterator  it;

    strncpy(module, pe->internal_name.c_str(), sizeof(module) - 1);

    // determine if this module already exists in our linked list.
    // if not attempt to locate the module in memory.
    if ((bp_node = ps_node_find_by_name(module, bp_modules)) == NULL)
    {
        // attempt to determine the module address / size.
        if (!ps_base_address(module, &base, &size))
        {
            printf("failed locating base address for module %s\n", module);
            return;
        }
    }

    // if a breakpoint list exists for the recently loaded module then parse it and set breakpoints.
    _snprintf(filename, sizeof(filename) - 1, "%s.bpl", module);

    if ((fp = fopen(filename, "r+")) == NULL)
        return;

    // add the bp_node to the linked list.
    bp_node = (node *) malloc(sizeof(node));
    
    bp_node->base = base;
    bp_node->size = size;
    
    strncpy(bp_node->name, module, sizeof(bp_node->name) - 1);

    ps_node_add(bp_node, &bp_modules, &num_bp_modules);

    // pe->winpe->ImageBase + pe->section[0]->VirtualAddress == 'base' but that's only in situations where
    // the first section is the executable section. most dlls are simply imagebase+0x1000 but we don't want
    // to make either assumption.
    // XXX - there is definetely a more elegant way of determining 'base'.
    printf("processing breakpoints for module %s at %08x\n", module, base);

    // process the breakpoint list line by line.
    for (int i = 0; fgets(line, sizeof(line), fp) != NULL; i++)
    {
        // line format: module name:function offset:offset
        // ignore malformatted lines.
        if (sscanf(line, "%127[^:]:%08x:%08x", module, &f_offset, &offset) == 0)
            continue;

        if (!dbg.bpx(bp_node->base + offset))
        {
            //printf("failed setting breakpoint @ 0x%08x\n", base + offset);
            continue;
        }

        // at this point a breakpoint was successfully loaded.
        loaded++;

        if (i % 100 == 0)
            printf("setting breakpoint %d\r", i);
    }

    printf("done. %d of %d breakpoints set.\n\n", loaded, i);
    fclose(fp);

    return;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////
// ps_node_add()
//
// add a breakpoint module node to the linked list (ordered).
//
void ps_node_add (node *to_add, node **head, int *num_nodes)
{
    node *cursor;
    node *tmp;
    node *last;

    // this is the first node.
    if ((*head) == NULL)
    {
        (*head)       = to_add;
        (*head)->next = NULL;
        
        (*num_nodes)++;
        return;
    }

    // this node is the new list head.
    if (to_add->base < (*head)->base)
    {
        tmp           = (*head);
        (*head)       = to_add;
        (*head)->next = tmp;
        
        (*num_nodes)++;
        return;
    }

    // find the ordered position for this node and insert it into the list.
    for (cursor = (*head)->next, last = (*head); cursor != NULL; cursor = cursor->next)
    {
        if (to_add->base < cursor->base)
        {
            to_add->next = cursor;
            last->next   = to_add;
            
            (*num_nodes)++;
            return;
        }

        last = cursor;
    }

    // add this node to the end of the list.
    to_add->next = NULL;
    last->next   = to_add;
    
    (*num_nodes)++;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////
// ps_node_find_by_address()
//
// given an address determine the module it would fall under.
//
node * ps_node_find_by_address (DWORD address, node *head)
{
    node *cursor;

    for (cursor = head; cursor != NULL; cursor = cursor->next)
        if (cursor->base <= address && address < cursor->base + cursor->size)
            return cursor;

    return NULL;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////
// ps_node_find_by_name()
//
// find a breakpoint module node by it's name.
//
node * ps_node_find_by_name (char *name, node *head)
{
    node *cursor;

    for (cursor = head; cursor != NULL; cursor = cursor->next)
        if (stricmp(cursor->name, name) == 0)
            return cursor;

    return NULL;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////
// ps_usage()
//
// display command line parameters and exit.
//
int ps_usage (void)
{
    printf("\nprocess stalker\n"
        "pedram amini <pedram.amini@gmail.com>\n"
           "compiled on "__DATE__"\n"
           "\n"
           "usage:\n"
           "  process_stalker <-a pid | -l filename | -la filename args>\n\n"
           "options:\n"
           "  [-b bp list]   specify the breakpoint list for the main module.\n"
           "  [-r recorder]  enter a recorder (0-9) from trace initiation.\n"
           "  [--one-time]   disable breakpoint restoration.\n"
           "  [--no-regs]    disable register enumeration / dereferencing.\n\n");
    
    exit(1);
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////
// callback functions
//
void initial_break (DEBUG_EVENT *db)
{
    char  line[256], module[128];
    DWORD f_offset, offset, base, size;
    int loaded = 0;
    node *bp_node;

    dbg.ActivateTraces();

    printf("initial break, tid = %04x.\n\n", dbg.FindThread( (DWORD)db->dwThreadId )->hThread);

    if (!dbg.get_thandle())
    {
        printf("manually setting thread handle.\n");
        dbg.set_thandle(dbg.FindThread( (DWORD)db->dwThreadId )->hThread);
    }

    // if an initial breakpoint list was provided, process it.
    if (bpl != NULL)
    {
        printf("loading breakpoints from %s\n", breakpoint_list);

        // process the breakpoint list line by line.
        for (int i = 0; fgets(line, sizeof(line), bpl) != NULL; i++)
        {
            // line format: module name:function offset:offset
            // ignore malformatted lines.
            if (sscanf(line, "%127[^:]:%08x:%08x", module, &f_offset, &offset) == 0)
                continue;
            
            // determine if this module already exists in our linked list.
            // if not attempt to locate the module in memory.
            if ((bp_node = ps_node_find_by_name(module, bp_modules)) == NULL)
            {
                // attempt to determine the module address / size.
                if (!ps_base_address(module, &base, &size))
                {
                    printf("failed locating base address for module %s\n", module);
                    continue;
                }

                // add a bp_node to the linked list.
                bp_node = (node *) malloc(sizeof(node));
                
                bp_node->base = base;
                bp_node->size = size;
                
                strncpy(bp_node->name, module, sizeof(bp_node->name) - 1);

                ps_node_add(bp_node, &bp_modules, &num_bp_modules);
            }

            // the '-25' means we want to reserve 25 left justified characters for the name.
            // the '.25' specifies that we want the string truncated after 25 characters.
            //printf("Setting breakpoint @%08x [%-25.25s] ... ", address, name);

            if (!dbg.bpx(bp_node->base + offset))
            {
                //printf("failed setting breakpoint @ 0x%08x\n", bp_node->base + offset);
                continue;
            }

            // at this point a breakpoint was successfully loaded.
            loaded++;

            if (i % 100 == 0)
                printf("setting breakpoint %d\r", i);

            // add function to splay tree.
            //if (offset == f_offset)
            //    function_list = splay_insert(address, name, function_list);
        }

        printf("done. %d of %d breakpoints set.\n", loaded, i);
        fclose(bpl);
    }
    // display the command menu.
    ps_commands();
}

// this function is called to process every breakpoint entry, so it should be as fast as possible.
void normal_break (DEBUG_EVENT *db)
{
    t_disassembly dis;
    DWORD         address;
    HANDLE        process;
    HANDLE        thread;
    node          *bp_node;
    bool          stalking = false;
    DWORD         tick_count;
    CONTEXT       context;
    LDT_ENTRY     selector_entry;
    DWORD         fs_base;
    DWORD         stack_top;
    DWORD         stack_bottom;

    tick_count = GetTickCount();
    address    = (DWORD)(db->u.Exception.ExceptionRecord.ExceptionAddress);
    thread     = dbg.FindThread((DWORD)db->dwThreadId)->hThread;
    process    = dbg.getProcessHandle();

    // bring the called function to the top of the list.
    //function_list = splay(address, function_list);

    // ensure the breakpoint lies in a module we are stalking.
    for (node *cursor = bp_modules; cursor != NULL; cursor = cursor->next)
    {
        if (address >= cursor->base && address <= cursor->base + cursor->size)
        {
                stalking = true;
                break;
        }
    }

    // if we're not stalking the current module, return now.
    if (!stalking)
        return;

    //
    // if we're recording, log the entry to the appropriate recorder file.
    //

    if (recorder_mode != NOT_RECORDING)
    {
        //function_list->recorded[recorder_mode]++;
        //printf("T:%04x [R%d] %08X %-25s [%5u] ", db->dwThreadId, recorder_mode, address, function_list->name, function_list->recorded[recorder_mode]);

        if (disassemble_flag)
            printf("%08x T:%08x [R%d] %08X ", tick_count, db->dwThreadId, recorder_mode, address);

        if ((bp_node = ps_node_find_by_address(address, bp_modules)) != NULL)
            fprintf(recorder, "%08x:%08x:%s:%08x:%08x\n", tick_count, db->dwThreadId, bp_node->name, bp_node->base, address - bp_node->base);
    }
    // else, not recording.
    else
    {
        if (disassemble_flag)
            printf("%08x T:%08x [bp] %08X ", tick_count, db->dwThreadId, address);
    }

    // if enabled, print the disassembly at the breakpoint address.
    if (disassemble_flag)
    {
        // XXX - wonder if there is any significant speed increase when we skip just the disassembly output.
        if (dbg.Disassemble(thread, address, &dis))
            printf("%s\n", dis.mnemonic.c_str());
        else
            printf("\n");
    }

    // if we are recording and register enumeration / dereferencing is enabled, process the registers we are interested in.
    if (recorder_mode != NOT_RECORDING && reg_enum_flag)
    {
        context.ContextFlags = CONTEXT_FULL;

        // get the thread context (containing the register values).
        if (GetThreadContext(thread, &context) == 0)
            return;

        // get the thread selector entry and calculate the 32-bit address for the FS register.
        if (GetThreadSelectorEntry(thread, context.SegFs, &selector_entry) == 0)
            return;

        fs_base = selector_entry.BaseLow + (selector_entry.HighWord.Bits.BaseMid << 16) + (selector_entry.HighWord.Bits.BaseHi << 24);
        
        // determine the top/bottom of the debuggee's stack.
        ReadProcessMemory(process, (void *)(fs_base + 4), &stack_top,    4, NULL);
        ReadProcessMemory(process, (void *)(fs_base + 8), &stack_bottom, 4, NULL);

        ps_analyze_register(process, tick_count, address, bp_node, stack_top, stack_bottom, context.Eax, "EAX");
        ps_analyze_register(process, tick_count, address, bp_node, stack_top, stack_bottom, context.Ebx, "EBX");
        ps_analyze_register(process, tick_count, address, bp_node, stack_top, stack_bottom, context.Ecx, "ECX");
        ps_analyze_register(process, tick_count, address, bp_node, stack_top, stack_bottom, context.Edx, "EDX");
        ps_analyze_register(process, tick_count, address, bp_node, stack_top, stack_bottom, context.Esi, "ESI");
        ps_analyze_register(process, tick_count, address, bp_node, stack_top, stack_bottom, context.Edi, "EDI");
    }

    // to restore the break point we just processed:
    //      - save the breakpoint address.
    //      - enable single stepping.
    //      - let the single step handler restore the breakpoint and disable single stepping.
    if (!dbg.one_time)
    {
        dbg.breakpoint_restore        = address;
        dbg.breakpoint_restore_thread = thread;
        dbg.SetSingleStep(thread, true);
    }
}


void itsdone (DEBUG_EVENT *db)
{
    printf("\nDebuggee terminated, doing the same\n");
    main_terminate = true;
}


void closer (t_Tracer_OpenTr *open)
{
    Debugger                *c;
    PROCESS_INFORMATION     ProcInfo;
    char                    bla[30];
    
    if (open->Definition->Name == "CreateProcessA")
    {
        printf("MAIN: Process created (CreateProcessA)\n");

        if (!ReadProcessMemory(dbg.getProcessHandle(),
                               (LPCVOID)(open->OutArgs[9].data.address),
                               &ProcInfo,
                               sizeof(ProcInfo),
                               NULL))
        {
            printf("Failed to read process memory at %08X\n", open->OutArgs[9].data.address);
        }
        else
        {
            c = new (Debugger);

            sprintf(bla,"Child %u",ProcInfo.dwProcessId);
            c->attach(ProcInfo.dwProcessId);
            c->log.Name= bla;

            Children.push_back(c);
        }
    }
    else if (open->Definition->Name == "CreateProcessAsUserA")
    {
        printf("MAIN: Process created (CreateProcessAsUserA)\n");

        if (!ReadProcessMemory(dbg.getProcessHandle(),
                               (LPCVOID)(open->OutArgs[10].data.address),
                               &ProcInfo,
                               sizeof(ProcInfo),
                               NULL))
        {
            printf("Failed to read process memory at %08X\n", open->OutArgs[10].data.address);
        }
        else
        {
            c = new (Debugger);

            sprintf(bla,"Child %u",ProcInfo.dwProcessId);
            c->attach(ProcInfo.dwProcessId);
            c->log.Name= bla;

            Children.push_back(c);
        }
    } 
}
