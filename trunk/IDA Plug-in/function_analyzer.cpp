/*
    Function Analyzer Class
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

    todo:
        - implicit edges are not currently being counted in the NEC count.
         (they are however enumerated in graph())
*/

#include <windows.h>
#include <stdlib.h>
#include <search.h>

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <expr.hpp>
#include <frame.hpp>
#include <gdl.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <md5.h>
#include <name.hpp>
#include <ua.hpp>

#include "function_analyzer.h"
#include "color_palette.h"

/////////////////////////////////////////////////////////////////////////////////////////
// constructors
//
// arguments:     fid - id of function to analyze.
//            OR  ea  - any address within the function.
// returns:   none.
//

function_analyzer::function_analyzer (int fid)
{
    func_t *fptr;
    ready = FALSE;

    if ((fptr = getn_func(fid)) == NULL)
        return;

    function_id = fid;

    constructor(fptr);
    ready = TRUE;
}


function_analyzer::function_analyzer (ea_t ea)
{
    func_t *fptr;
    ready = FALSE;

    if ((fptr = get_func(ea)) == NULL)
        return;

    function_id = get_func_num(ea);

    constructor(fptr);
    ready = TRUE;
}


/////////////////////////////////////////////////////////////////////////////////////////
// desctructor()
//
// arguments: none.
// returns:   none.
//

function_analyzer::~function_analyzer ()
{
    // free our dynamically allocated internal lists.
    qfree(calls_src);
    qfree(calls_dst);
    qfree(edges_src);
    qfree(edges_dst);
    qfree(nodes);
    qfree(instructions);
}


/////////////////////////////////////////////////////////////////////////////////////////
// add_call()
//
// add a call to our internal list.
//
// arguments: ea - effective address of call instruction we are adding to our list.
// returns:   false if call exists, true otherwise.
//

bool function_analyzer::add_call (ea_t ea)
{
    int i;

    // search for an existing call.
    for (i = 1; i <= num_calls; i++)
        if (calls_src[i] == ea)
            return FALSE;

    #ifdef FA_DEBUG
        msg("FA_DEBUG> add_call(%08x)\n", ea);
    #endif

    // no existing call was found. ensure we have space for the new call
    // we are about to add.
    if ((num_calls + 1) % 10 == 0)
    {
        calls_src = (ea_t *) qrealloc(calls_src, (num_calls + 10 + 1) * sizeof(ea_t));
        calls_dst = (ea_t *) qrealloc(calls_dst, (num_calls + 10 + 1) * sizeof(ea_t));
    }

    // record the new call.
    num_calls++;
    calls_src[num_calls] = ea;
    calls_dst[num_calls] = get_func_num(get_first_fcref_from(ea));

    return TRUE;
}


/////////////////////////////////////////////////////////////////////////////////////////
// add_edge()
//
// add an edge to our internal list.
//
// arguments: src - source address to draw the edge from.
//            dst - destination address to draw the edge to.
// returns:   false if edge exists, true otherwise.
//

bool function_analyzer::add_edge (ea_t src, ea_t dst)
{
    int i;

    // search for an existing edge.
    for (i = 1; i <= num_edges; i++)
        if (edges_src[i] == src && edges_dst[i] == dst)
            return FALSE;

    #ifdef FA_DEBUG
        msg("FA_DEBUG> add_edge(%08x, %08x)\n", src, dst);
    #endif

    // no existing edge was found. ensure we have space for the edge
    // pair we are about to add.
    if ((num_edges + 1) % 10 == 0)
    {
        edges_src = (ea_t *) qrealloc(edges_src, (num_edges + 10 + 1) * sizeof(ea_t));
        edges_dst = (ea_t *) qrealloc(edges_dst, (num_edges + 10 + 1) * sizeof(ea_t));
    }

    // record the new edge pair.
    num_edges++;
    edges_src[num_edges] = src;
    edges_dst[num_edges] = dst;

    return TRUE;
}


/////////////////////////////////////////////////////////////////////////////////////////
// add_instruction()
//
// add an instruction to our internal list.
//
// arguments: ea - effective address of instruction we are adding to our list.
// returns:   false if instruction already recorded, true otherwise.
//

bool function_analyzer::add_instruction (ea_t ea)
{
    int i;

    // search for an existing instruction.
    for (i = 1; i <= num_instructions; i++)
        if (instructions[i] == ea)
            return FALSE;

    #ifdef FA_DEBUG
        msg("FA_DEBUG> add_instruction(%08x)\n", ea);
    #endif

    // ensure we have space for the new node we are about to add.
    if ((num_instructions + 1) % 10 == 0)
        instructions = (ea_t *) qrealloc(instructions, (num_instructions + 10 + 1) * sizeof(ea_t));

    // record the new edge pair.
    num_instructions++;
    instructions[num_instructions] = ea;

    return TRUE;
}


/////////////////////////////////////////////////////////////////////////////////////////
// add_node()
//
// add a node to our internal list.
//
// arguments: ea - effective address of node we are adding to our list.
// returns:   false if node exists, true otherwise.
//

bool function_analyzer::add_node (ea_t ea)
{
    int i;

    // search for an existing node.
    for (i = 1; i <= num_nodes; i++)
        if (nodes[i] == ea)
            return FALSE;

    #ifdef FA_DEBUG
        msg("FA_DEBUG> add_node(%08x)\n", ea);
    #endif

    // no existing node was found. ensure we have space for the new node
    // we are about to add.
    if ((num_nodes + 1) % 10 == 0)
        nodes = (ea_t *) qrealloc(nodes, (num_nodes + 10 + 1) * sizeof(ea_t));

    // record the new node.
    num_nodes++;
    nodes[num_nodes] = ea;

    return TRUE;
}


/////////////////////////////////////////////////////////////////////////////////////////
// analyze() *** recursive ***
//
// arguments: ea - effective address to analyze from.
// returns:   none.
//

void function_analyzer::analyze (ea_t ea)
{
    char disasm_buf[FA_DISASM_BUFLEN];
    ea_t fcref;
    ea_t next;

    // create the first node.
    add_node(ea);

    #ifdef FA_DEBUG
        msg("FA_DEBUG> analyze(%08x)\n", ea);
    #endif

    while (ea != BADADDR)
    {
        // record the current instruction.
        add_instruction(ea);

        // decode the current instruction.
        ua_mnem(ea, disasm_buf, FA_DISASM_BUFLEN);

        // get the first far code reference from the current instruction.
        fcref = get_first_fcref_from(ea);

        // get the next viseable instructions from the current one.
        next = next_visea(ea);

        // if a xref exists and is a branch instruction.
        if (fcref != BADADDR && disasm_buf[0] == 'j')
        {
            // unconditional jump.
            if (strnicmp(disasm_buf, "jmp", 3) == 0)
            {
                #ifdef FA_DEBUG
                    msg("FA_DEBUG> begin unconditional jump @%08x\n", ea);
                #endif

                // if we are currently processing a far-off code fragment and come across a
                // xref back into our contiguous range then return. we do this because we want
                // our previous recursive self to analyze the contiguous range thereby resulting
                // in a more pleasant instruction order.
                if (ea < ea_start || ea > ea_end)
                    if (fcref >= ea_start && fcref <= ea_end)
                    {
                        #ifdef FA_DEBUG
                            msg("FA_DEBUG> xref back @%08x\n", ea);
                        #endif

                        // XXX - removed the following line:
                        //           add_node(fcref)
                        //       because it was chopping off nodes from being processed. we handle
                        //       these by adding "implicit nodes" in our graphing routine.
                        add_edge(ea, fcref);
                        return;
                    }


                // record the edge to the xref.
                add_edge(ea, fcref);

                // if we are currently processing contiguos code and the xref node is
                // far-off then process it first.
                if ((ea >= ea_start && ea <= ea_end) && (fcref < ea_start || fcref > ea_end))
                    if (add_node(fcref))
                        analyze(fcref);

                // if the next instruction lies within the range of our contiguous function
                // then consider adding and following that node.
                if (next >= ea_start && next <= ea_end)
                    if (add_node(next))
                        analyze(next);

                // if we haven't already processed the xref as a node, then do so.
                if (add_node(fcref))
                    analyze(fcref);

                #ifdef FA_DEBUG
                    msg("FA_DEBUG> end unconditional jump @%08x\n", ea);
                #endif

                return;
            }
            // conditional jump.
            else
            {
                #ifdef FA_DEBUG
                    msg("FA_DEBUG> begin conditional jump @%08x\n", ea);
                #endif

                // record the edge to the next instruction as well as to the xref.
                add_edge(ea, next);
                add_edge(ea, fcref);

                // if we are currently processing contiguos code and the xref node is
                // far-off then process it first.
                if ((ea >= ea_start && ea <= ea_end) && (fcref < ea_start || fcref > ea_end))
                    if (add_node(fcref))
                        analyze(fcref);

                // if the nodes haven't already been processed, follow them.
                if (add_node(next))
                    analyze(next);

                if (add_node(fcref))
                    analyze(fcref);

                #ifdef FA_DEBUG
                    msg("FA_DEBUG> end conditional jump @%08x\n", ea);
                #endif

                return;
            }
        }

        // if a xref exists and is a call instruction.
        if (is_call_insn(ea))
            add_call(ea);

        // if we are currently processing a far off code fragment and the current
        // instruction is a return. then return.
        if ((ea < ea_start || ea > ea_end) && strnicmp(disasm_buf, "ret", 3) == 0)
            return;

        // if we've reached the end of our routine, ensure the last instruction is
        // recorded and return.
        // XXX - yet another cheap hack, this may not even be necessary any more
        //       but there may have been a special case and i don't want to break
        //       my working code.
        if (ea == ea_end)
        {
            add_instruction(ea);
            return;
        }

        // analyze the next instruction.
        ea = next;
    }
}


/////////////////////////////////////////////////////////////////////////////////////////
// constructor()
//
// this function is called from one of the defined constructors and initializes the
// class object.
//
// arguments: fptr - pointer to function.
// returns:   none.
//

void function_analyzer::constructor (func_t *fptr)
{
    crc              = 0;
    disasm_flags     = 0;
    ea_start         = fptr->startEA;
    ea_end           = prev_visea(fptr->endEA);
    num_nodes        = 0;
    num_edges        = 0;
    num_calls        = 0;
    num_instructions = 0;
    size             = fptr->endEA - ea_start;

    // save the function name.
    get_func_name(fptr->startEA, function_name, sizeof(function_name) - 1);

    memset(md5, 0, sizeof(md5));

    // allocate some initial memory for our internal lists.
    calls_src    = (ea_t *) qalloc(10 * sizeof(ea_t));
    calls_dst    = (ea_t *) qalloc(10 * sizeof(ea_t));
    edges_src    = (ea_t *) qalloc(10 * sizeof(ea_t));
    edges_dst    = (ea_t *) qalloc(10 * sizeof(ea_t));
    nodes        = (ea_t *) qalloc(10 * sizeof(ea_t));
    instructions = (ea_t *) qalloc(10 * sizeof(ea_t));

    // default graph settings.
    finetuning            = TRUE;
    gml_ignore_self_loops = TRUE;
    gml_ins_color         = TRUE;
    manhattan_edges       = FALSE;
    sort_nodes            = FALSE;
    splines               = TRUE;
    strip_comments        = TRUE;
    layout_downfactor     = 100;
    xlspace               = 20;
    xspace                = 30;

    qstrncpy(color,            FA_COLOR_BG,          sizeof(color));
    qstrncpy(color_far_off,    FA_COLOR_NODE_FAROFF, sizeof(color_far_off));
    qstrncpy(color_node,       FA_COLOR_NODE,        sizeof(color_node));
    qstrncpy(layout_algorithm, "mindepthslow",       sizeof(layout_algorithm));
}


/////////////////////////////////////////////////////////////////////////////////////////
// crc_build_table()
//
// this function is responsible for initializing the CRC table.
//
// arguments: none.
// returns:   none.
//

void function_analyzer::crc_build_table (void)
{
    unsigned long crc;
    unsigned long polynomial = 0xEDB88320L;
    int i, j;

    for (i = 0; i < 256; i++)
    {
        crc = i;
        for (j = 8; j > 0; j--)
        {
            if (crc & 1)
                crc = (crc >> 1) ^ polynomial;
            else
                crc >>= 1;
        }

        crc_table[i] = crc;
    }
}


/////////////////////////////////////////////////////////////////////////////////////////
// crc_calculate()
//
// this function calculates the CRC checksum for the current function.
//
// arguments: none.
// returns:   none.
//

void function_analyzer::crc_calculate (void)
{
    unsigned char byte;
    char instruction[16];
    ea_t ea;
    ea_t i;

    crc = 0xFFFFFFFF;

    // step through the function instruction by instruction.
    for (ea = first_ea(); ea != BADADDR; ea = next_ea(ea))
    {
        // fill the 'cmd' structure.
        ua_ana0(ea);

        // we are uninterested in call instructions as the relative address of an
        // equivalent call may be different across two versions of a binary thereby
        // breaking our CRC matching.
        if (is_call_insn(ea))
            continue;

        // decode the instruction.
        ua_mnem(ea, instruction, sizeof(instruction));
        tag_remove(instruction, instruction, sizeof(instruction));

        // we are uninterested in jump instructions as the relative address of an
        // equivalent jump may be different across two versions of a binary thereby
        // breaking our CRC matching.
        if (get_first_fcref_from(ea) && instruction[0] == 'j')
            continue;

        // calculate the CRC over the length of the current instruction.
        for (i = ea; i < ea + cmd.size; i++)
        {
            byte = get_byte(i);
            crc = (crc >> 8) ^ crc_table[(crc ^ byte) & 0xFF];
        }
    }

    crc = crc ^ 0xFFFFFFFF;
}


/////////////////////////////////////////////////////////////////////////////////////////
// disasm()
//
// disassemble an instruction at the given address. we use a custom routine instead of
// an API routine like generate_disasm_line() because the API routine's output is
// influenced by user settings and our "static" routine is not.
//
// notes:     this routine is used mainly for the purpose of generating per function md5
//            signatures.
//
// arguments: ea          - effective address to disassemble at.
//            disasm_buf  - buffer to store disassembly output into.
// returns:   boolean value representing success of failure.
//

bool function_analyzer::disasm (ea_t ea, char *disasm_buf)
{
    char op_buf[512];
    char *p_op_buf;
    char *index;
    bool record_op;
    int op_num = 0;

    // ensure we are at the start of an instruction.
    if (!isCode(getFlags(ea)))
        return FALSE;

    // decode the instruction.
    ua_mnem(ea, disasm_buf, FA_DISASM_BUFLEN);
    tag_remove(disasm_buf, disasm_buf, FA_DISASM_BUFLEN);

    // if the user wants to tokenize jumps and this is a jump then do so now.
    if (disasm_flags & FA_TOKENIZE_JUMPS && get_first_fcref_from(ea) && disasm_buf[0] == 'j')
    {
        // we are dealing with a jxx instruction. replace the instruction with one of three
        // tokens. unconditional, signed or unsigned.

        // unconditional branching.
        // (jmp)
        if (strnicmp(disasm_buf, "jmp", 3) == 0)
        {
            qstrncpy(disasm_buf, FA_UNCONDITIONAL_TOKEN, FA_DISASM_BUFLEN);
            return TRUE;
        }

        // signed branching.
        // (jg, jge, jl, jle, jng, jnge, jnl, jnle, jno, jns, jo, js)
        if ((strstr(disasm_buf, "g")   ||   // jump if greater than
             strstr(disasm_buf, "l")   ||   // jump if less than
             strstr(disasm_buf, "s")   ||   // jump if signed/unsigned
             strstr(disasm_buf, "o"))  &&   // jump if overflow
            !strstr(disasm_buf, "jpo"))     // jump if odd parity (this is an unsigned operation)
        {
            qstrncpy(disasm_buf, FA_SIGNED_TOKEN, FA_DISASM_BUFLEN);
            return TRUE;
        }

        // unsigned branching.
        // (ja, jae, jb, jbe, jc, jcxz, je, jna, jnae, jnb, jnbe, jnc, jne, jnp, jnz, jp, jpe, jpo, jz)
        qstrncpy(disasm_buf, FA_UNSIGNED_TOKEN, FA_DISASM_BUFLEN);
        return TRUE;
    }

    // if the user is interested only in instructions, then return now.
    if (disasm_flags & FA_INSTRUCTIONS_ONLY)
        return TRUE;

    // if this is a call and the user has selected to ignore calls, then return now.
    if (disasm_flags & FA_IGNORE_CALLS && is_call_insn(ea))
        return TRUE;

    // decode the first operand.
    ua_outop(ea, op_buf, 512, op_num++);
    tag_remove(op_buf, op_buf, 512);
    p_op_buf = op_buf;

    // loop through the rest of the operands and concatenate them into one string.
    while(strlen(p_op_buf) != 0)
    {
        record_op = TRUE;

        // chop off the "large" prefix if it exists.
        if (strnicmp(p_op_buf, "large ", 6) == 0)
            p_op_buf += 6;

        // chop off the ds segment prefix if it exists.
        if (strnicmp(p_op_buf, "ds:", 3) == 0)
        {
            p_op_buf += 3;

            // if we have an operand of the format ds:406CF0h[esi*4] then we want to chop off
            // the hex value up to the first '['
            if ((index = strchr(p_op_buf, '[')) != NULL)
                p_op_buf = index;
        }

        // chop off the fs segment prefix if it exists.
        if (strnicmp(p_op_buf, "fs:", 3) == 0)
            p_op_buf += 3;

        // chop off the ss segment prefix if it exists.
        if (strnicmp(p_op_buf, "ss:", 3) == 0)
            p_op_buf += 3;

        // if we come across operands of the forms:
        //     - (offset dword_????+1)
        //     - dword ptr ????
        // just ignore them.
        if (strchr(p_op_buf, ')') || strstr(p_op_buf, " ptr "))
        {
            // decode the next operand ... if any.
            ua_outop(ea, op_buf, 512, op_num++);
            tag_remove(op_buf, op_buf, 512);
            p_op_buf = op_buf;
            continue;
        }

        // chop off the size prefix if it exists.
        if (strnicmp(p_op_buf, "byte ptr ",  9)  == 0) p_op_buf += 9;
        if (strnicmp(p_op_buf, "word ptr ",  9)  == 0) p_op_buf += 9;
        if (strnicmp(p_op_buf, "dbyte ptr ", 10) == 0) p_op_buf += 10;

        //
        // filter out the default "Name Representation" prefixes.
        //

        // 3-letter prefixes:
        //   sub_     instruction, subroutine start
        //   unk_     unexplored byte
        //   loc_     instruction
        //   off_     data, contains offset value
        //   seg_     data, contains segment address value
        //   asc_     data, ascii string
        //   flt_     floating point data, 32-bit (or array of floats)
        //   dbl_     floating point data, 64-bit (or array of doubles)

        if (strnicmp(p_op_buf, "sub_", 4) == 0 || strnicmp(p_op_buf, "unk_", 4) == 0 ||
            strnicmp(p_op_buf, "loc_", 4) == 0 || strnicmp(p_op_buf, "off_", 4) == 0 ||
            strnicmp(p_op_buf, "seg_", 4) == 0 || strnicmp(p_op_buf, "asc_", 4) == 0 ||
            strnicmp(p_op_buf, "flt_", 4) == 0 || strnicmp(p_op_buf, "dbl_", 4) == 0)
        {
            record_op = FALSE;
        }

        // 4-letter prefixes:
        //   byte_    data, byte (or array of bytes)
        //   word_    data, 16-bit (or array of words)
        //   stru_    structure (or array of structures)
        //   algn_    alignment directive

        if (record_op &&
           (strnicmp(p_op_buf, "byte_", 5) == 0 || strnicmp(p_op_buf, "word_", 5) == 0 ||
            strnicmp(p_op_buf, "stru_", 5) == 0 || strnicmp(p_op_buf, "algn_", 5) == 0))
        {
            record_op = FALSE;
        }

        // 5-letter prefixes:
        //   dword_   data, 32-bit (or array of dwords)
        //   qword_   data, 64-bit (or array of qwords)
        //   tbyte_   floating point data, 80-bit (or array of tbytes)

        if (record_op &&
           (strnicmp(p_op_buf, "dword_", 6) == 0 || strnicmp(p_op_buf, "qword_", 6) == 0 ||
            strnicmp(p_op_buf, "tbyte_", 6) == 0 || strnicmp(p_op_buf, "offset", 6) == 0))
        {
            record_op = FALSE;
        }

        // 6-letter prefixes:
        //   locret_  'return' instruction

        if (record_op && strnicmp(p_op_buf, "locret_", 7) == 0)
        {
            record_op = FALSE;
        }

        // if this op is still worthy of recording then do so.
        if (record_op)
        {
            qstrncat(disasm_buf, " ",      FA_DISASM_BUFLEN - strlen(p_op_buf) - 1);
            qstrncat(disasm_buf, p_op_buf, FA_DISASM_BUFLEN - strlen(p_op_buf) - 1);
        }

        // decode the next operand ... if any.
        ua_outop(ea, op_buf, 512, op_num++);
        tag_remove(op_buf, op_buf, 512);
        p_op_buf = op_buf;
    }

    return TRUE;
}


/////////////////////////////////////////////////////////////////////////////////////////
// gml_export()
//
// export the gml definition for a graph.
//
// arguments: file_path    - base path to write GML function graphs to.
//            base_node_id - base number to create node id's from.
// returns:   none.
//

void function_analyzer::gml_export (char *file_path, int base_node_id)
{
    FILE *fp    = NULL;     // graph output file.
    FILE *xrefs = NULL;     // xrefs output file.
    char disasm_buf[FA_DISASM_BUFLEN];
    char tmp_buf   [FA_DISASM_BUFLEN];
    char line_color[16];
    char gml_line[256];
    char path[1024];
    char color[10];
    char *tmp, *dis;
    int  i, len, this_width, width, height, amount;
    bool first_line;
    bool color_max = FALSE;
    bool color_on  = FALSE;
    ea_t ea;
    ea_t fcref;
    ea_t src;

    ///////////////////////////////////////////////////////////////////////////////////////////////
    // open the output files.
    //

    // construct the graph output file name as "file path + get_root_filename() + '-' + function address + .gml".
    _snprintf(path, sizeof(path) - 1, "%s\\%s-%08x.gml", file_path, get_root_filename(), ea_start);

    // open the graph output file.
    if ((fp = qfopen(path, "w+")) == NULL)
    {
        msg("gml_export> Failed to open %s for writing.\n", path);
        return;
    }

    // contruct the xrefs output file name as "file path + get_root_filename() + .xrefs".
    _snprintf(path, sizeof(path) - 1, "%s\\%s.xrefs", file_path, get_root_filename());

    // open the xrefs output file.
    if ((xrefs = qfopen(path, "a+")) == NULL)
    {
        msg("gml_export> Failed to open %s for writing.\n", path);
        return;
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    // graph header.
    //
    qfprintf(fp, "Creator \"process stalker - pedram amini\"\n"
                 "directed 1\n"
                 "graph [\n");

    ///////////////////////////////////////////////////////////////////////////////////////////////
    // graph nodes.
    //

    // graph the nodes.
    for (i = 1; i <= num_nodes; i++)
    {
        // open the node.
        qfprintf(fp, "  node [\n"
                     "    id %d\n"
                     "    template \"oreas:std:rect\"\n"
                     "    label \"<!--%d:%08x:%08x-->"GML_BASE_FONT_OPEN"\\\n<p><font color=#004080><b>%08x %s</b></font></p>\\\n",
                     base_node_id + i,
                     base_node_id + i,
                     ea_start,
                     nodes[i],
                     nodes[i],
                     (nodes[i] == ea_start) ? function_name : "");

        // minimum node width/height with 1 disassembly line.
        height = 70;
        width  = 0;

        // reset first_line flag.
        first_line = TRUE;

        // process each line within this node.
        for (ea = nodes[i]; ea != BADADDR; ea = next_ea(ea))
        {
            //
            // record a xref if this line is a call to another function within this module.
            //

            if (is_call_insn(ea))
            {
                fcref = get_first_fcref_from(ea);

                if (fcref >= inf.minEA && fcref <= inf.maxEA)
                    qfprintf(xrefs, "%08x:%08x:%08x\n", ea_start - inf.minEA, nodes[i] - inf.minEA, fcref - inf.minEA);
            }

            // clear our disassembly buffers.
            memset(disasm_buf, 0, sizeof(disasm_buf));
            memset(tmp_buf,    0, sizeof(tmp_buf));

            // generate the disassembly for the current effective address.
            generate_disasm_line(ea, tmp_buf, sizeof(tmp_buf));

            // add 15 pixels of height per disassembly line.
            height += 15;

            // reset the current line width.
            // 8 characters for the address plus a space, this number is later multiplied by 8 (8-pixels per character).
            this_width = 9;

            // strip out comments from the generated disassembly.
            // comments start with a semi-colon ';'.
            if (strip_comments)
            {
                if ((tmp = strchr(tmp_buf, ';')) != NULL)
                {
                    // step backwards to cut through all the whitespace.
                    for(tmp--; *tmp == ' '; tmp--)
                        *tmp = 0x00;
                }
            }
            // replace all double quotes (") with single quotes (').
            else
            {
                while ((tmp = strchr(tmp_buf, '"')) != NULL)
                    *tmp = '\'';
            }

            // convert IDA coloring to wingraph32 compatible format.
            for (tmp = tmp_buf, dis = disasm_buf; tmp <= tmp_buf + strlen(tmp_buf); tmp++)
            {
                // escape character on. (convert format)
                if (*tmp == COLOR_ON)
                {
                    // go to the next character.
                    tmp++;

                    if (gml_ins_color)
                    {
                        switch (*tmp)
                        {
                            case COLOR_LOCNAME:   qstrncat(disasm_buf, GML_COLOR_LOCNAME, FA_DISASM_BUFLEN); color_on = TRUE; break;
                            case COLOR_KEYWORD:   qstrncat(disasm_buf, GML_COLOR_KEYWORD, FA_DISASM_BUFLEN); color_on = TRUE; break;
                            case COLOR_REG:       qstrncat(disasm_buf, GML_COLOR_REG,     FA_DISASM_BUFLEN); color_on = TRUE; break;

                            case COLOR_FG_MAX:
                                qstrncat(disasm_buf, GML_COLOR_FG_MAX, FA_DISASM_BUFLEN);
                                // XXX - generate_disasm_line returns locational references in the form:
                                //           ????????loc_????????
                                ///      where ??????? is the 8 digit 0-padded hexidecimal address of the
                                //       location. the simplest way to deal with this is to simply increment
                                //       past the initial location address (the following +8) thereby only
                                //       leaving the remaining name to be used by our grapher.
                                tmp += 8;
                                color_max = TRUE;
                                break;
                            default:
                                continue;
                        }

                        dis += 20; // 20 = strlen(GML_COLOR_XXXXXX)
                    }
                }

                // escape character for color off, close the font directive.
                else if (*tmp == COLOR_OFF)
                {
                    tmp++;

                    if (gml_ins_color)
                    {
                        // for whatever reason COLOR_FG_MAX does not have a closing tag. when COLOR_FG_MAX is open
                        // we set a boolean flag and close the tag as soon as the first COLOR_OFF is found.
                        if (color_max)
                        {
                            color_max = FALSE;
                            qstrncat(disasm_buf, "</font>", FA_DISASM_BUFLEN);
                            dis += 7; // 7 = strlen("</font>")
                        }

                        // we use the color_on flag to ensure that we don't get any duplicate closing font tags
                        // that will break our formatting.
                        if (color_on)
                        {
                            color_on = FALSE;

                            switch (*tmp)
                            {
                                //case COLOR_SYMBOL:
                                case COLOR_LOCNAME:
                                case COLOR_KEYWORD:
                                case COLOR_REG:
                                    qstrncat(disasm_buf, "</font>", FA_DISASM_BUFLEN);
                                    dis += 7; // 7 = strlen("</font>")
                                    break;
                            }
                        }
                    }

                }

                // quote next character.
                else if (*tmp == COLOR_ESC)
                {
                    // go to the next character.
                    tmp++;

                    // copy the character as a string.
                    qsnprintf(disasm_buf, sizeof(disasm_buf) - 1, "%s0x%02x", disasm_buf, *tmp);

                    this_width += 2;
                }

                // inverse colors. (ignore these)
                else if (*tmp == COLOR_INV)
                    tmp++;

                // replace spaces with &nbsp;
                else if (*tmp == ' ')
                {
                    qstrncat(dis, "&nbsp;", FA_DISASM_BUFLEN - (dis - disasm_buf));
                    dis += 6;

                    this_width++;
                }

                // replace '<' and '>' with their HTML code equivalent.
                else if (*tmp == '<')
                {
                    qstrncat(dis, "&lt;", FA_DISASM_BUFLEN - (dis - disasm_buf));
                    dis += 4;

                    this_width++;
                }

                else if (*tmp == '>')
                {
                    qstrncat(dis, "&gt;", FA_DISASM_BUFLEN - (dis - disasm_buf));
                    dis += 4;

                    this_width++;
                }

                // escape all backslashes.
                else if (*tmp == '\\')
                {
                    qstrncat(dis, "\\\\", FA_DISASM_BUFLEN - (dis - disasm_buf));
                    dis += 2;

                    this_width++;
                }
                else
                {
                    *dis = *tmp;
                    dis++;

                    this_width++;
                }
            }

            // keep a running track of the longest line.
            if (this_width > width)
                width = this_width;

            // write this line to the output file.
            // XXX - GDE does not like lines longer then approx 250 bytes. within their
            //       their own GML files you won't find lines longer then approx 210 bytes.
            //       so we are forced to write long lines in little chunks.
            if (!first_line)
                qfprintf(fp, "<br>");
            else
                first_line = FALSE;

            qfprintf(fp, GML_COLOR_ADDRESS"%08x</font> ", ea);

            memset(gml_line, 0, sizeof(gml_line));

            for (len = 0, dis = disasm_buf ; len < strlen(disasm_buf); len += amount)
            {
                amount = 200;

                // if the end of the current chunk contains a backslash, back off some.
                while (*(dis+amount) == '\\')
                    amount--;

                _snprintf(gml_line, amount, "%s", dis);

                qfprintf(fp, "%s\\\n", gml_line);
                dis += amount;
            }

            // break if the next instruction is the start of another node.
            if (is_node(next_ea(ea)))
                break;

            // if the current instruction is far off.
            if (ea < ea_start || ea > ea_end)
            {
                memset(disasm_buf, 0, sizeof(disasm_buf));
                disasm(ea, disasm_buf);

                fcref = get_first_fcref_from(ea);

                // break if the current instruction returns back to our original code.
                if (fcref >= ea_start && fcref <= ea_start && strnicmp(disasm_buf, "jmp", 3) == 0)
                    break;

                if (strnicmp(disasm_buf, "ret", 3) == 0)
                    break;
            }
        }

        //
        // construct the graphics descriptor for this node and close it.
        //

        // entry point.
        if (nodes[i] == ea_start)
            qstrncpy(color, GML_COLOR_NODE_ENTRY, sizeof(color));

        // far off nodes.
        else if (nodes[i] < ea_start || nodes[i] > ea_end)
            qstrncpy(color, GML_COLOR_NODE_FAROFF, sizeof(color));

        // regular nodes.
        else
            qstrncpy(color, GML_COLOR_NODE, sizeof(color));

        qfprintf(fp, GML_BASE_FONT_CLOSE"\"\n"     // close the label.
                     "    graphics [\n"
                     "      w %d.0000000\n"
                     "      h %d.0000000\n"
                     "      fill \"%s\"\n"
                     "      line \"%s\"\n"
                     "      pattern \"1\"\n"
                     "      stipple 1\n"
                     "      lineWidth 1.0000000\n"
                     "      type \"rectangle\"\n"
                     "      width 1.0\n"
                     "    ]\n"
                     "  ]\n",
                     width * 8,
                     height,
                     color,
                     "#999999");
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    // graph edges.
    //

    // graph all the recorded edges.
    for (i = 1; i <= num_edges; i++)
    {
        // determine the source node by looking backwards until we find the start of a node.
        for (src = edges_src[i]; src != BADADDR; src = prev_visea(src))
            if (is_node(src))
                break;

        // prevent the creation of self-loops if the option to do so is enabled.
        // this option is available for orthogonal graphs as they can not contain self-loops.
        if (gml_ignore_self_loops && src == edges_dst[i])
            continue;

        // find the end of this node, ie: the branching instruction.
        for (fcref = BADADDR, ea = edges_src[i]; fcref == BADADDR; ea = next_ea(ea))
        {
            if ((fcref = get_first_fcref_from(ea)) != BADADDR)
            {
                memset(disasm_buf, 0, sizeof(disasm_buf));
                disasm(ea, disasm_buf);

                // we are looking for a jump.
                if (disasm_buf[0] != 'j')
                    fcref = BADADDR;
            }
        }

        // unconditional jump.
        if (strnicmp(disasm_buf, "jmp", 3) == 0)
            qstrncpy(line_color, "#000000", sizeof(line_color));
        // conditional jump, true branch.
        else if (fcref == edges_dst[i])
            qstrncpy(line_color, "#00FF00", sizeof(line_color));
        // conditional jump, false branch.
        else
            qstrncpy(line_color, "#FF0000", sizeof(line_color));

        qfprintf(fp, "  edge [\n"
                     "    source %d\n"
                     "    target %d\n"
                     "    generalization 0\n"
                     "    graphics [\n"
                     "      type \"line\"\n"
                     "      arrow \"none\"\n"
                     "      stipple 1\n"
                     "      lineWidth 1.0000000\n"
                     "      fill \"%s\"\n"
                     "    ]\n"
                     "  ]\n",
                     base_node_id + find_node_index(src),
                     base_node_id + find_node_index(edges_dst[i]),
                     line_color);
    }

    // graph the implicit edges.
    // these are the edges from one instruction to the next, where the next instruction is the
    // start of a new node.
    // branching / return instructions are ignored here.
    for (ea = first_ea(); ea != BADADDR; ea = next_ea(ea))
    {
        memset(disasm_buf, 0, sizeof(disasm_buf));
        disasm(ea, disasm_buf);

        if (strnicmp(disasm_buf, "ret", 3) == 0)
            continue;

        if (get_first_fcref_from(ea) != BADADDR && disasm_buf[0] == 'j')
            continue;

        if (is_node(next_ea(ea)))
        {
            // determine the source node by looking backwards until we find the start of a node.
            for (src = ea; src != BADADDR; src = prev_visea(src))
                if (is_node(src))
                    break;

            qfprintf(fp, "  edge [\n"
                         "    source %d\n"
                         "    target %d\n"
                         "    generalization 0\n"
                         "    graphics [\n"
                         "      type \"line\"\n"
                         "      arrow \"none\"\n"
                         "      stipple 1\n"
                         "      lineWidth 1.0000000\n"
                         "      fill \"#0000FF\"\n"
                         "    ]\n"
                         "  ]\n",
                         base_node_id + find_node_index(src),
                         base_node_id + find_node_index(next_ea(ea)));
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    // graph footer.
    //

    qfprintf(fp, "]\n");

    // close the output streams.
    qfclose(fp);
    qfclose(xrefs);
}


/////////////////////////////////////////////////////////////////////////////////////////
// graph()
//
// generate and display a graph for this routine.
//
// arguments: none.
// returns:   none.
//

void function_analyzer::graph (void)
{
    FILE *fp = NULL;
    char disasm_buf[FA_DISASM_BUFLEN];
    char tmp_buf   [FA_DISASM_BUFLEN];
    char path[1024];
    char *tmp, *dis;
    int  i;
    ea_t ea;
    ea_t fcref;
    ea_t src;

    // generate a random file name in the temp directory to store our graph.
    memset(path, 0, sizeof(path));
    qtmpnam(path, sizeof(path) - 1);

    // open the output file.
    if ((fp = qfopen(path, "wb")) == NULL)
    {
        msg("graph> Failed to open %s for writing.\n", path);
        return;
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    // graph header.
    //
    qfprintf(fp, "graph:\n"
                 "{\n"
                 "\ttitle:                \"graph of %08x\"\n"
                 "\tmanhattan_edges:      %s\n"
                 "\tsplines:              %s\n"
                 "\tfinetuning:           %s\n"
                 "\tlayoutalgorithm:      %s\n"
                 "\tlayout_downfactor:    %d\n"
                 "\txlspace:              %d\n"
                 "\txspace:               %d\n"
                 "\tcolor:                %s\n"
                 "\n"FA_COLOR_PALETTE"\n",
                 nodes[1],
                 manhattan_edges ? "yes" : "no",
                 splines         ? "yes" : "no",
                 finetuning      ? "yes" : "no",
                 layout_algorithm,
                 layout_downfactor,
                 xlspace,
                 xspace,
                 color);

    ///////////////////////////////////////////////////////////////////////////////////////////////
    // graph nodes.
    //

    // graph the nodes.
    for (i = 1; i <= num_nodes; i++)
    {
        // open the node.
        qfprintf(fp, "\tnode: { title: \"%08x\" label: \""FA_COLOR_LABEL"%08x:", nodes[i], nodes[i]);

        // insert the disassembly of this node into the label.
        for (ea = nodes[i]; ea != BADADDR; ea = next_ea(ea))
        {
            // clear our disassembly buffers.
            memset(disasm_buf, 0, sizeof(disasm_buf));
            memset(tmp_buf,    0, sizeof(tmp_buf));

            // generate the disassembly for the current effective address.
            generate_disasm_line(ea, tmp_buf, FA_DISASM_BUFLEN);

            // strip out comments from the generated disassembly.
            // comments start with a semi-colon ';'.
            if (strip_comments)
            {
                if ((tmp = strchr(tmp_buf, ';')) != NULL)
                {
                    // cut through all the whitespace.
                    for(tmp--; *tmp == ' '; tmp--)
                        *tmp = 0x00;
                }
            }
            // replace all double quotes (") with single quotes (').
            else
            {
                while ((tmp = strchr(tmp_buf, '"')) != NULL)
                    *tmp = '\'';
            }

            // convert IDA coloring to wingraph32 compatible format.
            for (tmp = tmp_buf, dis = disasm_buf; tmp <= tmp_buf + strlen(tmp_buf); tmp++)
            {
                // escape character on. (convert format)
                if (*tmp == COLOR_ON)
                {
                    // go to the next character.
                    tmp++;

                    switch (*tmp)
                    {
                        case COLOR_DEFAULT:   qstrncat(disasm_buf, FA_COLOR_DEFAULT,   FA_DISASM_BUFLEN); break;
                        case COLOR_REGCMT:    qstrncat(disasm_buf, FA_COLOR_REGCMT,    FA_DISASM_BUFLEN); break;
                        case COLOR_RPTCMT:    qstrncat(disasm_buf, FA_COLOR_RPTCMT,    FA_DISASM_BUFLEN); break;
                        case COLOR_AUTOCMT:   qstrncat(disasm_buf, FA_COLOR_AUTOCMT,   FA_DISASM_BUFLEN); break;
                        case COLOR_INSN:      qstrncat(disasm_buf, FA_COLOR_INSN,      FA_DISASM_BUFLEN); break;
                        case COLOR_DATNAME:   qstrncat(disasm_buf, FA_COLOR_DATNAME,   FA_DISASM_BUFLEN); break;
                        case COLOR_DNAME:     qstrncat(disasm_buf, FA_COLOR_DNAME,     FA_DISASM_BUFLEN); break;
                        case COLOR_DEMNAME:   qstrncat(disasm_buf, FA_COLOR_DEMNAME,   FA_DISASM_BUFLEN); break;
                        case COLOR_SYMBOL:    qstrncat(disasm_buf, FA_COLOR_SYMBOL,    FA_DISASM_BUFLEN); break;
                        case COLOR_CHAR:      qstrncat(disasm_buf, FA_COLOR_CHAR,      FA_DISASM_BUFLEN); break;
                        case COLOR_STRING:    qstrncat(disasm_buf, FA_COLOR_STRING,    FA_DISASM_BUFLEN); break;
                        case COLOR_NUMBER:    qstrncat(disasm_buf, FA_COLOR_NUMBER,    FA_DISASM_BUFLEN); break;
                        case COLOR_VOIDOP:    qstrncat(disasm_buf, FA_COLOR_VOIDOP,    FA_DISASM_BUFLEN); break;
                        case COLOR_CREF:      qstrncat(disasm_buf, FA_COLOR_CREF,      FA_DISASM_BUFLEN); break;
                        case COLOR_DREF:      qstrncat(disasm_buf, FA_COLOR_DREF,      FA_DISASM_BUFLEN); break;
                        case COLOR_CREFTAIL:  qstrncat(disasm_buf, FA_COLOR_CREFTAIL,  FA_DISASM_BUFLEN); break;
                        case COLOR_DREFTAIL:  qstrncat(disasm_buf, FA_COLOR_DREFTAIL,  FA_DISASM_BUFLEN); break;
                        case COLOR_ERROR:     qstrncat(disasm_buf, FA_COLOR_ERROR,     FA_DISASM_BUFLEN); break;
                        case COLOR_PREFIX:    qstrncat(disasm_buf, FA_COLOR_PREFIX,    FA_DISASM_BUFLEN); break;
                        case COLOR_BINPREF:   qstrncat(disasm_buf, FA_COLOR_BINPREF,   FA_DISASM_BUFLEN); break;
                        case COLOR_EXTRA:     qstrncat(disasm_buf, FA_COLOR_EXTRA,     FA_DISASM_BUFLEN); break;
                        case COLOR_ALTOP:     qstrncat(disasm_buf, FA_COLOR_ALTOP,     FA_DISASM_BUFLEN); break;
                        case COLOR_HIDNAME:   qstrncat(disasm_buf, FA_COLOR_HIDNAME,   FA_DISASM_BUFLEN); break;
                        case COLOR_LIBNAME:   qstrncat(disasm_buf, FA_COLOR_LIBNAME,   FA_DISASM_BUFLEN); break;
                        case COLOR_LOCNAME:   qstrncat(disasm_buf, FA_COLOR_LOCNAME,   FA_DISASM_BUFLEN); break;
                        case COLOR_CODNAME:   qstrncat(disasm_buf, FA_COLOR_CODNAME,   FA_DISASM_BUFLEN); break;
                        case COLOR_ASMDIR:    qstrncat(disasm_buf, FA_COLOR_ASMDIR,    FA_DISASM_BUFLEN); break;
                        case COLOR_MACRO:     qstrncat(disasm_buf, FA_COLOR_MACRO,     FA_DISASM_BUFLEN); break;
                        case COLOR_DSTR:      qstrncat(disasm_buf, FA_COLOR_DSTR,      FA_DISASM_BUFLEN); break;
                        case COLOR_DCHAR:     qstrncat(disasm_buf, FA_COLOR_DCHAR,     FA_DISASM_BUFLEN); break;
                        case COLOR_DNUM:      qstrncat(disasm_buf, FA_COLOR_DNUM,      FA_DISASM_BUFLEN); break;
                        case COLOR_KEYWORD:   qstrncat(disasm_buf, FA_COLOR_KEYWORD,   FA_DISASM_BUFLEN); break;
                        case COLOR_REG:       qstrncat(disasm_buf, FA_COLOR_REG,       FA_DISASM_BUFLEN); break;
                        case COLOR_IMPNAME:   qstrncat(disasm_buf, FA_COLOR_IMPNAME,   FA_DISASM_BUFLEN); break;
                        case COLOR_SEGNAME:   qstrncat(disasm_buf, FA_COLOR_SEGNAME,   FA_DISASM_BUFLEN); break;
                        case COLOR_UNKNAME:   qstrncat(disasm_buf, FA_COLOR_UNKNAME,   FA_DISASM_BUFLEN); break;
                        case COLOR_CNAME:     qstrncat(disasm_buf, FA_COLOR_CNAME,     FA_DISASM_BUFLEN); break;
                        case COLOR_UNAME:     qstrncat(disasm_buf, FA_COLOR_UNAME,     FA_DISASM_BUFLEN); break;
                        case COLOR_COLLAPSED: qstrncat(disasm_buf, FA_COLOR_COLLAPSED, FA_DISASM_BUFLEN); break;
                        case COLOR_FG_MAX:
                            qstrncat(disasm_buf, FA_COLOR_FG_MAX, FA_DISASM_BUFLEN);
                            // XXX - generate_disasm_line returns locational references in the form:
                            //           ????????loc_????????
                            ///      where ??????? is the 8 digit 0-padded hexidecimal address of the
                            //       location. the simplest way to deal with this is to simply increment
                            //       past the initial location address (the following +8) thereby only
                            //       leaving the remaining name to be used by our grapher.
                            tmp += 8;
                            break;
                        default:
                            qstrncat(disasm_buf, FA_COLOR_DEFAULT, FA_DISASM_BUFLEN);
                    }

                    dis += 3;
                }

                // escape character off. (ignore these)
                else if (*tmp == COLOR_OFF)
                    tmp++;

                // quote next character.
                else if (*tmp == COLOR_ESC)
                {
                    // go to the next character.
                    tmp++;

                    // copy the character as a string.
                    _snprintf(disasm_buf, sizeof(disasm_buf) - 1, "%s0x%02x", disasm_buf, *tmp);
                }

                // inverse colors. (ignore these)
                else if (*tmp == COLOR_INV)
                    tmp++;

                else
                {
                    *dis = *tmp;
                    dis++;
                }
            }

            // write this line to the output file.
            qfprintf(fp, "\n"FA_COLOR_ADDRESS"%08x %s", ea, disasm_buf);

            // break if the next instruction is the start of another node.
            if (is_node(next_ea(ea)))
                break;

            // if the current instruction is far off.
            if (ea < ea_start || ea > ea_end)
            {
                memset(disasm_buf, 0, sizeof(disasm_buf));
                disasm(ea, disasm_buf);

                fcref = get_first_fcref_from(ea);

                // break if the current instruction returns back to our original code.
                if (fcref >= ea_start && fcref <= ea_start && strnicmp(disasm_buf, "jmp", 3) == 0)
                    break;

                if (strnicmp(disasm_buf, "ret", 3) == 0)
                    break;
            }
        }

        //
        // select the appropriate color/shape for this node and close it.
        //

        // entry point.
        if (nodes[i] == ea_start)
            qfprintf(fp, "\" borderwidth: 5 color: %s }\n", color_node);

        // far off nodes.
        else if (nodes[i] < ea_start || nodes[i] > ea_end)
            qfprintf(fp, "\" color: %s }\n", color_far_off);

        // regular nodes.
        else
            qfprintf(fp, "\" color: %s }\n", color_node);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    // graph edges.
    //

    // graph all the recorded edges.
    for (i = 1; i <= num_edges; i++)
    {
        // determine the source node by looking backwards until we find the start of a node.
        for (src = edges_src[i]; src != BADADDR; src = prev_visea(src))
            if (is_node(src))
                break;

        qfprintf(fp, "\tedge: { sourcename: \"%08x\" targetname: \"%08x\"", src, edges_dst[i]);

        // find the end of this node, ie: the branching instruction.
        for (fcref = BADADDR, ea = edges_src[i]; fcref == BADADDR; ea = next_ea(ea))
        {
            if ((fcref = get_first_fcref_from(ea)) != BADADDR)
            {
                memset(disasm_buf, 0, sizeof(disasm_buf));
                disasm(ea, disasm_buf);

                // we are looking for a jump.
                if (disasm_buf[0] != 'j')
                    fcref = BADADDR;
            }
        }

        // unconditional jump.
        if (strnicmp(disasm_buf, "jmp", 3) == 0)
            qfprintf(fp, " color: black }\n");
        // conditional jump, true branch.
        else if (fcref == edges_dst[i])
            qfprintf(fp, " color: green }\n");
        // conditional jump, false branch.
        else
            qfprintf(fp, " color: red }\n");
    }

    // graph the implicit edges.
    // these are the edges from one instruction to the next, where the next instruction is the
    // start of a new node.
    // branching / return instructions are ignored here.
    for (ea = first_ea(); ea != BADADDR; ea = next_ea(ea))
    {
        memset(disasm_buf, 0, sizeof(disasm_buf));
        disasm(ea, disasm_buf);

        if (strnicmp(disasm_buf, "ret", 3) == 0)
            continue;

        if (get_first_fcref_from(ea) != BADADDR && disasm_buf[0] == 'j')
            continue;

        if (is_node(next_ea(ea)))
        {
            // determine the source node by looking backwards until we find the start of a node.
            for (src = ea; src != BADADDR; src = prev_visea(src))
                if (is_node(src))
                    break;

            qfprintf(fp, "\tedge: { sourcename: \"%08x\" targetname: \"%08x\" color: blue }\n", src, next_ea(ea));
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    // graph footer.
    //

    qfprintf(fp, "}\n");

    // close the output stream.
    qfclose(fp);

    // display the graph.
    display_gdl(path);
}


/////////////////////////////////////////////////////////////////////////////////////////
// find_node_index()
//
// determine the index into the node's list array for a given node address.
//
// arguments: ea - effective address of node to search for.
// returns:   node index or 0 on error.
//

int function_analyzer::find_node_index (ea_t ea)
{
    for (int i = 1; i <= num_nodes; i++)
        if (nodes[i] == ea)
            return i;

    return 0;
}


/////////////////////////////////////////////////////////////////////////////////////////
// is_node()
//
// determine whether a given address is the start of a new node.
//
// arguments: match - effective address to match against.
// returns:   true if match is the start of a new node, false otherwise.
//

bool function_analyzer::is_node (ea_t match)
{
    int i;

    // search for an existing node.
    for (i = 1; i <= num_nodes; i++)
        if (nodes[i] == match)
            return TRUE;

    return FALSE;
}


/////////////////////////////////////////////////////////////////////////////////////////
// md5_digest()
//
// calculates an md5 digest for a function by processing over the actual disassembled
// code.
//
// arguments: none.
// returns:   none.
//

void function_analyzer::md5_digest (void)
{
    struct MD5Context context;
    char disasm_buf[FA_DISASM_BUFLEN];
    unsigned char digest[16];
    ea_t ea;

    MD5Init(&context);

    // step through the function instruction by instruction.
    for (ea = first_ea(); ea != BADADDR; ea = next_ea(ea))
    {
        // grab the currently disassembled line.
        if (!disasm(ea, disasm_buf))
            continue;

        // update the md5 context.
        MD5Update(&context, (unsigned char *) &disasm_buf, strlen(disasm_buf));
    }

    MD5Final(digest, &context);

    // convert the digest into a 32 character hex string.
    qsnprintf(md5, sizeof(md5),
              "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
              digest[0],  digest[1],  digest[2],  digest[3],
              digest[4],  digest[5],  digest[6],  digest[7],
              digest[8],  digest[9],  digest[10], digest[11],
              digest[12], digest[13], digest[14], digest[15]);
}


/////////////////////////////////////////////////////////////////////////////////////////
// next_ea()
//
// return the next effective address as recorded in our internal list, instructions.
//
// arguments: ea - current effective address we are analyzing.
// returns:   the next effective address, BADDADDR on error.
//

ea_t function_analyzer::next_ea (ea_t ea)
{
    int i;

    // search through the instructions list for the current address.
    for (i = 1; i <= num_instructions - 1; i++)
        if (instructions[i] == ea)
            return instructions[i+1];

    // no address found.
    return BADADDR;
}


/////////////////////////////////////////////////////////////////////////////////////////
// prev_ea()
//
// return the previous effective address as recorded in our internal list, instructions.
//
// arguments: ea - current effective address we are analyzing.
// returns:   the previous effective address, BADDADDR on error.
//

ea_t function_analyzer::prev_ea (ea_t ea)
{
    int i;

    // search through the instructions list for the current address.
    for (i = 1; i <= num_instructions - 1; i++)
        if (instructions[i+1] == ea)
            return instructions[i];

    // no address found.
    return BADADDR;
}


/////////////////////////////////////////////////////////////////////////////////////////
// quick_sort() *** CURRENTLY UNUSED ***
//
// generic implementation of qsort algorithm. due to the nature of our analysis algorithm
// this routine is currently unused.
//
// arguments: lo - lower index of nodes array.
//            hi - upper inded of nodes array.
// returns:   none.
//

void function_analyzer::quick_sort (ea_t _lo, ea_t _hi)
{
    ea_t lo  = _lo;
    ea_t hi  = _hi;
    ea_t mid;
    ea_t tmp;

    if (_hi > _lo)
    {
        // arbitrarily establish partition element as the midpoint of the array.
        mid = nodes[ (_lo + _hi) / 2 ];

        // loop through the array until the indexes cross.
        while (lo <= hi)
        {
            // find the first element that is >= the partition element, start from the left.
            while ( (lo < _hi) && (nodes[lo] < mid) )
                lo++;

            // find the first element that is <= the partition element, start from the right.
            while ( (hi > _lo) && (nodes[hi] > mid) )
                hi--;

            // if the indexes have not crossed, swap.
            if (lo <= hi)
            {
                tmp = nodes[lo];
                nodes[lo] = nodes[hi];
                nodes[hi] = tmp;
                lo++;
                hi--;
            }

            // if the right index has not reached the left side of the array, sort the left partition.
            if (_lo < hi)
                quick_sort(_lo, hi);

            // if the left index has not reached the right side of the array, sort the right partition.
            if (lo < _hi)
                quick_sort(lo, _hi);
        }
    }
}


/////////////////////////////////////////////////////////////////////////////////////////
// run_analysis()
//
// runs the analysis on the current function.
//
// arguments: none.
// returns:   none.
//

void function_analyzer::run_analysis (void)
{
    int i;

    // run the analysis routine to generate an internal instruction list.
    analyze(ea_start);

    // add the implicit nodes. we want to ensure that all edge destinations are marked as a node.
    // XXX - see the "xxx" from analyze(). this is a cheap hack, but i'm tired.
    for (i = 1; i <= num_edges; i++)
        add_node(edges_dst[i]);

    // calculate CRC and MD5 signatures.
    crc_build_table();
    crc_calculate();
    md5_digest();
}