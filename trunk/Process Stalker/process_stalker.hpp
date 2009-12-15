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

#ifndef __PROCESS_STALKER_HPP__
#define __PROCESS_STALKER_HPP__

#define PS_ADDRESS_ON_STACK            1
#define PS_ADDRESS_ON_HEAP             2

#define NOT_RECORDING                  -1

#define PS_PAGE_NOACCESS               1
#define PS_PAGE_EXECUTABLE             2
#define PS_PAGE_WRITABLE               3
#define PS_PAGE_OTHER                  4

#define PS_EXPLORER_BUF_SIZE           64
#define PS_MINUMUM_STRING_LENGTH       6
#define PS_RECORD_NUM_BYTES            16

//
// linked list node structure.
//

typedef struct __node
{
    DWORD base;         // module base address.
    DWORD size;         // module size.
    char  name[128];    // module name.

    // pointer to next module.
    struct __node *next;
} node;

//
// function prototypes.
//

void   ps_analyze_register     (HANDLE, DWORD, DWORD, node *, DWORD, DWORD, DWORD, char *);
bool   ps_base_address         (char *, DWORD *, DWORD *);
void   ps_commands             (void);
int    ps_get_page_type        (HANDLE, DWORD);
bool   ps_is_printable_ascii   (unsigned char *, int);
bool   ps_is_printable_unicode (unsigned short *, int);
void   ps_load_dll_callback    (PEfile *);
void   ps_node_add             (node *, node **, int *);
node * ps_node_find_by_address (DWORD, node *);
node * ps_node_find_by_name    (char *, node *);
int    ps_usage                (void);

//
// callback functions.
//

void itsdone       (DEBUG_EVENT *db);
void initial_break (DEBUG_EVENT *db);
void normal_break  (DEBUG_EVENT *db);
void openr         (t_Tracer_OpenTr *open);
void closer        (t_Tracer_OpenTr *open);

#endif