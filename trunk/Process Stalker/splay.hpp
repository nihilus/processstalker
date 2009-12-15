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

#ifndef __SPLAY_HPP__
#define __SPLAY_HPP__

// splay tree structure.
typedef struct _stree
{
    struct _stree *left;
    struct _stree *right;
    DWORD         address;
    char          name[128];
    unsigned int  recorded[10];
} stree;

// function prototypes
stree * splay        (DWORD, stree *);
stree * splay_insert (DWORD, char *, stree *);
void    splay_print  (stree *, int);
void    splay_dump   (stree *, FILE *);

#endif