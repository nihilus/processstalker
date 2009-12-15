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

#include <windows.h>
#include <stdio.h>
#include "splay.hpp"

stree * splay (DWORD address, stree *tree)
{
    stree n, *left, *right, *tmp;

    // if there is no tree, return null.
    if (!tree)
        return NULL;

    n.left = n.right = NULL;
    left   = right   = &n;

    for (;;)
    {
        // the leaf we're looking for lies to the left of the current leaf.
        if (address < tree->address)
        {
            // if the current leaf has no left path, break.
            if (tree->left == NULL)
                break;

            // the leaf we're looking for lies to the left of the current leaf's
            // left node.
            if (address < tree->left->address)
            {
                // rotate right
                tmp        = tree->left;
                tree->left = tmp->right;
                tmp->right = tree;
                tree       = tmp;

                // if there is no left path, break.
                if (tree->left == NULL)
                    break;
            }

            // link right.
            right->left = tree;
            right       = tree;
            tree        = tree->left;
        }

        // the leaf we're looking for lies to the right of the current leaf.
        else if (address > tree->address)
        {
            // if the current leaf has no right path, break.
            if (tree->right == NULL)
                break;

            // the leaf we're looking for lies to the right of the current
            // leaf's left node.
            if (address > tree->right->address)
            {
                // rotate left.
                tmp         = tree->right;
                tree->right = tmp->left;
                tmp->left   = tree;
                tree        = tmp;

                // if there is no right path, break.
                if (tree->right == NULL)
                    break;
            }

            // link left.
            left->right = tree;
            left        = tree;
            tree        = tree->right;
        }

        // we've found the leaf we're looking for.
        else
        {
            break;
        }
    }

    // assemble.
    left->right = tree->left;
    right->left = tree->right;
    tree->left  = n.right;
    tree->right = n.left;

    return tree;
}


stree * splay_insert (DWORD address, char *name, stree *tree)
{
    stree *new_leaf;

    // allocate and initialize memory for our new leaf.
    new_leaf = (stree *) calloc(1, sizeof(stree));

    // ensure we got the memory we requested.
    if (!new_leaf)
    {
        // XXX - OUT OF MEMORY.
    }

    // set the new leafs internal data.
    new_leaf->address = address;
    strncpy(new_leaf->name, name, sizeof(new_leaf->name) - 1);

    // the leaf we're adding is the first one. initialize it's left and right
    // pointers and return the allocated leaf as the head of the tree.
    if (tree == NULL)
    {
        new_leaf->left = new_leaf->right = NULL;
        return new_leaf;
    }

    tree = splay(address, tree);

    // if the address to add is less than the splayed root leaf.
    if (address < tree->address)
    {
        // splice into the left of the root leaf.
        new_leaf->left  = tree->left;
        new_leaf->right = tree;
        tree->left = NULL;
        return new_leaf;
    }

    // if the address to add is greater than the splayed root leaf.
    else if (address > tree->address)
    {
        // splice into the right of the root leaf.
        new_leaf->right  = tree->right;
        new_leaf->left   = tree;
        tree->right = NULL;
        return new_leaf;
    }

    // node already exists in tree.
    else
    {
        free(new_leaf);
        return tree;
    }

    // XXX - not reached.
}


void splay_print (stree *leaf, int depth)
{
    int i;

    if (leaf == NULL)
        return;
    
    for (i = 0; i < depth; i++)
        printf(" ");

    printf("0x%08X %s\n", leaf->address, leaf->name);

    splay_print(leaf->left,  depth + 1);
    splay_print(leaf->right, depth + 1);
}


void splay_dump (stree *leaf, FILE *dump_file)
{
    if (leaf == NULL)
        return;

    if (leaf->left != NULL)
        fprintf(dump_file, "<edge label=\"\" source=\"%s\" target=\"%s\"/>\n", leaf->name, leaf->left->name);
    
    if (leaf->right != NULL)
        fprintf(dump_file, "<edge label=\"\" source=\"%s\" target=\"%s\"/>\n", leaf->name, leaf->right->name);

    splay_dump(leaf->left,  dump_file);
    splay_dump(leaf->right, dump_file);
}