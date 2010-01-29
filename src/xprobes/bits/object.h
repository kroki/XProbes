/*
  Copyright (C) 2010 Tomash Brechko.  All rights reserved.

  This file is part of XProbes.

  XProbes is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  XProbes is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with XProbes.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _XPROBES_BITS_OBJECT_H
#define _XPROBES_BITS_OBJECT_H 1

#include "module.h"
#include "list_node.h"


/*
  Increment _XPROBES_OBJECT_VERSION whenever object ABI is changed:
  either struct _xprobes_site or struct _xprobes_object has changes.
  Also increment CURRENT field in -version-info (src/Makefile.am).
*/
#define _XPROBES_OBJECT_VERSION  0


struct _xprobes_site
{
  const char *tag;
  char *proto;
  const struct _xprobes_probe *probe;
};


struct _xprobes_object
{
  struct _xprobes_list_node next;
  struct _xprobes_site *start;
  struct _xprobes_site *stop;
  char *name;
  int linked;
  unsigned int flags;
};


void _xprobes_object_link(struct _xprobes_object *object,
                          unsigned int object_version);

void _xprobes_object_unlink(struct _xprobes_object *object);

void _xprobes_noop();

extern struct _xprobes_probe _xprobes_probe_noop;

extern void (*_xprobes_action)();


#endif  /* ! _XPROBES_BITS_OBJECT_H */
