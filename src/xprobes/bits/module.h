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

#ifndef _XPROBES_BITS_MODULE_H
#define _XPROBES_BITS_MODULE_H 1

#include "list_node.h"
#include <time.h>


/*
  Increment _XPROBES_MODULE_VERSION whenever module ABI is changed:
  either struct _xprobes_probe or struct _xprobes_module has changed.
*/
#define _XPROBES_MODULE_VERSION  0


struct _xprobes_module;


struct _xprobes_probe
{
  const char *pattern;
  /*
    In XPROBES_PROBE() the string that proto points to is allocated as
    a compound literal, thus it is an lvalue.  We will modify it in
    compress_proto() later.  As an unfortunate side effect
    XPROBES_PROBE() can't be called inside a function.
  */
  char *proto;
  void (*func)();
  const char *tag;
  const struct _xprobes_module *module;
};


struct _xprobes_module
{
  struct _xprobes_list_node next;
  void *handle;
  char *name;
  int linked;
  time_t safe_unload_timestamp;
  unsigned int flags;

  int unload_delay;
  unsigned int probe_count;
  struct _xprobes_probe *probes;
  void (*command)(const char *cmd, int (*out)(const char *msg));
};


#endif  /* ! _XPROBES_BITS_MODULE_H */
