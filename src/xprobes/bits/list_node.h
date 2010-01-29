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

#ifndef _XPROBES_BITS_LIST_NODE_H
#define _XPROBES_BITS_LIST_NODE_H 1


struct _xprobes_list_node
{
  struct _xprobes_list_node *next;
  struct _xprobes_list_node *prev;
};


#endif  /* ! _XPROBES_BITS_LIST_NODE_H */
