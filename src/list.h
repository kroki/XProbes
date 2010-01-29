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

#ifndef LIST_H
#define LIST_H 1

#include "xprobes/bits/list_node.h"
#include <stddef.h>
#include <stdbool.h>


#define list_node  _xprobes_list_node


static inline
void
list_init(struct list_node *head)
{
  head->prev = head->next = head;
}


static inline
bool
list_empty(const struct list_node *head)
{
  return (head->next == head);
}


static inline
void
list_insert(struct list_node *head, struct list_node *node)
{
  head->prev->next = node;
  node->prev = head->prev;
  head->prev = node;
  node->next = head;
}


static inline
void
list_insert_first(struct list_node *head, struct list_node *node)
{
  list_insert(head->next, node);
}


static inline
void
list_remove(const struct list_node *node)
{
  node->prev->next = node->next;
  node->next->prev = node->prev;
}


#define LIST_INIT(head)                         \
  { .next = &head, .prev = &head }

#define list_next(node, type, memb)             \
  _list_node2data((node)->next, type, memb)

#define list_prev(node, type, memb)             \
  _list_node2data((node)->prev, type, memb)

#define list_end(head, p, memb)                 \
  (&(p)->memb == (head))

#define list_each(p, head, memb)                                \
  _list_each(p, head, memb, next, _list_label(__LINE__))

#define list_each_backward(p, head, memb)                       \
  _list_each(p, head, memb, prev, _list_label(__LINE__))


#define _list_label(unique)  _list_label2(unique)

#define _list_label2(unique)  _list_label_##unique

#define _list_each(p, head, memb, dir, label)                   \
  /* for ([type *] */ (p) = NULL; ; ({ goto label; }))          \
       if (false)                                               \
         {                                                      \
         label:                                                 \
           break;                                               \
         }                                                      \
       else                                                     \
         for (struct list_node *_list_it = (head)->dir;         \
              (((p) = _list_node2data(_list_it,                 \
                                      __typeof__(*(p)), memb)), \
               (_list_it != (head)                              \
                && ((_list_it = _list_it->dir), true)));        \
              /* nothing */ /* ) */

#define _list_node2data(node, type, memb)        \
  ((type *) ((char *) (node) - offsetof(type, memb)))


#endif  /* ! LIST_H */
