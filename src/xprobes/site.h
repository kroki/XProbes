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

#ifndef _XPROBES_SITE_H
#define _XPROBES_SITE_H 1

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "bits/object.h"


#define XPROBES_SITE(provider, name, proto, args)                       \
  do                                                                    \
    {                                                                   \
      extern void _xprobes_typecheck_##provider##_##name proto;         \
                                                                        \
      static char _xprobes_proto[] = #proto;                            \
      static                                                            \
        __attribute__((__section__("_xprobes_site"),                    \
                       __aligned__(__alignof__(struct _xprobes_site)))) \
        struct _xprobes_site _xprobes_site = {                          \
          /* .tag = */ #provider "_" #name,                             \
          /* .proto = */ _xprobes_proto,                                \
          /* .probe = */ &_xprobes.noop,                                \
        };                                                              \
                                                                        \
      const struct _xprobes_probe *probe_volatile =                     \
        _xprobes_site.probe;                                            \
      if (__builtin_expect(probe_volatile != &_xprobes.noop, 0))        \
        {                                                               \
          void (*action_volatile)(/* any */) = _xprobes.action;         \
          if (__builtin_expect(action_volatile != _xprobes_noop, 0))    \
            action_volatile();                                          \
          ((void (*) proto) probe_volatile->func) args;                 \
        }                                                               \
    }                                                                   \
  while (0)


/*
  Define _xprobes_site section even when no XPROBES_SITE() was used.
*/
__asm__(".section _xprobes_site, \"aw\", @progbits; .previous");


/*
  __start_<section> and __end_<section> are defined by the linker,
  thus they should be declared extern.  But we have to ensure they
  won't be merged if several objects are loaded, hence
  visibility("hidden").
*/
extern __attribute__((__visibility__("hidden")))
struct _xprobes_site __start__xprobes_site, __stop__xprobes_site;


static __attribute__((__section__(".gnu.linkonce._xprobes_object")))
struct _xprobes_object _xprobes_object = {
  /* .next =  */ { NULL, NULL },
  /* .start = */ &__start__xprobes_site,
  /* .stop = */ &__stop__xprobes_site,
  /* .name = */ NULL,
  /* .linked = */ 0,
  /* .flags = */ 0
};


__attribute__((__section__(".gnu.linkonce"),
               __visibility__("hidden"),
               __constructor__))
void
_xprobes_object_init(void);

void
_xprobes_object_init(void)
{
  /*
    Placing function definition in .gnu.linkonce section merges
    multiple definitions into one.  However .ctor and .dtor sections
    are simply concatenated, and thus have multiple references to this
    single function.  We use linked counter to perform construction
    and destruction exactly once.
  */
  if (++_xprobes_object.linked == 1)
    _xprobes_object_link(&_xprobes_object, _XPROBES_OBJECT_VERSION);
}


__attribute__((__section__(".gnu.linkonce"),
               __visibility__("hidden"),
               __destructor__))
void
_xprobes_object_destroy(void);

void
_xprobes_object_destroy(void)
{
  if (--_xprobes_object.linked == 0)
    _xprobes_object_unlink(&_xprobes_object);
}


#ifdef __cplusplus
}
#endif


#endif  /* ! _XPROBES_SITE_H */
