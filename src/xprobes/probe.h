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

#ifndef _XPROBES_PROBE_H
#define _XPROBES_PROBE_H 1

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "bits/module.h"


#define XPROBES_MODULE(command, unload_delay, probes...)        \
  static struct _xprobes_probe _xprobes_probes[] = {            \
    probes                                                      \
  };                                                            \
                                                                \
  struct _xprobes_module *                                      \
  xprobes_module(void)                                          \
  {                                                             \
    static struct _xprobes_module module = {                    \
      /* .next = */ { NULL, NULL },                             \
      /* .handle = */ NULL,                                     \
      /* .name = */ NULL,                                       \
      /* .linked = */ 0,                                        \
      /* .safe_unload_timestamp = */ 0,                         \
      /* .flags = */ 0,                                         \
                                                                \
      /* .unload_delay = */ unload_delay,                       \
      /* .probe_count = */ (sizeof(_xprobes_probes)             \
                            / sizeof(*_xprobes_probes)),        \
      /* .probes = */ _xprobes_probes,                          \
      /* .command = */ command                                  \
    };                                                          \
                                                                \
    return &module;                                             \
  }                                                             \
                                                                \
  extern const char _xprobes_require_semicolon


#ifndef __cplusplus

#define XPROBES_PROBE(pattern, func, proto)                     \
  {                                                             \
    /* .pattern = */ (pattern) ? (pattern) : "",                \
    /* .proto = */                                              \
      __builtin_choose_expr                                     \
        (__builtin_types_compatible_p(void (*) proto,           \
                                      __typeof__(&(func))),     \
         ((char []) { #proto }), (void) 0 /* can't be used */), \
    /* .func = */ (func),                                       \
    /* .tag = */ #func,                                         \
    /* .module = */ (const struct _xprobes_module *) 0          \
  }

#else  /* __cplusplus */

#define XPROBES_PROBE(pattern, func, proto)                             \
  {                                                                     \
    /* .pattern = */ (pattern) ? (pattern) : "",                        \
    /* .proto = */                                                      \
      ((void (*) proto) (func) == (func)                                \
       ? ((char []) { #proto }) : (char *) 0 /* never used */) ,        \
    /* .func = */ (void (*)()) (func),                                  \
    /* .tag = */ #func,                                                 \
    /* .module = */ (const struct _xprobes_module *) 0                  \
  }

#endif  /* __cplusplus */


/*
  visibility("protected") allows us to LD_PRELOAD several modules
  without symbol merge, and still find the symbol with dlsym().
*/
__attribute__((__visibility__("protected")))
struct _xprobes_module *xprobes_module(void);


__attribute__((__section__(".gnu.linkonce"),
               __visibility__("hidden"),
               __constructor__))
void
_xprobes_module_init(void)
{
  /*
    Suppose you preload a module with LD_PRELOAD, but do not run the
    program linked with libxprobes directly, but use, say, a wrapper
    script.  When interpreter is started with LD_PRELOAD in its
    environment, it won't be able to resolve _xprobes_module_link and
    _xprobes_module_unlink.  To avoid the link failure we do not
    require the symbols to be defined.
  */
  extern __attribute__((__weak__))
    void _xprobes_module_link(struct _xprobes_module *, unsigned int);

  if (_xprobes_module_link)
    {
      struct _xprobes_module *module = xprobes_module();
      if (++module->linked == 1)
        _xprobes_module_link(module, _XPROBES_MODULE_VERSION);
    }
}


__attribute__((__section__(".gnu.linkonce"),
               __visibility__("hidden"),
               __destructor__))
void
_xprobes_module_destroy(void)
{
  extern __attribute__((__weak__))
    void _xprobes_module_unlink(struct _xprobes_module *);

  if (_xprobes_module_unlink)
    {
      struct _xprobes_module *module = xprobes_module();
      if (--module->linked == 0)
        _xprobes_module_unlink(xprobes_module());
    }
}


#ifdef __cplusplus
}
#endif


#endif  /* ! _XPROBES_PROBE_H */
