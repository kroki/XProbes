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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "xprobes/bits/object.h"
#include "xprobes/bits/module.h"
#include "list.h"
#include "socket.h"
#include "restart.h"
#include "uitoa.h"
#include <stdbool.h>
#include <pthread.h>
#include <fnmatch.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>

#ifdef NEED_USCORE
#define USCORE "_"
#else
#define USCORE
#endif

#define UNUSED(arg)  if (arg) {}


#if 0
/*
  At least with glibc 2.11.1 pthread_sigmask() is the only symbol we
  use that is defined only in libpthread.  All other pthread_*()
  functions are defined in libc too.  Uncommenting this removes the
  dependency on -pthread, however it likely reduces portability too.
*/
#undef pthread_sigmask
#define pthread_sigmask  sigprocmask
#endif


void
_xprobes_noop()
{
  /* May be called with various argument lists.  */
}


struct _xprobes_probe _xprobes_probe_noop = {
  .func = _xprobes_noop
};

static struct _xprobes_probe probe_action_pending = {
  .func = _xprobes_noop
};

typedef void (*action_type)();

action_type _xprobes_action = _xprobes_noop;


static pthread_mutex_t sigmask_mutex = PTHREAD_MUTEX_INITIALIZER;

static sigset_t signal_mask;
/*
  Initializing inside_dlop to true prevents the access to signal_mask
  before it is initialized.
*/
static bool inside_dlop = true;
static bool version_mismatch = false;


static pthread_mutex_t data_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct _xprobes_probe *probe_noop = &_xprobes_probe_noop;

static struct list_node object_list = LIST_INIT(object_list);

static struct list_node module_enabled_queue = LIST_INIT(module_enabled_queue);
static struct list_node module_disabled_list = LIST_INIT(module_disabled_list);

static char command_buf[1024];
static char *command_args = NULL;

static int safe_unload_delay = 60;
static int signal_no;
static pid_t control_pid = 0;
static int control_socket = -1;
static bool control_write_enabled = false;

static bool need_newline = false;
static int cancel_state;
static struct sigaction sigpipe_orig;

static int signal_save_errno;
static pid_t my_pid = 0;


enum {
  NAME_ALLOCATED = 0x1,

  MANAGED = 0x2,

  PROTO_MISMATCH = 0x4,
  PROBE_OVERRIDE = 0x8,
  ERRORS = PROTO_MISMATCH | PROBE_OVERRIDE
};


static inline
void
ignore_sigpipe(void)
{
#if ! defined(MSG_NOSIGNAL) && ! defined(SO_NOSIGPIPE)
  static const struct sigaction ignore = { .sa_handler = SIG_IGN };

  /*
    We want to ignore possible SIGPIPE that we may generate on write.
    We assume that it is delivered *synchronously* and *only* to the
    thread doing the write.  So if it is reported as already pending
    (which means the thread blocks it), then we do not reset the
    action: if we generate SIGPIPE, it will be merged with the pending
    one (there's no queuing), and that suits us well.
  */
  sigset_t pending;
  sigpending(&pending);
  if (! sigismember(&pending, SIGPIPE))
    {
      int res = sigaction(SIGPIPE, &ignore, &sigpipe_orig);
      assert(res == 0);
    }
  else
    {
      sigpipe_orig.sa_handler = SIG_IGN;
    }
#endif  /* ! defined(MSG_NOSIGNAL) && ! defined(SO_NOSIGPIPE) */
}


static inline
void
restore_sigpipe(void)
{
#if ! defined(MSG_NOSIGNAL) && ! defined(SO_NOSIGPIPE)
  if (sigpipe_orig.sa_handler != SIG_IGN)
    {
      int res = sigaction(SIGPIPE, &sigpipe_orig, NULL);
      assert(res == 0);
    }
#endif  /* ! defined(MSG_NOSIGNAL) && ! defined(SO_NOSIGPIPE) */
}


static inline
void
lock_signal(void)
{
  int res = pthread_mutex_lock(&data_mutex);
  assert(res == 0);

  res = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
  assert(res == 0);

  control_write_enabled = true;

  signal_save_errno = errno;

  ignore_sigpipe();
}


static inline
void
unlock_signal(void)
{
  restore_sigpipe();

  errno = signal_save_errno;

  control_write_enabled = false;

  if (cancel_state != PTHREAD_CANCEL_DISABLE)
    {
      int dummy;
      int res = pthread_setcancelstate(cancel_state, &dummy);
      assert(res == 0);
    }

  int res = pthread_mutex_unlock(&data_mutex);
  assert(res == 0);
}


static inline
void
lock(void)
{
  /*
    To avoid recursive call to pthread_mutex_lock(&data_mutex) that
    may happen from the signal handler, we have to block the signal
    _before_ the call.  Additionally, we have to order calls to
    pthread_sigmask() to avoid the race, hence the second
    sigmask_mutex.
  */
  int res = pthread_mutex_lock(&sigmask_mutex);
  assert(res == 0);

  /*
    If inside_dlop is set, then the signal is blocked already by
    lock_action().  See comment in action_load().  Or it may mean that
    we haven't initialized signal_mask yet (constructor of some object
    blessed with xprobes is called before our own constructor).
  */
  if (! inside_dlop)
    {
      res = pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
      assert(res == 0);
    }

  res = pthread_mutex_lock(&data_mutex);
  assert(res == 0);
}


static inline
void
unlock(void)
{
  int res = pthread_mutex_unlock(&data_mutex);
  assert(res == 0);

  if (! inside_dlop)
    {
      res = pthread_sigmask(SIG_UNBLOCK, &signal_mask, NULL);
      assert(res == 0);
    }

  res = pthread_mutex_unlock(&sigmask_mutex);
  assert(res == 0);
}


static inline
void
lock_action(void)
{
  lock();

  int res = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
  assert(res == 0);

  control_write_enabled = true;

  ignore_sigpipe();
}


static inline
void
unlock_action(void)
{
  restore_sigpipe();

  control_write_enabled = false;

  if (cancel_state != PTHREAD_CANCEL_DISABLE)
    {
      int dummy;
      int res = pthread_setcancelstate(cancel_state, &dummy);
      assert(res == 0);
    }

  unlock();
}


static inline
int
control_write(const char *str)
{
  if (! control_write_enabled)
    return -1;

  if (! str)
    str = "(null)";

  size_t len = strlen(str);
  if (len == 0)
    return 1;

  int res = _xprobes_control_write(control_socket, str, len);
  if (res == 1)
    need_newline = (str[len - 1] != '\n');
  else
    need_newline = false;

  return res;
}


static
void
control_done(void)
{
  command_args = NULL;

  const char *eom;
  size_t eom_len;
  if (need_newline)
    {
      need_newline = false;
      eom = "\n\0";
      eom_len = 2;
    }
  else
    {
      eom = "\0";
      eom_len = 1;
    }

  int res = _xprobes_control_write(control_socket, eom, eom_len);
  if (res <= 0)
    {
      RESTART(close(control_socket));
      control_socket = -1;
      control_pid = 0;
    }
}


static
void
schedule_action(action_type action)
{
  assert(_xprobes_action == _xprobes_noop);
  assert(probe_noop == &_xprobes_probe_noop);
  assert(command_args != NULL);

  for (struct _xprobes_object *list_each(o, &object_list, next))
    for (struct _xprobes_site *s = o->start; s != o->stop; ++s)
      if (s->probe == &_xprobes_probe_noop)
        s->probe = &probe_action_pending;

  control_write("command in progress, waiting...\n");

  _xprobes_action = action;
  probe_noop = &probe_action_pending;
}


static
void
reset_action_pending(void)
{
  assert(_xprobes_action == _xprobes_noop);
  assert(probe_noop == &probe_action_pending);

  probe_noop = &_xprobes_probe_noop;

  for (struct _xprobes_object *list_each(o, &object_list, next))
    for (struct _xprobes_site *s = o->start; s != o->stop; ++s)
      if (s->probe == &probe_action_pending)
        s->probe = &_xprobes_probe_noop;
}


/*
  site_attach_module() returns 1 if it has attached site to a module
  (or it's possible to attach without errors and attach is false), -1
  on error, and 0 otherwise.
*/
static
int
site_attach_module(struct _xprobes_object *object,
                   struct _xprobes_site *site,
                   struct _xprobes_module *module,
                   bool attach)
{
  for (size_t i = 0; i < module->probe_count; ++i)
    {
      const struct _xprobes_probe *p = &module->probes[i];
      if (fnmatch(p->pattern, site->tag, 0) == 0)
        {
          if (strcmp(p->proto, site->proto) != 0)
            {
              assert(! attach);

              module->flags |= PROTO_MISMATCH;

              control_write("prototype mismatch:\n"
                            "site: ");
              control_write(site->tag);
              control_write(site->proto);
              control_write(" [");
              control_write(object->name);
              control_write("]\n"
                            "probe: ");
              control_write(p->pattern);
              control_write(" -> ");
              control_write(p->tag);
              control_write(p->proto);
              control_write("\n");

              return -1;
            }

          if (site->probe != probe_noop)
            {
              assert(! attach);

              module->flags |= PROBE_OVERRIDE;

              control_write("attempted probe override:\n"
                            "site: ");
              control_write(site->tag);
              control_write(site->proto);
              control_write(" [");
              control_write(object->name);
              control_write("] => ");
              control_write(site->probe->pattern);
              control_write(" -> ");
              control_write(site->probe->tag);
              control_write(" [");
              control_write(site->probe->module->name);
              control_write("]\n"
                            "probe: ");
              control_write(p->pattern);
              control_write(" -> ");
              control_write(p->tag);
              control_write("\ndisable attached module first\n");

              return -1;
            }

          if (attach)
            site->probe = p;

          return 1;
        }
    }

  return 0;
}


static
void
module_enable(struct _xprobes_module *module)
{
  module->flags &= ~ERRORS;

  for (struct _xprobes_object *list_each(o, &object_list, next))
    for (struct _xprobes_site *s = o->start; s != o->stop; ++s)
      if (site_attach_module(o, s, module, false) == -1)
        {
          /*
            We don't have to update safe_unload_timestamp, because the
            module wasn't enabled before the call.
          */
          list_insert(&module_disabled_list, &module->next);

          control_write("module is not enabled\n");

          return;
        }

  list_insert_first(&module_enabled_queue, &module->next);

  for (struct _xprobes_object *list_each(o, &object_list, next))
    for (struct _xprobes_site *s = o->start; s != o->stop; ++s)
      site_attach_module(o, s, module, true);
}


static
void
module_disable(struct _xprobes_module *module)
{
  if (module->flags & ERRORS)
    list_insert(&module_disabled_list, &module->next);
  else
    list_insert_first(&module_disabled_list, &module->next);

  if (module->flags & MANAGED)
    {
      int delay = (module->unload_delay > safe_unload_delay
                   ? module->unload_delay
                   : safe_unload_delay);
      module->safe_unload_timestamp = time(0) + delay;
    }

  for (struct _xprobes_object *list_each(o, &object_list, next))
    for (struct _xprobes_site *s = o->start; s != o->stop; ++s)
      if (s->probe->module == module)
        s->probe = probe_noop;
}


static
struct _xprobes_module *
find_module(struct list_node *modules, const char *name)
{
  for (struct _xprobes_module *list_each(m, modules, next))
    if (m->name && strcmp(m->name, name) == 0)
      return m;

  return NULL;
}


static
void
compress_proto(char *proto)
{
  if (! proto)
    return;

  bool last_is_id = false;

  char *beg = proto;
  while (*beg)
    {
      if (last_is_id)
        *proto++ = ' ';

      while (isspace(*beg))
        ++beg;

      if (last_is_id && ! (isalnum(*beg) || *beg == '_' || *beg == '$'))
        {
          last_is_id = false;
          --proto;
        }

      char *end = beg;
      while (*end && ! isspace(*end))
        ++end;

      if (end > beg)
        {
          if (isalnum(end[-1]) || end[-1] == '_' || end[-1] == '$')
            last_is_id = true;

          size_t len = end - beg;
          memmove(proto, beg, len);
          proto += len;

          beg = end;
        }
    }
  *proto = '\0';
}


static inline
const char *
addr2name(void *addr)
{
#ifdef ENABLE_DLADDR

  /*
    addr2name() is called from constructors, i.e., recursively from
    dlopen().  The user should enable dladdr() only if it's allowed to
    call it in this case (dlopen() has no lock, or the lock is
    recursive, or it is released before the call to constructor).
  */
  Dl_info info;
  int res = dladdr(addr, &info);

  return (res != 0 ? info.dli_fname : NULL);

#else  /* ! ENABLE_DLADDR */

  UNUSED(addr);

  return NULL;

#endif  /* ! ENABLE_DLADDR */
}


static inline
char *
get_name(void *addr)
{
  char buf[20];
  sprintf(buf, "%p", addr);
  /*
    strdup() may fail, but we allow name to be NULL.
  */
  return strdup(buf);
}


void
_xprobes_module_link(struct _xprobes_module *module,
                     unsigned int module_version)
{
  lock();

  if (module_version != _XPROBES_MODULE_VERSION)
    {
      /*
        We can't assume any fields of module structure, so we have to
        return.  If we are called from action_load(), report the error
        to the user.  Otherwise probe module is being preloaded.  In
        the latter case we can't report the error, but the user may
        attach later, see that the module is not listed, try to load
        it, and see the error message then.
      */
      if (inside_dlop)
        {
          version_mismatch = true;

          char version[11];
          uitoa(version, module_version);

          control_write("version mismatch: module v");
          control_write(version);
          control_write(" not supported\n");
        }

      unlock();

      return;
    }

  module->handle = NULL;
  module->flags = 0;

  if (inside_dlop)
    module->flags |= MANAGED;

  module->name = (char *) addr2name(module);
  if (! module->name)
    {
      module->flags |= NAME_ALLOCATED;
      if (inside_dlop)
        module->name = strdup(command_args);
      else
        module->name = get_name(module);
    }

  for (size_t i = 0; i < module->probe_count; ++i)
    {
      module->probes[i].module = module;
      compress_proto(module->probes[i].proto);
    }

  module_enable(module);

  unlock();
}


void
_xprobes_module_unlink(struct _xprobes_module *module)
{
  lock();

  list_remove(&module->next);

  if (module->flags & NAME_ALLOCATED)
    free(module->name);

  unlock();
}


void
_xprobes_object_link(struct _xprobes_object *object,
                     unsigned int object_version)
{
  if (object_version != _XPROBES_OBJECT_VERSION)
    {
      /*
        We can't assume any fields of object structure, so we have to
        return.  We can't report the error, however it shouldn't
        happen if you link with the libxprobes.
      */
      return;
    }

  lock();

  object->flags = 0;

  object->name = (char *) addr2name(object);
  if (! object->name)
    {
      object->flags |= NAME_ALLOCATED;
      object->name = get_name(object);
    }

  for (struct _xprobes_site *s = object->start; s != object->stop; ++s)
    {
      compress_proto(s->proto);
      s->probe = probe_noop;
    }

  /*
    Here and below the order of loops matters: we visit each site only
    once, attaching the _first_ matching probe.
  */
  for (struct _xprobes_site *s = object->start; s != object->stop; ++s)
    for (struct _xprobes_module *list_each(m, &module_enabled_queue, next))
      {
        int res = site_attach_module(object, s, m, false);
        if (res == -1)
          {
            /*
              list_each() has its own shadow iterator, it won't
              reference m again, so it is safe to relink m to another
              list.
            */
            list_remove(&m->next);
            module_disable(m);
          }
        else if (res == 1)
          {
            break;
          }
      }

  list_insert(&object_list, &object->next);

  for (struct _xprobes_site *s = object->start; s != object->stop; ++s)
    for (struct _xprobes_module *list_each(m, &module_enabled_queue, next))
      if (site_attach_module(object, s, m, true) == 1)
        break;

  unlock();
}


void
_xprobes_object_unlink(struct _xprobes_object *object)
{
  lock();

  if (object->flags & NAME_ALLOCATED)
    free(object->name);

  list_remove(&object->next);

  unlock();
}


static
int
close_handle(void *handle)
{
  inside_dlop = true;
  unlock();

  int res = dlclose(handle);
  if (res != 0)
    {
      const char *error;
#ifdef ENABLE_DLERROR
      error = dlerror();
#else
      error = "failed";
#endif

      lock();
      inside_dlop = false;

      control_write("dlclose(): ");
      control_write(error);
      control_write("\n");

      return res;
    }

  lock();
  inside_dlop = false;

  return 0;
}


static
void
action_load()
{
  if (! __sync_bool_compare_and_swap(&_xprobes_action,
                                     action_load, _xprobes_noop))
    return;

  lock_action();

  if (probe_noop != &probe_action_pending)
    goto error;                 /* Action was cancelled. */

  reset_action_pending();

  /*
    We are going to call one of the functions of dlopen() family.
    However some other thread could already call, say, dlopen() for
    the object blessed with xprobes.  This means that that thread is
    blocked in _xprobes_object_link() now, because we are holding the
    mutex.  Since dlopen() family is thread-safe (except for
    dlerror(), which we use conditionally), it may use its own mutex.
    If we call dlopen() right away we will block on that mutex,
    waiting for the thread that waits for us.  Thus to avoid the
    deadlock we release the mutex.  But we do this with unlock() (not
    unlock_action()), setting inside_dlop to true, to prevent
    premature signal unblocking and cancellation enabling.  This
    guarantees that no other command will be executed concurrently,
    and we won't be canceled in the middle.
  */
  inside_dlop = true;
  unlock();

  void *handle = dlopen(command_args, RTLD_NOW | RTLD_LOCAL);
  if (! handle)
    {
      const char *error;
#ifdef ENABLE_DLERROR
      error = dlerror();
#else
      error = "failed";
#endif

      lock();
      inside_dlop = false;

      control_write("dlopen(): ");
      control_write(error);

      goto error;
    }

  /*
    Use dlsym() instead of searching the list, because we can dlopen()
    a module that has been preloaded already, thus it won't be the
    first in the list, and we don't know what to look for.
  */
  struct _xprobes_module *(*get_module)(void) =
    dlsym(handle, USCORE "xprobes_module");
  if (! get_module)
    {
      const char *error;
#ifdef ENABLE_DLERROR
      error = dlerror();
#else
      error = "failed (probably symbol " USCORE "xprobes_module not found)";
#endif

      lock();
      inside_dlop = false;

      control_write("dlsym(): ");
      control_write(error);
      control_write("\n");

      if (close_handle(handle) == 0)
        control_write("not loaded");

      goto error;
    }

  lock();
  inside_dlop = false;

  if (version_mismatch)
    {
      version_mismatch = false;

      if (close_handle(handle) == 0)
        control_write("not loaded");

      goto error;
    }

  struct _xprobes_module *module = get_module();
  if (! module)
    {
      control_write("xprobes_module() returned NULL");

      goto error;
    }

  if ((module->flags & MANAGED) && ! module->handle)
    {
      module->handle = handle;

      control_write("loaded");
    }
  else
    {
      /*
        dlclose() here doesn't do any actual unload, so we expect it
        to succeed.
      */
      int res = close_handle(handle);
      assert(res == 0);

      if (module->flags & MANAGED)
        {
          control_write("already loaded, module ");
          control_write(module->name);
        }
      else
        {
          assert(! module->handle);
          control_write("already preloaded, module ");
          control_write(module->name);
        }
    }

 error:
  control_done();
  unlock_action();
}


static
void
action_unload()
{
  if (! __sync_bool_compare_and_swap(&_xprobes_action,
                                     action_unload, _xprobes_noop))
    return;

  lock_action();

  if (probe_noop != &probe_action_pending)
    goto done;                  /* Action was cancelled. */

  reset_action_pending();

  struct _xprobes_module *module =
    find_module(&module_disabled_list, command_args);
  assert(module);

  if (close_handle(module->handle) == 0)
    control_write("unloaded");

 done:
  control_done();
  unlock_action();
}


static
void
action_module_command()
{
  if (! __sync_bool_compare_and_swap(&_xprobes_action,
                                     action_module_command, _xprobes_noop))
    return;

  lock_action();

  if (probe_noop != &probe_action_pending)
    goto done;                  /* Action was cancelled. */

  reset_action_pending();

  size_t len = strlen(command_args);
  char *end = command_args;
  assert(! isspace(*end));
  while (*end && ! isspace(*end))
    {
      ++end;
      --len;
    }
  *end = '\0';

  struct _xprobes_module *module =
    find_module(&module_enabled_queue, command_args);
  if (! module)
    module = find_module(&module_disabled_list, command_args);
  assert(module);
  assert(module->command);

  if (len > 0)
    ++end;
  while (isspace(*end))
    ++end;

  if (need_newline)
    control_write("\n");

  module->command(end, control_write);

  if (need_newline)
    control_write("\n");

 done:
  control_done();
  unlock_action();
}


static
bool
command_cancel(void)
{
  if (probe_noop != &probe_action_pending)
    return true;                /* No action is pending. */

  control_write("command canceled");

  action_type action = _xprobes_action;
  bool action_token_acquired =
    (action != _xprobes_noop
     && __sync_bool_compare_and_swap(&_xprobes_action,
                                     action, _xprobes_noop));

  reset_action_pending();

  /*
    If action_token_acquired is true, this means that no other thread
    will be able to start action execution, and we don't have to wait.
    If action_token_acquired is false, then another thread has took
    action token before we did, and waits for us to release
    data_mutex.  Since we called reset_action_pending() already, the
    action will be a no-op, and will return shortly, but we have to
    wait for that.
  */
  if (action_token_acquired)
    {
      return true;
    }
  else
    {
      control_write(", waiting...");

      return false;
    }
}


static
bool
command_load(void)
{
  struct _xprobes_module *module =
    find_module(&module_enabled_queue, command_args);
  if (! module)
    module = find_module(&module_disabled_list, command_args);
  if (module)
    {
      if (module->flags & MANAGED)
        control_write("already loaded");
      else
        control_write("can't load preloaded module");

      return true;
    }

  schedule_action(action_load);

  return false;
}


static
bool
command_enable(void)
{
  struct _xprobes_module *module =
    find_module(&module_disabled_list, command_args);
  if (module)
    {
      list_remove(&module->next);
      module_enable(module);
    }
  else
    {
      if (find_module(&module_enabled_queue, command_args))
        control_write("already enabled");
      else
        control_write("not found");
    }

  return true;
}


static
bool
command_disable(void)
{
  struct _xprobes_module *module =
    find_module(&module_enabled_queue, command_args);
  if (module)
    {
      list_remove(&module->next);
      module_disable(module);
    }
  else
    {
      if (find_module(&module_disabled_list, command_args))
        control_write("already disabled");
      else
        control_write("not found");
    }

  return true;
}


static
bool
command_unload(void)
{
  struct _xprobes_module *module =
    find_module(&module_disabled_list, command_args);
  if (! module)
    {
      module = find_module(&module_enabled_queue, command_args);
      if (! module)
        {
          control_write("not loaded");
        }
      else
        {
          if (module->flags & MANAGED)
            control_write("can't unload, modules is enabled");
          else
            control_write("can't unload preloaded module");
        }

      return true;
    }

  if (! (module->flags & MANAGED))
    {
      control_write("can't unload preloaded module");

      return true;
    }

  time_t now = time(0);
  if (now < module->safe_unload_timestamp)
    {
      char seconds[11];
      uitoa(seconds, module->safe_unload_timestamp - now);

      control_write("module may be unloaded in ");
      control_write(seconds);
      control_write(" secs");

      return true;
    }

  schedule_action(action_unload);

  return false;
}


static
bool
command_command(void)
{
  char *end = command_args;
  assert(! isspace(*end));
  while (*end && ! isspace(*end))
    ++end;

  char save_end = *end;
  *end = '\0';

  struct _xprobes_module *module =
    find_module(&module_enabled_queue, command_args);
  if (! module)
    module = find_module(&module_disabled_list, command_args);
  if (! module)
    {
      control_write("module not found");

      return true;
    }
  if (! module->command)
    {
      control_write("module doesn't implement command method");

      return true;
    }

  *end = save_end;

  schedule_action(action_module_command);

  return false;
}


static
bool
command_version(void)
{
  char module_version[11];
  uitoa(module_version, _XPROBES_MODULE_VERSION);
  char object_version[11];
  uitoa(object_version, _XPROBES_OBJECT_VERSION);

  control_write(PACKAGE_VERSION);
  control_write(" (module v");
  control_write(module_version);
  control_write("; object v");
  control_write(object_version);
  control_write(")");

  return true;
}


static
bool
command_objects(void)
{
  for (struct _xprobes_object *list_each(o, &object_list, next))
    {
      control_write("  ");
      control_write(o->name);
      control_write("\n");
    }

  return true;
}


static
bool
command_sites(void)
{
  for (struct _xprobes_object *list_each(o, &object_list, next))
    {
      control_write(o->name);
      control_write(":\n");
      for (struct _xprobes_site *s = o->start; s != o->stop; ++s)
        {
          if (s->probe != probe_noop)
            control_write("* ");
          else
            control_write("  ");
          control_write(s->tag);
          control_write(s->proto);
          if (s->probe != probe_noop)
            {
              control_write(" => ");
              control_write(s->probe->pattern);
              control_write(" -> ");
              control_write(s->probe->tag);
              control_write(" [");
              control_write(s->probe->module->name);
              control_write("]\n");
            }
          else
            {
              control_write("\n");
            }
        }
    }

  return true;
}


static
bool
command_modules(void)
{
  for (struct _xprobes_module *list_each(m, &module_enabled_queue, next))
    {
      control_write("* ");
      control_write(m->name);
      if (m->flags & MANAGED)
        control_write("\n");
      else
        control_write(" (preloaded)\n");
    }

  time_t now = time(0);
  for (struct _xprobes_module *list_each(m, &module_disabled_list, next))
    {
      if (m->flags & PROTO_MISMATCH)
        control_write("P ");
      else if (m->flags & PROBE_OVERRIDE)
        control_write("O ");
      else
        control_write("  ");
      control_write(m->name);
      if (m->flags & MANAGED)
        {
          if (now >= m->safe_unload_timestamp)
            {
              control_write("\n");
            }
          else
            {
              char seconds[11];
              uitoa(seconds, m->safe_unload_timestamp - now);

              control_write(" (may be unloaded in ");
              control_write(seconds);
              control_write(" secs)\n");
            }
        }
      else
        {
          control_write(" (preloaded)\n");
        }
    }

  return true;
}


static
void
list_probes(struct _xprobes_module *module)
{
  control_write(module->name);
  control_write(":\n");
  for (size_t i = 0; i < module->probe_count; ++i)
    {
      const struct _xprobes_probe *p = &module->probes[i];
      control_write("  ");
      control_write(p->pattern);
      control_write(" ");
      control_write(p->proto);
      control_write(" -> ");
      control_write(p->tag);
      control_write("\n");
    }
}


static
bool
command_probes(void)
{
  for (struct _xprobes_module *list_each(m, &module_enabled_queue, next))
    list_probes(m);

  for (struct _xprobes_module *list_each(m, &module_disabled_list, next))
    list_probes(m);

  return true;
}


struct command
{
  const char *cmd;
  bool (*run)(void);
  bool hidden;
  bool async;
};


static bool command_help(void);


static struct command commands[] = {
  { .cmd = "load FILE", .run = command_load },
  { .cmd = "enable MODULE", .run = command_enable },
  { .cmd = "disable MODULE", .run = command_disable },
  { .cmd = "unload MODULE", .run = command_unload },
  { .cmd = "command MODULE [ARGS]", .run = command_command },
  { .cmd = "objects", .run = command_objects },
  { .cmd = "sites", .run = command_sites },
  { .cmd = "modules", .run = command_modules },
  { .cmd = "probes", .run = command_probes },

  { .cmd = "cancel", .run = command_cancel, .hidden = true, .async = true },
  { .cmd = "help", .run = command_help, .hidden = true },
  { .cmd = "version", .run = command_version, .hidden = true },
};


static
bool
command_help(void)
{
  for (size_t i = 0; i < sizeof(commands) / sizeof(*commands); ++i)
    {
      if (commands[i].hidden)
        continue;

      control_write(commands[i].cmd);
      control_write("\n");
    }

  return true;
}


static
bool
process_command(char *cmd)
{
  size_t len = strlen(cmd);
  char *end = cmd;
  assert(! isspace(*end));
  while (*end && ! isspace(*end))
    {
      ++end;
      --len;
    }
  *end = '\0';

  for (size_t i = 0; i < sizeof(commands) / sizeof(*commands); ++i)
    if (strncmp(commands[i].cmd, cmd, end - cmd) == 0
        && (commands[i].cmd[end - cmd] == ' '
            || commands[i].cmd[end - cmd] == '\0'))
      {
        if (! commands[i].async && probe_noop == &probe_action_pending)
          {
            control_write("command in progress, waiting...\n");

            return false;
          }

        if (len > 0)
          ++end;
        while (isspace(*end))
          ++end;
        command_args = end;

        return commands[i].run();
      }

  control_write("unknown command");

  return true;
}


static
bool
control_is_alive(void)
{
  /*
    We can't use kill(control_pid, 0), because we may lack the
    permissions to send the signals to control process.
  */
  static const char isalive[] = { ISALIVE_CHAR, '\0' };
  int res = control_write(isalive);

  return (res == 1);
}


static
void
signal_handler(int sig, siginfo_t *info, void *ctx)
{
  UNUSED(sig && ctx)

  if (info->si_code != SI_QUEUE)
    return;

  lock_signal();

  /* Check if we had fork()ed.  */
  pid_t current_pid = getpid();
  if (__builtin_expect(my_pid != current_pid, 0))
    {
      if (control_pid)
        {
          RESTART(close(control_socket));
          control_socket = -1;
          control_pid = 0;
        }
      my_pid = current_pid;
    }

  if (__builtin_expect(control_pid && control_pid != info->si_pid, 0))
    {
      if (control_is_alive())
        {
          char buf[64];
          int res = snprintf(buf, sizeof(buf),
                             "already connected, pid %d\n", (int) control_pid);
          if (res < 0 || res >= (int) sizeof(buf))
            goto error;

          int fd = _xprobes_open_socket(info->si_uid, info->si_pid, false);
          if (fd == -1)
            goto error;

          _xprobes_control_write(fd, buf, res + 1);
          RESTART(close(fd));

          goto error;
        }
      else
        {
          RESTART(close(control_socket));
          control_socket = -1;
          control_pid = 0;
        }
    }

  if (__builtin_expect(! control_pid, 0))
    {
      /*
        Cancel any pending command that could be left by another
        control if it has died.  We call this before opening a socket
        so that any output by command_cancel() is thrown away.
      */
      bool have_to_wait = ! command_cancel();

      control_socket = _xprobes_open_socket(info->si_uid, info->si_pid, false);
      if (control_socket == -1)
        goto error;

      control_pid = info->si_pid;

      if (have_to_wait)
        goto error;
      else
        goto done;
    }

  char *pos = command_buf;
  size_t room = sizeof(command_buf);
  while (room > 0)
    {
      ssize_t len = RESTART(read(control_socket, pos, room));
      if (len <= 0)
        {
          control_write("read() error");
          RESTART(close(control_socket));
          control_socket = -1;
          control_pid = 0;

          goto error;
        }
      pos += len;
      if (pos[-1] == '\0')
        break;

      room -= len;
    }
  if (room == 0)
    {
      control_write("command too long");
      RESTART(close(control_socket));
      control_socket = -1;
      control_pid = 0;

      goto error;
    }

  char *cmd = command_buf;
  while (isspace(*cmd))
    ++cmd;

  if (! process_command(cmd))
    goto error;

 done:
  control_done();

 error:
  unlock_signal();
}


static
void
process_options(const char *options)
{
  char key;
  char val[64];
  int consumed;
  while (sscanf(options, " %c=%63s%n", &key, val, &consumed) >= 2)
    {
      switch (key)
        {
        case 's':
          {
            char *end;
            unsigned long res = strtoul(val, &end, 10);
            if (*end != '\0' || res < 1 || res >= INT_MAX)
              {
                fprintf(stderr, "xprobes: invalid signal number '%s'\n", val);
                abort();
              }
            signal_no = res;
          }
          break;

        case 't':
          {
            char *end;
            unsigned long res = strtoul(val, &end, 10);
            if (*end != '\0' || res < 1 || res >= INT_MAX)
              {
                fprintf(stderr, "xprobes: invalid time value '%s'\n", val);
                abort();
              }
            safe_unload_delay = res;
          }
          break;

        default:
          fprintf(stderr, "xprobes: unknown key=value '%c=%s'\n", key, val);
          abort();
        }

      options += consumed;
    }
}


static __attribute__((__constructor__))
void
register_signal_handler(void)
{
  int res = pthread_mutex_lock(&sigmask_mutex);
  assert(res == 0);

  my_pid = getpid();
  signal_no = DEFAULT_SIGNAL;

  const char *options = getenv("XPROBES_OPTIONS");
  if (options)
    process_options(options);

  sigemptyset(&signal_mask);
  sigaddset(&signal_mask, signal_no);
  /* Allow access to signal_mask.  */
  inside_dlop = false;

  res = pthread_mutex_unlock(&sigmask_mutex);
  assert(res == 0);

  sigset_t empty;
  sigemptyset(&empty);
  struct sigaction action = {
    .sa_sigaction = signal_handler,
    .sa_flags = SA_SIGINFO | SA_RESTART,
    .sa_mask = empty,
  };
  res = sigaction(signal_no, &action, NULL);
  if (res != 0)
    {
      perror("xprobes");
      abort();
    }
}


static __attribute__((__destructor__))
void
unregister_signal_handler(void)
{
  control_write_enabled = false;

  static const struct sigaction action = { .sa_handler = SIG_DFL };
  sigaction(signal_no, &action, NULL);
}
