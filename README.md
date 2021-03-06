Explicit probes
===============

Explicit probes (XProbes for short) is a framework for static user
space probes.  It consists of a shared library `libxprobes` and its
header files, and `xprobes` control utility.  XProbes enables you to
define static probe sites in the source code, and later attach probe
modules to them.  Probes may be attached both at application startup,
and while the application is running.  `xprobes` control utility
provides commands for dynamic loading/unloading of probe modules,
listing available sites and probes, and module enabling/disabling.

Among XProbes features are:

* Easy to use.

    On application side single macro is used to defined probe sites.

    On probe module side two macros are used in a pair.

    Probes can be written in the same language as the application
    itself (we mean C and C++ here).  This means that probe code can
    access type definitions of the application code, and thus access
    structures, classes, and even their methods, in a natural way.

* Doesn't require special privileges to run.

    Probe modules are loaded to the application itself, not to the
    operating system kernel.

* Doesn't require debug info.

    Works with stripped binaries.

* Neglectable inactive probe site overhead.

    Inactive probe site is a single `if (unlikely(site == active))`
    statement, i.e., only few instructions.

* Minimal active probe site overhead.

    Active probe execution is simply a call to a function in another
    shared library.  No trap instruction (breakpoint) or system call
    is used.

* Type safe.

    On application side compilation will fail if site prototype
    doesn't match site argument list.

    On probe module side compilation will fail if probe prototype
    doesn't match actual probe function.

    At runtime probe module won't be enabled if one of its probe
    prototypes doesn't match the site prototype it was going to
    attach.

* Thread safe and synchronous cancellation safe.

    You may use sites in multi-threaded code, even with enabled
    synchronous cancellation.

* Lock free and non-blocking on probe path.

    Probes are executed without any locks.  It's a user's
    responsibility to serialize concurrent calls to probe callbacks
    if desired.

* Lock contention free and non-blocking on control path.

    Commands initiated with `xprobes` control utility (for instance,
    load new probe module) are executed by one of the application
    threads.  Other threads are not blocked during this execution.
    There is one exception: when you execute a command with `xprobes`
    utility, and some other application thread concurrently calls
    `dlopen()` on a library blessed with XProbes, there's a tiny time
    window during which one of this threads has to wait for the other.

* Several non-conflicting probe modules may be used simultaneously.

    You may enable several probe modules at once, unless they try to
    attach to the same site.  This provides for better modularity:
    you can keep a repository of different probe modules for
    different aspects of the application, and/or distribute probe
    modules with your library.

* Portable (to some extent).

    XProbes requires GNU compiler (GCC) version 4.1 or higher, and
    GNU assembler and linker (or compatible tools) to build, not only
    XProbes itself, but also the applications that use it and any
    probe modules.  Some of the attributes that it uses require ELF
    object file format.  On the other hand, it doesn't require GNU C
    library, so it may be used on any ELF system with installed GCC
    suite.


Example
-------

Here's a short example (you can also play with the code in `test/`
directory, build it with `make check`).

> NOTE: `xprobes` control utility uses Unix socket and a real-time
> signal to communicate with the application that links with
> `libxprobes`.  Default signal is `SIGRTMAX`.  For the application
> (i.e., `libxprobes`) you override the signal number with
> `XPROBES_OPTIONS='s=NUM'` environment setting, for `xprobes` utility use
> `--signal=NUM` option.

To bless you application with XProbes, include `<xprobes/site.h>` and
define probe sites with `XPROBES_SITE(provider, name, proto, args)` macro.

    #include <xprobes/site.h>

    void
    my_func(int i, int j, char *s)
    {
      ...
      XPROBES_SITE(my_app, my_func,
                   (const char *, int, bool),
                   (s, 3, i > j));
      ...
    }

Link you application with `-lxprobes`.  That's all.

Now suppose you want to attach a probe to that site.  First you have
to write one:

    #include <xprobes/probe.h>
    #include <stdbool.h>
    #include <stdio.h>
    #include <string.h>

    static int greater_count = 0;

    static
    void
    my_probe(const char *str, int three, bool greater)
    {
      if (greater)
        ++greater_count;
    }

    static
    void
    command(const char *cmd, int (*out)(const char *msg))
    {
      if (strcmp(cmd, "dump") == 0)
        {
          char buf[64];
          sprintf(buf, "greater_count: %d", greater_count);
          out(buf);
        }
      else
        {
          out("unknown command ");
          out(cmd);
        }
    }

    XPROBES_MODULE(command, 0,
      XPROBES_PROBE("my_app_*", my_probe, (const char *, int, bool)));


Macro prototypes are

    XPROBES_MODULE(command_callback, unload_delay, probes...);
    XPROBES_PROBE(pattern, callback, proto);

From this source you build probe module as a shared library, with
something like

    gcc -shared -fPIC -DPIC -g -O2 my_probe.c -o my_probe.so

Note that you don't have to link with `-lxprobes` (`libxprobes` has
internal ABI version check, so you won't be able to enable a probe
that was compiled with incompatible version of header file).

Now, if you wish to enable the probe right from the application start,
then you do

    $ LD_PRELOAD=/path/to/my_probe.so my_app

Alternatively, suppose we are talking about a server application that
is already running, and you are not allowed to restart it.  Then you
use `xprobes` utility:

    bash$ xprobes $(pidof my_app)
    Connecting... done
    xprobes>

First we want to learn what sites are available:

    xprobes> sites
    /path/to/my_app:
      my_app_my_func(const char*,int,bool)
    xprobes>

Good to know that the site we defined with `XPROBES_SITE()` is there.
Note that unnecessary spaces were removed from the prototype, to allow
us compare prototypes disregarding differences in whitespace (also
note that prototypes are compared as strings, so `(int)`, `(signed int)`
and `(int32_t)` are _different_ prototypes).

Now let's load the probe module:

    xprobes> load /path/to/my_probe.so
    command in progress, waiting...
    loaded
    xprobes>

When you see **"command in progress, waiting..."** message this means
that the command didn't execute immediately, but instead was scheduled
to the time the first probe site is hit (regardless of whether there's
a probe attached to it or not).  Since `my_app_my_func` is our only
site, `my_probe.so` won't be loaded until application calls
`my_func()`.  You may cancel command in progress by pressing `C-c`.

    xprobes> modules
    * /path/to/my_probe.so
    xprobes>

Loaded modules are automatically enabled.  An asterisk before the
module name indicates that the module is enabled.  Let's see what
probes it has:

    xprobes> probes
    /path/to/my_probe.so:
      my_app_* (const char*,int,bool) -> my_probe
    xprobes>

Here it is.  Now let's see what sites is has attached to:

    xprobes> sites
    /path/to/my_app:
      my_app_my_func(const char*,int,bool) => my_app_* -> my_probe [/path/to/my_probe.so]
    xprobes>

This tells us that `my_app_my_func` site was matched by `my_app_*`
pattern, and `my_probe function` from `/path/to/my_probe.so` was
attached to it (prototype check passed).

    xprobes> command /path/to/my_probe.so dump
    command in progress, waiting...
    greater_count: 16
    xprobes>

We called the command method of our probe module, and it output a
message telling that the probe was hit with `i > j` 16 times so far.

    xprobes> disable /path/to/my_probe.so
    xprobes> unload /path/to/my_probe.so
    module may be unloaded in 58 secs
    xprobes>

As said above, there are no locks on probe path.  We just disabled the
module, but other threads may not yet see the effect, and still call
probes from it.  So for safety the module is locked for 60 seconds
since the moment it was disabled (you can set other timeout with
`XPROBES_OPTIONS='t=NUM'`, also you may set it per module with the
second argument of `XPROBES_MODULE()`, but per module value is used
only if it is greater than that of `libxprobes`, i.e., you may only
increase the delay).

    xprobes> modules
      /path/to/my_probe.so (may be unloaded in 52 secs)
    xprobes>

It is left as an exercise to the reader to wait for that time...


License
-------

Copyright (C) 2010 Tomash Brechko.  All rights reserved.

libxprobes and corresponding header files are released under LGPLv3+.
xprobes control utility is released under GPLv3+ (it uses libreadline).
Essentially this means that all the functionality is available for
non-(L)GPLd code too.  See <http://www.gnu.org/licenses/> for further
details.
