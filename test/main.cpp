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
#include "../src/xprobes/site.h"
#include "../src/restart.h"
#include <dlfcn.h>
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <ctime>
#include <cerrno>

#ifdef NEED_USCORE
#define USCORE "_"
#else
#define USCORE
#endif


extern "C" {

const char *f(void);

const char *libshared_f(void);
const char *libshared_f2(void);

};


int
main(int argc, char *argv[])
{
  if (argc != 3)
    {
      std::cerr << "Usage: " << argv[0] << " MODULE COUNT" << std::endl;
      exit(2);
    }

  const char *module = argv[1];
  int count;
  {
    std::istringstream arg(argv[2]);
    arg >> count;
  }

  static const struct timespec delay = {
    /* .tv_sec = */ 10,
    /* .tv_nsec = */ 0
  };

  void *handle = NULL;
  const char *(*module_f)(void) = NULL;
  for (int i = 0; i < count; ++i)
    {
      XPROBES_SITE(xprobes_test_main,
                   (const char *),
                   (__func__));

      std::cout << __func__ << std::endl << std::endl;

      f();

      if (! handle && i % 3 == 0)
        {
          handle = dlopen(module, RTLD_LAZY);
          if (! handle)
            {
              std::cerr << "dlopen(): " << dlerror() << std::endl;
              exit(1);
            }

          module_f = (const char *(*)(void)) dlsym(handle, USCORE "module_f");
          if (! module_f)
            {
              std::cerr << "dlsym(): " << dlerror() << std::endl;
              exit(1);
            }

          std::cout << "shared module " << module << " loaded"
                    << std::endl << std::endl;
        }

      if (handle)
        {
          std::cout << module_f() << std::endl << std::endl;

          if (i % 5 == 4)
            {
              int res = dlclose(handle);
              if (res != 0)
                {
                  std::cerr << "dlclose(): " << dlerror() << std::endl;
                  exit(1);
                }
              handle = NULL;

              std::cout << "shared module " << module << " unloaded"
                        << std::endl << std::endl;
            }
        }

      std::cout << libshared_f() << std::endl << std::endl;

      std::cout << libshared_f2() << std::endl << std::endl;

      struct timespec remains = delay;
      RESTART(nanosleep(&remains, &remains));
    }

  return 0;
}
