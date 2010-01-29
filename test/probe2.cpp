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

#include "../src/xprobes/probe.h"
#include <iostream>


static
void
f1(const char *s)
{
  std::cout << s << " triggered probe2:f1" << std::endl;
}


static
void
f2(const char *s, int count)
{
  std::cout << s << " triggered probe2:f2 (" << count << ")" << std::endl;
}


static
void
command(const char *cmd, int (*out)(const char *msg))
{
  out("probe2:command: got '");
  out(cmd);
  out("'\n");
}


XPROBES_MODULE(command, 0,
               XPROBES_PROBE("xprobes_test_module", f2, (const char *, int)),
               XPROBES_PROBE("xprobes_test_libshared_*", f1, (const char *)));
