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

#ifndef RESTART_H
#define RESTART_H 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <unistd.h>
#include <errno.h>


#ifdef TEMP_FAILURE_RETRY

#define RESTART  TEMP_FAILURE_RETRY

#else  /* ! TEMP_FAILURE_RETRY */

#define RESTART(syscall)                        \
  ({                                            \
    __typeof__(syscall) _res;                   \
    do                                          \
      _res = syscall;                           \
    while (_res == -1 && errno == EINTR);       \
    _res;                                       \
  })

#endif  /* ! TEMP_FAILURE_RETRY */


#endif  /* ! RESTART_H */
