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

#ifndef SOCKET_H
#define SOCKET_H 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>


#define CONTROL_BUFFER_SIZE  1024


struct control_buffer
{
  char buf[CONTROL_BUFFER_SIZE];
  size_t used;
  char *end;
};


/*
  visibility("hidden") below are only to prevent namespace pollution,
  they have no runtime effects.
*/

__attribute__((__visibility__("hidden")))
int _xprobes_open_socket(uid_t uid, pid_t pid, bool own);

__attribute__((__visibility__("hidden")))
int _xprobes_control_write(int fd, const char *str, size_t len);

__attribute__((__visibility__("hidden")))
ssize_t _xprobes_control_read(int fd, struct control_buffer *buffer,
                              bool read_full);

__attribute__((__visibility__("hidden")))
void _xprobes_unlink_socket(uid_t uid, pid_t pid);


#endif  /* ! SOCKET_H */
