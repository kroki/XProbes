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
#include "socket.h"
#include "restart.h"
#include "uitoa.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <assert.h>


#define SOCKET_PREFIX  "/tmp/xprobes."
#define SAFE_UNIX_PATH_MAX  92


static
void
fill_socket_name(char *buf, size_t len, uid_t uid, pid_t pid)
{
  assert(len >= sizeof(SOCKET_PREFIX) - 1 + 10 + 1 + 10 + 1);

  memcpy(buf, SOCKET_PREFIX, sizeof(SOCKET_PREFIX) - 1);
  buf += sizeof(SOCKET_PREFIX) - 1;
  buf = uitoa(buf, (unsigned int) uid);
  *buf++ = '.';
  uitoa(buf, (unsigned int) pid);
}


int
_xprobes_open_socket(uid_t uid, pid_t pid, bool own)
{
  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  fill_socket_name(addr.sun_path, SAFE_UNIX_PATH_MAX, uid, pid);

  int type = SOCK_STREAM;
#ifdef SOCK_CLOEXEC
  type |= SOCK_CLOEXEC;
#endif
  int fd = socket(AF_UNIX, type, 0);
  if (fd == -1)
    return -1;

#ifndef SOCK_CLOEXEC
  {
    long flags = fcntl(fd, F_GETFD);
    flags |= FD_CLOEXEC;
    int res = fcntl(fd, F_SETFD, flags);
    if (res != 0)
      {
        RESTART(close(fd));
        return -1;
      }
  }
#endif

#ifdef SO_NOSIGPIPE
  {
    static const int enable = 1;
    int res = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE,
                         (void *) &enable, sizeof(enable));
    if (res == -1)
      {
        RESTART(close(fd));
        return -1;
      }
  }
#endif

  int res;
  if (! own)
    {
      res = RESTART(connect(fd,
                            (const struct sockaddr *) &addr, sizeof(addr)));
    }
  else
    {
      mode_t save_mask = umask(0);
      res = RESTART(bind(fd, (const struct sockaddr *) &addr, sizeof(addr)));
      if (res == -1 && errno == EADDRINUSE)
        {
          res = unlink(addr.sun_path);
          if (res == -1)
            return -1;

          res = RESTART(bind(fd,
                             (const struct sockaddr *) &addr, sizeof(addr)));
        }
      umask(save_mask);
    }
  if (res == -1)
    {
      RESTART(close(fd));
      return -1;
    }

  return fd;
}


int
_xprobes_control_write(int fd, const char *str, size_t len)
{
  if (fd == -1)
    return -1;

  int flags = 0;
#ifdef MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;
#endif

  while (len > 0)
    {
      ssize_t res = RESTART(send(fd, str, len, flags));
      if (res <= 0)
        return res;

      str += res;
      len -= res;
    }

  return 1;
}


/*
  _xprobes_control_read() reads zero-terminated packet from fd.  Data
  is returned in buffer->buf.

  When read_full is true, whole packet is read, and its length (not
  including terminating zero) is returned.  Any additional data from
  the next packet is left in the buffer, and is returned on the next
  call.

  When read_full is false, partial data read so far is placed in
  buffer->buf.  All chunks are zero-terminated, and chunk length (not
  including terminating zero) is returned.  If buffer->end != NULL
  then returned chunk is the last one in the packet.

  When filter_isalive is true, ISALIVE_CHAR is filtered from the input
  stream.

  On error _xprobes_control_read() returns:

    -1 if read() system call returned 0.
    -2 if read() system call returned -1.
    -3 if read_full is requested and buffer is too small.
*/
ssize_t
_xprobes_control_read(int fd, struct control_buffer *buffer,
                      bool read_full, bool filter_isalive)
{
  if (buffer->end)
    {
      buffer->used -= buffer->end + 1 - buffer->buf;
      memmove(buffer->buf, buffer->end + 1, buffer->used);
      buffer->end = memchr(buffer->buf, '\0', buffer->used);

      if (! read_full && buffer->used > 0)
        return (buffer->end
                ? buffer->end - buffer->buf
                : (ssize_t) buffer->used);
    }
  else
    {
      buffer->used = 0;
    }

  while (! buffer->end && buffer->used < CONTROL_BUFFER_SIZE - 1)
    {
      ssize_t res;

    retry:
      res = RESTART(read(fd, buffer->buf + buffer->used,
                         CONTROL_BUFFER_SIZE - 1 - buffer->used));
      if (res <= 0)
        return res - 1;

      if (filter_isalive)
        {
          char *pos = buffer->buf + buffer->used;
          char *isalive = pos;
          size_t rest = res;
          while ((isalive = memchr(isalive, ISALIVE_CHAR, rest)))
            {
              rest -= isalive + 1 - pos;
              memmove(isalive, isalive + 1, rest);
              --res;
            }
          if (res == 0)
            goto retry;
        }

      buffer->end = memchr(buffer->buf + buffer->used, '\0', res);
      buffer->used += res;
      buffer->buf[buffer->used] = '\0';

      if (! read_full)
        return (buffer->end
                ? buffer->end - buffer->buf
                : (ssize_t) buffer->used);
    }
  if (! buffer->end)
    return -3;

  return (buffer->end - buffer->buf);
}


void
_xprobes_unlink_socket(uid_t uid, pid_t pid)
{
  char file[SAFE_UNIX_PATH_MAX];
  fill_socket_name(file, SAFE_UNIX_PATH_MAX, uid, pid);

  unlink(file);
}
