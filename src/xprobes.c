/*
  Copyright (C) 2010 Tomash Brechko.  All rights reserved.

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "restart.h"
#include "socket.h"
#include <stdbool.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>

#define UNUSED(arg)  if (arg) {}


static int signal_no;
static pid_t control_pid;
static int control_socket;
static struct control_buffer reply = { .end = NULL };
static char *help = NULL;
static char *version = NULL;
static char *modules = NULL;

static const struct sigaction ignore = { .sa_handler = SIG_IGN };

static struct option options[] = {
  { .name = "signal", .val = 's', .has_arg = required_argument },
  { .name = "version", .val = 'v' },
  { .name = "help", .val = 'h' },
  { .name = NULL },
};


static
void
usage(FILE *out)
{
  fprintf(out,
          "Usage: xprobes [OPTIONS] PID\n"
          "\n"
          "PID is the process to control.\n"
          "\n"
          "Options are:\n"
          "  --signal, -s NUM            Use signal NUM (default is %d)\n"
          "  --version, -v               Print package version\n"
          "  --help, -h                  Print this message\n"
          "\n",
          signal_no);
}


static
void
process_options(int argc, char *argv[])
{
  int opt;
  while ((opt = getopt_long(argc, argv, "s:vh", options, NULL)) != -1)
    {
      switch (opt)
        {
        case 's':
          {          
            char *end;
            long res = strtol(optarg, &end, 10);
            if (*end != '\0' || res < SIGRTMIN || res > SIGRTMAX)
              {
                fprintf(stderr,
                        "%s: invalid signal number '%s',"
                        " should be between SIGRTMIN (%d) and SIGRTMAX (%d)\n",
                        argv[0], optarg, SIGRTMIN, SIGRTMAX);
                usage(stderr);
                exit(2);
              }
            signal_no = res;
          }
          break;

        case 'v':
          printf("%s\n%s\nReport bugs to <%s>.\n",
                 PACKAGE_STRING, PACKAGE_COPYRIGHT, PACKAGE_BUGREPORT);
          exit(0);

        case 'h':
          usage(stdout);
          exit(0);

        default:
          usage(stderr);
          exit(2);
        }
    }
  if (optind == argc - 1)
    {          
      char *end;
      unsigned long res = strtoul(argv[optind], &end, 10);
      if (*end != '\0' || res < 1 || res >= INT_MAX)
        {
          fprintf(stderr, "%s: invalid pid '%s'\n", argv[0], argv[optind]);
          usage(stderr);
          exit(2);
        }
      control_pid = (pid_t) res;
    }
  else
    {
      usage(stderr);
      exit(2);
    }
}


static
void
control_notify(void)
{
  static const union sigval val = { .sival_int = 0 };
  static const struct timespec delay = { .tv_nsec = 100000000 };

  int res = sigqueue(control_pid, signal_no, val);
  while (res == -1 && errno == EAGAIN)
    {
      nanosleep(&delay, NULL);
      res = sigqueue(control_pid, signal_no, val);
    }
  if (res == -1)
    {
      perror("sigqueue()");
      exit(1);
    }
}


static
void
unlink_socket(void)
{
  RESTART(close(control_socket));
  _xprobes_unlink_socket(getuid(), getpid());
  control_notify();
}


static
size_t
read_reply(bool read_full)
{
  ssize_t len = _xprobes_control_read(control_socket, &reply, read_full, true);
  if (len >= 0)
    return len;

  switch (len)
    {
    case -1:
      printf("failed to read from remote\n");
      break;

    case -2:
      perror("read()");
      break;

    case -3:
      printf("too long reply from remote\n");
      break;
    }

  exit(1);
}


static
char *
generate_command(const char *text, int next)
{
  static char *cmd;

  if (next)
    {
      while (*cmd != '\n')
        ++cmd;
      ++cmd;
    }
  else
    {
      cmd = help;
    }

  if (*cmd)
    {
      cmd = strstr(cmd, text);
      while (cmd && cmd != help && cmd[-1] != '\n') 
        cmd = strstr(cmd + 1, text);
    }

  if (cmd && *cmd)
    {
      char *p = cmd;
      while (*p && ! isspace(*p))
        ++p;

      char *res = strndup(cmd, p - cmd);
      cmd = p;

      return res;
    }

  rl_attempted_completion_over = 1;

  return NULL;
}


static
char *
generate_module(const char *text, int next)
{
  static char *module;

  if (next)
    {
      while (*module != '\n')
        ++module;
      ++module;
    }
  else
    {
      module = modules + 1;
      if (*module)
        ++module;
    }
  
  if (*module)
    {
      module = strstr(module, text);
      while (module && module > modules + 2 && module[-3] != '\n')
        module = strstr(module + 1, text);
    }

  if (module && *module)
    {
      char *p = module;
      while (*p && ! isspace(*p))
        ++p;

      char *res = strndup(module, p - module);
      module = p;

      return res;
    }

  rl_attempted_completion_over = 1;

  return NULL;
}


static
void
reset_modules(void)
{
  free(modules);
  modules = NULL;
}


static
char **
complete_command(const char *text, int start, int end)
{
  UNUSED(start);

  const char *p = rl_line_buffer;
  const char *e = rl_line_buffer + end;

  while (p < e && isspace(*p))
    ++p;

  const char *cmd = p;
  size_t cmd_len = 0;

  int index = 1;
  while (p < e)
    {
      while (p < e && ! isspace(*p))
        ++p;

      if (index == 1)
        cmd_len = p - cmd;

      if (p < e)
        {
          ++index;
          while (p < e && isspace(*p))
            ++p;
        }
    }

  if (index == 1)
    return rl_completion_matches(text, generate_command);

  char prefix[cmd_len + 1];
  memcpy(prefix, cmd, cmd_len);
  prefix[cmd_len] = '\0';

  cmd = strstr(help, prefix);
  if (! cmd || (cmd != help && cmd[-1] != '\n'))
    {
      /* Don't know how to complete.  */
      rl_attempted_completion_over = 1;
      return NULL;
    }

  while (--index > 0)
    {
      while (*cmd && ! isspace(*cmd))
        ++cmd;
      while (isspace(*cmd))
        ++cmd;
    }

  if (strncmp(cmd, "FILE", 4) == 0
      && (cmd[4] == '\n' || cmd[4] == ' '))
    return NULL; /* Default file name completion will be used.  */

  if (strncmp(cmd, "MODULE", 6) != 0
      || (cmd[6] != '\n' && cmd[6] != ' '))
    {
      /* Don't know how to complete.  */
      rl_attempted_completion_over = 1;
      return NULL;
    }

  if (! modules)
    {
      int res = _xprobes_control_write(control_socket,
                                       "modules", sizeof("modules"));
      if (res <= 0)
        {
          printf("write to remote failed\n");
          exit(1);
        }

      control_notify();

      size_t size = 1;
      do
        {
          size_t len = read_reply(false);
          modules = realloc(modules, size + len);
          if (! modules)
            {
              printf("realloc() failed\n");
              exit(1);
            }
          memcpy(modules + size - 1, reply.buf, len);
          size += len;
        }
      while (! reply.end);
      modules[size - 1] = '\0';
    }

  return rl_completion_matches(text, generate_module);
}


static
void
init_command_completion(void)
{
  static const char local_commands[] =
    "help\n"
    "version\n"
    "quit\n";

  int res = _xprobes_control_write(control_socket, "help", sizeof("help"));
  if (res <= 0)
    {
      printf("write to remote failed\n");
      exit(1);
    }

  control_notify();

  size_t len = read_reply(true);

  help = malloc(len + sizeof(local_commands));
  memcpy(help, reply.buf, len);
  memcpy(help + len, local_commands, sizeof(local_commands));

  res = _xprobes_control_write(control_socket, "version", sizeof("version"));
  if (res <= 0)
    {
      printf("write to remote failed\n");
      exit(1);
    }

  control_notify();

  len = read_reply(true);

  version = strndup(reply.buf, len);

  rl_attempted_completion_function = complete_command;
}


static
void
attach(void)
{
  int res = sigaction(SIGPIPE, &ignore, NULL);
  assert(res == 0);

  int fd = _xprobes_open_socket(getuid(), getpid(), true);
  if (fd == -1)
    {
      perror("_xprobes_open_socket()");
      exit(1);
    }

  atexit(unlink_socket);

  printf("Connecting... ");
  fflush(stdout);

  res = listen(fd, 1);
  if (res == -1)
    {
      perror("listen()");
      exit(1);
    }

  control_notify();

  control_socket = RESTART(accept(fd, NULL, NULL));
  if (control_socket == -1)
    {
      perror("accept()");
      exit(1);
    }

  RESTART(close(fd));

  size_t len = read_reply(true);
  if (len > 0)
    {
      fputs(reply.buf, stdout);
      exit(1);
    }

  init_command_completion();

  printf("done\n");
}


static sig_atomic_t canceled = 0;


static
void
handle_sigint(int sig)
{
  UNUSED(sig);

  int save_errno = errno;

  int res = _xprobes_control_write(control_socket, "cancel", sizeof("cancel"));
  if (res == 1)
    control_notify();

  res = sigaction(SIGINT, &ignore, NULL);
  assert(res == 0);

  canceled = 1;

  errno = save_errno;
}


static
void
loop(void)
{
  int res = sigaction(SIGINT, &ignore, NULL);
  assert(res == 0);

  struct sigaction sigint = {
    .sa_handler = handle_sigint,
    .sa_flags = SA_RESTART,
  };
  sigemptyset(&sigint.sa_mask);

  while (1)
    {
      char *line = readline("xprobes> ");

      reset_modules();

      if (! line)
        break;

      char *cmd = line;
      while (isspace(*cmd))
        ++cmd;

      if (*cmd == '\0')
        {
          free(line);
          continue;
        }

      size_t len = strlen(cmd);
      char *end = cmd + len;
      while (isspace(*--end))
        --len;
      end[1] = '\0';

      if (strcmp(cmd, "quit") == 0)
        {
          free(line);
          break;
        }

      if (cmd == line)
        add_history(line);

      if (strcmp(cmd, "help") == 0)
        {
          fputs(help, stdout);
          free(line);
          continue;
        }

      if (strcmp(cmd, "version") == 0)
        {
          printf("   control: %s\n"
                 "libxprobes: %s",
                 PACKAGE_VERSION, version);
          free(line);
          continue;
        }

      int res = _xprobes_control_write(control_socket, cmd, len + 1);
      if (res <= 0)
        {
          printf("write to remote failed\n");
          continue;
        }

      free(line);

      control_notify();

      res = sigaction(SIGINT, &sigint, NULL);
      assert(res == 0);

      do
        {
          read_reply(false);
          fputs(reply.buf, stdout);
        }
      while (! reply.end);

      res = sigaction(SIGINT, &ignore, NULL);
      assert(res == 0);

      if (canceled)
        {
          canceled = 0;
          do
            {
              read_reply(false);
              fputs(reply.buf, stdout);
            }
          while (! reply.end);
        }
    }
}


int
main(int argc, char *argv[])
{
  signal_no = DEFAULT_SIGNAL;

  process_options(argc, argv);

  attach();

  rl_readline_name = "xprobes";
  using_history();
  stifle_history(1000);

  loop();

  return 0;
}
