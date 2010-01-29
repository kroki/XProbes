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

#ifndef UITOA_H
#define UITOA_H 1

#include <stddef.h>


/*
  uitoa() converts unsigned int to zero-terminated string.  It assumes
  buf is large enough (will need at most 11 bytes).  It is safe to
  call this function from signal handler (otherwise you'd be using
  vanilla sprintf()).  Returns pointer to the end of the string.
*/
static inline
char *
uitoa(char *buf, unsigned int i)
{
  char *p = buf;
  do
    {
      int digit = i % 10;
      i /= 10;
      switch (digit)
        {
        case 0: *p++ = '0'; break;
        case 1: *p++ = '1'; break;
        case 2: *p++ = '2'; break;
        case 3: *p++ = '3'; break;
        case 4: *p++ = '4'; break;
        case 5: *p++ = '5'; break;
        case 6: *p++ = '6'; break;
        case 7: *p++ = '7'; break;
        case 8: *p++ = '8'; break;
        case 9: *p++ = '9'; break;
        }
    }
  while (i > 0);

  char *res = p;
  *p-- = '\0';

  while (p > buf)
    {
      char tmp = *p;
      *p-- = *buf;
      *buf++ = tmp;
    }

  return res;
}


#endif  /* ! UITOA_H */
