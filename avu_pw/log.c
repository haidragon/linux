/*
 * logging print function
 * <ryan@bitlackeys.com>
 */

#include "avu.h"

int printv(int type, char *fmt, ...)
{
	FILE *fd;

	va_list va;
	va_start (va, fmt);
 	
	if (type)
	{
		if ((fd = fopen(opts.logfile, "a+")) == NULL)
			goto end;

        	vfprintf (fd, fmt, va);
        	fflush (fd);
	}
 	end:
	if (!opts.nostdout)
 		vfprintf (stdout, fmt, va);
 	va_end (va);
 
	 return 0;
}

