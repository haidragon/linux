/* getshlib.c - Get the address of a function in a shared library and print it
 *
 * Copyright (c)2003 by Peter Busser <peter@adamantix.org>
 * This file has been released under the GNU Public Licence version 2 or later
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

/* OpenBSD 3.5 doesn't define RTLD_DEFAULT */
/* OpenBSD 3.6 does but it doesn't actually handle (segfaults on) RTLD_DEFAULT, sigh... */
#ifdef __OpenBSD__
#define RTLD_DEFAULT "libc.so"
#endif

int main( int argc, char *argv[] )
{
	void *handle;

	handle = dlopen( RTLD_DEFAULT, RTLD_LAZY );
	if( handle != NULL ) {
		void *sprintf;

		dlerror(); /* clear any errors */
		sprintf = dlsym( handle, "sprintf" );

		if( dlerror() == NULL ) {
			printf( "%0p\n", sprintf );
		}

		dlclose( handle );
	}
}
