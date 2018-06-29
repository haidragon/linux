/* shlibdata.c - Tests wether code in the .data segment of a shared library can
 *               be executed
 *
 * Copyright (c)2003 by Peter Busser <peter@adamantix.org>
 * This file has been released under the GNU Public Licence version 2 or later
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include "body.h"

const char testname[] = "Executable shared library data           ";

static char *shdata, *shdata2;

void doit( void )
{
	fptr func;
	void *handle;

	handle = dlopen( "shlibtest.so", RTLD_LAZY );
	if( handle == NULL ) {
		fprintf( stderr, "dlopen() returned NULL\n" );
		exit( 1 );
	}
	shdata = dlsym( handle, "shdata" );
	dlclose( handle );

	handle = dlopen( "shlibtest2.so", RTLD_LAZY );
	if( handle == NULL ) {
		fprintf( stderr, "dlopen() returned NULL\n" );
		exit( 1 );
	}
	shdata2 = dlsym( handle, "shdata" );
	dlclose( handle );

	/* Convert the pointer to a function pointer */
	func = shdata < shdata2 ? (fptr)shdata : (fptr)shdata2;

	/* Call the code in the buffer */
	func();

	/* It worked when the function returns */
	itworked();
}
