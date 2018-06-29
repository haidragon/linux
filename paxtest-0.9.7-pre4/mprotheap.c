/* mprotheap.c - Tests wether code on the heap can be executed after trying to
 *               use mprotect() to make it executable.
 *
 * Copyright (c)2003 by Peter Busser <peter@adamantix.org>
 * This file has been released under the GNU Public Licence version 2 or later
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "body.h"

const char testname[] = "Executable heap (mprotect)               ";

void doit( void )
{
	char *buf;
	fptr func;

	buf = malloc( 1 );
	if( buf == NULL ) {
		fprintf( stderr, "Out of memory\n" );
		exit( 1 );
	}

	/* Put a RETN instruction in the buffer */
	*buf = '\xc3';

	/* Try to make the buffer executable by using mprotect() */
	/* Due to a FreeBSD bug PROT_READ is required */
	do_mprotect( buf, 1, PROT_READ|PROT_EXEC );

	/* Convert the pointer to a function pointer */
	func = (fptr)buf;

	/* Call the code in the buffer */
	func();

	do_mprotect( buf, 1, PROT_READ|PROT_WRITE );

	/* It worked when the function returns */
	itworked();
}
