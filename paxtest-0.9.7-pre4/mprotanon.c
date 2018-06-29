/* mprotanon.c - Tests wether code can be executed in anonymous mappings
 *               after trying to use mprotect() to make it executable.
 *
 * Copyright (c)2003,2004 by Peter Busser <peter@adamantix.org>
 * This file has been released under the GNU Public Licence version 2 or later
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include "body.h"

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

const char testname[] = "Executable anonymous mapping (mprotect)  ";

void doit( void )
{
	char *buf;
	fptr func;

	buf = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if( buf == MAP_FAILED ) {
		fprintf( stderr, "mmap() returned NULL\n" );
		exit( 1 );
	}

	/* Put a RETN instruction in the buffer */
	*buf = '\xc3';

	/* Convert the pointer to a function pointer */
	func = (fptr)buf;

	/* Try to make the anonymous mapping executable first by using
	 * mprotect.
	 *
	 * Some people like to disable this call to make the results look
	 * better for their system.
	 *
	 * The whole purpose of this call is to figure out how the system
	 * handles mprotect() calls. If it allows the application to use
	 * mprotect() to override kernel settings, then that is something
	 * the user of this test suite may like to know.
	 *
	 * And yes, I know that this is how UNIX is supposed to work and that
	 * it is a design decision to allow this override. All the more reason
	 * to be honest and open about it and to tell the user why (s)he has
	 * to trade in a bit of security for compatibility.
	 *
	 * But then, it is of course easier to simply disable this mprotect()
	 * call than to fix your kernel and userland.
	 */
	/* Due to a FreeBSD bug PROT_READ is required */
	do_mprotect( buf, 1, PROT_READ|PROT_EXEC );

	/* Call the code in the buffer */
	func();

	/* It worked when the function returns */
	itworked();
}
