/* writetext.c - Test wether a .text sections can be written
 *
 * Copyright (c)2003 by Peter Busser <peter@adamantix.org>
 * This file has been released under the GNU Public Licence version 2 or later
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include "body.h"

const char testname[] = "Writable text segments                   ";

extern int shlibtest( void );

static void sigsegv( int sig )
{
	printf( "Killed\n" );
	exit( 1 );
}

void doit( void )
{
	char *buf;
	char c;

	buf = (char*)shlibtest;

	signal( SIGSEGV, sigsegv );

	/* Try to make the text writable first by using mprotect
	 *
	 * Some people like to disable this call to make the results look
	 * better for their system.
	 *
	 * The purpose of the mprotect() here is to *really* try to write to
	 * that piece of executable memory. If you want to know whether a box
	 * can be opened or not, you try to pull it open. Just looking at it,
	 * seeing that it is closed, and therefore concluding that it cannot
	 * be opened is rather lame.
	 *
	 * But then, it is of course easier to get good paxtest results by
	 * disabling this mprotect than to fix your kernel code and userland.
	 */
	do_mprotect( buf, 4096, PROT_READ|PROT_WRITE|PROT_EXEC );

	/* Try to write something */
	*buf = 'X';

	/* It worked when the function returns */
	itworked();
}
