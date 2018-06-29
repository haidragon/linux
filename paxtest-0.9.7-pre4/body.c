/* body.c - This part is shared by the test programs (except for the randomisation
 *          tests)
 *
 * Copyright (c)2003,2004 by Peter Busser <peter@adamantix.org>
 * This file has been released under the GNU Public Licence version 2 or later
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <unistd.h>

extern int doit( void );
extern const char testname[];

static void *test_thread(void *p)
{
	pause();
	return NULL;
}

int main( int argc, char *argv[] )
{
	int status;
	char *mode;
	/* This defaults to 1 as a safety mechanism. It is better to fail in
	 * blackhat mode, because kiddie mode can produce overly optimistic
	 * results.
	 */
	int paxtest_mode = 1;

	/* Dummy nested function */
	void dummy(void) {}

	mode = getenv( "PAXTEST_MODE" );
	if( mode == NULL ) {
		paxtest_mode = 1;
	} else {
		if( strcmp(mode,"0") == 0 ) {
			paxtest_mode = 0;
		} else if( strcmp(mode,"1") == 0 ) {
			paxtest_mode = 1;
		}
	}

	printf( "%s: ", testname );
	fflush( stdout );

	if( fork() == 0 ) {
		/* Perform a dirty (but not unrealistic) trick to circumvent
		 * the kernel protection.
		 */
		if( paxtest_mode == 1 ) {
			pthread_t thread;
			pthread_create(&thread, NULL, test_thread, dummy);
			doit();
			pthread_kill(thread, SIGTERM);
		} else {
			doit();
		}
	} else {
		wait( &status );
		if( WIFEXITED(status) == 0 ) {
			printf( "Killed\n" );
			exit( 0 );
		}
	}

	exit( 0 );
}

void itworked( void )
{
	printf( "Vulnerable\n" );
	exit( 1 );
}

void itfailed( void )
{
	printf( "Ok\n" );
	exit( 2 );
}


int do_mprotect( const void *addr, size_t len, int prot )
{
	void *ptr;
	int retval;
	long PAGESIZE = sysconf(_SC_PAGESIZE);

	/* Allign to a multiple of PAGESIZE, assumed to be a power of two */
	ptr = (char *)(((unsigned long) addr) & ~(PAGESIZE-1));

	retval = mprotect( ptr, len, prot );
	if( retval != 0 && errno == EINVAL ) {
		perror( "could not mprotect():" );
		exit( 1 );
	}

	return retval;
}

