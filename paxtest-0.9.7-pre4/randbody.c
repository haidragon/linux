/* randbody.c - This part is shared by the randomisation tests
 *
 * Copyright (c)2003 by Peter Busser <peter@adamantix.org>
 * This file has been released under the GNU Public Licence version 2 or later
 */

#include <stdio.h>

#define COUNT	(25)

const char testname[];
const char testprog[];

int main( int argc, char *argv[] )
{
	FILE *fp;
	int i;
	unsigned long tmp;
	unsigned long and;
	unsigned long or;
	int bits;

	printf( "%s: ", testname );

	and = ~0L;
	or = 0L;
	for( i = 0; i < COUNT; i++ ) {
		fp = popen( testprog, "r" );
		if( fp == NULL ) {
			perror( testprog );
			exit( 1 );
		}

		fscanf( fp, "%lx", &tmp );

		and &= tmp;
		or |= tmp;

		pclose( fp );
	}

	if( and == or ) {
		printf( "No randomisation\n" );
	} else {
		tmp = and ^ ~or;
		tmp = or & ~tmp;
		bits = 0;
		while( tmp != 0 ) {
			bits += (tmp%2);
			tmp >>= 1;
		}

		printf( "%d bits (guessed)\n", bits );
	}

	exit( 0 );
}

