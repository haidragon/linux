/* getstack.c - Get the location of the stack and print it
 *              (Idea by Peter Roozemaal)
 *
 * Copyright (c)2003 by Peter Busser <peter@adamantix.org>
 * This file has been released under the GNU Public Licence version 2 or later
 */

#include <stdio.h>

int main( int argc, char *argv[] ){
	char a;

	printf( "%p\n", &a );

	exit( 0 );
}

