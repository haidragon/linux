/* getmain.c - Get the address of the main function and print it
 *
 * Copyright (c)2003 by Peter Busser <peter@adamantix.org>
 * This file has been released under the GNU Public Licence version 2 or later
 */

#include <stdio.h>
#include <stdlib.h>

static void foo(void)
{
	printf( "%p\n", __builtin_return_address(0) );
}

int main( int argc, char *argv[] )
{
	foo();
}
