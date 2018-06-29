/* execstack.c - Tests wether code on the stack can be executed
 *
 * Copyright (c)2003 by Peter Busser <peter@adamantix.org>
 * This file has been released under the GNU Public Licence version 2 or later
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "body.h"

const char testname[] = "Executable stack                         ";

void doit( void )
{
	char buf[8192];
	fptr func;

	/* Put a RETN instruction in the buffer */
	buf[0] = '\xc3';

	/* Convert the pointer to a function pointer */
	func = (fptr)buf;

	/* Call the code in the buffer */
	func();

	/* It worked when the function returns */
	itworked();
}
