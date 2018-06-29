/* rettofunc1.c - Tests wether return to function exploits work or not.
 *
 * Copyright (c)2003,2004 by Peter Busser <peter@adamantix.org>
 * This file has been released under the GNU Public Licence version 2 or later
 */

#include <stdio.h>
#include <string.h>
#include "body.h"

const char testname[] = "Return to function (strcpy, RANDEXEC)    ";

fptr overflow[32] = {
	itworked, itworked, itworked, itworked, itworked, itworked, itworked, itworked,
	itworked, itworked, itworked, itworked, itworked, itworked, itworked, itworked,
	itworked, itworked, itworked, itworked, itworked, itworked, itworked, itworked,
	itworked, itworked, itworked, itworked, itworked, itworked, itworked, NULL
};

void doit( void )
{
	char buf[4];

	if (strlen((const char *)overflow) > 4) {
		strcpy( buf, (const char *)overflow );
	} else {
		fprintf( stderr, "paxtest: return address contains a NULL byte.\n" );
		exit(1);
	}
}
