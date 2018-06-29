/* shlibtest.c - Shared library used by the shared library tests.
 *
 * Copyright (c)2003 by Peter Busser <peter@adamantix.org>
 * This file has been released under the GNU Public Licence version 2 or later
 */

char shbss;

char shdata = '\xc3';

/* A function which does nothing, it only exists so it can be referenced */
int shlibtest( void )
{
	return 1;
}
