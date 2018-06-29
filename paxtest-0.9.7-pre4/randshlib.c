/* randshlib.c - Tests the randomisation of shared library loading
 * 
 * Copyright (c)2003 by Peter Busser <peter@adamantix.org>
 * This file has been released under the GNU Public Licence version 2 or later
 */

#ifndef RUNDIR
#error RUNDIR not defined
#endif

const char testname[] = "Shared library randomisation test        ";
const char testprog[] = RUNDIR"/getshlib";
