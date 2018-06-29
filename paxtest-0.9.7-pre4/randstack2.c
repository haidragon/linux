/* randstack.c - Tests the randomisation of the stack pointer.
 * 
 * Copyright (c)2003 by Peter Busser <peter@adamantix.org>
 * This file has been released under the GNU Public Licence version 2 or later
 */

#ifndef RUNDIR
#error RUNDIR not defined
#endif

const char testname[] = "Stack randomisation test (PAGEEXEC)      ";
const char testprog[] = RUNDIR"/getstack2";
