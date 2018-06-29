#include "avu.h"

void usage(void)
{
	printf("\n%sUNIX Anti-Virus tool (C) 2009 Ryan O'Neill\n", RED, END);
	printf("\n%s./avu [--opts] OR <directories> - Options:\n"
	       "[--help(-h)] - This menu\n"
	       "Feature 1. [--memscan (-m) <pid>] - Scan for memory resident viruses, if you do not specify a pid avu scans all processes\n"
	       "Feature 2. [--unpack  (-u) <executable>] - Unpack executables that have been protected using various packing algorithms (UPX, ELFcrypt, ELFfuck)\n"
	       "Feature 3. [Specifying directories scans for ELF viruses using heuristic analysis techniques]%s\n"
	       "\n%sExamples:\n"
	       "./avu /usr/bin /bin /sbin\n"
	       "./avu --unpack some_exec\n"
	       "./avu --memscan 7684\n"
	       "./avu --memscan%s\n\n", WHITE, END, GREEN, END);
	exit(0);
}

	       
