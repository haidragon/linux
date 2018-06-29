#include "avu.h"

void sighandle(int signal)
{
	printv((opts.logging)?1:2,"\tCaught signal 2\n");
	if (attached_to_process == 1)
		if (ptrace(PTRACE_DETACH, gpid, NULL, NULL) == -1)
	        	perror("ptrace_detach");
		else  
	printv((opts.logging)?1:2,"detached from process\n");
	exit(0);
} 

