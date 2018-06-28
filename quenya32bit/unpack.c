#include "elfmod.h"

	
extern char **global_envp;

int unpack_executable(char *path, char **args)
{
	int i, ret;
        int status;
	pid_t pid;
	long val;
	char outfile[260];
	struct  user_regs_struct reg;
	Elf32mem_t packed;	
	
	/* The # of single steps to take */ 
	unsigned long stepLen;
	
	if(LoadElf(path, MAP_PRIVATE, PROT_READ|PROT_WRITE, 0, 0, &packed) == -1)
        {
                printf("Unable to load ELF object: %s\n", path);
                return -1;
        }
	stepLen = packed.text_memsz;
	UnloadElf(&packed);

	printf("Text segment size: %d bytes\n", stepLen);
	
	if ((pid = fork()) < 0)
	{
		printf("fork() error: %s\n", strerror(errno));
		return -1;
	}

        if (pid == 0)
        {
                ptrace(PTRACE_TRACEME, 0, NULL, NULL);
                execve(path, args, global_envp);
		exit(0);
        }
   	waitpid(pid, &status, WNOHANG);
	
	for (i = 0; i < stepLen; i++)
	{
		ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
		wait(&status);
		ptrace(PTRACE_GETREGS, pid, NULL, &reg);
	}

	/* Lets unpack it! */
	PDump2ELF_child(pid, path);
	
	ptrace(PTRACE_KILL, pid, NULL, NULL);
	wait(&status);
	
}
	
	
