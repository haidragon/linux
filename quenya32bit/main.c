/* main.c - interface for ELF routines */

#include "elfmod.h"
#include <sys/utsname.h>
#include <setjmp.h>

#define ARGDELIM ":\t "
#define SUBDELIM "=,\n "

void Quenya_MainLoop(void);

/* necessary for our non-local goto */
/* to start at beginning of main loop */
/* after sighandler catches/blocks SIGINT */ 
jmp_buf env;
int libptrace_loaded = 0;
int maxlineNum = 0;

int global_debug = 0;	  /* Set debug output for any output */
int global_force_elf = 0; /* Load ELF objects that don't meet ELF specs */
char **global_envp;

struct options {
	int script_mode;
} opts = {0};
/* sighandler ignores SIGINT and jmps to beginning */
/* of quenya's main loop */
void sighandle(int sig)
{
	//echo_on();
	longjmp(env, sig);
}

/* Check to see if a string consists soley of numbers */
int IsInt(char *p)
{
	if (p == NULL)
		return 0;

	while (*p != '\0' && *p != '\n')
		if (*p >= '0' && *p <= '9')
			p++;
		else
			return 0;
	return 1;
}

/* note that this function strips a newline */
int IsHex(char *p)
{
	if (p[strlen(p) - 1] == '\n')
	    p[strlen(p) - 1] = '\0';

	if (*p == '0' && (*(p + 1) == 'x' || *(p + 1) == 'X'))
		p += 2;
	else
		return 0;
	while (*p != '\0')
		if ((*p >= '0' && *p <= '9') ||   /* 0 - 9 */
		    (*p >= 0x61 && *p <= 0x66) || /* A - F */
		    (*p >= 0x41 && *p <= 0x46))   /* a - f */
			p++;
		else
			return 0;	
	return 1;
}

int load_libptrace(void)
{
	libptrace_loaded = 1;

	if ((global_handle = dlopen(LIBPTRACE, RTLD_LAZY)) == NULL)
        {
                printf("Unable to open a neccessary shared object: %s\n", strerror(errno));
                return -1;
        }

        if ((Ptrace_open = (int (*)()) dlsym(global_handle, "ptrace_attach")) == NULL)
        {
                printf("Unable to locate symbol: ptrace_attach\n");
                return -1;
        }

        if ((Ptrace_close = (int (*)()) dlsym(global_handle, "ptrace_detach")) == NULL)
        {
                printf("Unable to locate symbol: ptrace_detach\n");
                return -1;
        }

        if ((Ptrace_read = (int (*)()) dlsym(global_handle, "ptrace_read")) == NULL)
        {
                printf("Unable to locate symbol: ptrace_read\n");
                return -1;
        }

	if ((Ptrace_write = (int (*)()) dlsym(global_handle, "ptrace_write")) == NULL)
        {
                printf("Unable to locate symbol: ptrace_write\n");
                return -1;
        }

        if ((Ptrace_errmsg = (char * (*)()) dlsym(global_handle, "ptrace_errmsg")) == NULL)
        {
                printf("Unable to locate symbol: ptrace_errmsg\n");
                return -1;
        }
	
	
}

void unload_libptrace(void)
{
	dlclose(global_handle);
}

struct termios tios_orig;	
void echo_off(void)
{ 
	struct termios tios;
	tcgetattr(0, &tios_orig);
	
	tios = tios_orig;
	tios.c_lflag &= ~ECHO;
	tios.c_cc[VMIN] = 1;
	tios.c_lflag &= ~ICANON;

	if(tcsetattr(fileno(stdin), TCSANOW, &tios) != 0)
	{
		printf("Termios failure\n");
		exit(0);
	}
}
 

void echo_on(void)
{
        struct termios tios;
	/*

	tios.c_lflag |= ECHO;
	tios.c_lflag |= ICANON;
	*/
	tios = tios_orig;
	tios.c_lflag |= ECHO;
	tios.c_lflag |= ICANON;

	if (tcsetattr(fileno(stdin), TCSANOW, &tios) != 0)
	{
		printf("Termios failure\n");
		exit(0);
	}
}

int GetMaxLine(void)
{ 
	struct winsize w;
  	if (ioctl(0, TIOCGWINSZ, &w) == -1)
	{
		perror("ioctl");
		exit(-1);
	}
	maxlineNum = w.ws_row;
	return maxlineNum;
}

int main(int argc, char **argv, char **envp)
{
	global_envp = envp;
	GetMaxLine();
	if (load_libptrace() == -1)
		exit(0);
	Quenya_MainLoop();
	unload_libptrace();
	/* we shouldn't get here */
	exit(0);
}

/* This is the main loop, its a wrapper for the library of */
/* ELF functions provided in the rest of the source code. The way objects */
/* are opened, and modified is a cross breed between making changes through msync */
/* but also read/write which allows for less flexibility, but is easiest to implement */
/* with modifications that require file size extension, sometime down the road */
/* adjustments will be made */
void Quenya_MainLoop(void)	
{
	char cmd[MAXSTR*2] = {0}, *p, *q, target_name[MAXSTR], source_name[MAXSTR];
	struct utsname uts;
	struct elf_list *current, *tmp, *listhead = NULL;
	struct cmd_list *current_cmd, *cmd_listhead = NULL;
	char **args, **subopts;
	char symbol_name[MAXSTR];

	/* misc */
	char file_type[MAXSTR];
	int unload, tokens, subtokens, etype;
	int num = 0;

	/* addsect args */
	uint32_t section_size;
	char section_name[MAXSTR];
	int section_index, section_type;
	Elf32_Shdr NewShdr;
	
	/* inject/insert args */
	uint8_t *payload;
	int8_t method, nojmp;
	uint32_t psize; //payload size
	Elf32_Addr start, stop; // address range to get payload from ELF object  
	Elf32_Addr injection_vaddr;
	char methodstr[MAXSTR];
	uint32_t jmp_code_offset;

	/* setup sig handler to catch sigint */
        struct sigaction act;
        sigset_t set;
        struct linking_info *lp;
        act.sa_handler = sighandle;
        sigemptyset (&act.sa_mask);
        act.sa_flags = 0;
        sigaction (SIGINT, &act, NULL);
        sigemptyset (&set);
        sigaddset (&set, SIGINT);

	/* misc */
	char ts[5];

	/* sht specific */
	int randstrtab_flags = 0;

	/* Reverse engineering */
	int ow_type = 0, ch;
	char tmp_arg[MAXSTR];
	int ret;

	banner();
	uname(&uts);

	for(;;)
	{
		if (opts.script_mode)
			goto loop_start;
		/* nonlocal goto in place; if we catch SIGINT, then start */
		/* right back here at the beginning of the loop */
		fflush(NULL);
		setjmp(env);	
		printf("\n%s[%sQuenya v0.1@%s%s]%s ", RED, WHITE, uts.nodename, RED, END);
loop_start:
		memset(cmd, 0, sizeof(cmd));
		fgets(cmd, sizeof(cmd)-1, stdin);
		if (cmd[0] == '\n' || cmd[0] == '\r')
			continue;
		if (opts.script_mode) {
			char *scriptLine = cmd;
			char *sp = NULL;

			memset(cmd, 0, sizeof(cmd));
			strncpy(cmd, sp, sizeof(cmd) - 1);
		}
		p = cmd;
		if (ExtractArgs(&args, ARGDELIM, cmd) > 1)
			while (*p != ' ')
				p++;	
		else
			while (*p != '\n')
				p++;
		*p = '\0';	
		current = listhead; 
		unload = 0; 
		if (strncasecmp(cmd, HELP, strlen(HELP)) == 0)
		{
			command_list();
			continue;
		}
		else
		if (strncasecmp(cmd, QUIT, strlen(QUIT)) == 0)
		{	
			unload_all(&listhead);
			exit(0);
		}
		else
		if (strncasecmp(cmd, PHT, strlen(PHT)) == 0)
		{
			p += 1;
			if ((tokens = ExtractArgs(&args, ARGDELIM, p)) == 0)
			{
				help(PHT_HELP);
				continue;
			}
			strncpy(target_name, args[0], MAXSTR);
			if (tokens == 1)
				target_name[strlen(target_name) - 1] = '\0';
			current = (struct elf_list *)add_elf(target_name, &listhead);
			if (!current)
				goto pht_done;

			if (current->elf.ehdr->e_phnum == 0)
			{
				printf("\n%s appears to have no program headers\n", target_name);
				goto pht_done;
			}
			if (!current)
				goto pht_done;
			if (tokens == 1)
			{
				dump_phdrs(&current->elf);
				goto pht_done;
			}

			pht_done:
			remove_elf((struct elf_list **)search_by_name(target_name, &listhead));
			free(args);
			continue;
		}
		else	
		if (strncasecmp(cmd, SHT, strlen(SHT)) == 0)
		{
			p += 1;
			if ((tokens = ExtractArgs(&args, ARGDELIM, p)) == 0)
			{
				help(SHT_HELP);
				continue;
			}		
			
			strncpy(target_name, args[0], MAXSTR);
			if (tokens == 1)
				target_name[strlen(target_name) - 1] = '\0';

			current = (struct elf_list *)add_elf(target_name, &listhead);
			if (!current)
				goto sht_done;
			if (tokens == 1)
			{
				dump_elf_sections(current->elf.mem);
				goto sht_done;
			}	
			
			/* Sub command "randstrtab" for randomizing string table (obfuscation) */
			if (strncasecmp(args[1], RANDSTRTAB, strlen(RANDSTRTAB)) == 0)
			{
				if (tokens > 2)
				{
					if (strncasecmp(args[2], "OPTS", 4) != 0)
					{
						help(RANDSTRTAB_HELP);
						goto sht_done;
					}
					
					if ((subtokens = ExtractArgs(&subopts, SUBDELIM, args[2])) < 2)
					{
						help(RANDSTRTAB_HELP);
						goto sht_done;
					}
					
					if (strncasecmp(subopts[1], "FLAG", 4) == 0)
						randstrtab_flags |= RANDOMIZE_STBL_FLAG_CONSISTENCY;
					else
					if (strncasecmp(subopts[1], "TYPE", 4) == 0)
						randstrtab_flags |= RANDOMIZE_STBL_TYPE_CONSISTENCY;
					else
					{
						printf("Unknown sub option: %s\n", subopts[1]);
						help(RANDSTRTAB_HELP);
						goto sht_done;
					}
					if (subtokens > 2)
					{
						 if (strncasecmp(subopts[2], "FLAG", 4) == 0)
                                                	randstrtab_flags |= RANDOMIZE_STBL_FLAG_CONSISTENCY;
                                        	 else
                                        	 if (strncasecmp(subopts[2], "TYPE", 4) == 0)
                                                 	randstrtab_flags |= RANDOMIZE_STBL_TYPE_CONSISTENCY;
                                        	 else
                                        	 {
                                                	printf("Unknown sub option: %s\n", subopts[2]);
                                                	help(RANDSTRTAB_HELP);
                                                	goto sht_done;
                                        	 }
					}
				}
				randomize_strtbl(current->elf.mem, target_name, randstrtab_flags);
				
			}
			else
			if (strncasecmp(args[1], LIST_SHT, strlen(LIST_SHT)) == 0)
			{
				if (tokens < 3)
				{
					help(SHT_HELP);
					goto sht_done;
				}
				
				if (tokens >= 3)
				{
					if (strncasecmp(args[2], SYM, strlen(SYM)) == 0)
					{
						if (tokens == 3)
							ListSymTable(&current->elf, SHT_SYMTAB, ~0L);
						else
						if (tokens >= 4)
						{
							if (!IsInt(args[3]))
							{
								printf("Argument 4 'index' must be in decimal form\n");
								help(SHT_HELP);
							}
							ListSymTable(&current->elf, SHT_SYMTAB, atoi(args[3]));
						}				 	
					}
					else
					if (strncasecmp(args[2], DYN, strlen(SYM)) == 0)
                                        {
                                                if (tokens == 3)
                                                        ListSymTable(&current->elf, SHT_DYNSYM, ~0L);
                                                else
                                                if (tokens >= 4)
                                                {
                                                        if (!IsInt(args[3]))
                                                        {
                                                                printf("Argument 4 'index' must be in decimal form\n");
                                                                help(SHT_HELP);
                                                        }
                                                        ListSymTable(&current->elf, SHT_DYNSYM, atoi(args[3]));
                                                }
                                        }
					else
					if (strncasecmp(args[2], REL, strlen(REL)) == 0)
					{
						if (tokens == 3)
							ListRelEntry(&current->elf, ~0L);
						if (tokens >= 4)
						{
							if (!IsInt(args[3]))
							{
								printf("Argument 4 'index' must be in decimal form\n");
								help(SHT_HELP);
							}
							ListRelEntry(&current->elf, atoi(args[3]));
						}
					}

				}
			 }
			 else
			 if (strncasecmp(args[1], MOD_SHT, strlen(MOD_SHT)) == 0)
			 {
			 	if (tokens < 5)
				{
					help(SHT_HELP);
					goto sht_done;
				}

				if (strncasecmp(args[2], SYM, strlen(SYM)) == 0)
				{
					if(!IsHex(args[4]))
					{
						printf("Argument 5 'value' must be in hex format as an offset or address\n");
						help(SHT_HELP);
					}
					if (ModifySymbol(args[3], &current->elf, strtoul(args[4], NULL, 16)) == 0)
					{
						printf("Failed to locate symbol: %s\n", args[3]);
						goto sht_done;
					}

				 	if (CommitChanges(&current->elf) < 0)
                        		{
                                		printf("Unable to commit changes\n");
                                		goto overwrite_done;
                        		}
					printf("Successfully modified symbol: %s with value: %0x\n", args[3], strtoul(args[4], NULL, 16));

				} 	
			}
				
			sht_done:
			remove_elf((struct elf_list **)search_by_name(target_name, &listhead));
			free(args);
			continue;
		}	
		else
		if (strncasecmp(cmd, LOADELF, strlen(LOADELF)) == 0)
		{
			p += 1;
			if (*p == 0x0)
			{
				help(LOAD_HELP);
				continue;
			}
			strncpy(target_name, p, MAXSTR);
			target_name[strlen(target_name) - 1] = '\0';
			current = (struct elf_list *)add_elf(target_name, &listhead);
			if (!current)
				continue;
			printf("%s File '%s' Successfully Loaded\n",  
			current->elf.typestr[current->elf.elf_type], current->name);
			continue;
		}
		else
		if (strncasecmp(cmd, UNLOADELF, strlen(UNLOADELF)) == 0)
		{
			p += 1;
			if (*p == 0x0)
			{
				help(UNLOAD_HELP);
				continue;
			}
			strncpy(target_name, p, MAXSTR);
			target_name[strlen(target_name) - 1] ='\0';

			if (remove_elf((struct elf_list **)search_by_name(target_name, &listhead)))
				unload = SUCCESS;
			if (unload)
				printf("File '%s' Successfully Unloaded\n", target_name);
			else
				printf("File '%s' does not appear to be loaded\n", target_name);
			continue;
		}
		else
		if (strncasecmp(cmd, RELOCATE, strlen(RELOCATE)) == 0)
		{	
			p += 1;
			if (ExtractArgs(&args, ARGDELIM, p) < 2)
			{
				help(RELOC_HELP);
				goto reloc_done;
			}

			strncpy(source_name, args[0], MAXSTR);
			strncpy(target_name, args[1], MAXSTR);
			
			target_name[strlen(target_name) - 1] = '\0';
			source_name[sizeof(source_name) - 1] = '\0';
			
			current = (struct elf_list *)add_elf(target_name, &listhead);
			if (!current)
				goto reloc_done;	
			if (ElfRelocate(&current->elf, source_name, TEXT_PADDING_INFECTION) == 0)
				printf("Injection/Relocation succeeded\n");
			else
				printf("Injection/Relocation failed\n");
			reloc_done:
			//remove_elf((struct elf_list **)search_by_name(target_name, &listhead));
			free(args);
			continue;
		}
		else
		if (strncasecmp(cmd, INJECT, strlen(INJECT)) == 0)
		{
			nojmp = 0;
			p += 1;
			if ((tokens = ExtractArgs(&args, ARGDELIM, p)) < 5)
			{
				help(INJECT_HELP);
				continue;
			}
			
			strncpy(target_name, args[0], MAXSTR);
			target_name[sizeof(target_name) - 1] = '\0';
			
			strncpy(source_name, args[1], MAXSTR-1);
			source_name[sizeof(source_name) - 1] = '\0';
		
			if (!IsHex(args[2]))
			{
				printf("Arg 3 (Start Address) must be in hex format\n");
				continue;
			}
			start = strtoul(args[2], NULL, 16);

			if (!IsHex(args[3]))
			{
				printf("Arg 4 (Stop Address) must be in hex format\n");
				continue;
			}
			stop = strtoul(args[3], NULL, 16);
			if (stop <= start)
			{
				printf("The Stop address must be larger than the Start address\n");
				continue;
			}
			psize = stop - start;
			
			strncpy(methodstr, args[4], MAXSTR);
			methodstr[sizeof(methodstr) - 1] = '\0';

			if (methodstr[strlen(methodstr) - 1] == '\n')
				methodstr[strlen(methodstr) - 1] = '\0';
			
			if (strcasecmp(methodstr, "TEXT_PADDING_INJECTION") == 0)
				method = TEXT_PADDING_INFECTION;
			else
			if (strcasecmp(methodstr, "TEXT_ENTRY_INJECTION") == 0)
				method = TEXT_ENTRY_INFECTION;
			else
			if (strcasecmp(methodstr, "DATA_SEGMENT_INJECTION") == 0)
				method = DATA_SEGMENT_INFECTION;
			else
			{
				printf("Arg 5 (Method of injection) must be one of the following:\n"
				       "TEXT_PADDING_INJECTION, TEXT_ENTRY_INJECTION, DATA_SEGMENT_INJECTION\n");
				continue;
			}
			
			if (tokens > 5)
				if (!strncasecmp(args[5], "--nojmp", 7))
					nojmp = 1;
		
			current = (struct elf_list *)add_elf(target_name, &listhead);
			if (!current)
				continue;
			jmp_code_offset = nojmp ? NO_JMP_CODE : psize - 4;

			injection_vaddr = inject_elf_binary( /* injection time */
			&current->elf, // elf descriptor for target
			elf2shell(source_name, start, stop, nojmp), // extract code from source object 
			psize, /* payload length */
			jmp_code_offset, /* offset into payload where jmp_code should be patched with original entry */
			method); /* method of injection */ 
			if (injection_vaddr != EFILE_ERR)
				printf("Injection succeeded, at 0x%x in %s\n", injection_vaddr, target_name);
			//remove_elf((struct elf_list **)search_by_name(target_name, &listhead));
			continue;
		}

		if (strncasecmp(cmd, ADDSECTION, strlen(ADDSECTION)) == 0)
		{	
			q = p + 1;
			if (q[strlen(q) - 1] == '\n')
				q[strlen(q) - 1] = '\0';

			tokens = ExtractArgs(&args, ARGDELIM, q);		
			if (tokens < 4)
			{
				help(ADDSECT_HELP);
				continue;
			}
			strncpy(target_name, args[0], MAXSTR);
		        target_name[sizeof(target_name) - 1] = '\0';
			
			if (!IsInt(args[1]))
			{
				printf("Arg 2 (Section index) must be an integer\n");
				continue;
			}
			section_index = atoi(args[1]);
			strncpy(section_name, args[2], MAXSTR);
		        section_name[sizeof(section_name) - 1] = '\0';
			
			if (!IsInt(args[3]))
			{
				printf("Arg 4 (Section Size) must be an integer\n");
				continue;
			}
			section_size = strtoul(args[3], NULL, 10);
			if (!IsInt(args[4]))
			{
				printf("Arg 5 (Section type) must be an integer: ('list sht types' for more info)\n");
				continue;
			}
			section_type = atoi(args[4]);
			current = (struct elf_list *)add_elf(target_name, &listhead);
			if (!current)
				continue;
			memset(&NewShdr, 0, sizeof(Elf32_Shdr));
			NewShdr.sh_size = section_size;
			NewShdr.sh_type = section_type;
			
			/* this function requires no CommitChanges() */
			if (AddSection(&current->elf, section_index, section_name, &NewShdr) == -1)
			{
				printf("Adding section failed\n");
				continue;
			}
			/* must reload after adding section if you want to do more changes */
			ElfReload(&current->elf);
			/* This function requires CommitChanges */
			/* extend whatever loadable segment the section maps to */
			extend_PT_LOAD(&current->elf, section_size, GetSegByIndex(&current->elf, section_index));
			
			if (CommitChanges(&current->elf) < 0)
			{
				printf("Unable to finish adding section\n");
				goto addsect_done;
			}
			printf("Successfully added section '%s' to %s file '%s'\n", section_name,
			current->elf.typestr[current->elf.elf_type], current->name);
			
			addsect_done:
			remove_elf((struct elf_list **)search_by_name(target_name, &listhead));
			continue;
		}	
		else
		if (strncasecmp(cmd, ENTRY, strlen(ENTRY)) == 0)
		{
			p += 1;
			if (ExtractArgs(&args, ARGDELIM, p) < 2)
			{
				help(ENTRY_HELP);
				continue;
			}
			strncpy(target_name, args[0], MAXSTR);
			target_name[sizeof(target_name) - 1] = '\0';

			if (!IsHex(args[1]))
			{
				printf("Arg 2 (entry point) must be in hexidecimal format\n");
				continue;
			}
			
			current = (struct elf_list *)add_elf(target_name, &listhead);
			if (!current)
				continue;
			current->elf.ehdr->e_entry = strtoul(args[1], NULL, 16);
			if (CommitChanges(&current->elf) < 0)
				printf("Unable to commit changes to %s\n", target_name);
			remove_elf((struct elf_list **)search_by_name(target_name, &listhead));
			printf("Successfully modified entry point to %s\n", args[1]);
			free(args);
			continue;
		}
		else
		if (strncasecmp(cmd, SHNUM, strlen(SHNUM)) == 0)
		{
			p += 1;
			if (ExtractArgs(&args, ARGDELIM, p) < 2)
                        {
                                help(SHNUM_HELP);
                                continue;
                        }
                        strncpy(target_name, args[0], MAXSTR);
		        target_name[sizeof(target_name) - 1] = '\0';
			if (!IsInt(args[1]))
                        {
				printf("Arg 2 (shnum) must be in decimal format\n");
				continue;
			}
			current = (struct elf_list *)add_elf(target_name, &listhead);
			if (!current)
                        	continue;
                        current->elf.ehdr->e_shnum = atoi(args[1]);
			if (CommitChanges(&current->elf) < 0)
                                printf("Unable to commit changes to %s\n", target_name);
                        remove_elf((struct elf_list **)search_by_name(target_name, &listhead));
			printf("Successfully modified shnum to %s\n", args[1]);
			free(args);
			continue;	
		}
		else
		if (strncasecmp(cmd, PHNUM, strlen(PHNUM)) == 0)
                {
                        p += 1;
                        if (ExtractArgs(&args, ARGDELIM, p) < 2)
                        {
                                help(PHNUM_HELP);
                                continue;
                        }
                        strncpy(target_name, args[0], MAXSTR); 
			target_name[sizeof(target_name) - 1] = '\0';

                        if (!IsInt(args[1]))
                        {
                                printf("Arg 2 (phnum) must be in decimal format\n");
                                continue;
                        }
                        current = (struct elf_list *)add_elf(target_name, &listhead);
                        if (!current)
                                continue;
                        current->elf.ehdr->e_phnum = atoi(args[1]);
                        if (CommitChanges(&current->elf) < 0)
                                printf("Unable to commit changes to %s\n", target_name);
                        remove_elf((struct elf_list **)search_by_name(target_name, &listhead));
                        printf("Successfully modified phnum to %s\n", args[1]);
                        free(args);
                        continue;
                }
		else
		if (strncasecmp(cmd, VERSION, strlen(VERSION)) == 0)
                {
                        p += 1;
                        if (ExtractArgs(&args, ARGDELIM, p) < 2)
                        {
                                help(VERSION_HELP);
                                goto vers_done;
                        }
                        strncpy(target_name, args[0], MAXSTR);
			target_name[sizeof(target_name) - 1] = '\0';

                        if (!IsHex(args[1]))
                        {
                                printf("Arg 2 (version) must be in hexadecimal format\n");
                                goto vers_done;
                        }
                        current = (struct elf_list *)add_elf(target_name, &listhead);
                        if (!current)
                                goto vers_done;
                        current->elf.ehdr->e_version = strtoul(args[1], NULL, 16);
                        if (CommitChanges(&current->elf) < 0)
                                printf("Unable to commit changes to %s\n", target_name);
                        remove_elf((struct elf_list **)search_by_name(target_name, &listhead));
                        printf("Successfully modified ELF version to %s\n", args[1]);
                        
			vers_done:
			free(args);
                        continue;
                }
		else
                if (strncasecmp(cmd, MACHINE, strlen(MACHINE)) == 0)
                {
                        p += 1;
                        if (ExtractArgs(&args, ARGDELIM, p) < 2)
                        {
                                help(MACHINE_HELP);
                                goto mach_done;
                        }
                        strncpy(target_name, args[0], MAXSTR);
			target_name[sizeof(target_name) - 1] = '\0';

                        if (!IsHex(args[1]))
                        {
                                printf("Arg 2 (machine) must be in hexadecimal format\n");
                                goto mach_done;
                        }
                        current = (struct elf_list *)add_elf(target_name, &listhead);
                        if (!current)
                                goto mach_done;
                        current->elf.ehdr->e_version = strtoul(args[1], NULL, 16);
                        if (CommitChanges(&current->elf) < 0)
                                printf("Unable to commit changes to %s\n", target_name);
                        remove_elf((struct elf_list **)search_by_name(target_name, &listhead));
                        printf("Successfully modified machine type to %s\n", args[1]);
                        
                        mach_done:
                        free(args);
                        continue;
                }
		else
		if (strncasecmp(cmd, ETYPE, strlen(ETYPE)) == 0)
		{
			p += 1;
			if (ExtractArgs(&args, ARGDELIM, p) < 2)
			{
				help(ETYPE_HELP);
				goto etype_done;
			}
			strncpy(target_name, args[0], MAXSTR);
			target_name[sizeof(target_name) - 1] = '\0';

			if (strncasecmp(args[1], "ET_EXEC", 7) == 0)
				etype = 2;
			else
			if (strncasecmp(args[1], "ET_REL", 6) == 0)
				etype = 1;
			else
			if (strncasecmp(args[1], "ET_DYN", 6) == 0)
				etype = 3;
			else
			if (strncasecmp(args[1], "ET_CORE", 7) == 0)
				etype = 4;
			else
			if (strncasecmp(args[1], "ET_NONE", 8) == 0)
				etype = 0;
			else
			{
				printf("Invalid type: %s\n", args[1]);
				help(ETYPE_HELP);
				goto etype_done;
			}
			current = (struct elf_list *)add_elf(target_name, &listhead);
                        if (!current)
				goto etype_done;
			current->elf.ehdr->e_type = etype;
			if (CommitChanges(&current->elf) < 0)
                                printf("Unable to commit changes to %s\n", target_name);
			remove_elf((struct elf_list **)search_by_name(target_name, &listhead));
                        printf("Successfully modified ELF type to %s\n", args[1]);
			
			etype_done:
			free(args);
			continue;
		}
		else
		if (strncasecmp(cmd, DISAS, strlen(DISAS)) == 0)
		{
			p += 1;
			if ((tokens = ExtractArgs(&args, ARGDELIM, p)) < 2)
			{
				help(DISAS_HELP);
				goto disas_done;
			}
			
			strncpy(target_name, args[0], MAXSTR);
			current = (struct elf_list *)add_elf(target_name, &listhead);
			if (!current)
				goto disas_done;
			
			if (IsHex(args[1]))
			{
				if (tokens >= 3)
					if (!IsInt(args[2]))
					{
						printf("Argument 3 'instruction count' must be in decimal form\n");
						displayDisas(NULL, &current->elf, FORMAT_ATT, strtoul(args[1], NULL, 16), atoi(args[2]));
						goto disas_done;
					}
				
				displayDisas(NULL, &current->elf, FORMAT_ATT, strtoul(args[1], NULL, 16), 0);
				goto disas_done;
			}
			
			strncpy(symbol_name, args[1], MAXSTR);
			/* no need to remove newline here because IsHex() does it for us anyway */
		//	symbol_name[strlen(symbol_name) - 1] = '\0';

			displayDisas(symbol_name, &current->elf, FORMAT_ATT, 0, 0);
			remove_elf((struct elf_list **)search_by_name(target_name, &listhead));

			disas_done: 
			free(args);
			continue;
		}
		else
		if (strncasecmp(cmd, OVERWRITE, strlen(OVERWRITE)) == 0)
		{
			p += 1;
                        if ((tokens = ExtractArgs(&args, ARGDELIM, p)) < 3)
                        {
                                help(OVERWRITE_HELP);
                                goto overwrite_done;
                        }

			strncpy(target_name, args[0], MAXSTR);
                        current = (struct elf_list *)add_elf(target_name, &listhead);
                        if (!current)
                                goto overwrite_done;
			
			if (!IsHex(args[1]))
			{
				printf("Argument 2 'virtual address' must be in hexadecimal format\n");
				goto overwrite_done;
			}
			
			if (!IsHex(args[2]))
			{
				printf("Argument 3 'insertion data' must be in hexadecimal format\n");
				goto overwrite_done;
			}
			
			/* default assumption is 1 byte value */
			ow_type = OW_BYTE;
			if (strncasecmp(args[3], "word", 4) == 0)
				ow_type = OW_WORD;
			else
			if (strncasecmp(args[3], "dword", 5) == 0)
				ow_type = OW_DWORD;
			else
			if (strncasecmp(args[3], "byte", 4) == 0)
				ow_type = OW_BYTE; 
			else
			printf("Argument 4 'data type' was not specified; assuming %s is meant as an 8 bit value\n", args[2]);	

			if (OverWrite(&current->elf, strtoul(args[1], NULL, 16), strtol(args[2], NULL, 16), ow_type) == -1)
			{
				printf("Unable to modify %s\n", target_name);
				goto overwrite_done;
			}
			if (CommitChanges(&current->elf) < 0)
			{
				printf("Unable to commit changes\n");
				goto overwrite_done;
			}
			printf("Successfully modified %s [%s]-> %s\n", target_name, args[1], args[2]); 
			overwrite_done:
			remove_elf((struct elf_list **)search_by_name(target_name, &listhead));

			free(args);
			continue;
		}
		else
		if (strncasecmp(cmd, REBUILD_ELF, strlen(REBUILD_ELF)) == 0)
		{
			p += 1;
			if (ExtractArgs(&args, ARGDELIM, p) < 2)
			{
				help(REBUILD_HELP);
				goto rebuild_done;
			}

			if (!IsInt(args[0]))
			{
				printf("Argument 1 'PID' must be in decimal form\n");
				goto rebuild_done;
			}
			
			args[1][strlen(args[1]) - 1] = '\0';
			if (PDump2ELF(atoi(args[0]), args[1]) != -1)
				printf("Successfully rebuilt ELF object from memory\n"
				       "Output executable location: %s\n", args[1]);
			else
				printf("Failed at rebuilding ELF object from memory\n");
			
			rebuild_done:
			free(args);
			continue;
		}
		else
		if (strncasecmp(cmd, LIST, strlen(LIST)) == 0)
		{
			
			p += 1;
			if (ExtractArgs(&args, ARGDELIM, p) < 1)
			{
				ts[0] = '.';
				ts[1] = '\n';
				ts[2] = '\0';
				lsdir(ts);
				goto list_done;
			}

			lsdir(args[0]);
			
			list_done:
			free(args);
			continue;
		}
		else
		if (strncasecmp(cmd, HIJACK, strlen(HIJACK)) == 0)
		{

			/*	    0	      1		    2		3
			 * hijack <mode> <binary/pid> <replacement> <original>
			 */
			p += 1;
			
			int hijack_mode;

			if (ExtractArgs(&args, ARGDELIM, p) < 4)
			{
				help(HIJACK_HELP);
				continue;
			}
			if (strcasecmp(args[0], "binary") == 0)
			{
				current = (struct elf_list *)add_elf(args[1], &listhead);
				if (!current)
				{
					printf("Unable to load ELF object: %s\n", args[1]);
					continue;
				}
				hijack_mode = BINARY_MODE_HIJACK;
				
			}
			else
			if (strcasecmp(args[0], "process") == 0)
			{
				if (!IsInt(args[1]))
				{
					printf("Argument 2 must be an integer (process ID)\n");
					continue;
				}
				hijack_mode = PROCESS_MODE_HIJACK;
			}
			else
			printf("Unknown mode: %s (Known modes are 'binary' and 'process')\n", args[0]);
			
			unsigned long SymVaddr = GetSymAddr(args[2], &current->elf);
			if (SymVaddr == 0)
			{
				printf("Unable to locate symbol: %s\n", args[2]);
				continue;
			}
			if (hijack_mode == BINARY_MODE_HIJACK)
			{
				*(char *)strchr(args[3], '\n') = '\0';
				ret = hijack_function(&current->elf, hijack_mode, SymVaddr, args[3]);
			}
			else
			 	ret = hijack_function(NULL, hijack_mode, SymVaddr, args[3]);
			
			if (ret == 0)
				printf("Succesfully hijacked function: %s\n", args[3]);
			else
				printf("Failure in hijacking function: %s\n"
				       "Make sure it is exported in the PLT/GOT\n", args[3]);

			if (hijack_mode == BINARY_MODE_HIJACK && !ret)
			{
				printf("Commiting changes into executable file\n");
				CommitChanges(&current->elf);
				remove_elf((struct elf_list **)search_by_name(args[1], &listhead));
			}
		}
		else		
		if (strncasecmp(cmd, SET_DEBUG, strlen(SET_DEBUG)) == 0)
		{
			p = cmd;
			if ((p = strchr(p, '=')) == NULL)
				continue;
			p++;
			if (*p == '0')
				global_debug = 0;
			else
			if (*p == '1')
				global_debug = 1;
			else
			{
				printf("unrecognized value: %c\n", *p);
				continue;
			}
			printf("Set debug value: %c\n", *p);

			continue;
		}
		else
		if (strncasecmp(cmd, SET_FORCE_ELF, strlen(SET_FORCE_ELF)) == 0)
		{
			p = cmd;
                        if ((p = strchr(p, '=')) == NULL)
                                continue;
                        p++;
                        if (*p == '0')
                                global_force_elf = 0;
                        else
                        if (*p == '1')
                                global_force_elf = 1;
                        else
                        {
                                printf("unrecognized value: %c\n", *p);
                                continue;
                        }
                        printf("Set force_elf value: %c\n", *p);

                        continue;
                }
		else
		if (strncasecmp(cmd, UNPACK, strlen(UNPACK)) == 0)
		{
			char exec_path[255];
			int ec = 0;

			p += 1;
			while (*p != 0x20 && *p != '\n')
			{
				exec_path[ec++] = *p;
				p++;
			}
			exec_path[ec] = '\0';
			
			if (*p == '\n')
			{
				unpack_executable(exec_path, NULL);
				continue;
			}
			
			p++;
			/* Create Arg vector for execv */
			ExecVector(&args, ARGDELIM, p);
			unpack_executable(exec_path, args);
			continue;
		}	
		else
		{
			printf("Unknown command: %s\n", cmd);
			continue;
		}

	}

	exit(0);
}

