#include "avu.h"

/* my cool itao implementation */

void itoa(uint16_t val, char *s)
{
        uint8_t c = 0, i = 0;

        while (val)
        {
                s[c++] = val % 10 + '0';
                val /= 10;
        }    
        
        s[c] = '\0';
	while (i < c / 2)
	{
		s[i] ^= s[c-i-1]; 
		s[c-i-1] ^= s[i];
		s[i] ^= s[c-i-1];
		i++;
	}
}

int parse_config(char *conf)
{
	FILE *fd;
	char buf[MAXBUF], *delim = "=\n";
	char *p, *q, *brk; 
 	
	if ((fd = fopen(conf, "r")) == NULL)
	{
		perror("fopen (config):");
		exit(-1);
	}

	
	while (fgets(buf, MAXBUF-1, fd))
	{
		if (buf[0] == '\n' || buf[0] == '#')
			continue;
		if ((p = strtok(buf, "="))) 
		{
			if (strcasecmp(p, "logging") == 0)
			{
				if ((p = strtok(NULL, "\n")))
				{ 
					if ((q = strtok_r(p, ":", &brk)))
					{
						q = strtok_r(NULL, "\n", &brk);

						if (strcasecmp(q, "nostdout") == 0)
							opts.nostdout = 1;
						else
						if (strcasecmp(q, "stdout") == 0)
							opts.nostdout = 0;
						else
						printf("The 'logging' directive does not recognize the second argument"
						       "defaulting to logfile %s and printing to stdout\n", opts.logfile);

		 	 		        if ((opts.logfile = strdup(p)) == NULL)
 	                                        {
                                                	perror("strdup");
                                                	exit(-1);
                                        	}
					}
					opts.logging = 1;
				}
				else
					printf("No logfile specified, ignoring 'logging' directive\n");
				continue;
			} else
			if (strcasecmp(p, "recursion") == 0)
			{
				if ((p = strtok(NULL, "\n")))
				{
					if (strcasecmp(p, "yes") == 0)
						opts.recursion = 1;
				}
			 	else
					printf("The 'recursion' directive requires either 'yes' or 'no', defaulting to no\n");
				continue;
			} else
			if (strcasecmp(p, "verbose") == 0)
			{
				if ((p = strtok(NULL, "\n")))
				{
					if (strcasecmp(p, "yes") == 0)
						opts.verbose = 1; 
				}
					else
						printf("The 'verbose' directive requires either 'yes' or 'no', defaulting to no\n");
					continue;
			} else
			if (strcasecmp(p, "debug") == 0)
			{
				if ((p = strtok(NULL, "\n")))
				{
					if (strcasecmp(p, "yes") == 0)
						opts.debug = 1;
				}
					else
						printf("The 'debug' directive requires either 'yes' or 'no', defaulting to no\n");
					continue;
			}
			else
			if (strcasecmp(p, "kill_infected_process") == 0)
			{
				if ((p = strtok(NULL, "\n")))
				{
					if (strcasecmp(p, "yes") == 0)
						opts.kp = 0;
				}
					else
						printf("The 'kill_infected_process' directive requires either 'yes' or 'no', defaulting to no\n");
					continue;
			}
			else
			if (strcasecmp(p, "host_entry_detection") == 0)
			{
				if ((p = strtok(NULL, "\n")))
				{
					if (strcasecmp(p, "default") == 0)
						opts.alternative_entry_detection = 0;
					else
					if (strcasecmp(p, "alt") == 0)
						opts.alternative_entry_detection = 1;
					else
						printf("The 'host_entry_detection' directive requires either 'default' or 'alt', defaulting to default\n");
					continue;
				}
			}
			else
			if (strcasecmp(p, "elf_disinfect") == 0)
			{
				if ((p = strtok(NULL, "\n")))
				{
					if (strcasecmp(p, "yes") == 0)
						opts.elf_disinfect = 1;
					else
					if (strcasecmp(p, "no") == 0)
						opts.elf_disinfect = 0;
					else
						printf("The 'elf_disinfect' directive requires either 'yes' or 'no', defaulting to yes\n");
				}
			}
			else
			if (strcasecmp(p, "extract_parasite") == 0)
			{
				if ((p = strtok(NULL, "\n")))
				{
					if (strcasecmp(p, "yes") == 0)
						opts.extract_parasite = 1;
					else
					if (strcasecmp(p, "no") == 0)
						opts.extract_parasite = 0;
					else
						printf("The 'extract_parasite' directive requires either 'yes' or 'no', defaulting to no\n");
				} 
			}
			if (strcasecmp(p, "check_plt_hijack") == 0)
			{
				if ((p = strtok(NULL, "\n")))
				{
					if (strcasecmp(p, "yes") == 0)
						opts.plt_hijack = 1;
					else
					if (strcasecmp(p, "no") == 0)
						opts.plt_hijack = 0;
					else
						printf("The 'check_plt_hijack' directive requires either 'yes' or 'no', defaulting to no\n");
				}
			}
		}
	}
	
	fclose(fd);
	return 0;
}
		

		
