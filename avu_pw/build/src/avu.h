/*
 * This code is a part of AVU (AV UNIX) (C) 2008 Ryan O'Neill
 * <ryan@bitlackeys.com>
 */

#define _GNU_SOURCE

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <elf.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include <signal.h>

#define BUF_SIZE 255
#define TMP "/tmp/av.tmp"
#define CONFIG_FILE "avu.conf"

#define TEXT_INFECTION 1
#define DATA_INFECTION 2
#define TEXT_PADDING_INFECTION 3

/* if a virus does not match a section within a binary */
/* then the method for discovering the host entry must not use */
/* section headers */
#define NO_SECTION 1
#define SECTION_EXISTS 2

/* infected files get backed up and quarantined in case something */
/* goes wrong during the disinfection process. They are zipped up */
/* and password protected within ZIPDIR */
#define ZIPDIR ".avu/"
#define AUTH "abc"
#define ZIP "/usr/bin/zip -P "

#define MAXBUF 255

/* signifies either a jmp or a push type entry return */
#define JMP 1
#define PUSH 2

/* signifies segment_header[TYPE], i.e segment_header[TEXT].p_offset */
#define TEXT 0
#define DATA 1

#define E 0 /* elf header */
#define P 1 /* program header */
#define S 2 /* section header */

#define SEV1 1 /* most severe */
#define SEV2 2
#define SEV3 3

#define PAXFLAGS 0x65041580

#define CONFIG "avu.conf"

#define GREEN "\033[0;40;32m"
#define RED   "\033[0;40;31m"
#define WHITE "\033[0;40;37m"
#define END   "\033[0m"

#define ULONG_MAX 0xf0000000
#define MAXSTR 512

struct options
{
	char verbose;
	char memscan;
	char logging;
	char recursion;
	char nostdout;
	char extract_parasite;
	char alternative_entry_detection;
	char kp;
	char debug;
	char plt_hijack;
	char elf_disinfect;
	char unpack;
	char *logfile;
	char *config;
};

extern struct options opts;

struct linux_dirent
{
        long d_ino;
        off_t d_off;
        unsigned short d_reclen;
        char d_name[];
};

struct segment_info
{
        /* reserved for elf errors */
        char NoSegment;

        /* segment info */
        unsigned long end_of_segment;
        Elf32_Word p_filesz;
        Elf32_Off  p_offset;
        Elf32_Word p_memsz;
        Elf32_Word p_vaddr;

};

struct linking_info
{
        char name[256];
        int index;
        int count;
        uint32_t r_offset;
        uint32_t r_info;
        uint32_t s_value;
        int r_type;
};

/* Elf32mem_t */
typedef struct 
{
        uint8_t *mem;     /* raw memory */
        /* Elf headers */
        Elf32_Shdr *shdr;
        Elf32_Phdr *phdr;
        Elf32_Ehdr *ehdr;
        
        uint8_t **section; /* sections   */
        uint32_t size;     /* file size  */
        int mode;          /* file mode  */
        int elf_type;      /* ET_DYN, ET_REL, ET_EXEC */
        char name[MAXSTR]; /* file name  */
        Elf32_Addr text_vaddr;
        Elf32_Addr data_vaddr;
        Elf32_Off text_offset;
        Elf32_Off data_offset;
        unsigned long text_filesz, text_memsz, data_filesz, data_memsz;
        char *typestr[7];
} Elf32mem_t; 

struct pt_load
{
        uint32_t text_filesz;
        uint32_t text_memsz;
        uint32_t text_offset;
        uint32_t text_vaddr;
        
        uint32_t data_filesz;
        uint32_t data_memsz;
        uint32_t data_offset;
        uint32_t data_vaddr;
};

extern int pt_interp;
extern int memvirus;
extern int failed_process;
extern int gpid;
extern int attached_to_process;
extern int file_size;
/* phdr->p_vaddr for text segment should always be 8048000 */
#define TEXT_VADDR 0x8048000

/* bit value macro */ 
#define BV (bit) (1 << (bit))

void mkzip_dir(uid_t, gid_t);
int quarantine(char *, char *);
int remove_infection(uint32_t, uint32_t, Elf32_Off, uint32_t, unsigned char *, char);
struct segment_info * query_elf_segments(unsigned char *);
unsigned long get_host_entry(unsigned char *, unsigned *);
int code_cmp(unsigned char *, unsigned *, int); 
int add_msg(int, int, char *, ...);
int integrity_check(unsigned char *, char *);
int virus_check(unsigned char *);
void fatal(char *);
int scan_process(int);
void itoa(uint16_t, char *);
void sighandle(int);
unsigned long memread(unsigned long *, unsigned long, unsigned int, int);
void find_relocs(unsigned char *);
int printv(int, char *, ...);
int ptrace_write(int pid, void *dst, const void *src, size_t len);
int  ExecVector(char ***argvp, char *delim, char *s);
char * MakeString(char **, int, char *);
int unpack_executable(char *, char **);
