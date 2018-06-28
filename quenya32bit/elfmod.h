#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <time.h>
#include <stdarg.h>
#include <sys/time.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <dlfcn.h>
#include <curses.h>
#include <pthread.h>

#include "libdasm-1.5/libdasm.h"

/* scrippies cool libptrace */
#include "libptrace/src/libptrace.h"

/* header for quenya commands */
#include "cmd.h"

#define SHT_VERSYM 0x6fffffff
#define SHT_VERNEED 0x6ffffffe

#define TMP_FILE ".elfmod-b1n"

//#define PAGE_SIZE 4096
/* static segment index for text/data */
#define TEXT 2
#define DATA 3

/* for overwrite() */
#define OW_BYTE 1
#define OW_WORD 2
#define OW_DWORD 3

/* flags for section obfuscation (string table randomization) */
#define RANDOMIZE_STBL_MIX 1
#define RANDOMIZE_STBL_TYPE_CONSISTENCY 2
#define RANDOMIZE_STBL_FLAG_CONSISTENCY 4

#define TEXT_PADDING_INFECTION 1
#define TEXT_ENTRY_INFECTION 2
#define DATA_SEGMENT_INFECTION 3

#define NO_JMP_CODE ~0L

#define BINARY_MODE_HIJACK 0
#define PROCESS_MODE_HIJACK 1

/* RETURN CODES */
#define EFILE_ERR -1 
#define EMAP_FAIL -2
#define ELOAD_ELF -3
#define EMALLOC -4

#define MAXSTR 255
#define MAXBUF 512

/* string table types */
#define SYM_STRTAB 1
#define SHD_STRTAB 2
#define DYN_STRTAB 3

/* ElfDup options */
#define ELFDUP_CLOSE 1
#define ELFDUP_NOFLAG 2

#define SUCCESS 1
#define FAILURE 0
#define WHITE "\033[0;37m"
#define RED   "\033[0;31m"
#define GREEN "\033[0;32m"
#define BLUE  "\033[0;34m"
#define END   "\033[0m"

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

struct type_strings
{
	uint32_t type;
	char name[64];
};

struct section_type
{
        char name[64];
        uint32_t type;
        int flags;
};

struct elf_mmap_args
{
	int flags;
	int prot;
	Elf32_Addr vaddr;
	Elf32_Off  off;
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
	uint32_t size;	   /* file size  */
	int mode;	   /* file mode  */
	int elf_type;	   /* ET_DYN, ET_REL, ET_EXEC */
	char name[MAXSTR]; /* file name  */
	Elf32_Addr text_vaddr;
	Elf32_Addr data_vaddr;
	Elf32_Off text_offset;
	Elf32_Off data_offset;
	unsigned long text_filesz, text_memsz, data_filesz, data_memsz;
	char *typestr[7];
} Elf32mem_t; 

struct cmd_list
{
	char cmd[512];
	struct cmd_list *next;
};

struct elf_list
{
        Elf32mem_t elf;
	char name[MAXSTR];
        struct elf_list *next;
};

typedef struct {
      Elf32_Addr	st_value;
      Elf32_Word	st_size;
      unsigned char	st_info;
      unsigned char	st_other;
} Elf32sym_t;


struct elf_list * add_elf(char *, struct elf_list **);
int remove_elf(struct elf_list **);
int AddSection(Elf32mem_t *, int, char *, Elf32_Shdr*);
uint8_t * allocate_memory (uint32_t, int, Elf32_Addr, int, int);
int LoadElf(char *, int, int, Elf32_Addr, Elf32_Off, Elf32mem_t *);
void UnloadElf(Elf32mem_t *);
void show_plt(struct linking_info *);
struct linking_info * get_plt(unsigned char *);
uint8_t * elf2shell(char *, Elf32_Addr, Elf32_Addr, int8_t);
Elf32_Sym *GetSymByName(char *name, Elf32_Shdr *, int, uint8_t *);
Elf32_Addr GetRelocSymAddr(char *name, Elf32_Shdr *, int, uint8_t *);
int ElfRelocate(Elf32mem_t *, char *, int);
int ReloadElf(Elf32mem_t *);
int extend_PT_LOAD(Elf32mem_t *, uint32_t, char);
Elf32_Addr GetBase(Elf32mem_t *, int);
int GetSegByIndex(Elf32mem_t *, int);
int dump_phdrs(Elf32mem_t *);
void dump_elf_sections(uint8_t *);
int randomize_strtbl(uint8_t *, char *, int);
int unload_all(struct elf_list **);
struct elf_list ** search_by_name(char *, struct elf_list **);
unsigned long inject_elf_binary(Elf32mem_t *, uint8_t *, int, int, int);
int displayDisas(char *, Elf32mem_t *, int, Elf32_Addr, uint32_t);
Elf32_Addr GetSymAddr(char *, Elf32mem_t *);
int OverWrite(Elf32mem_t *, Elf32_Addr, long, int);
int ListRelEntry(Elf32mem_t *, int);
int ListSymTable(Elf32mem_t *, int, int);
void echo_on(void);
void echo_off(void);
char * ParseScriptSyntax(char *line);

/* FOR LIBPTRACE */

#define LIBPTRACE "libptrace/src/.libs/libptrace.so"

void *global_handle;
int (*Ptrace_write)(struct ptrace_context *, void *, const void *, size_t);
int (*Ptrace_open)(struct ptrace_context *, pid_t);
int (*Ptrace_close)(struct ptrace_context *);
int (*Ptrace_read)(struct ptrace_context *, void *, void *, size_t);
int (*Ptrace_close)(struct ptrace_context *);
        //void * (*ptrace_elf_get_dynamic_entry)(struct ptrace_context *, struct link_map *, Elf32_Sword);
char * (*Ptrace_errmsg)(struct ptrace_context *);
