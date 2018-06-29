#include "avu.h"


/* 
 * The following struct contains information about oddities determined
 * by check_elf_binary() which are in turn noted with add_msg() and are
 * part of what determines whether or not we utilize the AV heuristics
 * or not. If a binary is too far out of ELF specification, then it may
 * cause the AV heuristics code to crash because it excepts certain structures
 * to be in place, or be a certain way. 
 */
struct oddity_count
{
        char **msg;
        int index;
        int severity[3];
        int msg_size;
        char name[50];
        int check;
} elfhdr[3];

int add_msg(int type, int severity, char *fmt, ...)
{

        char msg[MAXBUF];
        
        va_list va;
        va_start(va, fmt);
        vsnprintf(msg, MAXBUF-1, fmt, va);
        va_end(va);
        
        elfhdr[type].msg[elfhdr[type].index] = strdup(msg);
        elfhdr[type].msg_size += sizeof(char *);
        elfhdr[type].check++;
        elfhdr[type].severity[elfhdr[type].index] = severity;
        elfhdr[type].index++;

        if((elfhdr[type].msg = realloc(elfhdr[type].msg, elfhdr[type].msg_size)) == NULL)
        {
                perror("add_msg() - calloc()");
                exit(-1);
        }
        return 1;
        
}

void init_msg_buf(void)
{
        for (i = 0; i < 3; i++)
        {
                if((elfhdr[i].msg = calloc(2, sizeof(char *))) == NULL)
                {
                        perror("integrity_check - calloc()");
                        exit(-1);
                }
	
                elfhdr[i].check = 0;
                elfhdr[i].index = 0;
                elfhdr[i].msg_size = sizeof(char *) * 2;
        }
}

int check_elf_binary(char *path)
{
	uint8_t *mem;
	Elf_Ehdr *ehdr;
	Elf_Shdr *shdr;
	Elf_Phdr *phdr;

	int fd;

	if ((fd = open(path, O_RDONLY)) < 0)
	{
		vmsg("Failure in opening file: %s - %s\n", path, strerror(errno));
		return -1;
	}
	
	if (fstat(fd, &st)) < 0)
	{
		vmsg("Failure in getting size of file: %s - %s\n", path, strerror(errno));
		return -1;
	}

	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd);
	if (mem == MAP_FAILED)
	{
		vmsg("Failure in mmap'ng file: %s - %s\n", path, strerror(errno));
		return -1;	
	}

	ehdr = (Elf_Ehdr *)mem;	
	phdr = (Elf_Phdr *)(mem + ehdr->e_phoff);
	shdr = (Elf_Shdr *)(mem + ehdr->e_shoff);
	
 	if (ehdr->e_ident[0] != 0x7f && strcmp(&ehdr->e_ident[1], "ELF"))
       		return -1;

	/* 
	 * AVU Currently only handles executable ELF types.
	 */
	if (ehdr->e_type != ET_EXEC)
		return -1;
	
	/*
	 * AVU Currently only handles x86-32 
	 */
	int ELFCLASSX;
#ifdef X86_64
	ELFCLASSX = ELFCLASS64;
#else
	ELFCLASSX = ELFCLASS32;
#endif
	if (ehdr->e_ident[4] != ELFCLASSX && ehdr->e_ident[5] != ELFDATA2LSB && ehdr->e_ident[6] != EV_CURRENT)
                return -1;

        if (ehdr->e_machine != EM_386 && ehdr->e_machine != EM_860)
                return -1;

	/* 
	 * The program header entry size should typically be the same as ElfX_Phdr  	
	 * and thus e_phentsize should not report differently in normal circumstances.
	 */
	if (ehdr->e_phentsize != sizeof(Elf_Phdr))
        {
                if((tmp = (ehdr->e_phentsize < sizeof(Elf_Phdr)) ? 0 : 1) == 0)
                        add_msg(P, SEV1, "Phdr size is unusually small [%d] expected ELF value is [%d]\n", ehdr->e_phentsize, sizeof(Elf_Phdr));
                else
                        add_msg(P, SEV1, "Phdr size is unusually large [%d] expected ELF value is [%d]\n", ehdr 

        }
	
	
}

