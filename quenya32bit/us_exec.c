/*
 * Userland execve() implementation for elfscure, Elf Protector
 * Executes both static and dynamic binaries, with the ability to decrypt.
 * Author: Ryan O'Neill aka. Gerard`De Nerval
 * <ryan@bitlackeys.com>
 */
 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/mman.h>

struct segments
{
        Elf32_Addr text;
        Elf32_Addr data;
        int data_flags;
        int text_flags;
        uint32_t text_filesz;
        uint32_t text_poffset;
        uint32_t data_filesz;
        uint32_t text_memsz;
        uint32_t text_pvaddr;
        uint32_t data_memsz;
        uint32_t data_poffset;
        uint32_t data_off;
        unsigned long data_pvaddr;
        unsigned long image_size;

};

#define PAGE_SIZE 4096
#define AUX_COUNT 6

#define PAGEUP(x) (x + PAGE_SIZE - (x & (PAGE_SIZE - 1)))

#define PAGEDOWN(x) (x & ~(PAGE_SIZE - 1))
#define MAXBUF 255

#define STACK_SIZE (PAGE_SIZE << 2)

char interp[MAXBUF];
int argcnt = 0;
int arglen = 0;
char dynamic = 0;
char data_exists = 0;
long doff;

uint8_t *load_binary(uint8_t *, struct segments);


#define jmp_addr(stack, addr) __asm__ __volatile__("mov %0, %%esp\n" \
					    "push %1\n" \
					    "mov $0, %%eax\n" \
					    "mov $0, %%ebx\n" \
					    "mov $0, %%ecx\n" \
					    "mov $0, %%edx\n" \
					    "mov $0, %%esi\n" \
					    "mov $0, %%edi\n" \
					    "mov $0, %%ebp\n" \
					    "ret" :: "r" (stack), "g" (addr))	

	    
/* get all sorts of info necessary for loading our segments */
int seginfo(uint8_t *mem, struct segments *seg, int phoff)
{
	int i, no_data = 0;
	Elf32_Phdr *phdr = (Elf32_Phdr *)(mem + phoff);
	seg->text_flags = 0;
	seg->data_flags = 0;
	
	for (i = phoff; i > 0; i--, phdr++)
	{
		if (phdr->p_type == PT_LOAD && !phdr->p_offset)
		{
			/* p_align is a page size for text/data */
			/* lets get the total image_size for the */
			/* loadable segments */
			seg->text_memsz = PAGEUP(phdr->p_memsz);
			seg->image_size = PAGEUP(phdr->p_memsz);
			seg->text_filesz = phdr->p_filesz;
			seg->text_poffset = phdr->p_offset;
			seg->text_pvaddr = phdr->p_vaddr;
			seg->text = phdr->p_vaddr;
				
			if (phdr->p_flags & PF_X)
				seg->text_flags |= PROT_EXEC;
			if (phdr->p_flags & PF_R)
				seg->text_flags |= PROT_READ;
			if (phdr->p_flags & PF_W)
				seg->text_flags |= PROT_WRITE;
			phdr++;
			if (phdr->p_type == PT_LOAD && phdr->p_offset)
				data_exists = 1;
			else
			return 0;	
			seg->data_memsz = PAGEUP(phdr->p_memsz);
			seg->image_size += PAGEUP(phdr->p_memsz);
			seg->data_filesz = phdr->p_filesz;
			seg->data = phdr->p_vaddr; 
			seg->data_poffset = phdr->p_offset;
			seg->data_pvaddr = phdr->p_vaddr;
		
		        if (phdr->p_flags & PF_X)
                                seg->data_flags |= PROT_EXEC;
                        if (phdr->p_flags & PF_R)
                                seg->data_flags |= PROT_READ;
                        if (phdr->p_flags & PF_W)
                                seg->data_flags |= PROT_WRITE;

			return 0;
		}
	} 
	return -1;
}

int get_interp(uint8_t *mem, int phoff)
{
	int i;
	Elf32_Phdr *phdr = (Elf32_Phdr *)(mem + phoff);
	char buf[80];

	for (i = phoff; i > 0; i--, phdr++)
	{
		if (phdr->p_type == PT_INTERP)
		{
			if (phdr->p_vaddr < 0x08048000)
				break;	
			memcpy(interp, (mem + phdr->p_offset), sizeof(buf));
			/* this is not what we want */
			if (interp[0] == 'E' || interp[1] == 'E')
				break;
			else
			{	
				dynamic = 1;
				return 0;
			}
		}
	}
	return -1;

}

uint8_t *load_linker(char *path)
{
	int fd;
	struct stat st;
	uint8_t *mem;
	struct segments seg;
	Elf32_Ehdr *ehdr;
	uint8_t *linker;

        if ((fd = open(path, O_RDONLY)) == -1)
        {
                perror("linker open");
                return NULL;
        }

        if (fstat(fd, &st) == -1)
        {
                perror("fstat");
                return NULL;
        }

        mem = mmap(NULL, 108988, PROT_READ, MAP_PRIVATE, fd, 0);
        if (mem == MAP_FAILED)
        {
                perror("mmap");
               	return NULL;
        }
	ehdr = (Elf32_Ehdr *)mem;

	if(seginfo(mem, &seg, ehdr->e_phoff))
        {
                printf("exec: Could not locate loadable segments: text, data\n");
                return NULL;
        }
	int i;			
	linker = load_binary(mem, seg);
	return linker;
}

int unmap_current(int pid)
{
	int i, j, count = 0;
	FILE *fd;
	char buf[MAXBUF], line[MAXBUF]; 
	char *p, tmp[8];
	unsigned long start, end;
	
	sprintf(buf, "/proc/%d/maps", pid);
	
	if ((fd = fopen(buf, "r")) == NULL)
	{
		perror("fopen");
		return -1;
	}

	for (i = 0; i < (data_exists ? 3 : 1); i++)
	{
		fgets(line, MAXBUF, fd);
		p = line;
		
		for (j = 0; *p++ != '-'; j++)
			 tmp[j] = *p;
		start = strtoul(tmp, NULL, 16);
		
		for (j = 0; *p++ != ' '; j++)
			 tmp[j] = *p;
		end = strtoul(tmp, NULL, 16);

		munmap((void *)start, (long)(end - start));
			
	}
	return 0;
}
int xrand(int seed)
{
        srand(seed);
        return ((rand() % (8192 << 6)));
}

uint8_t *load_binary(uint8_t *mem, struct segments seg)
{
	uint8_t *p;
	uint32_t offset;
	unsigned long load;
	Elf32_Ehdr *ehdr; 

	//printf("load_binary(): seg.text: 0x%lx\n", seg.text);
	
	if (seg.text)
		p = mmap((uint8_t *)seg.text, seg.image_size, PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0);
	else
	        p = mmap((uint8_t *)seg.text, seg.image_size, PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

	if (p == MAP_FAILED)
	{
		perror("mmap");
		return NULL;
	}

	/* load text segment, copy text filesz */
	memcpy((uint8_t *)p, mem, seg.text_filesz);

	/* protect text segment which includes the page aligned padding */
	if (mprotect((uint8_t *)p, seg.text_memsz, seg.text_flags))
	{
		munmap(p, seg.image_size);
		return NULL;
	}
	
	if (data_exists)
	{
		offset = seg.data_pvaddr - seg.text_pvaddr;
		load = p + PAGEDOWN(offset);

		memcpy((uint8_t *)(p + offset), (mem + seg.data_poffset), seg.data_filesz);

		if (mprotect((uint8_t *)load, seg.data_memsz, seg.data_flags))
		{
			munmap(p, seg.image_size);
			return NULL;
		}

	}
	return p;
}

/* we temporarily save our stack arguments into a mmap'd region */
uint8_t * saveargs(int argc, char *argv[])
{
	uint8_t *mem, *mp;
	int size = 0, i = 0, tmp = argc;
	int j;

	while (tmp-- > 0)
		size += strlen(argv[i++]); 
	size += argc;

	argcnt = argc;
	arglen = size;

	mem = mmap(0x10000000, size + 12, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (mem == MAP_FAILED)
	{
		perror("mmap");
		return NULL;
	}

	mp = mem;
	j = 0;
	for (i = 0; i < argc; i++)
	{
		while(j < strlen(argv[i]))
			mem[j] = argv[i][j++];
		mem += strlen(argv[i]) + 1;
		j = 0;
	}
	return mp;
}

void * build_stack(uint8_t *saved_mem, uint8_t *bin_mem, Elf32_Ehdr *ld)
{
	char *s, *ptr, **argv, **envp, *arg;
	uint8_t *auxv;
	int i,  count = 0, argc = argcnt, len, auxlen;
	
	/* target executable */
	Elf32_Ehdr *exec = (Elf32_Ehdr *)bin_mem;
	
	/* entry point */
	void (*entry)();

	/* stack pointer */
	unsigned long *esp, *p;
	
	count += 4; 	   // argc
	count += argc * 4; // *argv[]
	count += 4;        // NULL 
	count += 4; 	   // *envp[]
	count += 4;	   // NULL
	count += arglen;   // length of ascii args
	/* Create room for AUXV if necessary */
	if (dynamic)
		count += AUX_COUNT * sizeof(Elf32_auxv_t);
	
	/* aligned padding */
	count = (count + 3) & ~3;
	
	/* length of auxv */
	auxlen = (dynamic ? (sizeof(Elf32_auxv_t) * AUX_COUNT) : 0);

	/* argv/envp are stored here */
	s = (char *)saved_mem;

	/* INITIALIZE STACK */ 
	uint8_t *mem = mmap((void *)0x20000000, STACK_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_GROWSDOWN|MAP_FIXED, -1, 0);
	if (mem == MAP_FAILED)
	{
		printf("mmap failed\n");
		exit(-1);
	}
	
	/* SET STACK POINTER */
	esp = mem + STACK_SIZE;
	esp -= count;
	p = esp;

	/*
	 -= diet glibc init looks like =-
	 pop %ecx		#argc
	 mov %esp, %esi 	#argv
 	 push %ecx		 

	 # next we put envp addr into %eax 
	 lea    0x4(%esi,%ecx,4),%eax 
 
	 # after the next 3 lines our stack looks like [argc, argv, envp] 
	 push %eax
	 push %esi
	 push %ecx  
	*/
	
	*esp++ = argc;
	arg = (char *)esp + (argc * 4) + 12;
	
	while (argc--) 
	{
		strcpy(arg, s); 
		len = strlen(s) + 1;
		s += len; *esp++ = arg;
		arg += len;
	} 

	/* here we setup our auxillary vector for the linker */
	if (dynamic)
	{
		auxv = esp;

		/* PAGE SIZE */
		*(long *)auxv++ = AT_PAGESZ;
		*(long *)auxv++ = 4096;
		
		/* PTR TO PROGRAM HEADER TABLE */
		*(long *)auxv++ = AT_PHDR;
		*(long *)auxv++ = (unsigned long)(Elf32_Ehdr *)exec + exec->e_phoff;
	
		/* SIZE OF PROGRAM HEADER ENTRIES */
		*(long *)auxv++ = AT_PHENT;
		*(long *)auxv++ = sizeof(Elf32_Phdr);
		
		/* NUMBER OF PROGRAM HEADERS */
		*(long *)auxv++ = AT_PHNUM;
		*(long *)auxv++ = exec->e_phnum;
		
		/* TARGET EXEC ENTRY POINT */
		*(long *)auxv++ = AT_ENTRY;
		*(long *)auxv++ = exec->e_entry;
		
		/* DO I HAVE TO SAY? */
		*(long *)auxv++ = AT_NULL;
		*(long *)auxv++ = 0;
	}
	
	/* for dynamic binaries our entry point is in the linker */
	/* otherwise we jump right into the target entry */
	if (ld)
                entry  = (void(*)())(ld + ld->e_entry);
        else
                entry = (void(*)())(exec->e_entry);
	
 	/* set our stack pointer and jump to target entry point */      	
	jmp_addr(p, entry);

	/* definately shouldn't get here */
}

/* To setup the heap we reset the program break with brk() */ 
int build_heap(uint8_t *mem)
{
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)mem;
	Elf32_Phdr *phdr = (Elf32_Phdr *)(mem + ehdr->e_phoff);
	int i;

	for (i = ehdr->e_phnum; i-- > 0; phdr++)
		if (phdr->p_type == PT_LOAD && phdr->p_offset)
			brk((uint8_t *)phdr->p_vaddr + phdr->p_memsz + 4096);
	return 0;
}
	
int userland_exec(char *filename, char *phrase, int argc, char **argv, int size)
{
	int fd;
	struct stat st;
	struct segments segment;
	uint8_t *mem, *link_mem, *args_mem, *bin_mem;
	void (*entry)();
	int ival, i, j, len;
	uint8_t *esp;
	uint32_t *key, *shifted;
	long fsize;

	Elf32_Ehdr *interpreter = NULL;
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	
	/* Elf headers for dynamic linker lib */
	
	if (phrase)
	{
		key = (uint32_t *) malloc(strlen(phrase) * sizeof(uint32_t));
		shifted = (uint32_t *)malloc(strlen(phrase) * sizeof(uint32_t));
	}

	if ((fd = open(filename, O_RDONLY)) == -1)
	{
		perror("binary open");
		exit(-1);
	}

	if (fstat(fd, &st) < 0)
	{
		perror("fstat");
		goto done;
	}
	
	/* lets map the executable into memory */
	mem = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED)
	{
		perror("mmap");
		goto done;
	}
	
	ehdr = (Elf32_Ehdr *)mem;
	phdr = (Elf32_Phdr *)(mem + ehdr->e_phoff);

	if (!phrase)
		goto no_decrypt;

	//printf("Decrypting text segment of %s\n", filename);
	fsize = (long)*(long *)&mem[8];
	
	printf("encrypted body: %d bytes\n", fsize);
	printf("pass phrase: %s\n", phrase);
	
	for (i = 0; i < strlen(phrase); i++)
	             key[i] = 0x1000 + xrand((int)phrase[i]);
	for (len = 0, i = 0; i < strlen(phrase); i++, len++)
               if (i)
                       shifted[i] = (key[i] << (key[i-1] + (3 & ~3)));
               else
                       shifted[i] = (key[i] << (key[i] + (3 & ~3)));
	j = 0;
        for (i = sizeof(Elf32_Ehdr); i < fsize; i++)
        {
               if (j % 4)
                       mem[i] = mem[i] ^ (shifted[j++] >> (key[j-1] & ~3));
               else
                       mem[i] = mem[i] ^ (shifted[j++] << (key[j-1] & ~2));
               if (j >= len)
              	 j = 0;
        }
	/* we skipped decryption */
	no_decrypt:
	/* retreive information about loading the segments */ 
	if(seginfo(mem, &segment, ehdr->e_phoff))
	{
		printf("exec: Could not locate loadable segments: text, data\n");
		goto done;
	}

		/* find the interpreter for dynamic linking */
	ival = get_interp(mem, ehdr->e_phoff);

	if (unmap_current(getpid()) == -1)
	{
		printf("Unable to unmap current segments\n");
		goto done;
	}
	if (!ival)
		if ((link_mem = load_linker(interp)) == NULL)
		{
			printf("exec: Unable to load %s\n", interp);
			goto done;
		}
		else
			interpreter = (Elf32_Ehdr *)link_mem;
	if (interpreter)
		printf("Interpreter is at: %lx\n", interpreter + interpreter->e_entry);

	/* load the main binary into memory */
	if ((bin_mem = load_binary(mem, segment)) == NULL)
	{
		printf("exec: Unable to load binary\n");
		goto done;
	}
	ehdr = (Elf32_Ehdr *)bin_mem;
	phdr = (Elf32_Phdr *)(bin_mem + ehdr->e_phoff);

	if (data_exists)
		if (build_heap(bin_mem) == -1)
		{
			printf("exec: Unable to setup heap\n");
			goto done;
		}
	
	/* save the exec args until we setup our stack */
	if ((args_mem = saveargs(argc, argv)) == NULL)
	{
		printf("exec: Unable to save args\n");
		goto done;
	}

	if (build_stack(args_mem, bin_mem, interpreter) == -1)
	{
		printf("exec: Unable to setup stack\n");
		goto done;
	}

	if (interpreter)
		entry  = (void(*)())(interpreter + interpreter->e_entry);
	else
		entry = (void(*)())(entry);

	done:
	/* shouldn't get here! */
	close(fd);
	munmap(mem, size);
	exit(0);
}
