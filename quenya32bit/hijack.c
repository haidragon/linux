

/*
 * This bit of code is pretty straightforward but only works on 
 * some 90% of the boxes I've tried it on. I'm fairly certain something
 * in glibc has changed on newer versions. More experimentation is required.
 * -ElfMaster
 */

#include "elfmod.h"

extern int global_debug;
int hijack_function(Elf32mem_t *target, int mode, unsigned long new_vaddr, char *function)
{
	int i;
	uint8_t *mem;
	unsigned long got_entry = 0;
	Elf32_Dyn *dyn;
	struct linking_info *lp;

	switch(mode)
	{
	case BINARY_MODE_HIJACK:
		printf("Attempting to hijack function: %s\n", function);

		for (i = 0; i < target->ehdr->e_phnum; i++)
			if (target->phdr[i].p_type == PT_DYNAMIC)
			{
				 dyn = (Elf32_Dyn *)(target->mem + target->phdr[i].p_offset);
                        	 break;
                	}
		if ((lp = (struct linking_info *)get_plt(target->mem)) == NULL)
        	{
               		printf("Unable to get GOT/PLT info, failure...\n");
               		return -1;
        	}
		for (i = 0; i < lp[0].count; i++)
              		if (strcmp(lp[i].name, function) == 0)
               		{
				got_entry = target->data_offset + lp[i].r_offset - target->data_vaddr;
				if (global_debug)
					printf("GOT Offset for %s: 0x%x\n", lp[i].name, got_entry);
				break;
			}
		if (got_entry == 0)
			return -1;
		printf("Modifying GOT entry for %s\n", function);
		*(unsigned long *)&target->mem[got_entry] = new_vaddr;
		return 0;
	}

}	
					
	
