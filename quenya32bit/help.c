#include "elfmod.h"

void command_list(void)
{
	printf("Quenya v0.1 command list: \n");
	printf("For a description of each command, type the command without arguments\n\n"
	       "\n- Injection / Relocation --\n"
	       "  inject <target> <source> <start> <stop> 'METHOD' --nojmp (Optional)\n"
	       "  reloc <source> <target> (Same as 'inject' but adds complete relocation of symbols)\n"
	       "\n- SHT/Section modification --\n"
	       "  addsect <target> <index> <name> <size> <type>\n"
	       "  sht <target> - sub commands:\n"
	       "  	sht <target> list sym/rel/dyn\n"
	       "	sht <target> add sym/rel/dyn <name> <value>\n"
	       "	sht <target> mod sym/rel/dyn <name> <value>\n"
	       "	sht <target> randstrtab <opts>\n" 
	       "	sht list types\n"
	       "\n- PHT/Program Header modification\n" 
               "  addseg <target> <index> <offset> <filesz>  <memsz> <vaddr> <paddr> <flags> <type>\n"
	       "  pht <target> - sub commands:\n"
	       "  	pht <target> list phdr <index>\n"
 	       "	pht <target> mod phdr <index>\n"
	       "\n - ELF Header (ehdr) modification --\n"
	       "  entry <target> <entry_point>\n"
	       "  shnum <target> <shnum>\n"
	       "  phnum <target> <phnum>\n"
	       "  version <target> <version>\n"
	       "  machine <target> <machine>\n"
	       "  etype <target> <type>\n" 
	       "\n - Function hijacking (ET_REL or PLT\GOT)\n"
	       "  hijack <mode ('binary' or 'process')> <binary/pid> <newfunc> <oldfunc>\n"
	       "\n- Reverse Engineering\n"
	       "  disas <target> <symbol/vaddr> <# of lines>\n"
	       "  ow <target> <vaddr/offset> <data> <size> (byte,word,dword)\n"
	       "  fill <target> <vaddr/offset> <data> <length> (byte,word,dword)\n\n"
	       "  (Advanced Functions) \n"
	       "  rebuild <PID> <output executable>\n"
	       "  ul_exec <target> \n"
	       "  pack <executable> <unique key>\n"
	       "  unpack <executable> <output_exec>\n"
	       "\n - Global variable adjustments\n"
	       "  debug=<value> (Print debug output)\n"
	       "  force_elf=<value> (Force loading of ELF objects)\n\n"); 

}

void help(int topic)
{
	switch(topic)
	{
	case LOAD_HELP:
		printf("Command 'load' will load the target ELF object into memory, this command is presently unnecessary\n"
		       "Usage: load <target>\n");
		break;
	case UNLOAD_HELP:
		printf("Command 'unload' will unload the target ELF object from memory, this command is presently unnecessary\n"
		"Usage: unload <target>\n");
		break;
	case RELOC_HELP:
		printf("Command 'reloc' will inject and relocate the source ET_REL file into the target ET_EXEC\n"
	       "Usage: reloc <source> <target>\n");
		break;
	case INJECT_HELP:
		printf("Command 'inject' will inject the source object (EXEC,REL,DYN) code specified by the address/offset\n"
		"range start/stop, into the target file (Generally ET_EXEC). The payload code will be patched with jmp\n"
		"code that will return to the original entry point of the executable. The following methods may be used\n"
		"TEXT_PADDING_INJECTION, TEXT_ENTRY_INJECTION, DATA_SEGMENT_INJECTION\n"
		"Usage: inject <target> <source> <start> <stop> 'METHOD' --nojmp (Optional for no jmp code)\n");
		break;
	case ADDSECT_HELP:
		  printf("Command 'addsect' will add a section to a target ELF file at a chosen index\n"
			 "The section will not contain any data. Command 'sht list types' to see section_types\n"
                         "addsect <target_file> <section_index> <section_name> <section_size> <section_type>\n\n");

		break;
	case ENTRY_HELP:
		printf("Command 'entry' will modify the entry point address of an ELF object (ehdr->e_entry)\n"
		       "entry <target> <entry_point>\n\n");
	break;
	case SHNUM_HELP:
		printf("Command 'shnum' will modify the shnum field of an ELF object (ehdr->e_shnum)\n"
		       "shnum <target> <shnum>\n\n");
	break;
	case PHNUM_HELP:
		 printf("Command 'phnum' will modify the phnum field of an ELF object (ehdr->e_phnum)\n"
                       "phnum <target> <phnum>\n\n");
	break;

	case VERSION_HELP:
		printf("Command 'version' will modify the version field of an ELF object (ehdr->e_version)\n"
			"version <target> <version>\n");
	break;
	case MACHINE_HELP:
		printf("Command 'machine' will modify the machine field of an ELF object (ehdr->e_machine)\n"
			"machine <target> <machine>\n");
	break;
	case ETYPE_HELP:
		 printf("Command 'etype' will modify the type field of an ELF object (ehdr->e_type)\n"
                        "etype <target> <machine>\n");
	break;
	case DISAS_HELP:
		printf("Command 'disas' will disassemble a given symbol in the target ELF object\n"
		       "disas <target> <symbol>\n");
	break;
	case REBUILD_HELP:
		printf("Command 'rebuild' will rebuild a process image into an ELF executable\n"
		       "rebuild <pid> <output_exec>\n");
	break;
	case HIJACK_HELP:
		printf("Command 'hijack' will allow you to hijack a function so that the replacement\n"
			"function is called instead. The replacement function is either present through\n"
			"ET_REL injection (on disk) which is done using the 'reloc' command which updates\n"
			"the target symbol table. In this case, the mode arg should be 'disk' and the type arg\n"
			"should be 'rel'. The other option is using type 'plt' which only works on\n"
			"hijacking shared library calls, but can be used in mode 'disk' or mode 'memory' in \n"
			"which case you can perform shared object injection on a process. If you want the new\n"
			"function to call the original function once done, then select 'call_orig=YES', otherwise NO.\n"
			"you may use 'grsec' as a final argument if the target process has grsec mprotect restrictions\n"
			"in which case the shared object injection will not work unless the special 'grsec' arg is\n"
			"included. Note: It will only work of grsec has not disabled ptrace()\n");
		break;		
	case OVERWRITE_HELP:
		printf("Command 'ow' will allow you to overwrite a specified memory location with given value that\n"
		       "that is specified in hexadecimal. You may specify that this value is to be a byte, word, or dword\n"
		       "ow <target> <vaddr/offset> <data> <type> (byte,word,dword)\n"
		       "example: ow testprog 0x8048b30 0x0 dword\n");
		break;
	case FILL_HELP:
		printf("Command 'fill' will allow you to fill a specified memory region starting at <vaddr/offset> for <length>\n"
		       "amount of <size>, where size is either a byte, a word, or a dword\n"
		       "fill <target> <vaddr/offset> <data> <length> <type> (byte,word,dword)\n"
		       "example: fill testprog 0x8049ff0 0x0 16 byte\n");
		break;
	}
}


	
