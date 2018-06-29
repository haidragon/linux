/*
 * In this case we are patching our push/ret shellcode at the first
 * byte so return_entry_start = 1, but modify this to whatever offset
 * into the shellcode your 'push $entry_point; ret' starts at. (To jmp back to original entry point)
 */
int return_entry_start = 1;


char parasite[] =
	"\x68\x00\x00\x00\x00"      
	"\xc3";             
;
