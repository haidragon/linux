#include <sys/syscall.h>

 
int _write (int fd, void *buf, int count)
{
  long ret;
 
  __asm__ __volatile__ ("pushl %%ebx\n\t"
                        "movl %%esi,%%ebx\n\t"
                        "int $0x80\n\t" "popl %%ebx":"=a" (ret)
                        :"0" (SYS_write), "S" ((long) fd),
                        "c" ((long) buf), "d" ((long) count));
  if (ret >= 0) {
    return (int) ret;
  }
  return -1;
}

int evil_func(void)
{
	_write(1, "HAHA puts() has been hijacked bitch!\n", 37);
	//puts("hi\n");
}


