#include "avu.h"


int ptrace_open(int pid)
{
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL))
		return -1;
}

int ptrace_write(int pid, void *dst, const void *src, size_t len)
{
        int sz = len / sizeof(void *);
        unsigned char *s = (unsigned char *)src;
        unsigned char *d = (unsigned char *)dst;

        while (sz-- != 0)
        {
                if (ptrace(PTRACE_POKEDATA, pid, d, *(void **)s) == -1)
                        return -1;
                s += sizeof(void *);
                d += sizeof(void *);
        }
        
        return 0;
}

int ptrace_read(int pid, void *dst, const void *src, size_t len)
{
        
        int sz = len / sizeof(void *);
        unsigned char *s = (unsigned char *)src;
        unsigned char *d = (unsigned char *)dst;
        long word;

        while (sz-- != 0)
        {
                word = ptrace(PTRACE_PEEKDATA, pid, s, NULL);
                if (word == -1 && errno)
                        return -1;
                *(long *)d = word;
                s += sizeof(long);
                d += sizeof(long);
        }

        return 0;
}

void ptrace_close(int pid)
{
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

