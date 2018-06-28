#include "elfmod.h"
#include <dirent.h>

char * GetTypeName(char *path, char *type)
{
	int fd;
	struct stat st;
	uint8_t *mem;
	Elf32_Ehdr *ehdr;

	if ((fd = open(path, O_RDONLY)) == -1)
		return NULL;
	
	if (fstat(fd, &st) < 0)
		return NULL;
	
	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED)
		return NULL;
	
	ehdr = (Elf32_Ehdr *)mem;	
	if (ehdr->e_ident[0] != 0x7f && strcmp(&ehdr->e_ident[1], "ELF"))
		return NULL;
		
	switch (ehdr->e_type)
	{
	case ET_EXEC:
		strcpy(type, "ET_EXEC");
		break;
	case ET_REL:
		strcpy(type, "ET_REL");
		break;
	case ET_DYN:
		strcpy(type, "ET_DYN");
		break;
	case ET_CORE:
		strcpy(type, "ET_CORE");
		break;
	case ET_NONE:
		strcpy(type, "ET_NONE");
		break;
	}
	
	munmap(mem, st.st_size);
	close(fd);
	return type;
}

int GetType(char *path)
{
        int fd, tmp;
        struct stat st;
        uint8_t *mem;
	Elf32_Ehdr *ehdr;

        if ((fd = open(path, O_RDONLY)) == -1)
                return -1;

        if (fstat(fd, &st) < 0)
                return -1;

        mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (mem == MAP_FAILED)
                return -1;

        ehdr = (Elf32_Ehdr *)mem;
	if (ehdr->e_ident[0] != 0x7f && strcmp(&ehdr->e_ident[1], "ELF"))
		return -1;

	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN &&
	    ehdr->e_type != ET_REL && ehdr->e_type != ET_CORE && ehdr->e_type != ET_NONE)
		return -1;
	
	tmp = ehdr->e_type;
	munmap(mem, st.st_size);
	close(fd);

        return (tmp);
}

int
lsdir (char *Dir)
{
	int fd, i, bpos, nread;
	DIR *dd;
	char name[64];
	struct stat st;
	struct dirent *d;
	char path[MAXSTR * 2] = {0};
	char dir[MAXSTR];

	strncpy(dir, Dir, MAXSTR-2);
	if (dir[strlen(dir) - 1] != '/')
		dir[strlen(dir) - 1] = '/';
	
	if ((dd = opendir(dir)) == NULL)
		if (errno == ENOTDIR)
		{
			if ((fd = open(dir, O_RDONLY)) == -1)
				return -1;
			fstat(fd, &st);
			if ((st.st_mode & S_IFMT) == S_IFREG)
				if(GetType(dir) != -1)
				{
					printf("[%s]-> %s\n", GetTypeName(dir, name), dir);
					return 0;
				}
		}
	 	else
			return -1;

		while((d = readdir(dd)) != NULL)
		{
			strncpy(path, dir, MAXSTR-1);
			strncat(path, d->d_name, MAXSTR-1);	
			if (GetType(path) != -1)
			{
				if (strcmp(GetTypeName(path, name), "ET_EXEC") == 0)
				{
					if (path[0] == '.' && path[1] == '/')
						printf("[%s%s%s]\t%s\n", GREEN, GetTypeName(path, name), END, &path[2]);
					else
						printf("[%s%s%s]\t%s\n", GREEN, GetTypeName(path, name), END, path);
				}
				else
			        if (strcmp(GetTypeName(path, name), "ET_REL") == 0)
                                {
                                        if (path[0] == '.' && path[1] == '/')
                                                printf("[%s%s%s]\t%s\n", RED, GetTypeName(path, name), END, &path[2]);
                                        else
                                                printf("[%s%s%s]\t%s\n", RED, GetTypeName(path, name), END, path);
                                }
				else
				if (strcmp(GetTypeName(path, name), "ET_DYN") == 0)
                                {
                                        if (path[0] == '.' && path[1] == '/')
                                                printf("[%s%s%s]\t%s\n", BLUE, GetTypeName(path, name), END, &path[2]);
                                        else
                                                printf("[%s%s%s]\t%s\n", BLUE, GetTypeName(path, name), END, path);
                                }


			}
			else
				continue;
		}
	
	close(fd);
	closedir(dd);
	return 0;
}
