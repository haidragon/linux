#include "elfmod.h"

struct cmd_list * add_cmd(char *cmd, struct cmd_list **root)
{
	struct cmd_list *tmp;
	
	if ((tmp = malloc(sizeof(struct cmd_list))) == NULL)
        {
                perror("malloc");
                exit(-1);
        }
	
	strncpy(tmp->cmd, cmd, sizeof(tmp->cmd));
	tmp->cmd[sizeof(tmp->cmd) - 1] = '\0';
	
	tmp->next = *root;
	*root = tmp;
	return *root;
}

struct elf_list * add_elf(char *name, struct elf_list **root)
{
        struct elf_list *tmp;
	
	if ((tmp = malloc(sizeof(struct elf_list))) == NULL)
	{
		perror("malloc");
		exit(-1);
	}

	strncpy(tmp->name, name, sizeof(tmp->name));
	tmp->name[sizeof(tmp->name) - 1] = '\0';

	if(LoadElf(name, MAP_SHARED, PROT_READ|PROT_WRITE, 0, 0, &tmp->elf) == -1)
        {
                printf("Could not load %s\n", name);
                return NULL;
        }

        tmp->next = *root;
        *root = tmp;
	return *root;
}

struct elf_list * Reload_ElfLink(struct elf_list **current)
{
	struct elf_list *tmp;

	/* lets unload the elf descriptor so we can reload */
	/* and get a copy of the updated file */
	ElfReload(&(*current)->elf);
	return *current;
}
	
int remove_elf(struct elf_list **current)
{
	struct elf_list *tmp;
	
	if (current != NULL)
	{
		UnloadElf(&(*current)->elf);
		tmp = (*current)->next;
		free(*current);
		*current = tmp;
		return 1;
	}
	return 0;
}

int unload_all(struct elf_list **current)
{
        struct elf_list *tmp;
	
	if (current)
       		while (*current != NULL)
        	{
			UnloadElf(&(*current)->elf);
               		tmp = (*current)->next;
               	 	free(*current);
                	*current = tmp;
        	}
        return 0;
}
		
struct elf_list ** search_by_name(char *name, struct elf_list **current)
{
	while(*current != NULL)
	{
		if (strcmp((*current)->name, name) == 0)
			return current;
		current = &(*current)->next;
	}
	return NULL;
}

			
	
