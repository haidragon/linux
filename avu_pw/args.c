#include "avu.h"

/* My Special little parse function modified slightly */
/* For creating an argument vector for execlp() */

int ExecVector(char ***argvp, char *delim, char *s)
{

        int tokens;
        char *t, *snew;

        snew = s + strspn(s, delim);

        if ((t = calloc (strlen (snew) + 1, sizeof (char))) == NULL)
        {
                *argvp = NULL;
                tokens = -1;
        }
        else
                strcpy(t, snew);


        if (strtok(t, delim) == NULL)
                tokens = 0;
        else
                for (tokens = 1; strtok(NULL, delim) != NULL; tokens++)
                        ;

        if ((*argvp = calloc(tokens + 3, sizeof(char *))) == NULL)
                tokens = -1;
        else
        if (tokens > 0)
        {

                bzero(t, strlen(snew));
                strcpy(t, snew);
                **argvp = strtok(t, delim);
                int i;
                for (i = 1; i < tokens + 1; i++)
                        *((*argvp) + i) = strtok(NULL, delim);
                *((*argvp) + i) = NULL;
        }
        else
                **argvp = NULL;

        return tokens;

}

char *MakeString(char **argv, int argc, char *string)
{
	int i;
		
	for (i = 0; i < argc; i++)
	{
		printf("attaching %s to %s\n", argv[i], string);
		strcat(string, argv[i]);
	}
	return string;
}

