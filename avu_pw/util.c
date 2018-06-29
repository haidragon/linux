/*
 * Quarantine files using password protected zips.
 * <ryan@Bitlackeys.com>
 */


#include "avu.h"

void mkzip_dir(uid_t uid, gid_t gid)
{
	mkdir(ZIPDIR, 775);
	if(chown(ZIPDIR, uid, gid) == -1)
		perror("chown");

}

int quarantine(char *path, char *filename)
{
	FILE *pd;
	char s[255];
	char cmd[80];
	char zip[170];
	int ret;

	strncpy(cmd, ZIP, sizeof(cmd) - strlen(AUTH) - 1);
	strcat(cmd, AUTH);

	strncpy(zip, ZIPDIR, sizeof(zip) - 1);

	if (strlen(filename) > sizeof(zip) - (strlen(ZIPDIR) + 3))
		return 0;

	strcat(zip, filename);
	strcat(zip, ".zip");

	snprintf(s, sizeof(s)-1, "%s %s %s", cmd, zip, path);
	
	ret = system(s);
	if (ret == 127 || ret == -1)
		return 0;
	return 1;

}

	

		
	
