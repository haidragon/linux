#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>

int check_serial(char val)
{
	int ret;
	if (val != 'a')
		ret = -1;
	else
		ret = 0;
	return ret;
}

int main(void)
{
	char buf[20];
	int val;
	printf("Please enter serial number: ");
	val = getchar();
	int ret;
	if ((ret = check_serial(val)) == -1)
	{
		printf("Invalid serial number, exiting...\n");
		exit(0);
	}
	printf("\n\nWelcome to the software!!!\n\n");
	exit(0);
}

