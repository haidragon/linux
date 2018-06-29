

int vmsg(int type, char *fmt, ...)
{
	FILE *fd;

	va_list va;
	va_start (va, fmt);
 	
	vfprintf (stdout, fmt, va);
 	va_end (va);
 
	return 0;
}

