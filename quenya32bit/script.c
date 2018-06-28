/*
 * This source file contains an add-on to Quenya that allows
 * for reasonably flexible scripting support.
 */
#include "script.h"

struct line_element {
	char *line;
	struct {
		int assignment;
		int declaration;
		int function;
		int loop;
		int file;
		int method;
	} nature;
	
	uint8_t **string; /* Array of strings */
	int *integer;

	struct line_element *next;
	struct line_element *prev;	
	
};

struct elfobj {
	Elf32_Phdr phdr[256]; 
	Elf32_Shdr shdr[256]; 
	Elf32_Ehdr ehdr;
	
	Elf32_Addr *GOT; //global _offset_table 
	
};
typedef struct elfobj elfobj;
typedef struct line_element element;


/*
 * Internal methods are different than functions.
 * methods relate to scripting language specific
 * functions. Whereas actual functions are Quenya
 * features and are called by an internal method
 * that in turn will call a quenya function.
 * The internal method 'function' allows one to
 * call a Quenya function.
 */
struct internal_method internal_method[] = {
	
	{PRINT, 	   "print"},
	/*
	 * Internal method to print strings
	 * that do not originate from Quenya.
	 */
	
	{SHOW_FUNC_OUTPUT, "show_func_output"},
	/*
	 * Internal method to print the output
	 * of a Quenya function.
	 */

	{FILE_OBJECT, 	   "file"},
	
	/*
	 * An internal method to a files contents
	 * into an array, as well as file object
	 * data.
	 */
	{CALL_FUNC,	   "function"} 
	/*
	 * An internal method to invoke a quenya
	 * function.
	 */
	
};
	
void add_to_front(element *new, element **root)
{
        element *tmp = (element *)malloc(sizeof(element));
        element *current = *root;

        if (current)
                while (current->prev != NULL)
                        current = current->prev;

        tmp->next = current;
        *root = current;
        (*root)->prev = tmp;
}

void add_to_back(element *new, element **root)
{
        element *tmp = (element *)malloc(sizeof(element));
        element *current = root;

        if (current)
                while (current->next != NULL)
                        current = current->next;
        tmp->prev = current;
        *root = current;
        (*root)->next = tmp;
}

int check_file_object(char *line) 
{
	char *p;

	if (!strstr(line, "file"))
		return 0;
	
	if (strchr(line, '(') != NULL) 
		return 1;
	
	/* The string has 'file' in it 
	 * but does not contain syntax
	 * that suggests an array of a file object.	
	 */
	return 0;
		
}

/*
 * This function simply determines the nature of
 * the line of code. I.E is it an internal method
 * or is it a variable declaration, loop, etc.
 */
int determine_code_type(struct code_nature *code, char *line)
{
	char *p;
	char *s;
	int i;

	/* Find our first character */
	for (p = line; *p == 0x20; p++) 
		;
	if (*p == '\0')
		return -1;

	code->properties = VOID_ATTRIBUTE;

	switch(*p) {
		case '@':
			if (check_file_object(line) > 0) {
				code->properties = ARRAY_FILE_OBJECT;
				break;
			}
			code->properties = ARRAY_ASSIGNMENT;
			break;
		case '(':
			if (strchr(line, ')')) {
				code->properties = QUENYA_FUNCTION;
				break;
			}
			code->properties = FUNCTION_PARSE_ERROR;
			break;
	}
	if ((p = strchr(line, '='))) {
		p += 1;
		if (*p == 0x20) {
			while (*p != '\0') {
				p++;
				if (*p && *p != 0x20) {
					code->properties = VARIABLE_ASSIGNMENT;
					break;
				} 
			}
		} else {
			if (*p != '\n' && *p != '\0')
				code->properties = VARIABLE_ASSIGNMENT;
		}
	}
	for (p = line; *p != '\0' && *p != '\n'; p++) {
		if (strncasecmp(p, "while", 5) == 0) {
			code->properties = LOOP;
			break;
		}
	}

	if (code->properties == VOID_ATTRIBUTE) {
		for (i = 0; i < 4; i++)
			if (strstr(line, internal_method[i].method_name))
				code->properties = INTERNAL_METHOD;
	}

	if (code->properties == VOID_ATTRIBUTE)
		return -1;

	return 0;

}

char * ParseScriptSyntax(char *line)
{
	char *l, *r, *p; 
	int i, j, ret;
	struct code_nature nature = {0};
	
	element *root;
	element *element_new;

	static int lno = 0; /* Line number */
	
	for (p = line; *p == 0x20; p++)
		;
	if (*p == '#') 
		return COMMENT;

	r = determine_code_type (&nature, line);
	switch (nature.properties) {
		case VARIABLE_ASSIGNMENT:
				handle_assign_variable(element_new, &root, line);
				break;
		case QUENYA_FUNCTION:
				handle_quenya_function(element_new, &root, line);
				break;
		case FUNCTION_PARSE_ERROR:
				handle_parse_error(line);
				break;
		case LOOP:
				handle_loop_condition(element_new, &root, line);
				break;
		case ARRAY_ASSIGNMENT:
				handle_array_assignment(element_new, &root, line);
				break;
		case ARRAY_FILE_OBJECT:
				handle_array_file_object(element, &root, line);
				break;
		case INTERNAL_METHOD:
				handle_internal_method(element, &root, line);
				break;
		case VOID_ATTRIBUTE:
				handle_void_attribute(element, &root, line);
				break;
	}

	/* Increase the line count */
	lno++;
	
	
} 
