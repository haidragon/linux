#include "elfmod.h"

#define COMMENT NULL

enum code_properties {
	VARIABLE_ASSIGNMENT,
	VARIABLE_DECLARATION,
	QUENYA_FUNCTION,
	FUNCTION_PARSE_ERROR,
	LOOP,
	ARRAY_ASSIGNMENT,
	ARRAY_FILE_OBJECT,
	INTERNAL_METHOD,
	VOID_ATTRIBUTE
};

struct code_nature {
	int exceptions;
	enum code_properties properties;
};

enum method_types {
	PRINT,
	SHOW_FUNC_OUTPUT,
	FILE_OBJECT,
	CALL_FUNC
};

struct internal_method {
	enum method_types type;
	char method_name[256];
};

			
