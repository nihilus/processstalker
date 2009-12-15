#include <stdio.h>
#include <stdarg.h>

#include "..\log.hpp"

#include "lex.h"
#include "parse.h"
#include "tracedefs.hpp"



unsigned short Tracer_Type_Size[] = { 4, 4, 4, 4, 4, 4, 4, 4, 4 }; 


Logger *lg = NULL;
int errors = 0;

// Function called by the parser when an error occurs while parsing
// (parse error or stack overflow)
void yyerror(char *msg) {
	errors++;

	if ( NULL != lg)
		lg->append(LOG_ERROR,"line %u: %s\n",lineno,msg);
}

// This function is called by the lexer when the end-of-file
// is reached; you can reset yyin (the input FILE*) and return 0
// if you want to process another file; otherwise just return 1.
extern "C" int yywrap(void) {
  return 1;
}

char *GetTypeName(t_Tracedef_Ctype t) {
	switch (t) {
	case tr_VOID:		return "void";
	case tr_PVOID:		return "void*";
	case tr_INT:		return "int";
	case tr_PINT:		return "int*";
	case tr_CHAR:		return "char";
	case tr_PCHAR:		return "char*";
	case tr_PFMTCHAR:	return "fmtchar*";
	case tr_PWCHAR:		return "wchar*";
	case tr_PFMTWCHAR:	return "fmtwchar*";
	default:			return "UNKNOWN???";
	}
}

char *GetDirName(t_Tracedef_Direction d) {
	switch(d) {
	case in:	return "[in]";
	case out:	return "[out";
	case both:	return "[both]";
	default:	return "";
	}
}

// The main program: just report all tokens found
bool LoadTraceDef (Logger *l, char *filename)  {
	
	//
	// Assign logger instance pointer, so the parser stuff
	// can log the same way we do
	//
	lg = l;

	errors=0;
	if ( NULL == (yyin = fopen(filename,"rt")) ){
		lg->append(LOG_ERROR,"LoadTraceDef(): Could not open file '%s'\n",
			filename);
		return false;
	}

	TraceDefinitions.clear();

	yyparse (); // call the parser

	lg->append(LOG_DEBUG,"%u Trace definitions from '%s' loaded\n",
		TraceDefinitions.size(),filename);

	return errors ? false : true;
}

