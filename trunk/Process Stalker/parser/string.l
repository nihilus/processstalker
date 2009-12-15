/* Lexical analyzer for Parser for Prototype Declarations and commands */

%{

/* ------------------------------------------------------------------
   Initial code (copied verbatim to the output file)
   ------------------------------------------------------------------ */

// Includes
#include <string.h>   // strcpy, strncpy
#include <io.h>       // isatty
#ifdef MSVC
#define  isatty _isatty  // for some reason isatty is called _isatty in VC..
#endif

#define  _LEX_CPP_   // make sure our variables get created
#include "lex.h"
#include "parse.cpp.h"

extern "C" { int yywrap (); } // the yywrap function is declared by the caller

// Forward references
void Identifier ();
void StringConstant ();
void EatComment ();

//// End of inititial code
%}

/* ------------------------------------------------------------------
   Some macros (standard regular expressions)
   ------------------------------------------------------------------ */

LETTER   [a-zA-Z_]
DIGIT    [0-9]
HEXDIGIT [0-9a-fA-F]
HEXVAL   0x{HEXDIGIT}({HEXDIGIT})*
IDENT    {LETTER}({LETTER}|{DIGIT})*
MODIDENT {LETTER}({LETTER}|{DIGIT}|\.)*
STR      \"[^\"]*\"
WSPACE   [ \t]+


/* ------------------------------------------------------------------
   The lexer rules
   ------------------------------------------------------------------ */
%%

"char"		{return CT_CHAR;}
"int"		{return CT_INT; }
"void"		{return CT_VOID;}
"fmtchar"	{return CT_FMTCHAR; }
"wchar"		{return CT_WCHAR; }
"fmtwchar"	{return CT_FMTWCHAR; }

"in"	{return DIR_IN; }
"out"	{return DIR_OUT;}
"both"	{return DIR_BOTH;}

"__cdecl"		{ return CALL_CDECL; }
"__fastcall"	{ return CALL_FASTCALL; }
"__stdcall"		{ return CALL_STDCALL; }

"="		{return '=';}
"=="	{return EQUAL;}
","		{return ',';}
";"		{return ';';}
":"		{return ':';}
"("		{return '(';}
")"		{return ')';}
"{"		{return '{';}
"}"		{return '}';}
"["		{return '[';}
"]"		{return ']';}
"*"		{return '*';}

{IDENT}  {Identifier ();             /* identifier: copy name */
          return ID;}
{HEXVAL} { Identifier(); 
          return HEXID; }
{MODIDENT} { Identifier ();
			 return MODID; }
{STR}    {StringConstant ();         /* string constant: copy contents */
          return STRING;}
"//"     {EatComment();}             /* comment:    skip */
\n       {lineno++;}                 /* newline:    count lines */
{WSPACE} {}                          /* whitespace: (do nothing) */
.        {return ERROR_TOKEN;}       /* other char: error, illegal token */

%%

/* ------------------------------------------------------------------
   Additional code (again copied verbatim to the output file)
   ------------------------------------------------------------------ */

// The comment-skipping function: skip to end-of-line
void EatComment()  {
	char c;

   while ((c = yyinput()) != '\n' && c != 0);
	lineno++;
}

// Pass the id name
void Identifier ()  {
   yylval.str = new char[strlen(yytext)+1];
   strcpy (yylval.str, yytext);
}

// Pass the string constant
void StringConstant()  {
   int l = strlen(yytext)-2;
   yylval.str = new char[l+1];
   strncpy (yylval.str, &yytext[1], l); yylval.str[l] = 0;
}
