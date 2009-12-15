/* Parser for Prototype Declarations and commands */

%{

/* ------------------------------------------------------------------
   Initial code (copied verbatim to the output file)
   ------------------------------------------------------------------ */

// Includes
#include <malloc.h>  // _alloca is used by the parser
#include <string.h>  // strcpy

#include "lex.h"     // the lexer

// Some yacc (bison) defines
#define YYDEBUG 1	      // Generate debug code; needed for YYERROR_VERBOSE
#define YYERROR_VERBOSE // Give a more specific parse error message 

// Forward references
void yyerror (char *msg);



//
// This is used for the C-Style Flex/Yacc code -> C++ code transition 
//
#include <string>
#include <vector>
#include <stack>

using namespace std;

#include "tracedefs.hpp"

t_Tracevector			TraceDefinitions;

//
// END transition code
//

//
// Temporary Variables for use in the sub-expressions
// while parsing. This is ugly, but nobody said I'm a 
// coder.
//
t_Tracedef_Def				TT;

stack<t_Tracedef_Ctype>			TempArgs;
stack<t_Tracedef_Direction>		TempDirs;
stack<string>					TempNames;

t_Tracedef_Ctype			RetType;
string						RetMatch = "";
t_Tracedef_Ctype			TempType;
string						TempName  = "";
string						TempName2 = "";
string						TempMatch = "";
string						TempMod = "";
t_Tracedef_Direction		TempDir = unknown;
t_Tracedef_Callconv			TempCall = CV_CDECL;

void ClearTempArgs() {
	while (!TempArgs.empty()) TempArgs.pop();
	while (!TempDirs.empty()) TempDirs.pop();
	while (!TempNames.empty()) TempNames.pop();
}

void ReInitTemps() {
	RetMatch = "";
	TempMatch = "";
	TempName = "";
	TempMod = "";
	TempName2 = "";
	TempDir = unknown;
	TempCall = CV_CDECL;
}

%}

/* ------------------------------------------------------------------
   Yacc declarations
   ------------------------------------------------------------------ */

/* The structure for passing value between lexer and parser */
%union {
   char *str;
}

%token ERROR_TOKEN  
%token EQUAL
%token CT_CHAR
%token CT_INT
%token CT_VOID
%token CT_FMTCHAR
%token CT_WCHAR
%token CT_FMTWCHAR
%token DIR_IN
%token DIR_OUT
%token DIR_BOTH
%token CALL_CDECL
%token CALL_FASTCALL
%token CALL_STDCALL

%token <str> ID STRING HEXID MODID

%expect 1  
           
%%

/* ------------------------------------------------------------------
   Yacc grammar rules
   ------------------------------------------------------------------ */

program
		: statement_list
		;

statement_list
      : statement_list statement
      | /* empty */
      ;

statement
      : ';'				{ /* ignore */ }
	  | return_expression name_expression '('  ')' ';'						{

						TT.Args.clear();
						TT.Return = RetType;
						TT.ReturnMatch = RetMatch;
						TT.Name = TempName2;
						TT.Module = TempMod;
						TT.CallConv = TempCall;
						TraceDefinitions.push_back(TT);
						
						ReInitTemps();
						ClearTempArgs();
						}
      | return_expression name_expression '(' arguments_expression ')' ';'	{
						t_Tracedef_Argument			ag;

						TT.Args.clear();
						TT.Return = RetType;
						TT.ReturnMatch = RetMatch;
						TT.Name = TempName2;
						TT.Module = TempMod;
						TT.CallConv = TempCall;
						
						while (!TempArgs.empty()) {
							ag.Type = TempArgs.top();
							ag.Dir = TempDirs.top();
							ag.Name = TempNames.top();
							TT.Args.insert( TT.Args.begin(), ag );
							TempArgs.pop();
							TempDirs.pop();
							TempNames.pop();
						}

						TraceDefinitions.push_back(TT);
						
						ReInitTemps();
						ClearTempArgs();

						}
      | error ';'		{/* ignore */}
      ;

arguments_expression
		: single_argument								{	TempDirs.push(TempDir); 
															TempArgs.push(TempType);
															TempNames.push(TempName); 
														}
		| arguments_expression ',' single_argument		{	TempDirs.push(TempDir); 
															TempArgs.push(TempType); 
															TempNames.push(TempName);
														}
		;

return_expression
		: ctype_expression					{ RetMatch = ""; TempMatch=""; RetType = TempType; }
		| string EQUAL ctype_expression		{ RetMatch = TempMatch; TempMatch=""; RetType = TempType; }
		| /* empty */						{ RetType = tr_VOID; RetMatch = ""; TempMatch=""; }
		;

single_argument
		: directed_ctype identifier			
		| directed_ctype					{ TempName = ""; }
		;

directed_ctype
		: '[' DIR_IN ']' ctype_expression		{ TempDir = in; }
		| '[' DIR_OUT ']'  ctype_expression		{ TempDir = out; }
		| '[' DIR_BOTH ']'  ctype_expression	{ TempDir = both; }
		| ctype_expression						{ TempDir = unknown; }
		;

ctype_expression
		: CT_CHAR				{ TempType = tr_CHAR; }
		| CT_CHAR '*'			{ TempType = tr_PCHAR; }
		| CT_INT				{ TempType = tr_INT; }
		| CT_INT '*'			{ TempType = tr_PINT; }
		| CT_VOID				{ TempType = tr_VOID; }
		| CT_VOID '*'			{ TempType = tr_PVOID; }
		| CT_FMTCHAR '*'		{ TempType = tr_PFMTCHAR; }
		| CT_WCHAR '*'			{ TempType = tr_PWCHAR; }
		| CT_FMTWCHAR '*'		{ TempType = tr_PFMTWCHAR; }
		;

name_expression
		: callconv mod_identifier ':' identifier		{ TempName2 = TempName; }
		| callconv identifier							{ TempName2 = TempName; TempMod = ""; } 
		;

callconv
		: CALL_CDECL			{ TempCall = CV_CDECL; }
		| CALL_FASTCALL			{ TempCall = CV_FASTCALL; }
		| CALL_STDCALL			{ TempCall = CV_STDCALL; }
		| /* empty */			{ TempCall = CV_CDECL; }
		;

mod_identifier
		: MODID					{ TempMod = $1; }
		;

identifier
		: ID					{ TempName = $1; }
		| HEXID					{ TempName = $1; }
		;

string
		: STRING				{ TempMatch = $1; }
		;

%%
/* ------------------------------------------------------------------
   Additional code (again copied verbatim to the output file)
   ------------------------------------------------------------------ */

