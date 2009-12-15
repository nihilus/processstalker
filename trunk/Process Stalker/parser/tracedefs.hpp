#ifndef __TRACEDEFS_HPP__
#define __TRACEDEFS_HPP__

#include <string>
#include <vector>

using namespace std;

#include "windows.h"

#include "..\log.hpp"


typedef enum __TRACEDEF_CALLING_CONVENTION {
	CV_CDECL,
	CV_FASTCALL,
	CV_STDCALL
} t_Tracedef_Callconv;

typedef enum __TRACEDEF_DIRECTION{
	unknown,
	in,
	out,
	both
} t_Tracedef_Direction;

typedef vector<t_Tracedef_Direction>			t_Dirvector;
typedef vector<t_Tracedef_Direction>::iterator	t_Dirvector_Iterator;

//
// WARNING:
// When adding new types, make sure that tracedefs.cpp:Tracer_Type_Size[]
// is extended as well as the tracer's OpenTraceRecord and CloseTraceRecord
// are adjusted. Also, the default demo's main.cpp may no longer work.
// string.l and string.y must be adjusted for the parser to understand the 
// new type definition as well.
// Summary: adding a type is simple, but watch out for the many different 
// places. 
//

typedef enum __TRACEDEF_CTYPES {
	tr_VOID,						// void
	tr_PVOID,						// void*
	tr_INT,							// int
	tr_PINT,						// int*
	tr_CHAR,						// char
	tr_PCHAR,						// char*
	tr_PFMTCHAR,					// char* to format string
	tr_PWCHAR,						// wchar* (UNICODE, WideChar)
	tr_PFMTWCHAR					// wchar* to format string
} t_Tracedef_Ctype;

typedef vector<t_Tracedef_Ctype>			t_Ctypevector;
typedef vector<t_Tracedef_Ctype>::iterator	t_Ctypevector_Iterator;

typedef union __TRACEDEF_ARGUMENT_DATA {
		DWORD				address;
		DWORD				value;
		char				c;
} t_Tracedef_ArgValue;

//
// Sizes of types, in case someone needs to change
// them later for funny binaries. Can be accessed by 
// t_Tracedef_Ctypes
// 
extern unsigned short Tracer_Type_Size[];

//
// Arguments to functions
//
typedef struct __TRACEDEF_ARGUMENT {
	t_Tracedef_Ctype		Type;
	t_Tracedef_Direction	Dir;
	string					Name;

	//
	// Value
	//
	t_Tracedef_ArgValue		data;
	//
	// comment contains for example the extracted
	// string from a char* 
	//
	string					comment;
	//
	// This will hold the information where
	// to obtain the variable when the function 
	// returns - to defeat funny stack adjustments
	//
	DWORD					StackAddr;
} t_Tracedef_Argument;

typedef vector<t_Tracedef_Argument>				t_Argumentvector;
typedef vector<t_Tracedef_Argument>::iterator	t_Argumentvector_Iterator;

//
typedef struct __TRACEDEF_STRUCT {
	t_Tracedef_Ctype		Return;			// Return type, filled by parser
	string					ReturnMatch;	// Return match, filled by parser
	string					Name;			// Function name, filled by parser, potentially 0x12345 style
	string					Module;			// Module name, filled by parser
	t_Tracedef_Callconv		CallConv;		// The calling convention, filled by the parser
	t_Argumentvector		Args;			// Arguments, filled by parser
} t_Tracedef_Def;

typedef vector<t_Tracedef_Def>				t_Tracevector;
typedef vector<t_Tracedef_Def>::iterator	t_Tracevector_Iterator;

//
// defined in string.y
//
extern t_Tracevector			TraceDefinitions;

//
// defined in tracedefs.cpp
//
bool LoadTraceDef(Logger *l, char *filename);
char *GetTypeName(t_Tracedef_Ctype t);
char *GetDirName(t_Tracedef_Direction d);

#endif __TRACEDEFS_HPP__