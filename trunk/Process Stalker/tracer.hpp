#ifndef __TRACER_HPP__
#define __TRACER_HPP__

#include <string>
#include <vector>
#include <map>

using namespace std;

#pragma warning ( disable: 4786 )

#include "log.hpp"
#include "debugger.hpp"
#include "pecoff.hpp"

#include "parser/tracedefs.hpp"


#define IS_A_IN_B(a,as,b,bs)	( ((a)>=(b)) && ( ((a)+(as)) <= ((b)+(bs)) ) )

//
// For function call tracing
//

typedef struct __OPEN_TRACES {
	DWORD				ThreadID;				// ThreadID of the trace
	DWORD				caller;					// who called thisone
	t_Tracedef_Def		*Definition;			// pointer to the definition
	t_Argumentvector	InArgs;					// arguments incomming
	t_Argumentvector	OutArgs;				// arguments when done
	t_Tracedef_ArgValue	Return;					// return value
	string				Notes;					// Notes added by different stages
} t_Tracer_OpenTr;

typedef vector<t_Tracer_OpenTr*>				t_OpenTracevector;
typedef vector<t_Tracer_OpenTr*>::iterator		t_OpenTracevector_Iterator;
// renaming for the public
typedef t_Tracer_OpenTr							t_Tracer_Result;
typedef vector<t_Tracer_OpenTr*>				t_Resultvector;
typedef vector<t_Tracer_OpenTr*>::iterator		t_Resultvector_Iterator;

typedef struct __TRACED_FUNC {
	DWORD						Address;		// resolved address
	t_Tracedef_Def				*Definition;	// pointer to the definition
	t_OpenTracevector			returns;		// outstanding returns from this function
} t_Tracer_Function;

typedef vector<t_Tracer_Function>				t_Activevector;
typedef vector<t_Tracer_Function>::iterator		t_Activevector_Iterator;

//
// For Buffer tracing (experimental!)
//
typedef struct __TRB {
	DWORD						address;			// mirrored from the map key
	DWORD						Size;
	DWORD						wrCount;			// how often this buffer is written to
	struct __TRP				*Page;
	bool						inactive;			// used for flagging by SingleStep
} t_Tracer_Buffer;

typedef struct __TRP {
	DWORD						address;			// mirrored from the map key
	DWORD						OriginalProtection;
	DWORD						Size;
	bool						TemporaryRestore;
	vector <t_Tracer_Buffer *>	Buffers;
} t_Tracer_Page;

typedef struct __SNGL {
	bool						General;
	bool						PageBlock;
	bool						SingleStepTrace;
	DWORD						LastAddr;
	DWORD						AddrCnt;
} t_Tracer_SSReasons;

typedef map <DWORD,t_Tracer_Buffer*>			t_BufferMap;
typedef map <DWORD,t_Tracer_Buffer*>::iterator	t_BufferMap_Iterator;
typedef map <DWORD,t_Tracer_Page*>				t_PageMap;
typedef map <DWORD,t_Tracer_Page*>::iterator	t_PageMap_Iterator;


typedef struct __TR_EXCLUDE {
	DWORD						Address;
	string						Name;
} t_Tracer_Exclude;

typedef vector <t_Tracer_Exclude>			t_Exclude;
typedef vector <t_Tracer_Exclude>::iterator	t_Exclude_Iterator;

//
// Global trace config
//

typedef struct __TRACER_ANALYSE {
	bool			FormatGuess;		// Guess arguments to format functions
	bool			StackDelta;			// Inspect the delta between the current ESP/EBP and a buffer
	DWORD			StackDeltaV;		// The value for StackDelta
	UINT			CodePage;			// CodePage for the translation of WideChars
} t_Tracer_Analysis;



class Tracer: public Debugger {
public:

	//
	// Member variable for logging
	//
	Logger					log;

	//
	// Function Trace definitions 
	//
	t_Tracer_Analysis		Analysis;
	t_Tracevector			Traces;				// defined traces
	t_Activevector			ActiveTraces;		// currently traced functions
	t_OpenTracevector		OpenTraces;			// Have seen entry but not leave
	t_Resultvector			Results;

	//
	// Member variables for Buffer tracing (experimental!)
	//
	t_BufferMap				Buffers;
	t_PageMap				Pages;
	t_Tracer_SSReasons		Stepping;

	t_Exclude				Excludes;
	DWORD					ExcludeRet;

	//
	// Constructor and Destructor
	//
	Tracer();
	virtual ~Tracer();

	//
	// Overloaded functions from the debugger
	// 
	bool ReBuildMemoryMap(void);
	virtual DWORD E_FirstBreakpoint(DEBUG_EVENT *d);
	virtual DWORD E_Breakpoint(DEBUG_EVENT *d);
	virtual DWORD E_AccessViolation(DEBUG_EVENT *d);
	virtual DWORD E_SingleStep(DEBUG_EVENT *d);
	virtual DWORD D_CreateThread(DEBUG_EVENT *d);
	virtual DWORD D_ExitThread(DEBUG_EVENT *d);
	//
	// Loading and managing traces
	// 
	bool LoadTraceDefinitions(char *filename);
	bool GetTraceString(t_Tracedef_Def *t, string *s);
	bool ActivateTraces(void);
	//
	// Callback functions for tracing
	//
	void SetOpenRecordFunction(void (*fname)(t_Tracer_OpenTr *));
	void SetCloseRecordFunction(void (*fname)(t_Tracer_OpenTr *));

	//
	// Buffer tracing (experimental!)
	//
	bool TraceBuffer(DWORD addr, DWORD size);
	bool RemoveTraceBuffer(t_Tracer_Buffer *buf);
	bool DisableAllTraces(void);
	bool EnableAllTraces(void);
	bool AddExclude(char *f);

	//
	// Currently only for debug purposes
	//
	bool SingleStepTrace(void);

protected:
	//
	// callbacks
	//
	void	(*rOpenFunc)(t_Tracer_OpenTr *);		// called after a record was opened
	void	(*rCloseFunc)(t_Tracer_OpenTr *);		// called after a record was closed

	//
	// Function tracing
	//
	t_Tracer_OpenTr *OpenTraceRecord(DEBUG_EVENT *d, t_Tracedef_Def *def);
	bool CloseTraceRecord(DEBUG_EVENT *d, t_Tracer_OpenTr *open);
	
	// 
	// minor Analysis stuff
	//
	void AnalysePCHAR(DWORD address, bool MultiByte, string *res);
	void AnalyseStack(DWORD address, t_Tracer_OpenTr *open);

	DWORD MemStrLen(DWORD address,bool MultiByte);
	bool MemStrCpy(DWORD address, bool MultiByte, string *s);
	void BeautifyString(string *s);
	void WideChar2String(WCHAR *w, string *s);

	//
	// Buffer tracing (experimental!)
	//
	bool GuardBufferPage(t_Tracer_Buffer *buf, DWORD addr, DWORD size);
	t_Debugger_memory *FindPageByAddress(DWORD addr, DWORD size);
	DWORD GetCaller(DWORD tid);

};
#endif __TRACER_HPP__
