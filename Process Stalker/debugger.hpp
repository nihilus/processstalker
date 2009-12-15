#ifndef __DEBUGGER_HPP__
#define __DEBUGGER_HPP__

#include <windows.h>
#include <string>
#include <vector>
#include <map>

#include "log.hpp"
#include "pecoff.hpp"
#include "blackmagic.hpp"

using namespace std;
#pragma warning( disable : 4786 4800 )

#define EFLAGS_CARRY		0x00000001
#define EFLAGS_PARITY		0x00000004
#define EFLAGS_AUXCARRY		0x00000010
#define EFLAGS_ZERO			0x00000040
#define EFLAGS_SIGN			0x00000080
#define EFLAGS_TRAP			0x00000100
#define EFLAGS_INTENABLE	0x00000200
#define EFLAGS_DIRECTION	0x00000400
#define EFLAGS_OVERFLOW		0x00000800
#define EFLAGS_IOPL			0x00003000
#define EFLAGS_NESTEDTASK	0x00004000
#define EFLAGS_RESUME		0x00010000
#define EFLAGS_VIRT8086		0x00020000
#define EFLAGS_ALIGNMENT	0x00040000
#define EFLAGS_VIRTUALINT	0x00080000
#define EFLAGS_VIRTINTPEND	0x00100000
#define EFLAGS_IDFLAG		0x00200000

//
// Structure generally returned by Disassembly methods
//

typedef struct {
	string			mnemonic;			// obvious
	unsigned int	size;				// size of the instruction
	string			comment;			// comments added by the disassembler

	DWORD			jmpaddr;			// Destination of jump/call/return
	int				optype[3];			// Type of operand 
	int				opsize[3];			// Size of operand, bytes
	bool			opgood[3];			// Whether address and data valid
	DWORD			opdata[3];			// Actual value or address
} t_disassembly;


//
// Structures for the Debugger itself
//

typedef struct {
	bool						IsMainThread;				// true if this is the main thread
	DWORD						ThreadID;					// ThreadID, obtained the hard way
	HANDLE						hThread;
	DWORD						TLB;						// ThreadLocalBase 
	DWORD						startAddress;				// thread starting address
	THREAD_BASIC_INFORMATION	basics;						// magic
	TEB							ThreadEnvironmentBlock;		// the TEB of this thread
	DWORD						StackP;
} t_Debugger_thread;


typedef struct {
	DWORD			address;			// Address of the Breakpoint
	BYTE			origop;				// Original Byte that got replaced by 0xCC
	bool			active;				// Active or not
} t_Debugger_breakpoint;


typedef struct DMRY{
	DWORD						address;	// mirrored for faster access
	string						Name;		// Who does it belong to if any
    string                      Type;		// section type (.rsrc, .text, .data) added by pedram
	MEMORY_BASIC_INFORMATION	basics;		// Details delivered by Windows
} t_Debugger_memory;

typedef map <DWORD,t_Debugger_memory*>				t_MemoryMap;
typedef map <DWORD,t_Debugger_memory*>::iterator	t_MemoryMap_Iterator;

typedef struct __DEBUGGER_CPU {
	DWORD		EAX;
	DWORD		ECX;
	DWORD		EDX;
	DWORD		EBX;
	DWORD		ESI;
	DWORD		EDI;
	DWORD		ESP;
	DWORD		EBP;
	DWORD		EIP;
	DWORD		EFlags;

	WORD		CS;
	WORD		DS;
	WORD		ES;
	WORD		FS;
	WORD		GS;
	WORD		SS;
} t_Debugger_CPU;



class Debugger {

public:
	// pedram - process stalking (lazy, didn't add a getter / setter)
	DWORD  breakpoint_restore;
    HANDLE breakpoint_restore_thread;
	bool   one_time;

    // pedram - process stalker dynamic function pointers
    typedef BOOL (WINAPI *lpfDebugSetProcessKillOnExit) (BOOL);
    typedef BOOL (WINAPI *lpfDebugActiveProcessStop)    (DWORD);

    lpfDebugSetProcessKillOnExit pDebugSetProcessKillOnExit;
    lpfDebugActiveProcessStop    pDebugActiveProcessStop;

	//
	// member variable for logging
	//
	Logger		log;

	//
	// datastructures
	//
	SYSTEM_INFO								SystemInfo;
	PEfile									PEimage;
	vector		<t_Debugger_thread*>		Threads;
	vector		<PEfile*>					Files;
	vector		<t_Debugger_breakpoint*>	Breakpoints;
	t_MemoryMap								MemoryMap;

	//
	// constructor and destructor
	//
	Debugger(void);
	virtual ~Debugger(void);

	// 
	// process and thread mgmt methods
	//
	bool load(char *filename);
	bool load(char *filename, char *commandline);
	bool attach(char *name, bool childonly);
	bool attach(unsigned int pid);
	bool detach(void);

	bool suspendTh(HANDLE th);
	bool resumeTh(HANDLE th);
	bool ReadTEB(HANDLE th);
	t_Debugger_thread *FindThread(HANDLE h);
	t_Debugger_thread *FindThread(DWORD tid);
	bool ReBuildMemoryMap(void);

	//
	// in case someone needs those
	//
	HANDLE getProcessHandle(void) { return hProcess; }
	char *getImageName(void) { return (char *)(imagename.c_str()); }

	//
	// Managing Breakpoints and such
	//
	bool bpSet(t_Debugger_breakpoint *bp);
	bool bpRestore(t_Debugger_breakpoint *bp);
	bool bpx(DWORD addr);
	bool bpDisable(DWORD addr);
	bool bpRemove(DWORD addr);

	// 
	// callback function assignment
	//
	void set_inital_breakpoint_handler(void (*handler)(DEBUG_EVENT*) );
	void set_breakpoint_handler(void (*handler)(DEBUG_EVENT*) );
	void set_exit_handler(void (*handler)(DEBUG_EVENT*) );
	void set_unhandled_handler(void (*handler)(DEBUG_EVENT*) );
	
	// pedram - process stalker
	void set_load_dll_handler(void (*handler)(PEfile *));

	//
	// running the show
	//
	bool run(unsigned int msec);
	bool SetSingleStep(bool stepping);
	bool SetSingleStep(HANDLE hhThread, bool stepping);
	void Break(void);
	bool GetCPUContext(HANDLE hhThread, t_Debugger_CPU *cpu);
	bool SetCPUContext(HANDLE hhThread, t_Debugger_CPU *cpu);
	bool SetEIP(HANDLE hhThread, DWORD neweip);

	//
	// Disassembly wrapper around libdisasm
	//
	bool Disassemble(HANDLE hhThread, DWORD addr, t_disassembly *dis);
	bool Disassemble(DWORD addr, char *buffer, t_Debugger_CPU *cpu, t_disassembly *dis);
	bool JCondition(char *buffer, unsigned int blen, t_Debugger_CPU *cpu);

	//
	// Methods to be overloaded by anyone using this 
	//
	virtual DWORD E_FirstBreakpoint(DEBUG_EVENT *d)			{ return DBG_EXCEPTION_NOT_HANDLED; };
	virtual DWORD E_Breakpoint(DEBUG_EVENT *d)				{ return DBG_EXCEPTION_NOT_HANDLED; };
	
	// pedram - process stalker
	//virtual DWORD E_SingleStep(DEBUG_EVENT *d)			{ return DBG_EXCEPTION_NOT_HANDLED; };
	//virtual DWORD E_AccessViolation(DEBUG_EVENT *d)		{ return DBG_EXCEPTION_NOT_HANDLED; };
	DWORD E_SingleStep(DEBUG_EVENT *);
	DWORD E_AccessViolation(DEBUG_EVENT *);
	
	virtual DWORD E_DatatypeMisallignment(DEBUG_EVENT *d)	{ return DBG_EXCEPTION_NOT_HANDLED; };
	//....
	virtual DWORD D_CreateThread(DEBUG_EVENT *d)			{ return DBG_CONTINUE; };
	virtual DWORD D_CreateProcess(DEBUG_EVENT *d)			{ return DBG_CONTINUE; };
	virtual DWORD D_ExitThread(DEBUG_EVENT *d)				{ return DBG_CONTINUE; };
	virtual DWORD D_ExitProcess(DEBUG_EVENT *d)				{ return DBG_CONTINUE; };
	virtual DWORD D_LoadDLL(DEBUG_EVENT *d)					{ return DBG_CONTINUE; };
	virtual DWORD D_UnloadDLL(DEBUG_EVENT *d)				{ return DBG_CONTINUE; };
	virtual DWORD D_OutputDebugString(DEBUG_EVENT *d)		{ return DBG_CONTINUE; };

	// Supplementary functions
	void SetGlobalLoglevel(unsigned int level);

    // pedram added getters
    unsigned int get_pid     (void) { return pid;      }
    unsigned int get_tid     (void) { return mthread;  }
    HANDLE       get_phandle (void) { return hProcess; }
    HANDLE       get_thandle (void) { return hThread;  }
    
    // pedram added setters
    void set_phandle  (HANDLE p) { hProcess = p; }
    void set_thandle  (HANDLE t) { hThread  = t; }

private:

	bool SetDebugPrivilege( HANDLE hProcess );
	bool FindModuleName( DWORD ProcessID, string *name );

	t_Debugger_thread *AddThread(DWORD threadID, HANDLE ht, DWORD lpStartAddress, DWORD lpThreadLocalBase);
	void RemoveThread(DWORD threadID);
	void RemoveDLL(DWORD BaseAddress);

	void default_unhandled(DEBUG_EVENT *d);

protected:

	bool			active;		// are we currently debugging anything?

	bool			first_breakpoint;	// This is a little flag that is true when we start 
										// and then dropped to false, because we need to 
										// call the PopulateByProcess() function for the 
										// main image once all the DLLs are loaded

	unsigned int	pid;		// currently debugged process
	unsigned int	mthread;	// main thread of the process
	HANDLE			hProcess;	// process handle
	HANDLE			hThread;	// main thread handle
	string			imagename;	// name of the currently debugged image

	void			(*fbpfunc)(DEBUG_EVENT*);	// function to be called when initial BP is hit
	void			(*bpfunc)(DEBUG_EVENT*);	// function to be called when BP is hit
	void			(*exitfunc)(DEBUG_EVENT*);	// function to be called when debugee exits
	void			(*unhfunc)(DEBUG_EVENT*);	// function to be called when debugee failed
												// to handle an exception
	// pedram - process stalker
	// call back function for when a dll is loaded.
	void (*load_dll_callback)(PEfile *);
};

#endif // __DEBUGGER_HPP__