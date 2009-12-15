#include <windows.h>
#include <WinNT.h>
#include <Tlhelp32.h>

extern "C" {
#include "libdisasm/vclibdisasm/libdis.h"
}

#include "debugger.hpp"
#include "log.hpp"
#include "blackmagic.hpp"

Debugger::Debugger() {
    HMODULE h_kernel32;

    // initialize member variables
    pid              = 0;
    mthread          = 0;
    active           = false;
    fbpfunc          = NULL;
    bpfunc           = NULL;
    exitfunc         = NULL;
    unhfunc          = NULL;
    imagename        = "";
    hThread          = NULL;
    hProcess         = NULL;
    first_breakpoint = true;
    one_time         = false;

    // pedram - process stalker
    load_dll_callback = NULL;

    log.Name = "Debugger";

    // pedram dynamically resolve function pointers;
    pDebugSetProcessKillOnExit = NULL;
    pDebugActiveProcessStop    = NULL;

    if ((h_kernel32 = LoadLibrary("kernel32.dll")) != NULL)
    {
        pDebugSetProcessKillOnExit = (lpfDebugSetProcessKillOnExit) GetProcAddress(h_kernel32, "DebugSetProcessKillOnExit");
        pDebugActiveProcessStop    = (lpfDebugActiveProcessStop)    GetProcAddress(h_kernel32, "DebugActiveProcessStop");

        // ensure both function pointers resolved.
        if (!pDebugSetProcessKillOnExit || !pDebugActiveProcessStop)
        {
            pDebugSetProcessKillOnExit = NULL;
            pDebugActiveProcessStop    = NULL;
        }
    }

    // 
    // make sure we are allowed to do magics
    //
    if ( SetDebugPrivilege(GetCurrentProcess()) ) 
        log.append(LOG_VERBOSE,"Debugger: Debug privileges obtained\n");
    else 
        log.append(LOG_WARNING,"Debugger: Failed to obtain debug privileges\n");

    disassemble_init(0, INTEL_SYNTAX);
    if (!InitBlackmagic())
        log.append(LOG_ERROR,"Debugger: Black Magic not available\n");

    GetSystemInfo(&SystemInfo);
}


Debugger::~Debugger() {
    unsigned int            i;
    PEfile                  *sentenced;
    unsigned int            size;
    t_MemoryMap_Iterator    it;

    // delete Thread infos
    size=Threads.size();
    for (i=0; i<size; i++) {
        log.append(LOG_DEBUG,
            "~Debugger(): deleting thread information for handle %X\n",
            (Threads.back())->hThread );
        delete ( Threads.back() );
        Threads.pop_back();
    }

    // delete File information
    size=Files.size();
    for (i=0; i<size; i++) {
        log.append(LOG_DEBUG,"~Debugger(): deleting file information %u/%u (%s)\n",
            i+1,size,Files.back()->internal_name.c_str());
        sentenced = Files.back();
        Files.pop_back();
        delete(sentenced);
    }

    // delete Memory Map
    for (it = MemoryMap.begin(); it != MemoryMap.end(); ++it )
    {
        log.append(LOG_DEBUG,
            "~Debugger(): deleting memory information for address 0x%08X\n",
            (it->second)->address );
        delete( it->second );
    }

    MemoryMap.clear();

    disassemble_cleanup();
    Exorcism();

}


DWORD Debugger::E_SingleStep(DEBUG_EVENT *db)
{
    if (!one_time)
    {
        // restore the saved breakpoint and continue execution as normal.
        bpx(breakpoint_restore);
        SetSingleStep(breakpoint_restore_thread, false);
    }

    return DBG_CONTINUE;
}


DWORD Debugger::E_AccessViolation(DEBUG_EVENT *db)
{
    t_disassembly dis;
    DWORD         address;
    HANDLE        thread;

    address = (DWORD)(db->u.Exception.ExceptionRecord.ExceptionAddress);
    thread  = FindThread((DWORD)db->dwThreadId)->hThread;

    printf("ACCESS VIOLATION Thread:%04x 0x%08X ", db->dwThreadId, address);
    
    if (Disassemble(thread, address, &dis))
        printf("%s\n", dis.mnemonic.c_str());
    else
        printf("\n");

    return DBG_CONTINUE;
}


bool Debugger::load(char *filename)
{
    return load(filename, NULL);
}


bool Debugger::load(char *filename, char *commandline)
{
    PROCESS_INFORMATION     pi;
    STARTUPINFO             si;
    char *cp_filename;

    first_breakpoint = true;
    si.cb            = sizeof(si);
    
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    // pedram - process stalking
    // CreateProcess() seems to work better with command line arguments when the
    // filename is passed as NULL.

    if (commandline != NULL)
        cp_filename = NULL;
    else
        cp_filename = filename;

    if(
        CreateProcess(cp_filename,   // filename of the process
            commandline,             // command line arguments if present
            NULL,                    // Process handle not inheritable. 
            NULL,                    // Thread handle not inheritable. 
            FALSE,                   // Set handle inheritance to FALSE. 
            DEBUG_ONLY_THIS_PROCESS, // debug the process, but not spawned off childs
            NULL,                    // Use parent's environment block. 
            NULL,                    // Use parent's starting directory. 
            &si,                     // Pointer to STARTUPINFO structure.
            &pi)                     // Pointer to PROCESS_INFORMATION structure.
            ) {

        //
        // CreateProcess worked
        //

        pid       = pi.dwProcessId;
        mthread   = pi.dwThreadId;
        hProcess  = pi.hProcess;
        hThread   = pi.hThread;
        imagename = filename;
        active    = true;

        log.append(LOG_INFO,"Process %u (%s) loaded\n",pid,filename);

        PEimage.internal_name=filename;

        return true;
    } else {

        log.append(LOG_ERROR,"Failed to load file '%s'\n",filename);

        return false;
    }
}


bool Debugger::attach(char *name, bool childonly) 
{
    HANDLE          snap;
    PROCESSENTRY32  proc;
    char            drive[_MAX_DRIVE];
    char            dir[_MAX_DIR];
    char            fname[_MAX_FNAME];
    char            fnameP[_MAX_FNAME];
    char            ext[_MAX_EXT];
    DWORD           aapid = 0;


    if ( INVALID_HANDLE_VALUE == 
        (snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0)) ){
        log.append(LOG_ERROR,"Failed to get Snapshot on Processes\n");
        return false;
    }

    proc.dwSize = sizeof(proc);
    if ( ! Process32First(snap,&proc) ) {
        log.append(LOG_ERROR,"Could not query process data\n");
        CloseHandle(snap);
        return false;
    } 

    do {
        _splitpath(proc.szExeFile,drive,dir,fname,ext);
        if (!stricmp(fname,name)) {

            if (childonly) {
                string      parrent;

                FindModuleName( proc.th32ParentProcessID, &parrent);
                _splitpath(parrent.c_str(),drive,dir,fnameP,ext);

                if (stricmp(fnameP,name)) {
                    log.append(LOG_WARNING,
                        "Not attaching to %s (%u), because it's not a child of itself\n",
                        fname,proc.th32ProcessID);
                } else {
                    log.append(LOG_WARNING,
                        "Attaching to %s (%u), because it's a child of %u\n",
                        fname,proc.th32ProcessID,proc.th32ParentProcessID);
                    aapid = proc.th32ProcessID;
                }
            } else {
                // not child only, simply attach
                aapid = proc.th32ProcessID;
            }
        }

    } while ( Process32Next(snap,&proc) );

    CloseHandle(snap);

    if ( 0 != aapid) {
        log.append(LOG_INFO,"attach(): Attaching to PID %u\n",aapid);
        attach(aapid);
        return true;
    } else {
        if (!childonly)
            log.append(LOG_WARNING,"Process named '%s' not found\n",name);
        return false;
    }
}


bool Debugger::attach(unsigned int apid)
{
    first_breakpoint=true;

    FindModuleName(apid,&(PEimage.internal_name));

    if ( DebugActiveProcess(apid) ) {
        //
        // attaching to the process worked
        //

        pid=apid;
        
        log.append(LOG_VERBOSE,"attached to process %u\n",apid);

        return (active=true);

    } else {

        log.append(LOG_ERROR,"DebugActiveProcess failed while attaching to process %u\n",apid);

        return false;
    }
}


bool Debugger::detach(void)
{
    vector <t_Debugger_breakpoint*>::iterator it;
    t_Debugger_breakpoint                     *bp = NULL;

    if (!active)
        return false;

    // ensure the appropriate API routines were resolved.
    if (!pDebugSetProcessKillOnExit || !pDebugActiveProcessStop)
        return false;

    // disable all active breakpoints.
    for (it = Breakpoints.begin(); it < Breakpoints.end(); it++)
    {
        bp = (*it);
        bpRestore(bp);
    }
        
    pDebugSetProcessKillOnExit(FALSE);

    if (!pDebugActiveProcessStop(pid))
        return false;

    // pedram added.
    active = false;

    return true;
}


bool Debugger::suspendTh(HANDLE th) {
    DWORD       rv;
        
    //
    // Suspend the thread for reading the context
    //
    if ( (rv=SuspendThread(th)) < 0 ) {
        log.appendError(LOG_ERROR,"could not suspend current thread %08X",th);
        return false;
    } else if ( 0 == rv ) {
        log.append(LOG_DEBUG,"SuspendThread succeeded\n");
        return true;
    } else {
        log.append(LOG_WARNING,"Thread already suspended\n");
        return true;
    }
}


bool Debugger::resumeTh(HANDLE th) {
    DWORD       rv;

    //
    // Resume the thread 
    //
    if ( (rv=ResumeThread(th)) < 0 ) {
        log.appendError(LOG_ERROR,"could not resume current thread %08X",th);
        return false;
    } else if ( 0 == rv ) {
        log.append(LOG_DEBUG,"ResumeThread succeeded\n");
        return true;
    } else {
        log.append(LOG_WARNING,"Thread still suspended after resume\n");
        return true;
    }
}


bool Debugger::ReadTEB(HANDLE th) {
    vector <t_Debugger_thread*>::iterator   it;
    bool                                    rv;
    DWORD                                   in;

    for (it = Threads.begin(); it < Threads.end(); it++) {
        if ( (*it)->hThread == th ) {

            rv = ReadProcessMemory(
                hProcess,
                (LPCVOID)(*it)->basics.TebBaseAddress,
                &( (*it)->ThreadEnvironmentBlock ),
                sizeof( TEB ),
                &in);
        }
    }

    return rv;
}


t_Debugger_thread *Debugger::FindThread(HANDLE th) {
    vector <t_Debugger_thread*>::iterator   it;

    for (it = Threads.begin(); it < Threads.end(); it++) {
        if ( (*it)->hThread == th ) {
            return (*it);
        }
    }
    return NULL;
}


t_Debugger_thread *Debugger::FindThread(DWORD tid) {
    vector <t_Debugger_thread*>::iterator   it;

    for (it = Threads.begin(); it < Threads.end(); it++) {
        if ( (*it)->ThreadID == tid ) {
            return (*it);
        }
    }
    return NULL;
}


bool Debugger::ReBuildMemoryMap(void) {
    t_MemoryMap_Iterator                    mit;
    DWORD                                   caddr;
    t_Debugger_memory                       *mem;
    vector <PEfile*>::iterator              it;
    vector <t_section_header*>::iterator    si;

    // 
    // Remove old memory map
    //
    
    for (mit = MemoryMap.begin(); mit != MemoryMap.end(); ++mit) {
        delete( mit->second );
    }
    MemoryMap.clear();

    caddr=0;
    mem = NULL;
    do {

        if ( NULL == mem ) {
            //
            // only allocate mem if we don't have a usable from the last
            // loop iteration
            //
            if ( NULL == (mem=new(t_Debugger_memory)) ){
                log.append(LOG_ERROR,"ReBuildMemoryMap(): could not allocate %u bytes\n",
                    sizeof(t_Debugger_memory));
                return false;
            }
        }

        if ( 0 == VirtualQueryEx(
            hProcess,
            (LPCVOID)caddr,
            &(mem->basics),
            sizeof(MEMORY_BASIC_INFORMATION)) ){

            log.append(LOG_DEBUG,"ReBuildMemoryMap(): Failed to query address 0x%08X\n",
                caddr);

            /*
            // 
            // Not sure here, logically, this would make sense but my feeling is that 
            // the failing of VirtualQueryEx signifies the end of the mapped address
            // space of the process
            //
            caddr += SystemInfo.dwPageSize;
            continue;
            */
            delete(mem);
            break;
        }

        mem->address = (DWORD)mem->basics.BaseAddress;
        caddr += mem->basics.RegionSize;

        if ( mem->basics.State == MEM_COMMIT ) {
            bool        namedone;

            namedone=false;
            for ( si = PEimage.section.begin(); 
            (si < PEimage.section.end()) && (!namedone);
            si++ ){
                    if ( ( (PEimage.winpe->ImageBase + (*si)->VirtualAddress) >= mem->address)
                        && ( (PEimage.winpe->ImageBase +(*si)->VirtualAddress) 
                        <= (mem->address + mem->basics.RegionSize)) ){
    
                        // pedram
                        mem->Name = PEimage.internal_name.substr(PEimage.internal_name.rfind("\\") + 1);
                        mem->Type = "";
                        mem->Type.append( (char*)((*si)->Name) );
                        //mem->Name = "main image (";
                        //mem->Name.append( (char*)((*si)->Name) );
                        //mem->Name.appendu(")");
                        namedone=true;
                        break;
                    }
            }

            for ( it = Files.begin(); (!namedone) && (it < Files.end()); it++) {
                for ( si = (*it)->section.begin(); 
                (!namedone) && (si < (*it)->section.end());
                si++) {

                    if ( 
                        ( ((*it)->winpe->ImageBase+(*si)->VirtualAddress) >= mem->address)
                        && ( ((*it)->winpe->ImageBase + (*si)->VirtualAddress) 
                        <= (mem->address + mem->basics.RegionSize)) ){

                        // pedram
                        mem->Name = (*it)->internal_name;
                        mem->Type = "";
                        mem->Type.append( (char*)((*si)->Name) );
                        //mem->Name.append(" (");
                        //mem->Name.append( (char*)((*si)->Name) );
                        //mem->Name.append(")");
                        namedone = true;
                    }
                } // for si
            } // for it

            log.append(LOG_DEBUG,"Adding memory page %s at 0x%08X (%u bytes)\n",
                mem->Name.c_str(),mem->address, mem->basics.RegionSize);

            // add to map and mark mem as needs-to-be-allocated
            MemoryMap[(DWORD)mem->basics.BaseAddress]=mem;
            mem = NULL;

        } else if ( mem->basics.State == MEM_RESERVE ){
            log.append(LOG_DEBUG,"Adding reserved memory page at 0x%08X (%u bytes)\n",
                mem->address, mem->basics.RegionSize);
            mem->Name = "Reserved";

            // add to map and mark mem as needs-to-be-allocated
            MemoryMap[(DWORD)mem->basics.BaseAddress]=mem;
            mem = NULL;

        } else if ( mem->basics.State == MEM_FREE ){
            log.append(LOG_DEBUG,"Skipped memory page at 0x%08X (%u bytes)\n",
                mem->address, mem->basics.RegionSize);
        } else {
            log.append(LOG_ERROR,
                "ReBuildMemoryMap(): page at 0x%08X has unknown state %08X\n",
                mem->address,mem->basics.State);
            return false;
        }

    } while (caddr < 0xFFFF0000);

    return true;
}
    

bool Debugger::bpSet(t_Debugger_breakpoint *bp) {
    DWORD                       oldprot, oldprot2;
    BYTE                        ccByte = 0xCC;

    //
    // Make the page in question writable 
    //
    if ( ! VirtualProtectEx(
        hProcess,
        (LPVOID)bp->address,
        sizeof(BYTE),
        PAGE_EXECUTE_READWRITE,
        &oldprot) ){

        log.append(LOG_ERROR,
            "bpSet(): Failed to obtain write access to page at 0x%08X\n",
            bp->address);
        return false;
    }

    //
    // Read original opcode
    //
    if (!ReadProcessMemory(
        hProcess,
        (LPCVOID)bp->address,
        &(bp->origop),
        sizeof(BYTE),
        NULL) ){

        log.append(LOG_ERROR,"bpSet(): Failed to read byte at 0x%08X\n",
            bp->address);
        return false;
    }

    //
    // replace with 0xCC
    //
    if (!WriteProcessMemory(
        hProcess,
        (LPVOID)bp->address,
        &ccByte,
        sizeof(ccByte),
        NULL) ){

        log.append(LOG_ERROR,"bpSet(): Failed to write byte at 0x%08X\n",
            bp->address);
        return false;
    }

    //
    // restore original permissions
    //
    if ( ! VirtualProtectEx(
        hProcess,
        (LPVOID)bp->address,
        sizeof(BYTE),
        oldprot,
        &oldprot2) ){

        log.append(LOG_ERROR,
            "bpSet(): Failed to restore access to page at 0x%08X\n",
            bp->address);
        return false;
    }

    FlushInstructionCache(hProcess,NULL,0);

    log.append(LOG_DEBUG,"bpSet(): Breakpoint at %08X activated\n",
        bp->address);

    return true;
}


bool Debugger::bpRestore(t_Debugger_breakpoint *bp) {
    DWORD                       oldprot, oldprot2;

    //
    // Make the page in question writable 
    //
    if ( ! VirtualProtectEx(
        hProcess,
        (LPVOID)bp->address,
        sizeof(BYTE),
        PAGE_EXECUTE_READWRITE,
        &oldprot) ){

        log.append(LOG_ERROR,
            "bpRestore(): Failed to obtain write access to page at 0x%08X\n",
            bp->address);
        return false;
    }

    //
    // replace with original byte
    //
    if (!WriteProcessMemory(
        hProcess,
        (LPVOID)bp->address,
        &(bp->origop),
        sizeof(bp->origop),
        NULL) ){

        log.append(LOG_ERROR,"bpRestore(): Failed to write byte at 0x%08X\n",
            bp->address);
        return false;
    }

    //
    // restore original permissions
    //
    if ( ! VirtualProtectEx(
        hProcess,
        (LPVOID)bp->address,
        sizeof(BYTE),
        oldprot,
        &oldprot2) ){

        log.append(LOG_ERROR,
            "bpRestore(): Failed to restore access to page at 0x%08X\n",
            bp->address);
        return false;
    }

    FlushInstructionCache(hProcess,NULL,0);

    log.append(LOG_DEBUG,"bpRestore(): original code %02X at %08X restored\n",
        bp->origop,bp->address);

    return true;
}


bool Debugger::bpx(DWORD addr)
{
    vector <t_Debugger_breakpoint*>::iterator   it;
    t_Debugger_breakpoint       *bp = NULL;

    for (it = Breakpoints.begin(); it < Breakpoints.end(); it++)
        if ((*it)->address == addr)
            bp = (*it);

    if ( NULL == bp )
    {
        if (NULL == (bp=new(t_Debugger_breakpoint)))
        {
            log.append(LOG_ERROR,"bpx(): could not allocate %u bytes\n", sizeof(t_Debugger_breakpoint));
            return false;
        }
    }
    else
    {
        if (bp->active)
        {
            log.append(LOG_DEBUG, "bpx(): Breakpoint at %08X already active\n",addr); 
            return false;
        }
    }

    bp->address = addr;
    bp->active  = true;

    if (!bpSet(bp))
    {
        return false;
    }
    else
    {
        Breakpoints.push_back(bp);
        return true;
    }
}


bool Debugger::bpDisable(DWORD addr) {
    vector <t_Debugger_breakpoint*>::iterator   it;
    t_Debugger_breakpoint                       *bp = NULL;

    
    for ( it = Breakpoints.begin(); it < Breakpoints.end(); it++) {
        if ( (*it)->address == addr ) {
            bp = (*it);
            break;
        }
    }

    if ( NULL == bp ) {
        log.append(LOG_ERROR,"bpDisable(): No known breakpoint at %08X\n",
            addr);
        return false;
    }

    bpRestore(bp);

    bp->active = false;

    return true;
}


bool Debugger::bpRemove(DWORD addr) {
    vector <t_Debugger_breakpoint*>::iterator   it;
    t_Debugger_breakpoint                       *bp = NULL;

    for ( it = Breakpoints.begin(); it < Breakpoints.end(); it++) {
        if ( (*it)->address == addr ) {
            bp = (*it);
            break;
        }
    }

    if ( NULL == bp ) {
        log.append(LOG_ERROR,"bpRemove(): No known breakpoint at %08X\n",
            addr);
        return false;
    }

    if (bp->active) bpRestore(bp);

    Breakpoints.erase(it);
    delete(bp);

    return true;
}


void Debugger::set_breakpoint_handler(void (*handler)(DEBUG_EVENT*) ) {

    bpfunc = handler;
}


void Debugger::set_exit_handler(void (*handler)(DEBUG_EVENT*) ) {

    exitfunc = handler;
}


void Debugger::set_unhandled_handler(void (*handler)(DEBUG_EVENT*) ) {

    unhfunc = handler;
}


void Debugger::set_inital_breakpoint_handler(void (*handler)(DEBUG_EVENT*) ) {

    fbpfunc = handler;
}

// pedram - process stalker
void Debugger::set_load_dll_handler(void (*handler)(PEfile *))
{
    load_dll_callback = handler;
}

bool Debugger::run(unsigned int msec) {
    DEBUG_EVENT         d;                                  // debugging event information 
    DWORD               dwContinueStatus = DBG_CONTINUE;    // exception continuation 
    PEfile              *pe;
    t_Debugger_thread   *td;
    vector <t_Debugger_breakpoint*>::iterator   bpit;       // finding breakpoints
    t_Debugger_breakpoint                       *bp;

    // 
    // get right back if we are not (or no longer) running
    //
    if (!active) return false;
    
    //
    // Wait for Windows to return a debug event to us
    //
    if ( WaitForDebugEvent(&d, msec) ) {

        log.append(LOG_DEBUG,"Debug event encountered\n");
        
        // Process the debugging event code. 
        
        switch (d.dwDebugEventCode) 
        { 
        case EXCEPTION_DEBUG_EVENT: 
            // Process the exception code. When handling 
            // exceptions, remember to set the continuation 
            // status parameter (dwContinueStatus). This value 
            // is used by the ContinueDebugEvent function. 
            log.append(LOG_DEBUG," .. debug event\n");
            
            switch (d.u.Exception.ExceptionRecord.ExceptionCode) 
            { 
            case EXCEPTION_BREAKPOINT: 
                // First chance: Display the current 
                // instruction and register values. 

                // 
                // scan our software breakpoints to see if we need to 
                // repatch memory
                //
                bp = NULL;
                for ( bpit = Breakpoints.begin(); bpit < Breakpoints.end(); bpit++) {
                    if ( (*bpit)->address == (DWORD)d.u.Exception.ExceptionRecord.ExceptionAddress ){
                        bp = (*bpit);
                        break;
                    }
                }

                // it's been one of our soft breakpoints
                if ( NULL != bp ) {
                    bpRestore(bp);
                    SetEIP(
                        FindThread((DWORD)d.dwThreadId)->hThread,
                        (DWORD)d.u.Exception.ExceptionRecord.ExceptionAddress);

                    bp->active = false;
                }

                //
                // Minor hack to populate information when we see the first
                // Windows-driven break
                //
                if (first_breakpoint) {
                    PEimage.PopulateByProcess(hProcess);
                    ReBuildMemoryMap();
                    first_breakpoint = false;

                    // call overloady
                    E_FirstBreakpoint(&d);

                    if ( NULL != fbpfunc )
                        (*fbpfunc)(&d);

                } else {

                    // call overloady
                    E_Breakpoint(&d);

                    if ( NULL != bpfunc ) 
                        (*bpfunc)(&d);
                }

                /*
                //
                // WARNING: The resume flag doesn't work - at least not this way
                // I assume the Windows Debug API implicit or explicit clears this
                // flag, may be even unintentionally
                //

                //
                // Check if the user deleted or disabled the breakpoint
                // If not, reestablish and set the resume flag
                //
                for ( bpit = Breakpoints.begin(); bpit < Breakpoints.end(); bpit++) {
                    if ( (*bpit)->address == (DWORD)d.u.Exception.ExceptionRecord.ExceptionAddress ){
                        t_Debugger_CPU  cpu;

                        bp = (*bpit);
                        if (GetCPUContext( FindThread((DWORD)d.dwThreadId)->hThread,&cpu)) {
                            cpu.EFlags = cpu.EFlags | EFLAGS_RESUME;
                            SetCPUContext( FindThread((DWORD)d.dwThreadId)->hThread,&cpu);
                            bp->active = true;
                            bpSet(bp);

                            log.push(LOG_DEBUG);
                            log.append(LOG_DEBUG,
                                "Breakpoint %08X reestablished and resume flag set\n",
                                bp->address);
                            log.pop();
                        }
                        break;
                    }
                }
                */

                break;
                    
            case EXCEPTION_SINGLE_STEP: 
                // First chance: Update the display of the 
                // current instruction and register values. 
                
                log.append(LOG_DEBUG,"... single step event\n");
                
                // call overloady
                dwContinueStatus = E_SingleStep(&d);
                break;

            // --------------------------------------------
            //
            // Bad things that can happen but we don't care 
            //
            // --------------------------------------------

            case EXCEPTION_ACCESS_VIOLATION: 
                // First chance: Pass this on to the system. 
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                log.append(LOG_INFO,"Access violation at %08X\n",
                    d.u.Exception.ExceptionRecord.ExceptionAddress);

                //
                // call overloady
                dwContinueStatus = E_AccessViolation(&d);
                log.append(LOG_DEBUG,"AV return: %s\n",dwContinueStatus==DBG_CONTINUE?"Continue":"Unhandled");

                if ( 0 == d.u.Exception.dwFirstChance ) {
                    // Last chance: Display an appropriate error. 
                    dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                    log.append(LOG_WARNING,
                        "Program failed to handle Access violation at %08X\n",
                        d.u.Exception.ExceptionRecord.ExceptionAddress);
                    if ( NULL != unhfunc) (*unhfunc)(&d); else default_unhandled(&d);
                } 
                break;
                            
            case EXCEPTION_DATATYPE_MISALIGNMENT: 
                // First chance: Pass this on to the system. 
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                log.append(LOG_INFO,"Datatype misaligment at %08X\n",
                    d.u.Exception.ExceptionRecord.ExceptionAddress);
                if ( 0 == d.u.Exception.dwFirstChance ) {
                    // Last chance: Display an appropriate error. 
                    log.append(LOG_WARNING,
                        "Program failed to handle Data misalignment at %08X\n",
                        d.u.Exception.ExceptionRecord.ExceptionAddress);
                    if ( NULL != unhfunc) (*unhfunc)(&d); else default_unhandled(&d);
                }
                break;
                
            case DBG_CONTROL_C: 
                // First chance: Pass this on to the system. 
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                log.append(LOG_INFO,"CTRL-C at %08X\n",
                    d.u.Exception.ExceptionRecord.ExceptionAddress);
                if ( 0 == d.u.Exception.dwFirstChance ) {
                    // Last chance: Display an appropriate error. 
                    log.append(LOG_WARNING,
                        "Program failed to handle CTRL-C at %08X\n",
                        d.u.Exception.ExceptionRecord.ExceptionAddress);
                    if ( NULL != unhfunc) (*unhfunc)(&d); else default_unhandled(&d);
                }
                break;
                
            case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: 
                // First chance: Pass this on to the system. 
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                log.append(LOG_INFO,"Array bound exceeded at %08X\n",
                    d.u.Exception.ExceptionRecord.ExceptionAddress);
                if ( 0 == d.u.Exception.dwFirstChance ) {
                    // Last chance: Display an appropriate error. 
                    log.append(LOG_WARNING,
                        "Program failed to handle Array bound exceeded at %08X\n",
                        d.u.Exception.ExceptionRecord.ExceptionAddress);
                    if ( NULL != unhfunc) (*unhfunc)(&d); else default_unhandled(&d);
                }
                break;
                
            case EXCEPTION_ILLEGAL_INSTRUCTION: 
                // First chance: Pass this on to the system. 
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                log.append(LOG_INFO,"Illegal Instruction at %08X\n",
                    d.u.Exception.ExceptionRecord.ExceptionAddress);
                if ( 0 == d.u.Exception.dwFirstChance ) {
                    // Last chance: Display an appropriate error. 
                    log.append(LOG_WARNING,
                        "Program failed to handle Illegal Instruction at %08X\n",
                        d.u.Exception.ExceptionRecord.ExceptionAddress);
                    if ( NULL != unhfunc) (*unhfunc)(&d); else default_unhandled(&d);
                }
                break;
                
            case EXCEPTION_IN_PAGE_ERROR: 
                // First chance: Pass this on to the system. 
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                log.append(LOG_INFO,"In-Page error at %08X\n",
                    d.u.Exception.ExceptionRecord.ExceptionAddress);
                if ( 0 == d.u.Exception.dwFirstChance ) {
                    // Last chance: Display an appropriate error. 
                    log.append(LOG_WARNING,
                        "Program failed to handle In-Page error at %08X\n",
                        d.u.Exception.ExceptionRecord.ExceptionAddress);
                    if ( NULL != unhfunc) (*unhfunc)(&d); else default_unhandled(&d);
                }
                break;
                
            case EXCEPTION_INT_DIVIDE_BY_ZERO: 
                // First chance: Pass this on to the system. 
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                log.append(LOG_INFO,"Devide by Zero at %08X\n",
                    d.u.Exception.ExceptionRecord.ExceptionAddress);
                if ( 0 == d.u.Exception.dwFirstChance ) {
                    // Last chance: Display an appropriate error. 
                    log.append(LOG_WARNING,
                        "Program failed to handle Devide by Zero at %08X\n",
                        d.u.Exception.ExceptionRecord.ExceptionAddress);
                    if ( NULL != unhfunc) (*unhfunc)(&d); else default_unhandled(&d);
                }
                break;
            
            case EXCEPTION_INT_OVERFLOW: 
                // First chance: Pass this on to the system. 
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                log.append(LOG_INFO,"Integer Overflow at %08X\n",
                    d.u.Exception.ExceptionRecord.ExceptionAddress);
                if ( 0 == d.u.Exception.dwFirstChance ) {
                    // Last chance: Display an appropriate error. 
                    log.append(LOG_WARNING,
                        "Program failed to handle Integer Overflow at %08X\n",
                        d.u.Exception.ExceptionRecord.ExceptionAddress);
                    if ( NULL != unhfunc) (*unhfunc)(&d); else default_unhandled(&d);
                }
                break;
            
            case EXCEPTION_PRIV_INSTRUCTION: 
                // First chance: Pass this on to the system. 
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                log.append(LOG_INFO,"Privileged Instruction at %08X\n",
                    d.u.Exception.ExceptionRecord.ExceptionAddress);    
                if ( (0 == d.u.Exception.dwFirstChance) || 
                    (d.u.Exception.ExceptionRecord.ExceptionFlags == EXCEPTION_NONCONTINUABLE) ) {
                    // Last chance: Display an appropriate error. 
                    log.append(LOG_WARNING,
                        "Program failed to handle Privileged Instruction at %08X\n",
                        d.u.Exception.ExceptionRecord.ExceptionAddress);
                    if ( NULL != unhfunc) (*unhfunc)(&d); else default_unhandled(&d);
                }
                break;
            
            case EXCEPTION_STACK_OVERFLOW: 
                // First chance: Pass this on to the system. 
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                log.append(LOG_INFO,"Stack Overflow at %08X\n",
                    d.u.Exception.ExceptionRecord.ExceptionAddress);
                if ( 0 == d.u.Exception.dwFirstChance ) {
                    // Last chance: Display an appropriate error. 
                    log.append(LOG_WARNING,
                        "Program failed to handle Stack Overflow at %08X\n",
                        d.u.Exception.ExceptionRecord.ExceptionAddress);
                    if ( NULL != unhfunc) (*unhfunc)(&d); else default_unhandled(&d);
                }
                break;
            
            default:
                // Handle other exceptions. 
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                log.append(LOG_INFO,"UNKNOWN EXCEPTION at %08X (code %08X)\n",
                    d.u.Exception.ExceptionRecord.ExceptionAddress,
                    d.u.Exception.ExceptionRecord.ExceptionCode);
                if ( 0 == d.u.Exception.dwFirstChance ) {
                    // Last chance: Display an appropriate error. 
                    log.append(LOG_WARNING,
                        "Program failed to handle unknown exception at %08X\n",
                        d.u.Exception.ExceptionRecord.ExceptionAddress);
                    if ( NULL != unhfunc) (*unhfunc)(&d); else default_unhandled(&d);
                }
                break;
            } 
            break;

            
            case CREATE_THREAD_DEBUG_EVENT: 
                // As needed, examine or change the thread's registers 
                // with the GetThreadContext and SetThreadContext functions; 
                // and suspend and resume thread execution with the 
                // SuspendThread and ResumeThread functions. 
                log.append(LOG_DEBUG," .. create thread event\n");
                AddThread(d.dwThreadId,
                    d.u.CreateThread.hThread,
                    (DWORD)d.u.CreateThread.lpStartAddress,
                    (DWORD)d.u.CreateThread.lpThreadLocalBase);
                // call overloady
                D_CreateThread(&d);
                break;
                
            case CREATE_PROCESS_DEBUG_EVENT: 
                // As needed, examine or change the registers of the 
                // process's initial thread with the GetThreadContext and 
                // SetThreadContext functions; read from and write to the 
                // process's virtual memory with the ReadProcessMemory and 
                // WriteProcessMemory functions; and suspend and resume 
                // thread execution with the SuspendThread and ResumeThread 
                // functions. Be sure to close the handle to the process image 
                // file with CloseHandle.
                log.append(LOG_DEBUG," .. create process event\n");

                hProcess = d.u.CreateProcessInfo.hProcess;
                hThread = d.u.CreateProcessInfo.hThread;

                if ( imagename.length() == 0 ) {
                    if (NULL == d.u.CreateProcessInfo.lpImageName )
                        imagename="[UNKNOWN]";
                    else 
                        imagename = (char *)d.u.CreateProcessInfo.lpImageName;
                }
                
                log.append(LOG_INFO,"attached to process %u (%s, proc handle %X, main thread handle %X)\n",
                    pid,imagename.c_str(),hProcess,hThread);

                //
                // Add information about the main thread
                // 
                td=AddThread(d.dwThreadId,hThread,0,0);
                td->IsMainThread = true;
                
                if (d.u.CreateProcessInfo.nDebugInfoSize > 0) 
                    log.append(LOG_VERBOSE,"process has %u bytes DebugInfo\n",
                    d.u.CreateProcessInfo.nDebugInfoSize);
                else 
                    log.append(LOG_VERBOSE,"process has no DebugInfo\n");

                //
                // read the interesting data from the file
                //
                PEimage.log.set( log.getLevel() );

                if (! PEimage.PEOpen(d.u.CreateProcessInfo.hFile) ) {
                    log.append(LOG_ERROR,"Failed to open the main program image file\n");
                } else {
                    if ( ! PEimage.parse() ) {
                        log.append(LOG_ERROR,"Failed to parse the main program's image file\n");
                    } else {
                        if ( (DWORD)d.u.CreateProcessInfo.lpBaseOfImage != 
                            PEimage.winpe->ImageBase ){

                            log.append(LOG_DEBUG,"Image Base address is memory 0x%08X"
                                "(file header 0x%08X) - Adjusting\n",
                                (DWORD)d.u.CreateProcessInfo.lpBaseOfImage,
                                PEimage.winpe->ImageBase);

                            PEimage.winpe->ImageBase = (DWORD)d.u.CreateProcessInfo.lpBaseOfImage;
                        }

                        // PopulateByProcess() is called upon the initial breakpoint 
                        // for the main image, since only then most of the Imports 
                        // are resolved. Now, no library is loaded yet if we started
                        // this using CreateProcess()
                        log.append(LOG_INFO,"Debugger::run(): Loaded and parsed main image (%s)\n",
                            PEimage.internal_name.c_str());
                    }
                }   
                PEimage.PEClose();

                // call overloady
                D_CreateProcess(&d);

                break;

                
            case EXIT_THREAD_DEBUG_EVENT: 
                // Display the thread's exit code. 
                log.append(LOG_DEBUG," .. exit thread event\n");
                RemoveThread(d.dwThreadId);

                // call overloady
                D_ExitThread(&d);
                break;
                
            case EXIT_PROCESS_DEBUG_EVENT: 
                // Display the process's exit code. 
                log.append(LOG_INFO,"Process exit, code %u\n",
                    d.u.ExitProcess.dwExitCode);

                if ( NULL != exitfunc ) {
                    log.append(LOG_DEBUG,"Calling the user's exit handler\n");
                    (*exitfunc)(&d);
                }
                active = false;

                // call overloady
                D_ExitProcess(&d);
                break;
                
            case LOAD_DLL_DEBUG_EVENT: 
                // Read the debugging information included in the newly 
                // loaded DLL. Be sure to close the handle to the loaded DLL 
                // with CloseHandle.
                log.append(LOG_DEBUG," .. load DLL event\n");

                //
                // Use the PEfile reader/parser to obtain all the interesting
                // information from the file. 
                //
                if ( NULL == (pe = new(PEfile)) ){
                    log.append(LOG_ERROR,"Debugger::run(): Could not allocate %u bytes"
                        " memory for DLL object!\n",sizeof(PEfile));
                    CloseHandle(d.u.LoadDll.hFile);

                } else {
                    
                    //pe->log.set( log.getLevel() );
                    
                    if ( pe->PEOpen(d.u.LoadDll.hFile) && pe->parse() ) {
                        //
                        // DLL open and parsed
                        //
                        if ( ((DWORD)d.u.LoadDll.lpBaseOfDll) != pe->winpe->ImageBase ) {
                            log.append(LOG_DEBUG,"DLL Base address is memory 0x%08X (file header 0x%08X) - Adjusting\n",
                                (DWORD)d.u.LoadDll.lpBaseOfDll,
                                pe->winpe->ImageBase);

                            pe->winpe->ImageBase = (DWORD)d.u.LoadDll.lpBaseOfDll;
                        }   

                        // populate the info.
                        pe->PopulateByProcess(hProcess);

                        log.append(LOG_INFO, "Debugger::run(): Loaded and parsed module %s\n", pe->internal_name.c_str());
                        
                        Files.push_back(pe);

                    }
                    
                    // pedram - process stalker.
                    if (load_dll_callback != NULL)
                        (*load_dll_callback)(pe);

                    pe->PEClose();
                }

                // call overloady.
                D_LoadDLL(&d);
                break;
                
            case UNLOAD_DLL_DEBUG_EVENT: 
                // Display a message that the DLL has been unloaded. 
                log.append(LOG_DEBUG," .. unload DLL event\n");
                RemoveDLL((DWORD)d.u.UnloadDll.lpBaseOfDll);

                // call overloady
                D_UnloadDLL(&d);
                break;
                
            case OUTPUT_DEBUG_STRING_EVENT: 
                // Display the output debugging string. 
                log.append(LOG_DEBUG," .. output debug string event\n");

                // call overloady
                D_OutputDebugString(&d);
                break;
                
        } 
        
        // Resume executing the thread that reported the debugging event. 
        
        ContinueDebugEvent(d.dwProcessId, d.dwThreadId, dwContinueStatus); 
        
        return true;

    } else {

        log.appendError(LOG_DEBUG,"no debug event...");

        return false;
    }
}


bool Debugger::SetSingleStep(bool stepping) {

    return SetSingleStep(hThread,stepping);
}


bool Debugger::SetSingleStep(HANDLE hhThread, bool stepping) {
    CONTEXT     ctx;

    ctx.ContextFlags = CONTEXT_CONTROL;
    if ( ! GetThreadContext(hhThread, &ctx) ) {
        log.appendError(LOG_ERROR,"could not get thread context");
        return false;
    }

    if (stepping) {
        ctx.EFlags = ctx.EFlags | EFLAGS_TRAP;
        log.append(LOG_DEBUG,
            "SetSingleStep(): enabled single stepping for thread %08X - EIP %08X\n",
            hhThread,ctx.Eip);
    } else {
        ctx.EFlags = ctx.EFlags & ( 0xFFFFFFFFFF ^ EFLAGS_TRAP) ;
        log.append(LOG_DEBUG,
            "SetSingleStep(): disabled single stepping for thread %08X - EIP %08X\n",
            hhThread,ctx.Eip);
    }

    if ( ! SetThreadContext(hhThread, &ctx) ) {
        log.appendError(LOG_ERROR,"could not set thread context");
        return false;
    }

    return true;
}


void Debugger::Break(void) {
    //
    // Get the main thread's EIP and set a breakpoint 
    //

}


bool Debugger::GetCPUContext(HANDLE hhThread, t_Debugger_CPU *cpu) {
    CONTEXT     ctx;

    ctx.ContextFlags = CONTEXT_FULL;
    if ( ! GetThreadContext(hhThread, &ctx) ) {
        log.appendError(LOG_ERROR,"GetCPUContext(): could not get thread context");
        return false;
    }

    cpu->EAX = ctx.Eax;
    cpu->ECX = ctx.Ecx;
    cpu->EDX = ctx.Edx;
    cpu->EBX = ctx.Ebx;
    cpu->ESI = ctx.Esi;
    cpu->EDI = ctx.Edi;
    cpu->EBP = ctx.Ebp;
    cpu->ESP = ctx.Esp;
    cpu->EIP = ctx.Eip;
    cpu->CS = ctx.SegCs;
    cpu->DS = ctx.SegDs;
    cpu->ES = ctx.SegEs;
    cpu->FS = ctx.SegFs;
    cpu->GS = ctx.SegGs;
    cpu->SS = ctx.SegSs;
    cpu->EFlags = ctx.EFlags;

    log.append(LOG_DEBUG,"CPU Context read at EIP = 0x%08X\n",cpu->EIP);
    return true;
}


bool Debugger::SetCPUContext(HANDLE hhThread, t_Debugger_CPU *cpu) {
    CONTEXT     ctx;

    ctx.Eax = cpu->EAX;
    ctx.Ecx = cpu->ECX;
    ctx.Edx = cpu->EDX;
    ctx.Ebx = cpu->EBX;
    ctx.Esi = cpu->ESI;
    ctx.Edi = cpu->EDI;
    ctx.Ebp = cpu->EBP;
    ctx.Esp = cpu->ESP;
    ctx.Eip = cpu->EIP;
    ctx.SegCs = cpu->CS;
    ctx.SegDs = cpu->DS;
    ctx.SegEs = cpu->ES;
    ctx.SegFs = cpu->FS;
    ctx.SegGs = cpu->GS;
    ctx.SegSs = cpu->SS;
    ctx.EFlags = cpu->EFlags;

    ctx.ContextFlags = CONTEXT_FULL;
    if ( ! SetThreadContext(hhThread, &ctx) ) {
        log.appendError(LOG_ERROR,"SetCPUContext(): could not set thread context");
        return false;
    }
    log.append(LOG_DEBUG,"CPU Context written at EIP = 0x%08X\n",cpu->EIP);

    return true;
}


bool Debugger::SetEIP(HANDLE hhThread, DWORD neweip) {
    CONTEXT     ctx;

    ctx.ContextFlags = CONTEXT_CONTROL;
    if ( ! GetThreadContext(hhThread, &ctx) ) {
        log.appendError(LOG_ERROR,"could not get thread context");
        return false;
    }

    ctx.Eip = neweip;
        
    if ( ! SetThreadContext(hhThread, &ctx) ) {
        log.appendError(LOG_ERROR,"could not set thread context");
        return false;
    }

    log.append(LOG_DEBUG,"Set EIP to 0x%08X\n",ctx.Eip);

    return true;
}


bool Debugger::Disassemble(HANDLE hhThread, DWORD addr, t_disassembly *dis) {
    char            buffer[21];
    unsigned int    buflen = sizeof(buffer)-1;
    DWORD           in;
    t_Debugger_CPU  cpu;
    
    //
    // try to read 20 bytes and if this didn't work go down from there 
    // until only one byte could be read.
    //
    ZeroMemory(buffer,sizeof(buffer));
    while ( ! ReadProcessMemory(hProcess,(LPCVOID)addr,buffer,buflen,&in) ) {
        
        buflen--;
        ZeroMemory(buffer,sizeof(buffer));

        if ( 0 == buflen ) {
            log.append(LOG_WARNING,
                "Disassemble(): could not even read one byte at 0x%08X\n",
                addr);
            return false;
        }
    }

    if ( ! GetCPUContext(hhThread,&cpu) )
        return false;

    if (! Disassemble(addr,buffer,&cpu,dis) ) 
        return false;

    return true;
}


bool Debugger::Disassemble(DWORD addr, char *buffer,
                           t_Debugger_CPU *cpu, t_disassembly *dis) {
    struct instr    cmd;
    unsigned int    s;
    unsigned int    i;
    char            textbuf[1024];
    char            *tp = textbuf;
    int             types[3];

    /*
    struct instr {
        char    mnemonic[16];      // mnemonic for instruction 
        char    dest[32];          // string representation of operand 'dest' 
        char    src[32];           // string representation of operand 'src' 
        char    aux[32];           // string representation of operand 'aux' 
        int     mnemType;          // mnemonic type 
        int     destType;          // operand type for 'dest' 
        int     srcType;           // operand type for 'src' 
        int     auxType;           // operand type for 'aux' 
        int     size;              // size of instruction 
    };
    */

    ZeroMemory(dis,sizeof(t_disassembly));

    //
    // try to disassemble 
    //
    s = disassemble_address(buffer,&cmd);

    if ( 0 == s ) {
        //
        // Disassembly failed
        //
        _snprintf(textbuf,sizeof(textbuf)-1,"db 0x%02X",buffer[0]);
        dis->mnemonic = textbuf;
        dis->size = 0;
        dis->comment = "Illegal Instruction";

        return false;

    } else {
        //
        // Disassembly worked
        //

        //
        // first, check for modifiers such as REP
        //
        if ( 0 != (cmd.mnemType & INS_REPZ)) {
            tp += sprintf(tp,"REP ");
        } 
        if ( 0 != (cmd.mnemType & INS_REPNZ) ){
            tp += sprintf(tp,"REPNZ ");
        } 
        if ( 0 != (cmd.mnemType & INS_LOCK) ){
            tp += sprintf(tp,"LOCK ");
        } 
        if ( 0 != (cmd.mnemType & INS_DELAY) ){
            tp += sprintf(tp,"DELAY ");
        }
        
        //
        // now add the mnemonic
        //
        tp += sprintf(tp,"%s ",cmd.mnemonic);

        // 
        // argument types
        //
        types[0]=cmd.destType;
        types[1]=cmd.srcType;
        types[2]=cmd.auxType;

        //
        // loop through the arguments
        //
        for (i=0; i<3; i++) {

            log.append(LOG_DEBUG,"Disassemble(): type of argument %u is %08X\n",
                i,types[i]);

            //
            // do the text stuff
            //
            switch ( i ) {
            case 0:
                tp += sprintf(tp,"%s", cmd.dest);
                break;
            case 1:
                tp += sprintf(tp,"%s", cmd.src);
                break;
            case 2:
                tp += sprintf(tp,"%s", cmd.aux);
                break;
            }
            if ( (i<2) && (types[i+1]!=OP_UNK) ) tp += sprintf(tp,",");

            //
            // now analyse
            //
            if ( types[i] == OP_UNK) {

                dis->opgood[i] = false;
                
            } else if ( types[i] && OP_REG ) {

                dis->opgood[i] = true;
                
            } else {

                dis->opgood[i] = true;
                
            }   

        } // for all arguments

        //
        // Analyse instruction destination
        //
        log.append(LOG_DEBUG,"Instruction type: %08X\n",cmd.mnemType);

        if ( INS_BRANCH == (cmd.mnemType & INS_TYPE_MASK) ) {

            log.append(LOG_DEBUG, "Instruction is branch, destination is %08X\n", dis->opdata[0]);
            dis->jmpaddr = dis->opdata[0];
            //pedram
            //printf("jmpaddr = src[%s] dest[%s] aux[%s]\n", cmd.src, cmd.dest, cmd.aux);

        } else if ((cmd.mnemType & INS_TYPE_MASK) == INS_BRANCHCC) {
            
            if ( JCondition(buffer,s,cpu) ){
                log.append(LOG_DEBUG,"Instruction is conditional branch,"
                    " destination is %08X (Jump TAKEN)\n",dis->opdata[0]);

            } else {
                log.append(LOG_DEBUG,"Instruction is conditional branch,"
                    " destination is %08X (Jump NOT taken)\n",dis->opdata[0]);
            }

        } else if ((cmd.mnemType & INS_TYPE_MASK) == INS_CALL) {    
        } else if ((cmd.mnemType & INS_TYPE_MASK) == INS_CALLCC) {  
        } else if ((cmd.mnemType & INS_TYPE_MASK) == INS_RET) { 
        } else if ((cmd.mnemType & INS_TYPE_MASK) == INS_LOOP) {    
        } else {
            //
            // Instruction does not affect dataflow directly
            // Therefore, the next instruction should be following this one
            //
            dis->jmpaddr = addr + s;
        }

        dis->size = s;
        dis->mnemonic = textbuf;

        return true;
    }
}


bool Debugger::JCondition(char *buffer, unsigned int blen, t_Debugger_CPU *cpu) {

    if (2 == blen) {
        // 
        // Should be one of the Jcc
        //
        if ( (buffer[0]&0x70) == 0x70 ) {
            switch (buffer[0]&0x0F) {
            case 0x0:   return ( (cpu->EFlags & EFLAGS_OVERFLOW) != 0 );
            case 0x1:   return ( (cpu->EFlags & EFLAGS_OVERFLOW) == 0 );
            case 0x2:   return ( (cpu->EFlags & EFLAGS_CARRY) != 0 );
            case 0x3:   return ( (cpu->EFlags & EFLAGS_CARRY) == 0 );
            case 0x4:   return ( (cpu->EFlags & EFLAGS_ZERO) != 0 );
            case 0x5:   return ( (cpu->EFlags & EFLAGS_ZERO) == 0 );
            case 0x6:   return ( ((cpu->EFlags & EFLAGS_CARRY) !=  0) && ((cpu->EFlags & EFLAGS_ZERO) != 0));
            case 0x7:   return ( ((cpu->EFlags & EFLAGS_CARRY) ==  0) && ((cpu->EFlags & EFLAGS_ZERO) == 0));
            case 0x8:   return ( (cpu->EFlags & EFLAGS_SIGN) != 0);
            case 0x9:   return ( (cpu->EFlags & EFLAGS_SIGN) == 0);
            case 0xA:   return ( (cpu->EFlags & EFLAGS_PARITY) != 0);
            case 0xB:   return ( (cpu->EFlags & EFLAGS_PARITY) == 0);
            case 0xC:   return ( (
                            ((cpu->EFlags & EFLAGS_OVERFLOW)>>4) // this is now on the same position as SIGN
                            ^
                            (cpu->EFlags & EFLAGS_SIGN)
                            ) != 0 );
            case 0xD:   return ( (
                            ((cpu->EFlags & EFLAGS_OVERFLOW)>>4) // this is now on the same position as SIGN
                            ^
                            (cpu->EFlags & EFLAGS_SIGN)
                            ) == 0 );
            case 0xE:   return ( 
                            ((
                            ((cpu->EFlags & EFLAGS_OVERFLOW)>>4) // this is now on the same position as SIGN
                            ^
                            (cpu->EFlags & EFLAGS_SIGN)
                            ) != 0 )
                            ||
                            ( (cpu->EFlags & EFLAGS_ZERO) != 0)
                            );
            case 0xF:   return ( 
                            ((
                            ((cpu->EFlags & EFLAGS_OVERFLOW)>>4) // this is now on the same position as SIGN
                            ^
                            (cpu->EFlags & EFLAGS_SIGN)
                            ) == 0 )
                            &&
                            ( (cpu->EFlags & EFLAGS_ZERO) == 0)
                            );
            default:
                log.append(LOG_ERROR,"This should never happen!\n");
            } // case
        } else {
            log.append(LOG_ERROR,"JCondition(): unknown 2-byte conditional jump opcode\n");
        }
    } else if (3 == blen) {
        //
        // Should be one of the unsigned Jcc
        //
        if ( (buffer[0]==0x0F) && ((buffer[1]&0x80) == 0x80) ) {
            switch (buffer[1]&0x0F) {
            case 0x0:   return ( (cpu->EFlags & EFLAGS_OVERFLOW) != 0 );
            case 0x1:   return ( (cpu->EFlags & EFLAGS_OVERFLOW) == 0 );
            case 0x2:   return ( (cpu->EFlags & EFLAGS_CARRY) != 0 );
            case 0x3:   return ( (cpu->EFlags & EFLAGS_CARRY) == 0 );
            case 0x4:   return ( (cpu->EFlags & EFLAGS_ZERO) != 0 );
            case 0x5:   return ( (cpu->EFlags & EFLAGS_ZERO) == 0 );
            case 0x6:   return ( ((cpu->EFlags & EFLAGS_CARRY) !=  0) && ((cpu->EFlags & EFLAGS_ZERO) != 0));
            case 0x7:   return ( ((cpu->EFlags & EFLAGS_CARRY) ==  0) && ((cpu->EFlags & EFLAGS_ZERO) == 0));
            case 0x8:   return ( (cpu->EFlags & EFLAGS_SIGN) != 0);
            case 0x9:   return ( (cpu->EFlags & EFLAGS_SIGN) == 0);
            case 0xA:   return ( (cpu->EFlags & EFLAGS_PARITY) != 0);
            case 0xB:   return ( (cpu->EFlags & EFLAGS_PARITY) == 0);
            case 0xC:   return ( (
                            ((cpu->EFlags & EFLAGS_OVERFLOW)>>4) // this is now on the same position as SIGN
                            ^
                            (cpu->EFlags & EFLAGS_SIGN)
                            ) != 0 );
            case 0xD:   return ( (
                            ((cpu->EFlags & EFLAGS_OVERFLOW)>>4) // this is now on the same position as SIGN
                            ^
                            (cpu->EFlags & EFLAGS_SIGN)
                            ) == 0 );
            case 0xE:   return ( 
                            ((
                            ((cpu->EFlags & EFLAGS_OVERFLOW)>>4) // this is now on the same position as SIGN
                            ^
                            (cpu->EFlags & EFLAGS_SIGN)
                            ) != 0 )
                            ||
                            ( (cpu->EFlags & EFLAGS_ZERO) != 0)
                            );
            case 0xF:   return ( 
                            ((
                            ((cpu->EFlags & EFLAGS_OVERFLOW)>>4) // this is now on the same position as SIGN
                            ^
                            (cpu->EFlags & EFLAGS_SIGN)
                            ) == 0 )
                            &&
                            ( (cpu->EFlags & EFLAGS_ZERO) == 0)
                            );
            default:
                log.append(LOG_ERROR,"This should never happen!\n");
            } // case
        } else {
            log.append(LOG_ERROR,"JCondition(): unknown 3-byte conditional jump opcode\n");
        }
    } else {
        //
        // shouldn't happen
        //
        log.append(LOG_ERROR,
            "JCondition(): unknown %u-byte conditional jump opcode\n",blen);
    }

    return false;
}


void Debugger::SetGlobalLoglevel(unsigned int level) {
    vector <PEfile*>::iterator  pi;
    
    log.set(level);
    PEimage.log.set(level);
    pi = Files.begin();
    while (pi != Files.end()) {
        (*pi)->log.set(level);
        pi++;
    }
}



// -----------------------------------------------------------------------------
// 
// private functionality
//
// -----------------------------------------------------------------------------


// Function to set priviledges stolen from Dan Kurc by Halvar, 
// in turn stolen from him by FX
bool Debugger::SetDebugPrivilege( HANDLE hProcess ) {
    LUID luid ;
    TOKEN_PRIVILEGES privs ;
    HANDLE hToken = NULL ;
    DWORD dwBufLen = 0 ;
    char buf[1024] ;
    
    ZeroMemory( &luid,sizeof(luid) ) ;
    
    if(! LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &luid ))
        return false ;
    
    privs.PrivilegeCount = 1 ;
    privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED ;
    memcpy( &privs.Privileges[0].Luid, &luid, sizeof(privs.Privileges[0].Luid )
        ) ;
    
    
    if( ! OpenProcessToken( hProcess, TOKEN_ALL_ACCESS,&hToken))
        return false ;
    
    if( !AdjustTokenPrivileges( hToken, FALSE, &privs,
        sizeof(buf),(PTOKEN_PRIVILEGES)buf, &dwBufLen ) )
        return false ;
    
    return true ;
}


bool Debugger::FindModuleName(DWORD ProcessID, string *name) {
    HANDLE          snap;
    MODULEENTRY32   mod;

    mod.dwSize = sizeof(MODULEENTRY32);
    if ( INVALID_HANDLE_VALUE == 
        (snap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,ProcessID)) ){
        log.append(LOG_ERROR,"Failed to get Snapshot on Process\n");
        return false;
    }

    if ( Module32First(snap,&mod) ) {
        log.append(LOG_DEBUG,"Module 1 name and path: %s, %s\n",
            mod.szModule, mod.szExePath);
        (*name) = mod.szExePath;
        CloseHandle(snap);
        return true;
    } else {
        log.append(LOG_ERROR,"Failed to get module information for snapshot\n");
        CloseHandle(snap);
        return false;
    }
}


t_Debugger_thread *Debugger::AddThread(DWORD threadID, HANDLE ht, DWORD lpStartAddress, DWORD lpThreadLocalBase) {
    t_Debugger_thread   *td = new(t_Debugger_thread);
    t_Debugger_CPU      cpu;

    td->ThreadID = threadID;
    td->hThread = ht;
    td->startAddress = (DWORD)lpStartAddress;
    td->TLB = (DWORD)lpThreadLocalBase;

    ReadThreadBasicInformation(td->hThread, &(td->basics) );

    Threads.push_back(td);

    log.append(LOG_DEBUG,"Thread handle %X (TLB %08X, Start %08X) added\n",
        td->hThread, td->startAddress, td->TLB );

    log.append(LOG_DEBUG," TEB Base Address: %08X\n",td->basics.TebBaseAddress);

    if ( ! ReadTEB(td->hThread) ) {
        log.append(LOG_ERROR,"Failed to read TEB at %08X\n",
            td->basics.TebBaseAddress);
    } else {
        log.append(LOG_DEBUG,"Thread ID to this HANDLE: %u\n",
            td->ThreadEnvironmentBlock.ClientId.UniqueThread);
        
        if ( td->ThreadID != (DWORD) td->ThreadEnvironmentBlock.ClientId.UniqueThread) {
            log.append(LOG_WARNING,
                "Thread ID for thread %08X is %08X, TEB->ClientId says %08X\n",
                td->hThread,td->ThreadID, td->ThreadEnvironmentBlock.ClientId.UniqueThread);
        }
    }

    GetCPUContext(td->hThread,&cpu);
    td->StackP = cpu.ESP;
    log.append(LOG_DEBUG,"Thread's Stack pointer: %08X\n",td->StackP);

    return td;
}


void Debugger::RemoveThread(DWORD threadID) {
    vector <t_Debugger_thread*>::iterator   it;

    for (it=Threads.begin(); it<Threads.end(); it++) {
        if ( (*it)->ThreadID == threadID ) {
            log.append(LOG_DEBUG,
                "RemoveThread(): Removing Thread ID %u (HANDLE %08X)\n",
                (*it)->ThreadID, (*it)->hThread);
            Threads.erase(it);
            break;
        }
    }
}


void Debugger::RemoveDLL(DWORD BaseAddress) {
    vector <PEfile*>::iterator      it;

    for (it = Files.begin(); it<Files.end(); it++) {
        if ( (*it)->winpe->ImageBase == BaseAddress) {
            log.append(LOG_DEBUG,
                "RemoveDLL(): Removing DLL at 0x%08X (%s)\n",
                (*it)->winpe->ImageBase, (*it)->internal_name.c_str());
            Files.erase(it);
            break;
        }
    }
}


void Debugger::default_unhandled(DEBUG_EVENT *d) {
    active=false;
}