#include <string>
#include <vector>
#include <map>

using namespace std;

#pragma warning ( disable: 4786 ) // doesn't work anyway

#include "log.hpp"
#include "debugger.hpp"
#include "pecoff.hpp"
#include "tracer.hpp"
#include "parser/tracedefs.hpp"


Tracer::Tracer() {
	log.Name="Tracer";
	Stepping.General = false;
	Stepping.PageBlock = false;

	Analysis.FormatGuess = false;
	Analysis.StackDelta = false;
	Analysis.StackDeltaV = 0;
	Analysis.CodePage = CP_ACP;

	rOpenFunc = NULL;
	rCloseFunc = NULL;
}


Tracer::~Tracer() {
	t_PageMap_Iterator		pmi;
	t_BufferMap_Iterator	bmi;
	unsigned int			size,i;

	for ( pmi = Pages.begin(); pmi != Pages.end(); ++pmi )
		delete (pmi->second);
	Pages.clear();

	for ( bmi = Buffers.begin(); bmi != Buffers.end(); ++bmi )
		delete ( bmi->second );
	Buffers.clear();

	log.append(LOG_DEBUG,"~Tracer(): Freeing %u results\n",Results.size());
	size = Results.size();
	for (i=0; i<size; i++) {
		delete(Results.back());
		Results.pop_back();
	}

	log.append(LOG_DEBUG,"~Tracer(): Freeing %u open traces\n",OpenTraces.size());
	size=OpenTraces.size();
	for (i=0; i<size; i++) {
		delete(OpenTraces.back());
		OpenTraces.pop_back();
	}
}


bool Tracer::ReBuildMemoryMap(void) {
	t_MemoryMap_Iterator					mit;
	vector <t_Debugger_thread*>::iterator	thi;
	t_Debugger_memory						*pg;

	if ( ! Debugger::ReBuildMemoryMap() ) 
		return false;
	
	mit = MemoryMap.begin();
	while ( mit != MemoryMap.end() ) {
		
		if ( Pages.find( mit->first ) != Pages.end() ) {
			log.append(LOG_DEBUG,
				"ReBuildMemoryMap: fixing permission data for page %08X\n",
				mit->first);
			mit->second->basics.Protect = 
				(Pages[ mit->first ])->OriginalProtection;
		}
		mit++;
	}

	thi = Threads.begin();
	while ( thi != Threads.end() ){
		if ( NULL != (pg=FindPageByAddress((*thi)->StackP,1)) ){
			pg->Name = "stack of Thread";
		}
		thi++;
	}

	return true;
}


DWORD Tracer::E_FirstBreakpoint(DEBUG_EVENT *d) {
	log.append(LOG_DEBUG,"Initial Breakpoint at %08X\n",
		d->u.Exception.ExceptionRecord.ExceptionAddress);

	return DBG_CONTINUE;
}


DWORD Tracer::E_Breakpoint(DEBUG_EVENT *d) {
	t_Activevector_Iterator		avi;
	t_Tracer_OpenTr				*rtcaller;
	t_OpenTracevector_Iterator	reti;
	t_Exclude_Iterator			exi;


	log.append(LOG_DEBUG,"Breakpoint at %08X\n",
		d->u.Exception.ExceptionRecord.ExceptionAddress);

	// no, it's not called avi because it's as slow as the movies
	avi = ActiveTraces.begin();
	while ( avi != ActiveTraces.end() ) {

		if ( (*avi).Address == (DWORD)d->u.Exception.ExceptionRecord.ExceptionAddress ) {
			//
			// This is a traced function
			//
			log.append(LOG_DEBUG,"Breakpoint caused by traced function %s\n",
				(*avi).Definition->Name.c_str());
			
			if ( NULL == (rtcaller = OpenTraceRecord(d,(*avi).Definition)) ){
				log.append(LOG_ERROR,"Could not open trace record\n");
			} else {
				(*avi).returns.push_back ( rtcaller );
				bpx( rtcaller->caller );
				log.append(LOG_DEBUG,"Breakpoint for return from %s set at %08X\n",
					(*avi).Definition->Name.c_str(), rtcaller->caller);
			}
			return DBG_CONTINUE;

		} else {
			//
			// May be this is a return from a traced function
			//
			reti = (*avi).returns.begin();
			while ( reti != (*avi).returns.end() ) {
				if ( 
					((*reti)->caller == (DWORD)d->u.Exception.ExceptionRecord.ExceptionAddress) 
					&& 
					((*reti)->ThreadID == (DWORD)d->dwThreadId )
					) {
					//
					// return from traced function
					//
					log.append(LOG_DEBUG,"Return from traced function %s to %08X\n",
						(*avi).Definition->Name.c_str(), (*reti)->caller );

					log.append(LOG_DEBUG,"ReEstablishing breakpoint at %08X\n",
						(*avi).Address);
					bpx( (*avi).Address );

					CloseTraceRecord(d, (*reti));

					//
					// Delete this vector entry (memory is already freed by 
					// CloseTraceRecord()... or rather passed to Results)
					//
					(*avi).returns.erase(reti);
			
					log.append(LOG_DEBUG,"Open returns for '%s': %u\n",
						(*avi).Definition->Name.c_str(), (*avi).returns.size());

					// 
					// no matter what, the iterator is toast by now so
					// exit loop immediately
					//
					//reti = (*avi).returns.end();
					return DBG_CONTINUE;
				}
				reti++;
			}
		}

		avi++;
	}

	
	if (Buffers.size() > 0) {
		//
		// It was not one of the traced functions, may be it's one of the 
		// exclude functions for buffer tracing
		//
		if ( ExcludeRet == (DWORD)d->u.Exception.ExceptionRecord.ExceptionAddress) {
			log.append(LOG_INFO,"Buffer tracing resumed\n");
			EnableAllTraces();
			ExcludeRet = 0;
		} else {
			exi = Excludes.begin();
			while (exi != Excludes.end()) {
				if ( (*exi).Address == (DWORD)d->u.Exception.ExceptionRecord.ExceptionAddress ){
					log.append(LOG_DEBUG,"Exclude breakpoint found\n");
					ExcludeRet = GetCaller(d->dwThreadId);
					bpx(ExcludeRet);
					DisableAllTraces();
					log.append(LOG_INFO,"Buffer tracing suspended until %08X\n",
						ExcludeRet);
					return DBG_CONTINUE;
				}
				exi ++;
			}
		}
	}

	// 
	// we did not claim responsibility for this 
	// breakpoint, so we can hardly say DBG_CONTINUE
	//
	return DBG_EXCEPTION_NOT_HANDLED;
}


DWORD Tracer::E_AccessViolation(DEBUG_EVENT *d) {
	vector <t_Tracer_Buffer *>::iterator	it;
	t_Tracer_Buffer				*buf;
	DWORD						AVaddr;
	bool						AVwrite;
	bool						ItWasMe = false;
	t_Debugger_memory			*pg;
	t_Tracer_Page				*tp;
	DWORD						oprot;
	bool						BufferDeleted = false;


	//
	// Get info on the AV
	//
	AVwrite = 
		d->u.Exception.ExceptionRecord.ExceptionInformation[0] == 0?
		false:true;

	AVaddr = (DWORD)d->u.Exception.ExceptionRecord.ExceptionInformation[1];

	log.append(
		d->u.Exception.dwFirstChance != 0?LOG_DEBUG:LOG_WARNING,
		"AccessViolation EIP = %08X while %s %08X\n",
		(DWORD)d->u.Exception.ExceptionRecord.ExceptionAddress,
		AVwrite==true?"writing to":"reading from",
		AVaddr);



	//
	// whether or not this was one of our traced buffers, 
	// check if it's a page we blocked for the tracing
	//
	if ( NULL == (pg = FindPageByAddress(AVaddr,1)) ){
		log.append(LOG_WARNING,"AccessViolation EIP = %08X while %s %08X\n",
			(DWORD)d->u.Exception.ExceptionRecord.ExceptionAddress,
			AVwrite==true?"writing to":"reading from",
			AVaddr);
		log.append(LOG_WARNING,
			"E_AccessViolation: Offending access not in mapped memory?\n");
	} else {
		if ( Pages.end() != Pages.find( pg->address ) ) {

			tp = Pages[ pg->address ];

			if ( tp->TemporaryRestore ) {

				MEMORY_BASIC_INFORMATION	bi;

				VirtualQueryEx(hProcess,(LPVOID)pg->address,&bi,sizeof(bi));
				log.append(LOG_WARNING,"%08X should be fine. Protections: I %08X, C %08X\n",
					pg->address,bi.AllocationProtect,bi.Protect);

				log.append(LOG_WARNING,
					"Page access blocked by us for page %08X, but should\n"
					"be restored already.\n"
					"Doing exactly nothing!\n",
					pg->address);

			} else {
				
				//
				// we claim responsibility 
				//

				log.append(LOG_DEBUG,
					"Page access blocked by us for page %08X, restoring.\n",
					pg->address);
				
				for ( it = tp->Buffers.begin(); it < tp->Buffers.end(); it++) {
					if ( IS_A_IN_B( AVaddr, 1, (*it)->address, (*it)->Size) ){
						log.append(LOG_DEBUG,
							"This is the traced buffer %08X(%u)\n",
							(*it)->address, (*it)->Size);
						ItWasMe=true;
						buf = (*it);
					}
				} // for all buffers of this page


				if ( ItWasMe ) {
					//
					// This is one of the traced buffers being accessed
					//
					log.append(LOG_VERBOSE,
						"Traced buffer access:\n"
						" %08X %s %08X (Buffer %08X(%u))\n",
						(DWORD)d->u.Exception.ExceptionRecord.ExceptionAddress,
						AVwrite?"writing to":"reading from",
						AVaddr,
						buf->address,
						buf->Size);

					if (AVwrite) {
						buf->wrCount++;
						log.append(LOG_VERBOSE,"%uth time writing\n",buf->wrCount);
					}

					if (buf->wrCount > 4) {
						log.push(LOG_DEBUG);
						RemoveTraceBuffer(buf);
						log.pop();
					}

				}
				

				//
				// Restore !
				// 
				if ( ! VirtualProtectEx(hProcess,(LPVOID)tp->address,
					tp->Size,
					tp->OriginalProtection,
					&oprot) ){

					log.append(LOG_ERROR,
						"Could not restore permissions for page %08X\n",
						tp->address);

				} else {
					//
					// Access level restored, so claim the AV as resolved
					//
					log.append(LOG_DEBUG,
						"Restored permissions for page %08X to %08X (from %08X)\n",
						tp->address,tp->OriginalProtection,oprot);

					//
					// Only singlestep if the buffer is still traced
					//
					if (!BufferDeleted) {
						SetSingleStep(
							FindThread((DWORD)(d->dwThreadId))->hThread,
							true);
						Stepping.General = true;
						Stepping.PageBlock = true;
						
						tp->TemporaryRestore = true;
					}

					return DBG_CONTINUE;
				}
			} 

		} else {
			
			log.append(LOG_DEBUG,
				"Page %08X NOT blocked by us\n",
				pg->address);
		}
	} // FindPageByAddress
			
	return DBG_EXCEPTION_NOT_HANDLED;
}


DWORD Tracer::E_SingleStep(DEBUG_EVENT *d) {
	t_PageMap_Iterator	mit;
	//
	// Speed up the whole thing by remembering if we had any 
	// good reason to SingleStep 
	//
	if ( Stepping.General ) {

		Stepping.General = false;

		//
		// for restoring Page Blocks ?
		//
		if ( Stepping.PageBlock ) {

			Stepping.PageBlock = false;

			//
			// Deal with page block restore
			//
			for ( mit = Pages.begin(); mit != Pages.end(); ++mit) {
			
				if ( mit->second->TemporaryRestore ) {
					log.append(LOG_DEBUG,
						"SingleStep (%08X): Found %08X temporarily restored, blocking\n",
						(DWORD)d->u.Exception.ExceptionRecord.ExceptionAddress,
						mit->first);
					
					if ( ! VirtualProtectEx(hProcess,
						(LPVOID)mit->first,
						mit->second->Size,
						PAGE_NOACCESS,
						&(mit->second->OriginalProtection))
						) {
						log.appendError(LOG_ERROR,"Could not block page %08X",
							mit->first);
					} else {
						log.append(LOG_DEBUG,"Blocked page %08X again.\n",
							mit->first);
						mit->second->TemporaryRestore = false;
					}
				}
			}
		} // if (Stepping.PageBlock)
		
		if ( Stepping.SingleStepTrace ) {

			if ( (DWORD)d->u.Exception.ExceptionRecord.ExceptionAddress 
				!= Stepping.LastAddr ) {
				t_Debugger_CPU		cpu;

				if (Stepping.AddrCnt > 0)
					log.append(LOG_INFO," repeated %u times\n",
					Stepping.AddrCnt);

				GetCPUContext(
					FindThread((DWORD)(d->dwThreadId))->hThread
					,&cpu);

				log.append(LOG_INFO,"%08X ( EIP %08X  ESP %08X )\n",
					(DWORD)d->u.Exception.ExceptionRecord.ExceptionAddress,
					cpu.EIP,cpu.ESP);
				Stepping.LastAddr =
					(DWORD)d->u.Exception.ExceptionRecord.ExceptionAddress;
				Stepping.AddrCnt=0;
			} else {
				Stepping.AddrCnt++;
			}


			SetSingleStep(
						FindThread((DWORD)(d->dwThreadId))->hThread,
						true);
			Stepping.General = true;
		}


		return DBG_CONTINUE;

	} else { // if (Stepping.General)
		//
		// No, not us
		//
		return DBG_EXCEPTION_NOT_HANDLED;
	}
}


DWORD Tracer::D_CreateThread(DEBUG_EVENT *d) {
	ReBuildMemoryMap();
	return DBG_CONTINUE;
}


DWORD Tracer::D_ExitThread(DEBUG_EVENT *d) {
	ReBuildMemoryMap();
	return DBG_CONTINUE;
}


bool Tracer::LoadTraceDefinitions(char *filename) {
	t_Tracevector_Iterator		it;

	if ( LoadTraceDef(&log,filename) ) {
		//
		// Copy trace data from TraceDefinitions (yacc-transport vehicle)
		// to classes member structure
		//
		it = TraceDefinitions.begin();
		while ( it != TraceDefinitions.end() ) {
			Traces.push_back( (*it) );
			it++;
		}
		TraceDefinitions.clear();

		log.append(LOG_INFO,"%u function trace definitions loaded from %s\n",
			Traces.size(), filename);

		return true;
	} else {
		log.append(LOG_ERROR,"Failed to load trace definitions from %s\n",
			filename);
		return false;
	}
}


bool Tracer::GetTraceString(t_Tracedef_Def *t, string *s) {
	t_Argumentvector_Iterator	at;
	char						*str;
	char						*p;

	str = new char[4096];
	p = str;

	if ( t->ReturnMatch.length() >0 )
			p += sprintf(p,"(must match '%s') ",t->ReturnMatch.c_str() );

	p += sprintf(p,"%s ", GetTypeName(t->Return));

	if ( t->Module.length() > 0) 
		p += sprintf(p,"[%s]:",t->Module.c_str());

	p += sprintf(p,"%s (", t->Name.c_str() );
		
	at = t->Args.begin();
	while ( at != t->Args.end() ){
		if ( (*at).Dir != unknown )
			p += sprintf(p,"%s ", GetDirName ( (*at).Dir ) );
		p += sprintf(p,"%s", GetTypeName ( (*at).Type ) );
		if ( (*at).Name.length() != 0)
			p += sprintf(p," %s", (*at).Name.c_str() );
		at++;
		if ( at != t->Args.end()) 
			p += sprintf(p,", ");
	}

	p += sprintf(p,")");

	(*s) = str;

	return true;
}


bool Tracer::ActivateTraces(void) {

#define ADD_AND_REINITIALIZE	{ func.returns.clear(); func.Definition = &(*trcs); ActiveTraces.push_back ( func ); \
									bpx( func.Address ); cnt++; FuncFound=true; }

	unsigned int				cnt = 0;
	t_Tracevector_Iterator		trcs;
	t_Tracer_Function			func;
	vector <PEfile*>::iterator	DLL;
	bool						FuncFound;


	ActiveTraces.clear();
	OpenTraces.clear();

	for (trcs = Traces.begin(); trcs < Traces.end(); trcs++) {
		
		func.Address = 0;
		func.Definition = NULL;
		func.returns.clear();
		FuncFound = false;

		if ( ((*trcs).Name.length()>2)
			&&
			(((*trcs).Name.c_str())[0] == '0')
			&&
			(((*trcs).Name.c_str())[1] == 'x')
			) {
			//
			// ok, this looks like a straight forward address
			//
			func.Address = strtoul((*trcs).Name.c_str(),(char **)NULL,16);
			
			log.append(LOG_DEBUG,"Converted %s to %08X\n",
				(*trcs).Name.c_str(),func.Address);
			
			ADD_AND_REINITIALIZE;

		} else {
			//
			// function name
			// First see if there are any exports in the main image
			// that match this name
			//

			func.Address = PEimage.ExportByName( (char *) (*trcs).Name.c_str() );

			if ( 0x00 == func.Address ) {
				//
				// Hmm, that was not an export from the main image,
				// which is unlikely to begin with. Check the DLLs.
				//
				for ( DLL = Files.begin(); DLL < Files.end(); DLL++) {

					if ( (*trcs).Module.length() > 0)
						if ( _stricmp( (*DLL)->internal_name.c_str(), (*trcs).Module.c_str()) ){
							log.append(LOG_DEBUG,"Module name %s != %s\n",
								(*DLL)->internal_name.c_str(), (*trcs).Module.c_str());
							continue;
						}

					if ( 0x00 != (func.Address = (*DLL)->ExportByName( (char *) (*trcs).Name.c_str() )) ){
						//
						// yes, function found
						//
						ADD_AND_REINITIALIZE;
						
						log.append(LOG_INFO,"Tracing for %s:%s (%08X) activated\n",
							(*DLL)->internal_name.c_str(), (*trcs).Name.c_str(), func.Address);
						
						//
						// We don't break here, since there might be multiple DLLs 
						// exporting the same name but under a different DLL:Ordinal 
						// key conbination
						//
						
						//break;
					} else {
						log.append(LOG_DEBUG,"Function '%s' not found in %s\n",
							(*trcs).Name.c_str(), (*DLL)->internal_name.c_str());
					}
				}
			} // not in main image exports
			else {
				log.append(LOG_DEBUG,"Function '%s' exported by main image (%08X)\n",
					(*trcs).Name.c_str(), func.Address );

				ADD_AND_REINITIALIZE;
			}
		}

		//
		// Now, let's see if we somehow determined where this 
		// function is
		//

		if ( ! FuncFound ) {
			//
			// no, didn't work
			//
			log.append(LOG_ERROR,"ActivateTraces(): Function %s not found\n",
				(*trcs).Name.c_str());	
		} 	
		
	} // for all functions to trace

	ReBuildMemoryMap();

	//
	// experimental
	AddExclude("RtlAllocateHeap");
	AddExclude("RtlCreateHeap");
	AddExclude("RtlDestroyHeap");
	AddExclude("RtlFreeHeap");
	AddExclude("RtlReAllocateHeap");
	// /experimental
	//

	return cnt>0?true:false;
}


void Tracer::SetOpenRecordFunction(void (*fname)(t_Tracer_OpenTr*)) {

	rOpenFunc = fname;

}


void Tracer::SetCloseRecordFunction(void (*fname)(t_Tracer_OpenTr*)) {

	rCloseFunc = fname;

}
	

//
// HIGHLY experimental
//


bool Tracer::TraceBuffer(DWORD addr, DWORD size) {
	t_Tracer_Buffer			*tb;

	if ( Buffers.find( addr ) != Buffers.end() ) {
		log.append(LOG_ERROR,"Buffer at %08X is already traced\n");
		return false;
	}

	if ( NULL == (tb=new(t_Tracer_Buffer)) ){
		log.append(LOG_ERROR,"Could not allocate %u bytes\n",
			sizeof(t_Tracer_Buffer));
		return false;
	}

	//
	// Guard the page
	//
	if ( ! GuardBufferPage(tb,addr,size) ) {
		delete(tb);
		return false;
	} 

	tb->address = addr;
	tb->Size = size;
	tb->wrCount = 0;
	Buffers[addr] = tb;

	return true;
}


bool Tracer::RemoveTraceBuffer(t_Tracer_Buffer *buf) {
	t_BufferMap_Iterator					bmi;
	t_PageMap_Iterator						pmi;
	vector <t_Tracer_Buffer *>::iterator	vbi;

	if ( Buffers.end() == (bmi=Buffers.find(buf->address) ) ){
		log.append(LOG_ERROR,
			"RemoveTraceBuffer(): %08X not in map\n",buf->address);
		return false;
	}

	if ( Pages.end() == (pmi=Pages.find( buf->Page->address )) ){
		log.append(LOG_ERROR,
			"RemoveTraceBuffer(): Could not find page of buffer %08X\n",
			buf->address);
		return false;
	}

	Buffers.erase( bmi );

	vbi = pmi->second->Buffers.begin();
	while (vbi != pmi->second->Buffers.end() ) {
		if ((*vbi)->address == buf->address) {
			log.append(LOG_DEBUG,
				"Erasing buffer %08X from Page %08X\n",
				(*vbi)->address,pmi->first);
			pmi->second->Buffers.erase(vbi);
		}
	}

	if ( 0 == pmi->second->Buffers.size() ) {
		log.append(LOG_DEBUG,
			"No buffers left in page %08X, deleting\n",
			pmi->first);
		Pages.erase( pmi );
	}

	log.append(LOG_VERBOSE,"Buffer %08X removed from trace\n",
		buf->address);

	delete(buf);

	return true;
}


bool Tracer::DisableAllTraces(void) {
	t_PageMap_Iterator		pmi;
	DWORD					op;

	pmi = Pages.begin();
	while ( pmi != Pages.end() ) {
		log.append(LOG_DEBUG,"Temporarily restoring page %08X\n",
			pmi->first);

		if ( ! VirtualProtectEx(hProcess,
			(LPVOID)pmi->second->address,
			pmi->second->Size,
			pmi->second->OriginalProtection,
			&op) ){

			log.append(LOG_ERROR,
				"DisableAllTraces(): failed to unblock Page %08X\n",
				pmi->first);
			return false;
		}
		pmi->second->TemporaryRestore = true;
		pmi++;
	}

	return true;
}


bool Tracer::EnableAllTraces(void) {
	t_PageMap_Iterator		pmi;
	t_Exclude_Iterator		exi;

	pmi = Pages.begin();
	while ( pmi != Pages.end() ) {
		log.append(LOG_DEBUG,"ReBlocking access to page %08X\n",
			pmi->first);

		if ( ! VirtualProtectEx(hProcess,
			(LPVOID)pmi->second->address,
			pmi->second->Size,
			PAGE_NOACCESS,
			&(pmi->second->OriginalProtection) ) ){

			log.append(LOG_ERROR,
				"DisableAllTraces(): failed to block Page %08X\n",
				pmi->first);
			return false;
		}
		pmi->second->TemporaryRestore = false;
		pmi++;
	}

	exi = Excludes.begin();
	while ( exi != Excludes.end() ) {
		bpx( (*exi).Address );
		exi++;
	}

	return true;
}


bool Tracer::AddExclude(char *f) {
	vector <PEfile*>::iterator	DLL;
	t_Tracer_Exclude			ex;

	if ( 0 != (ex.Address = PEimage.ExportByName(f)) ) {
		ex.Name = f;
	} else {
		DLL = Files.begin();
		while ( DLL != Files.end() ) {
			if ( 0 != (ex.Address = (*DLL)->ExportByName(f)) ) {
				ex.Name = f;
				break;
			}
			DLL++;
		}
	}

	if (ex.Name.length() == 0) {
		log.append(LOG_DEBUG,"Failed to add exclude %s\n",f);
		return false;
	} else {
		Excludes.push_back(ex);
		bpx(ex.Address);
		log.append(LOG_DEBUG,"Added exclude %s\n",f);
		return true;
	}
}


bool Tracer::SingleStepTrace(void) {

	SetSingleStep(hThread,true);
	Stepping.General = true;
	Stepping.SingleStepTrace = true;

	log.append(LOG_INFO,"Single stepping main thread\n");
	
	return true;
}


// -------------------------------------------------------------------
//
// Protected functionality
//
// -------------------------------------------------------------------


t_Tracer_OpenTr *Tracer::OpenTraceRecord(DEBUG_EVENT *d, t_Tracedef_Def *def) {
	t_Debugger_CPU			cpu;
	t_Tracer_OpenTr			*open;
	HANDLE					hhThread;
	DWORD					StackDW;
	DWORD					espc;
	t_Argumentvector_Iterator	atv;
	t_Tracedef_Argument		a;


	if ( NULL == (open = new(t_Tracer_OpenTr)) ){
		log.append(LOG_ERROR,"Could not allocate %u bytes\n",
			sizeof(t_Tracer_OpenTr));
		return NULL;
	}

	open->ThreadID = d->dwThreadId;
	open->Definition = def;

	hhThread = FindThread(d->dwThreadId)->hThread;
	if ( ! GetCPUContext(hhThread,&cpu) ){
		log.append(LOG_ERROR,"OpenTraceRecord(): Could not get CPU context\n");
		delete(open);
		return 0x00;
	}

	if ( ! ReadProcessMemory(
		hProcess,
		(LPCVOID)cpu.ESP,
		&StackDW,
		sizeof(StackDW),
		NULL) ){
	
		log.append(LOG_ERROR,
			"OpenTraceRecord(): could not read process memory at %08X\n",
			cpu.ESP);
		delete(open);
		return 0x00;
	}

	open->caller = StackDW;		// The return address is on the stack
	espc=cpu.ESP+4;				// first argument is 4 above the return address

	atv = def->Args.begin();
	while ( atv != def->Args.end() ) {

		a.data.address = 0x00;
		a.comment = "";

		a.Type = (*atv).Type;
		a.Name = (*atv).Name;
		a.Dir = (*atv).Dir;

		if ( ! ReadProcessMemory(
			hProcess,
			(LPCVOID)espc,
			&StackDW,
			sizeof(StackDW),
			NULL) ){
			
			log.append(LOG_ERROR,
				"OpenTraceRecord(): could not read process memory at %08X\n",
				espc);
			delete(open);
			return 0x00;
		}

		a.StackAddr = espc;

		espc += Tracer_Type_Size[(*atv).Type];

		//
		// read the value
		//
		switch ( (*atv).Type ) {
		case tr_VOID:		
			// do nothing
			break;
		case tr_INT:
			a.data.value = StackDW;
			break;
		case tr_CHAR:
			a.data.c = (char)(StackDW&0xFF);
			break;
		case tr_PVOID:		
			a.data.address = StackDW;
			AnalyseStack( a.data.address, open);
			break;
		case tr_PINT:
			a.data.address = StackDW;
			break;
		case tr_PCHAR:
			a.data.address = StackDW;
			//
			// Only analyse if not outgoing
			//
			if ( out != a.Dir ) {
				AnalysePCHAR( a.data.address, false, &(a.comment) );
				AnalyseStack( a.data.address, open);
			} else {
				a.comment="\"\"";
			}
			break;
		case tr_PFMTCHAR:
			a.data.address = StackDW;
			//
			// Only analyse if not outgoing
			//
			if ( out != a.Dir ) {
				AnalysePCHAR( a.data.address, false, &(a.comment) );
				AnalyseStack( a.data.address, open);
				if ( (a.comment.length()>2) 
					&& (a.comment.find("%") == string::npos) )
					open->Notes += "No format specifier, potential format string vulnerability.\n";
			} else {
				a.comment="\"\"";
			}
			break;
		case tr_PWCHAR:
			a.data.address = StackDW;
			//
			// Only analyse if not outgoing
			//
			if ( out != a.Dir ) {
				AnalysePCHAR( a.data.address, true, &(a.comment) );
				AnalyseStack( a.data.address, open);
			} else {
				a.comment="\"\"";
			}
			break;
		case tr_PFMTWCHAR:
			a.data.address = StackDW;
			//
			// Only analyse if not outgoing
			//
			if ( out != a.Dir ) {
				AnalysePCHAR( a.data.address, true, &(a.comment) );
				AnalyseStack( a.data.address, open);
				if ( (a.comment.length()>2) 
					&& (a.comment.find("%") == string::npos) )
					open->Notes += "No format specifier, potential format string vulnerability.\n";
			} else {
				a.comment="\"\"";
			}
			break;
		default:
			log.append(LOG_ERROR,"OpenTraceRecord(): Unknown argument type!\n");
		}

		open->InArgs.push_back(a);
		atv++;
	}

	OpenTraces.push_back(open);

	// call callback function
	if ( NULL != rOpenFunc ) 
		(*rOpenFunc)(open);

	return (open);
}


bool Tracer::CloseTraceRecord(DEBUG_EVENT *d, t_Tracer_OpenTr *open) {
	t_Debugger_CPU			cpu;
	HANDLE					hhThread;
	DWORD					StackDW;
	DWORD					espc;
	t_Argumentvector_Iterator	atv;
	t_Tracedef_Argument		a;
	t_OpenTracevector_Iterator	oti;
	bool					Match = false;
	bool					MatchOnRet = false;
	string					retstr;


	//
	// First, mark the trace as no longer open (even if we fail later)
	//
	for ( oti = OpenTraces.begin(); oti < OpenTraces.end(); oti++) {
		if ( (*oti) == open ) {
			log.append(LOG_DEBUG,"Open Trace record found, deleting\n");
			OpenTraces.erase( oti );
			break;
		}
	}


	hhThread = FindThread(d->dwThreadId)->hThread;

	if ( ! GetCPUContext(hhThread,&cpu) ){
		log.append(LOG_ERROR,"AddTraceRecord(): Could not get CPU context\n");
		return false;
	}


	//
	// Extract the return value and potentially a returned string
	//
	
	switch ( open->Definition->Return ) {
	case tr_VOID:		
		open->Return.value = 0x00;
		break;
	case tr_INT:
	case tr_PINT:
		open->Return.value = cpu.EAX;
		break;
	case tr_PVOID:
		AnalyseStack( cpu.EAX, open);
		open->Return.value = cpu.EAX;
		break;
	case tr_CHAR:
		open->Return.c=(char)(cpu.EAX&0xFF);
		break;
	case tr_PCHAR:
	case tr_PFMTCHAR:
		MatchOnRet = true;
		open->Return.address = cpu.EAX;
		AnalysePCHAR( cpu.EAX, false, &(retstr) );
		AnalyseStack( cpu.EAX, open);
		break;
	case tr_PWCHAR:
	case tr_PFMTWCHAR:
		MatchOnRet = true;
		open->Return.address = cpu.EAX;
		AnalysePCHAR( cpu.EAX, true, &(retstr) );
		AnalyseStack( cpu.EAX, open);
		break;
	default:
		log.append(LOG_ERROR,"CloseTraceRecord(): Unknown return type\n");
	}
	
	espc=cpu.ESP;
	
	atv = open->InArgs.begin();
	while ( atv != open->InArgs.end() ) {
		
		a.data.address = 0x00;
		a.comment = "";
		
		a.Type = (*atv).Type;
		a.Name = (*atv).Name;
		a.Dir = (*atv).Dir;

		
		if ( ! ReadProcessMemory(
			hProcess,
			(LPCVOID) (*atv).StackAddr,
			&StackDW,
			sizeof(StackDW),
			NULL) ){
			
			log.append(LOG_ERROR,
				"CloseTraceRecord(): could not read process memory at %08X\n",
				(*atv).StackAddr);
			return false;
		}
		
		switch ( (*atv).Type ) {
		case tr_VOID:		
			// do nothing
			break;
		case tr_INT:
			a.data.value = StackDW;
			break;
		case tr_CHAR:
			a.data.c = (char)(StackDW&0xFF);
			break;
		case tr_PVOID:		
		case tr_PINT:
			a.data.address = StackDW;
			break;
		case tr_PCHAR:
		case tr_PFMTCHAR:
			a.data.address = StackDW;

			// 
			// only do for outgoing or both
			//
			if ( (*atv).Dir != in ) {

				if ( (0 == a.data.address) && ( 0 != (*atv).data.address ) ) {
					log.append(LOG_VERBOSE,
						"Inspecting former buffer location of %s's argument\n",
						open->Definition->Name.c_str());
					AnalysePCHAR( (*atv).data.address, false, &(a.comment) );
				} else {
					AnalysePCHAR( a.data.address, false, &(a.comment) );
				}
				//
				// If MatchOnRet is not set 
				// copy this string over to the one used by the matching later
				//
				if ( (!MatchOnRet) && (a.Dir != in) ) {
					retstr = a.comment;
					MatchOnRet = true;
				}
			} else {
				a.comment="\"\"";
			}
			
			break;
		case tr_PWCHAR:
		case tr_PFMTWCHAR:
			a.data.address = StackDW;

			if ( (*atv).Dir != in ) {

				if ( (0 == a.data.address) && ( 0 != (*atv).data.address ) ) {
					log.append(LOG_VERBOSE,
						"Inspecting former buffer location of %s's argument\n",
						open->Definition->Name.c_str());
					AnalysePCHAR( (*atv).data.address, true, &(a.comment) );
				} else {
					AnalysePCHAR( a.data.address, true, &(a.comment) );
				}
				//
				// If MatchOnRet is not set 
				// copy this string over to the one used by the matching later
				//
				if ( (!MatchOnRet) && (a.Dir != in) ) {
					retstr = a.comment;
					MatchOnRet = true;
				}
			} else {
				a.comment="\"\"";
			}
			break;
		default:
			log.append(LOG_ERROR,"CloseTraceRecord(): Unknown argument type!\n");
		}
		
		
		open->OutArgs.push_back(a);
		atv++;
	} // stack walk

	//
	// do matching
	//
	if ( (open->Definition->ReturnMatch.length() > 0) && (MatchOnRet) ) {
		//
		// We are supposed to match
		//
		log.append(LOG_DEBUG,"Matching '%s' against '%s'...\n",
			open->Definition->ReturnMatch.c_str(),
			retstr.c_str());

		if ( retstr.find( open->Definition->ReturnMatch ) == string::npos )	{
			log.append(LOG_DEBUG," ... not matching\n");
			delete(open);
		} else {
			log.append(LOG_DEBUG," ... matches!\n");
			Results.push_back(open);
		}
	
	} else {
		// 
		// not supposed to match anything, just add 
		//
	
		Results.push_back(open);
	}

	if ( NULL != rCloseFunc ) 
		(*rCloseFunc)(open);

	return true;
}


void Tracer::AnalysePCHAR(DWORD address, bool MultiByte, string *res) {
	string					a;
	string					b;
	t_Debugger_memory		*pg;


	if (address == 0x00) {
		(*res) = "(null)";
		return;
	}

	if (!MemStrCpy(address,MultiByte,&a)) {
		(*res) = "(invalid address)";
		return;
	}

	//
	// From here on, wchars are normal strings as well
	//
	BeautifyString(&a);
	b = "\"" + a + "\"";

	if ( NULL != (pg=FindPageByAddress(address,a.length())) ){
		if ( pg->Name.length() > 0) {
			b += " in ";
			b += pg->Name;
		}
	}

	*res=b;
}


void Tracer::AnalyseStack(DWORD address, t_Tracer_OpenTr *open) {
	t_Debugger_CPU		cpu;
	char				overflow[32];
	t_Debugger_memory	*pg;


	if (! Analysis.StackDelta ) {
		log.append(LOG_VERBOSE,"AnalyseStack():turned off\n");
		return;
	}

	if ( NULL == (pg=FindPageByAddress(address,1)) ) {
		return;
	}

	if ( (pg->Name.length() == 0)
		|| 
		(pg->Name.find("stack") == string::npos) ) {
		return;
	}
	

	if (! GetCPUContext( FindThread(open->ThreadID)->hThread, &cpu) ){
		log.append(LOG_ERROR,"AnalyseStack(): Failed to get CPU context\n");
		return;
	}

	log.append(LOG_VERBOSE,"AnalyseStack(): %08X (ESP = %08X, EBP = %08X)\n",
		address,cpu.ESP,cpu.EBP);

	if ( (cpu.ESP & 0xFFFF0000) == (cpu.EBP & 0xFFFF0000) ) {
		// 
		// probably a EBP based function
		//
		if ( address < cpu.EBP ) {
			sprintf(overflow,"%08X: ",address);
			open->Notes += overflow;
			open->Notes += "probably local function stack buffer (";
			sprintf(overflow,"%u",cpu.EBP-address);
			open->Notes += overflow;
			open->Notes += " bytes from EBP)\n";
		} else {
			sprintf(overflow,"%08X: ",address);
			open->Notes += overflow;
			open->Notes += "probably stack buffer of a calling function\n";
		}
	} else {
		//
		// the two most significant bytes of EBP and ESP are not equal
		//
		if ( address < cpu.ESP ) {
			sprintf(overflow,"%08X: ",address);
			open->Notes += overflow;
			open->Notes += "Address below ESP! Strange.\n";
		} else {
			if ( (address - cpu.ESP) < Analysis.StackDeltaV ) {
				sprintf(overflow,"%08X",address);
				open->Notes += "StackDelta: ";
				open->Notes += overflow;
				open->Notes += " ";
				sprintf(overflow,"%u",address - cpu.ESP);
				open->Notes += overflow;
				open->Notes += " bytes from ESP\n";
			}
		}
	}
}


bool Tracer::MemStrCpy(DWORD address, bool MultiByte, string *s) {
	DWORD	tlen;

	if ( MultiByte ) {
		WCHAR	*t;

		tlen = MemStrLen(address,MultiByte);

		t=new( WCHAR[tlen+2] );
		if (!ReadProcessMemory(hProcess,(LPCVOID)address,t,tlen,NULL)) {
			delete(t);
			return false;
		}
		WideChar2String((WCHAR*)t,s);
	} else {
		char	*t;
		
		tlen = MemStrLen(address,MultiByte);

		t=new( char[tlen+1] );
		if (!ReadProcessMemory(hProcess,(LPCVOID)address,t,tlen,NULL)) {
			delete(t);
			return false;
		}
		(*s) = (char*)t;
		delete(t);
	}
	return true;
}


DWORD Tracer::MemStrLen(DWORD address, bool MultiByte) {
	DWORD	cnt=0;
	BYTE	c=1;
	WORD	m;

	if ( MultiByte ) {
		do {
			if (!ReadProcessMemory(hProcess,(LPCVOID)address,&m,sizeof(m),NULL) )
				return cnt;
			cnt += 2;
			address += 2;
		} while ( m != 0x0000 );
	} else {
		do {
			if (!ReadProcessMemory(hProcess,(LPCVOID)address,&c,sizeof(c),NULL) )
				return cnt;
			cnt ++;
			address ++;
		} while ( c != 0x00 );
	}
	return cnt;
}


void Tracer::BeautifyString(string *s) {
	unsigned int	l;
	string			bs;
	char			esc[5];

	for ( l=0; l<(*s).length(); l++) {
		if ( ((*s)[l]>=0x20) && ((*s)[l]<=0x7E) ){
			sprintf(esc,"%c",(char)(*s)[l]);
		} else {
			sprintf(esc,"\\x%02X",(unsigned int)((*s)[l]) & 0xFF );
		}
		bs += esc;
	}

	log.append(LOG_DEBUG,"BeautifyString(): in '%s' - out '%s'\n",
		(*s).c_str(), bs.c_str());
	(*s)=bs;
}


void Tracer::WideChar2String(WCHAR *w, string *s) {
	char	*t = NULL;
	int		req;

	if (0 == wcslen(w)) {
		(*s)="";
		return;
	}

	req=WideCharToMultiByte(Analysis.CodePage,0,w,-1,t,0,NULL,NULL);
	if ( 0 == req ) {
		log.appendError(LOG_ERROR,"WideCharToMultiByte() failed !");
		(*s)="";
		return;
	}

	t=new(char[req+1]);
	WideCharToMultiByte(Analysis.CodePage,0,w,-1,t,req,NULL,NULL);
	(*s)=(char*)t;
	delete (t);
}


//
// HIGHLY experimental
//


bool Tracer::GuardBufferPage(t_Tracer_Buffer *buf, DWORD addr, DWORD size) {
	t_Debugger_memory						*mp;
	DWORD									oprot;
	t_Tracer_Page							*pg;

	//
	// Make sure our information is current
	//
	ReBuildMemoryMap();

	//
	// find the appropriate page
	//
	if ( NULL == (mp=FindPageByAddress(addr,size)) ) {
		log.append(LOG_ERROR,
			"GuardBufferPage(): Buffer %08X(%u) is not in mapped memory\n",
			addr,size);
		return false;
	}

	if ( Pages.find( mp->address ) == Pages.end() )
		pg = NULL;
	else
		pg = Pages[ mp->address ];

	if ( NULL == pg ) {
		if ( NULL == (pg=new(t_Tracer_Page)) ){
			log.append(LOG_ERROR,
				"GuardBufferPage(): could not allocate %u bytes\n",
				sizeof(t_Tracer_Page));
		}
		log.append(LOG_DEBUG,"Tracing in new Page %08X\n", mp->address);

		if ( ! VirtualProtectEx(hProcess,
			(LPVOID)mp->address,mp->basics.RegionSize,
			PAGE_NOACCESS,&oprot) ){
			log.append(LOG_ERROR,
				"GuardBufferPage(): Buffer %08X(%u) could not be guarded (o: %X)\n",
				addr,size,oprot);
			return false;

		} 

		log.append(LOG_INFO,"Page %08X for Buffer %08X(%u) guarded\n",
			mp->address,addr,size);

		//pg->OriginalProtection = it->second->basics.Protect;
		pg->OriginalProtection = oprot;
		pg->address = mp->address;
		pg->Size = mp->basics.RegionSize;
		pg->TemporaryRestore = false;
		Pages[ mp->address ] = pg;

		//
		// Double-Mesh the Page<->Buffer information
		//
		buf->Page = pg;
		pg->Buffers.push_back( buf );

	} else {
		log.append(LOG_DEBUG,"Page %08X already in trace\n", mp->address);
	}

	return true;
}


t_Debugger_memory *Tracer::FindPageByAddress(DWORD addr, DWORD size) {
	t_MemoryMap_Iterator	mit;
	DWORD					tsize = 0xFFFFFFFF;
	t_Debugger_memory		*tpage = NULL;

	for (mit=MemoryMap.begin(); mit != MemoryMap.end(); ++mit) {
		//log.append(LOG_DEBUG,"... %08X %08X (%08X)\n",addr,mit->second->address,mit->first);

		if ( addr >= mit->second->address ) {

			if ( (addr+size) <= 
				(mit->second->address + mit->second->basics.RegionSize) ){

				//
				// it is within this page, but let's keep looking for
				// a smaller match
				//
				//log.append(LOG_DEBUG,
				//	"First match: Buffer %08X(%4u) in Page %08X(%4u)\n",
				//	addr,size,mit->second->address,mit->second->basics.RegionSize);

				if ( mit->second->basics.RegionSize < tsize ) {
					tpage = mit->second;
					tsize = mit->second->basics.RegionSize;
				}
			}

		} else {
			//
			// done, we are over the mark
			//
			
			if (NULL != tpage) {
				log.append(LOG_DEBUG,
					"FindPageByAddress(): Buffer %08X(%4u) in Page %08X(%4u) %s\n",
					addr,size,tpage->address,tpage->basics.RegionSize,
					tpage->Name.length()==0?"":tpage->Name.c_str());
			}
			
			return tpage;
		}

	}

	return NULL;
}


DWORD Tracer::GetCaller(DWORD tid) {
	t_Debugger_CPU		cpu;
	DWORD				v;

	if ( ! GetCPUContext( FindThread(tid)->hThread, &cpu) ) return 0;
	if (!ReadProcessMemory(hProcess,(LPCVOID)cpu.ESP,&v,sizeof(v),NULL)) return 0;
	return v;
}