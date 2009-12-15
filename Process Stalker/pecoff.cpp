#include <windows.h>
#include <time.h>
#include <vector>
#include <string>
#include <string.h>

#include "pecoff.hpp"
#include "log.hpp"
#include "blackmagic.hpp"


char *DebugTypes[] = {
		"Unknown debug type",
		"COFF",
		"CodeView",
		"FPO",
		"Misc",
		"Exception",
		"FixUp",
		"OMAP to Src",
		"OMAP from Src",
		"Borland",
		"Reserved"
};


// ***********************************************************************
// PEcoff_import class
// ***********************************************************************


PEcoff_import::PEcoff_import(void) {
	Name = "";
}


PEcoff_import::~PEcoff_import(void) {
	unsigned int	i,size;

	size = functions.size();
	for (i=0; i<size; i++) {
		delete( functions.back() );
		functions.pop_back();
	}
}


DWORD PEcoff_import::FunctionByName(char *name) {
	string		n = name;
	vector <t_pecoff_import_func *>::iterator	it;

	for ( it = functions.begin() ; it < functions.end(); it++) {
		if ( (*it)->Name == n )
			return (*it)->Address;
	}
	return 0;
}


char *PEcoff_import::FunctionByAddress(DWORD addr) {
	vector <t_pecoff_import_func *>::iterator	it;

	for ( it = functions.begin() ; it < functions.end(); it++) {
		if ( (*it)->Address == addr ) 
			return (char *)((*it)->Name.c_str());
	}
	return NULL;
}


// ***********************************************************************
// PEfile main class
// ***********************************************************************


PEfile::PEfile() {
	fh = INVALID_HANDLE_VALUE;
	pe = NULL;
	winpe = NULL;
	datadir = NULL;

	log.Name="PEfile";
}


PEfile::PEfile(HANDLE handle) {
	fh = INVALID_HANDLE_VALUE;
	pe = NULL;
	winpe = NULL;
	datadir = NULL;

	log.Name="PEfile";

	PEOpen(handle);
}


PEfile::~PEfile() {
	unsigned int		i,j;
	unsigned int		size;
	unsigned int		size2;


	if ( INVALID_HANDLE_VALUE != fh ) {
		CloseHandle(fh);
		log.append(LOG_DEBUG,"PEfile: Closed file handle\n");
	}

	if ( NULL != pe )
		delete(pe);

	if ( NULL != winpe )
		delete(winpe);

	if ( NULL != datadir )
		delete(datadir);

	size = section.size();
	for (i=0; i<size; i++) {
		log.append(LOG_DEBUG,"~PEfile(): Deleting section %u/%u\n",i+1,size);
		delete ( section.back() );
		section.pop_back();
	}

	size = exports.size();
	for (i=0; i<size; i++) {
		log.append(LOG_DEBUG,"~PEfile(): Deleting export %u/%u\n",i+1,size);
		delete ( exports.back() );
		exports.pop_back();
	}

	size = imports.size();
	for (i=0; i<size; i++) {
		size2 = imports[i]->functions.size();
		for (j=0; j<size2; j++) {
			log.append(LOG_DEBUG,"~PEfile(): Deleting import function %u/%u\n",j+1,size2);
			delete( imports[i]->functions.back() );
			imports[i]->functions.pop_back();
		}
	}

	size = imports.size();
	for (i=0; i<size; i++) {
		log.append(LOG_DEBUG,"~PEfile(): Deleting import %u/%u\n",i+1,size);
		delete( imports.back() );
		imports.pop_back();
	}
}


bool PEfile::PEOpen(char *fname) {
	SECURITY_ATTRIBUTES		se;

	se.nLength = sizeof(SECURITY_ATTRIBUTES);
	se.lpSecurityDescriptor = NULL;
	se.bInheritHandle = false;

	//
	// Funny as it is, you should open a file in Windows using CreateFile, 
	// not OpenFile.
	// see http://blogs.msdn.com/oldnewthing/archive/2004/03/02/82639.aspx
	//
	if ( INVALID_HANDLE_VALUE == (fh= 
			CreateFile(fname,
				GENERIC_READ,
				FILE_SHARE_READ,
				&se,
				OPEN_EXISTING,
				FILE_FLAG_SEQUENTIAL_SCAN,
				NULL)) ){
		log.append(LOG_ERROR,"Failed to open PE file %s\n",fname);
		return false;
	} else {
		log.append(LOG_DEBUG,"File %s open\n",fname);
		return true;
	}
}


bool PEfile::PEOpen(HANDLE handle) {

	fh = handle;
	log.append(LOG_DEBUG,"Assigned handle via PEfile::PEOpen(%08X)\n",handle);
	return true;
}


void PEfile::PEClose(void) {

	CloseHandle(fh);
	fh = INVALID_HANDLE_VALUE;
}


bool PEfile::parse(void) {

	if ( INVALID_HANDLE_VALUE == fh ) {
		log.append(LOG_WARNING,"parse() called with filehandle being 0\n");
		return false;
	}

	if ( ! ReadDOS() ) {
		log.append(LOG_ERROR,"parse(): ReadDOS() failed\n");
		return false;
	}

	if ( ! ReadCOFF() ) return false;

	if ( ! ReadPE32() ) return false;

	if ( ! ReadSectionHeaders() ) return false;

	if ( ! ReadDebug() ) return false;

	return true;
}


bool PEfile::PopulateByProcess(HANDLE hProcess) {
	unsigned int	size,size2,i,j;

	//
	// Delete potentially existing info, because we might
	// get called several times
	// 

	size = exports.size();
	for (i=0; i<size; i++) {
		delete ( exports.back() );
		exports.pop_back();
	}

	size = imports.size();
	for (i=0; i<size; i++) {
		size2 = imports[i]->functions.size();
		for (j=0; j<size2; j++) {
			delete( imports[i]->functions.back() );
			imports[i]->functions.pop_back();
		}
	}

	size = imports.size();
	for (i=0; i<size; i++) {
		delete( imports.back() );
		imports.pop_back();
	}

	//
	// Deal with the exports
	//
	if ( ! PopulateExport(hProcess) ) return false;

	// 
	// Deal with the imports
	//
	if ( ! PopulateImport(hProcess) ) return false;

	return true;
}


bool PEfile::PopulateByFile(void) {
	unsigned int	size,size2,i,j;

	//
	// Delete potentially existing info, because we might
	// get called several times
	// 

	size = exports.size();
	for (i=0; i<size; i++) {
		delete ( exports.back() );
		exports.pop_back();
	}

	size = imports.size();
	for (i=0; i<size; i++) {
		size2 = imports[i]->functions.size();
		for (j=0; j<size2; j++) {
			delete( imports[i]->functions.back() );
			imports[i]->functions.pop_back();
		}
	}

	size = imports.size();
	for (i=0; i<size; i++) {
		delete( imports.back() );
		imports.pop_back();
	}

	//
	// Deal with the exports
	//
	if ( ! PopulateExportByFile(fh) ) return false;

	//
	// Deal with the imports
	//
	if ( ! PopulateImportByFile(fh) ) return false;

	return true;
}


DWORD PEfile::ExportByName(char *name) {
	vector <t_pecoff_export*>::iterator		ex;

	for ( ex = exports.begin(); ex < exports.end(); ex++) {
		if ( ! strcmp((*ex)->Name.c_str(), name) ) {
			//
			// here, skip if it's a forwarded export
			//
			if ( ! (*ex)->Forwarded ) {
				log.append(LOG_DEBUG,
					"Returning export address %08X for %s\n",
					(*ex)->Address, name);
				return (*ex)->Address;
			} else {
				log.append(LOG_DEBUG,
					"Export address %08X for %s forwarded. Skipping\n",
					(*ex)->Address, name);
			}
		}
	}

	return 0x00;
}


DWORD PEfile::ImportByName(char *name) {
	string			n = name;
	string			module;
	unsigned int	colonp;
	vector <PEcoff_import *>::iterator	it;

	if ( string::npos == (colonp = n.find(":")) ){
		//
		// no module information was given
		//
		log.append(LOG_DEBUG,"Looking for import '%s' in all modules\n",
			name);

		for (it = imports.begin(); it < imports.end(); it++) {
			if ( 0 != (colonp=(*it)->FunctionByName(name)) ) {
				log.append(LOG_DEBUG,
					"Returning import's address %08X from module %s\n",
					colonp,(*it)->Name.c_str());
				return colonp;
			}
		}
		return 0;

	} else {
		//
		// module information was given
		//
		module = n.substr(0,colonp);
		n.erase(0,colonp+1);

		log.append(LOG_DEBUG,"Looking for import '%s' in module %s\n",
			n.c_str(),module.c_str());

		for (it = imports.begin(); it < imports.end(); it++) {

			if ( ! _stricmp(module.c_str(),(*it)->Name.c_str()) ){

				if ( 0 != (colonp = (*it)->FunctionByName((char *)(n.c_str()))) ){
					log.append(LOG_DEBUG,
						"Returning import's address %08X from module %s\n",
						colonp,(*it)->Name.c_str());
					return colonp;
				} else {
					log.append(LOG_DEBUG,
						"Module found but FunctionByName returned 0\n");

					return 0;
				}
			} else {
				// module name doesn't match

				log.append(LOG_DEBUG," '%s' != '%s' ...\n",
					module.c_str(),(*it)->Name.c_str() );

				return 0;
			}
		}

		return 0;
	}
}


DWORD PEfile::ProcessStrlen(HANDLE hProcess, DWORD address) {
	DWORD	cnt=0;
	BYTE	c=1;

	while ( c!=0x00 ) {
		if ( ! ReadProcessMemory(hProcess,(LPCVOID)address,&c,sizeof(c),NULL) ){
			return 0;
		}

		cnt++;
		address++;
	}

	return cnt;
}


bool PEfile::ProcessStrCpy(HANDLE hProcess, DWORD address, string *dest) {
	char						*tname;
	DWORD						tnamelen;

	tnamelen = ProcessStrlen(hProcess,address);

	tname = new ( char[tnamelen+1] );
	if ( ! ReadProcessMemory(hProcess,(LPCVOID)(address),tname,tnamelen,NULL) ){
		log.append(LOG_ERROR,"ProcessStrCpy(): Failed to read process memory at 0x%08X\n",
			address);
		delete(tname);
		return false;
	} else {
		(*dest) = (char*)tname;
	}
	delete (tname);

	return true;
}


// -----------------------------------------------------------------------------
//
// PRIVATE METHODS
//
// -----------------------------------------------------------------------------


DWORD PEfile::RVA2Offset(DWORD rva) {
	DWORD									offset;
	vector <t_section_header*>::iterator	it;
	t_section_header						*shdr = NULL;

	for ( it = section.begin(); it < section.end(); it++) {
		if ( 
			(rva >= (*it)->VirtualAddress)
			&& 
			( rva <= ((*it)->VirtualAddress + (*it)->VirtualSize))
		){
			shdr = (*it);
			break;
		}
	}

	if ( NULL == shdr) {
		log.append(LOG_DEBUG,"RVA2Offset(): RVA %08X is in no section\n",
			rva);
		return 0;
	} else {
		log.append(LOG_DEBUG,"RVA %08X is in section %s (%08X)\n",
			rva,shdr->Name,shdr->VirtualAddress);
	}

	offset = shdr->VirtualAddress - shdr->PointerToRawData;

	log.append(LOG_DEBUG,"RVA in file is %08X\n",
		rva-offset);

	return (rva-offset);
}


bool PEfile::ReadDOS(void) {
	WORD	signature;
	WORD	ssv;
	DWORD	in;

	SetFilePointer(fh,0,NULL,FILE_BEGIN);

	if ( ! ReadFile(fh,&signature,sizeof(signature),&in,NULL) ) {
		log.append(LOG_ERROR,"ReadDOS(): failed to read signature\n");
		return false;
	}

	if ( signature != 0x5A4D ) {
		log.append(LOG_ERROR,"ReadDOS(): incorrect signature %04X\n",signature);
		return false;
	}

	SetFilePointer(fh,0x18,NULL,FILE_BEGIN);

	if ( ! ReadFile(fh,&ssv,sizeof(ssv),&in,NULL) ){
		log.append(LOG_ERROR,"ReadDOS(): failed to read SS value\n");
		return false;
	}

	if ( ssv < 0x40 ) {
		log.append(LOG_WARNING,"ReadDOS(): does not appear to be a Windows file\n");
	}

	SetFilePointer(fh,0x3C,NULL,FILE_BEGIN);

	if ( ! ReadFile(fh,&peoffset,sizeof(peoffset),&in,NULL) ){
		log.append(LOG_ERROR,"ReadDOS(): failed to read PE offset\n");
		return false;
	}

	log.append(LOG_DEBUG,"ReadDOS(): PE header offset = 0x%08X\n",peoffset);
	return true;
}


bool PEfile::ReadCOFF(void) {
	DWORD	pe_sig;
	DWORD	in;

	SetFilePointer(fh,peoffset,NULL,FILE_BEGIN);

	if ( ! ReadFile(fh,&pe_sig,sizeof(pe_sig),&in,NULL) ){
		log.append(LOG_ERROR,"ReadCOFF(): failed to read PE signature\n");
		return false;
	}

	if ( pe_sig != 0x00004550 ) {
		log.append(LOG_ERROR,"ReadCOFF(): invalid PE signature 0x%08X\n",pe_sig);
		return false;
	}

	if ( ! ReadFile(fh,&coff,sizeof(coff),&in,NULL) ){
		log.append(LOG_ERROR,"ReadCOFF(): failed to read PE signature\n");
		return false;
	} else {
		log.append(LOG_DEBUG,"ReadCOFF(): COFF header %d bytes read\n",in);
	}	

	log.append(LOG_VERBOSE,
		"COFF Header:\n"
		"  Machine type: %X\n"
		"  Number of Sections: %u\n"
		"  TimeDateStamp: %s"
		"  Pointer to Symbol table: %08X\n"
		"  Number of Symbols: %u\n"
		"  Size of Optional Header: %u\n"
		"  Characteristics: %04X\n",
		coff.machine,
		coff.NumberOfSections,
		ctime((long *)&(coff.TimeStamp)),
		coff.PointerToSymbolTable,
		coff.NumberOfSymbols,
		coff.SizeOfOptionalHeader,
		coff.Characteristics);

	if ( 0x14C != coff.machine ) 
		log.append(LOG_WARNING,"ReadCOFF(): File is not for IA32 Platform!\n");

	return true;
}


bool PEfile::ReadPE32(void) {
	DWORD						in;
	t_optional_header_peplus	p;
	DWORD						base;
	DWORD						size_remaining;

	if ( sizeof(p) > coff.SizeOfOptionalHeader ) {
		log.append(LOG_ERROR,"ReadPE32(): COFF SizeOfOptionalHeader is too small\n");
		return false;
	}
	size_remaining = coff.SizeOfOptionalHeader;

	if ( ! ReadFile(fh,&p,sizeof(p),&in,NULL) ){
		log.append(LOG_ERROR,"ReadPE32(): failed to read PE32 header\n");
		return false;
	}
	size_remaining -= sizeof(p);

	if ( p.Magic == PECOFF_MAGIC_PE ) {

		if ( ! ReadFile(fh,&base,sizeof(base),&in,NULL) ){
			log.append(LOG_ERROR,"ReadPE32(): failed to read PE32 header last entry\n");
			return false;
		}
		size_remaining -= sizeof(base);

		pe = new(t_optional_header_pe);
		memcpy(pe,&p,sizeof(p));
		pe->BaseOfData = base;
		peplus=false;

	} else if ( p.Magic == PECOFF_MAGIC_PEPLUS ) {

		pe = (t_optional_header_pe *) new(t_optional_header_peplus);
		memcpy(pe,&p,sizeof(p));
		peplus=true;

	} else {

		log.append(LOG_ERROR,"ReadPE32(): illegal PE32 header magic: %08X\n",p.Magic);
		return false;

	}

	if (peplus) 
		log.append(LOG_VERBOSE,
			"PE32+ Header:\n"
			"  Magic: %04X\n"
			"  Linker Version: %u.%u\n"
			"  Size of Code: %u\n"
			"  Size of Initialized Data: %u\n"
			"  Size of Uninitialized Data: %u\n",
			"  Address of Entry Point: 0x%08X\n"
			"  Base of Code: 0x%08X\n",
			pe->Magic,
			pe->LinkerMajor, pe->LinkerMinor,
			pe->SizeOfCode,
			pe->SizeOfInitializedData,
			pe->SizeOfUninitializedData,
			pe->AddressOfEntryPoint,
			pe->BaseOfCode);
	else
		log.append(LOG_VERBOSE,
			"PE32 Header:\n"
			"  Magic: %04X\n"
			"  Linker Version: %u.%u\n"
			"  Size of Code: %u\n"
			"  Size of Initialized Data: %u\n"
			"  Size of Uninitialized Data: %u\n"
			"  Address of Entry Point: 0x%08X\n"
			"  Base of Code: 0x%08X\n"
			"  Base of Data: 0x%08X\n",
			pe->Magic,
			pe->LinkerMajor, pe->LinkerMinor,
			pe->SizeOfCode,
			pe->SizeOfInitializedData,
			pe->SizeOfUninitializedData,
			pe->AddressOfEntryPoint,
			pe->BaseOfCode,
			pe->BaseOfData);

	//
	// read the windows specific PE header
	//

	if ( ! peplus ) {

		if ( (size_remaining) < sizeof(t_optional_windows_pe) ) {
			log.append(LOG_ERROR,"ReadPE32(): COFF SizeOfOptionalHeader is too"
				" small for Windows specific header\n");
			return false;
		}

		winpe = new(t_optional_windows_pe);

		if ( ! ReadFile(fh,winpe,sizeof(t_optional_windows_pe),&in,NULL) ){
			log.append(LOG_ERROR,"ReadPE32(): failed to read PE32 windows header\n");
			return false;
		}
		size_remaining -= sizeof(t_optional_windows_pe);

	} else {
		//
		// PE32+
		//
		if ( (size_remaining) < sizeof(t_optional_windows_peplus) ) {
			log.append(LOG_ERROR,"ReadPE32(): COFF SizeOfOptionalHeader is too"
				" small for Windows specific header\n");
			return false;
		}

		winpe = (t_optional_windows_pe *) new(t_optional_windows_peplus);

		if ( ! ReadFile(fh,winpe,sizeof(t_optional_windows_peplus),&in,NULL) ){
			log.append(LOG_ERROR,"ReadPE32(): failed to read PE32 windows header\n");
			return false;
		}
		size_remaining -= sizeof(t_optional_windows_peplus);
	}

	log.append(LOG_VERBOSE,
		"Windows specific optional header:\n"
		"  Image Base: 0x%08X\n"
		"  Section Alignment: 0x%X\n"
		"  File Alignment: 0x%X\n"
		"  Operating System: %u.%u\n"
		"  Image Version: %u.%u\n"
		"  Subsystem Version: %u.%u\n"
		"  Reserved: 0x%X\n"
		"  Size of Image: %u\n"
		"  Size of Headers: %u\n"
		"  Checksum: 0x%X\n"
		"  Subsystem: 0x%X\n"
		"  DLL Characteristics: %04X\n"
		"  Size of Stack Reserve: %u\n"
		"  Size of Stack Commit: %u\n"
		"  Size of Heap Reserve: %u\n"
		"  Size of Heap Commit: %u\n"
		"  Loader Flags: %08X\n"
		"  Number of RVA and Size entries: %u\n",
		winpe->ImageBase,
		winpe->SectionAlignment,
		winpe->FileAlignment,
		winpe->OperatingSystemMajor, winpe->OperatingSystemMinor,
		winpe->ImageVersionMajor, winpe->ImageVersionMinor,
		winpe->SubsystemMajor, winpe->SubsystemMinor,
		winpe->Reserved,
		winpe->SizeOfImage,
		winpe->SizeOfHeaders,
		winpe->Checksum,
		winpe->Subsystem,
		winpe->DLLCharacteristics,
		winpe->SizeOfStackReserve,
		winpe->SizeOfStackCommit,
		winpe->SizeOfHeapReserve,
		winpe->SizeOfHeapCommit,
		winpe->LoaderFlags,
		winpe->NumberOfRVAAndSizes);

	//
	// read data directory tables
	//

	if ( size_remaining < (winpe->NumberOfRVAAndSizes * sizeof(t_image_data_directory)) ){
		log.append(LOG_ERROR,"ReadPE32(): COFF SizeOfOptionalHeader is too"
			" small for data directories\n");
		return false;
	}

	datadir = new (t_data_directories);
	ZeroMemory(datadir,sizeof(t_data_directories));

	if ( ! ReadFile(
		fh,
		datadir, 
		(winpe->NumberOfRVAAndSizes * sizeof(t_image_data_directory)), 
		&in, 
		NULL) ){
		log.append(LOG_ERROR,"ReadPE32(): failed to read data directories\n");
		return false;
	}

	log.append(LOG_VERBOSE,
		"Data directories:\n"
		"  Export: 0x%X, %u\n"
		"  Import: 0x%X, %u\n"
		"  Resource: 0x%X, %u\n"
		"  Exception: 0x%X, %u\n"
		"  Certificate: 0x%X, %u\n"
		"  Base Relocation: 0x%X, %u\n"
		"  Debug: 0x%X, %u\n"
		"  Architecture: 0x%X, %u\n"
		"  Global Ptr: 0x%X, %u\n"
		"  Thread Local Storage: 0x%X, %u\n"
		"  Load Config: 0x%X, %u\n"
		"  Bound Import: 0x%X, %u\n"
		"  Import Address: 0x%X, %u\n"
		"  Delay Import: 0x%X, %u\n"
		"  COM+ Runtime: 0x%X, %u\n"
		"  Reserved: 0x%X, %u\n",
		datadir->Export,
		datadir->Import,
		datadir->Resource,
		datadir->Exception,
		datadir->Certificate,
		datadir->Base_relocation,
		datadir->Debug,
		datadir->Architecture,
		datadir->GlobalPtr,
		datadir->ThreadLocalStorage,
		datadir->LoadConfig,
		datadir->BoundImport,
		datadir->ImportAddress,
		datadir->DelayImport,
		datadir->COMplus,
		datadir->Reserved);

	return true;
}


bool PEfile::ReadSectionHeaders(void) {
	DWORD										in;
	char										tName[9];
	unsigned int								i;
	t_section_header							*s;
	vector <t_section_header*>::iterator		it;

	i=1;
	while ( i <= coff.NumberOfSections ) {

		s = new (t_section_header);

		if ( ! ReadFile(fh,s,sizeof(t_section_header),&in,NULL) ){
			log.append(LOG_ERROR,"ReadSectionHeaders(): failed to read section header %u\n",i);
			return false;
		}

		section.push_back(s);
		log.append(LOG_DEBUG,"ReadSectionHeaders(): Section header %u (%u Bytes) loaded\n",i,in);
		i++;
	}

	for (it=section.begin(); it < section.end(); it++) {

		memcpy(tName,&((*it)->Name),sizeof((*it)->Name));
		
		log.append(LOG_VERBOSE,
			"Section info:\n"
			"  Name: %s\n"
			"  Virtual Size: 0x%X (%u)\n"
			"  Virtual Address: 0x%08X\n"
			"  Size of Raw Data: %u\n"
			"  Pointer to Raw Data: 0x%08X\n"
			"  Pointer to Relocations: 0x%08X\n"
			"  Pointer to Line numbers: 0x%08X\n"
			"  Number of Relocations: %u\n"
			"  Number of Line numbers: %u\n"
			"  Characteristics: %08X\n",
			tName,
			(*it)->VirtualSize,
			(*it)->VirtualSize,
			(*it)->VirtualAddress,
			(*it)->SizeOfRawData,
			(*it)->PointerToRawData,
			(*it)->PointerToRelocations,
			(*it)->PointerToLineNumbers,
			(*it)->NumberOfRelocations,
			(*it)->NumberOfLineNumbers,
			(*it)->Characteristics);
	}

	return true;
}


bool PEfile::ReadDebug(void) {
	DWORD						debug_dir;
	DWORD						dircnt;
	DWORD						currentdir = 0;
	t_image_debug_directory		dir;
	DWORD						in;


	log.append(LOG_DEBUG,"----ReadDebug(%s)----\n",internal_name.c_str());

	if ( 0 == datadir->Debug.RVA ) {
		log.append(LOG_DEBUG,"Image has no debug information\n");
		return true;
	}

	debug_dir = RVA2Offset( datadir->Debug.RVA );
	dircnt = datadir->Debug.Size / sizeof(t_image_debug_directory);
	log.append(LOG_DEBUG,"Found %u debug director%s at file position 0x%X\n",
		dircnt,dircnt==1?"y":"ies",debug_dir);

	while ( currentdir < dircnt  ) {

		SetFilePointer(fh,
			debug_dir + (currentdir*sizeof(t_image_debug_directory)),
			NULL,
			FILE_BEGIN);

		if ( ! ReadFile(fh,(LPVOID)&dir,sizeof(dir),&in,NULL) ) {
			log.append(LOG_ERROR,
				"ReadDebug(): Failed to read Debug directory with %u left\n",
				dircnt);
			return false;
		}

		log.append(LOG_VERBOSE,
			"Debug Directory:\n"
			"  Characteristics: %08X\n"
			"  TimeDateStamp: %s"
			"  Version: %u.%u\n"
			"  Type: %s\n"
			"  Size of Data: %u\n"
			"  Address of Raw Data: %08X\n"
			"  Pointer to Raw Data: %08X\n",
			dir.Characteristics,
			ctime( (time_t*)&(dir.TimeDateStamp)),
			dir.MajorVersion, dir.MinorVersion,
			DEBUG_TYPE_NAME(dir.Type),
			dir.SizeOfData,
			dir.AddressOfRawData,
			dir.PointerToRawData);

		switch (dir.Type) {
		case IMAGE_DEBUG_TYPE_COFF:
			ReadDebug_COFF(dir.PointerToRawData);
			break;
		case IMAGE_DEBUG_TYPE_CODEVIEW:
			ReadDebug_CodeView(dir.PointerToRawData);
			break;
		case IMAGE_DEBUG_TYPE_FPO:
			ReadDebug_FPO(dir.PointerToRawData);
			break;
		case IMAGE_DEBUG_TYPE_MISC:
			ReadDebug_Misc(dir.PointerToRawData);
			break;
		default:
			log.append(LOG_VERBOSE,
				"Don't know how to process %s debug information\n",
				DEBUG_TYPE_NAME(dir.Type));
		}

		currentdir++;
	}

	return true;
}


bool PEfile::ReadDebug_COFF(DWORD fileoffset) {
	DWORD						in;
	t_image_coff_symbols		coff;

	SetFilePointer(fh,fileoffset,NULL,FILE_BEGIN);

	if ( ! ReadFile(fh,(LPVOID)&coff,sizeof(coff),&in,NULL) ){
		log.append(LOG_ERROR,"Could not read COFF symbols\n");
		return false;
	}

	log.append(LOG_VERBOSE,
		"COFF Symbol data:\n"
		"  Number of Symbols: %u\n"
		"  LVA to first Symbol: %08X\n"
		"  Number of Linenumbers: %u\n"
		"  LVA to first Linenumber: %08X\n"
		"  RVA to first byte of code: %08X\n"
		"  RVA to last byte of code: %08X\n"
		"  RVA to first byte of data: %08X\n"
		"  RVA to last byte of data: %08X\n",
		coff.NumberOfSymbols,
		coff.LvaToFirstSymbol,
		coff.NumberOfLinenumbers,
		coff.LvaToFirstLinenumber,
		coff.RvaToFirstByteOfCode,
		coff.RvaToLastByteOfCode,
		coff.RvaToFirstByteOfData,
		coff.RvaToLastByteOfData);


	return true;
}


bool PEfile::ReadDebug_CodeView(DWORD fileoffset) {
	DWORD						in;
	t_codeview_signature		sig;
	t_codeview_external			ext;
	string						fname;
	char						bla[5];
	

	SetFilePointer(fh,fileoffset,NULL,FILE_BEGIN);
	ZeroMemory(bla,sizeof(bla));
	
	if ( ! ReadFile(fh,(LPVOID)&sig,sizeof(sig),&in,NULL) ){
		log.append(LOG_ERROR,"Could not read codeview signature\n");
		return false;
	}

	memcpy(bla,&(sig.Signature),4);
	
	log.append(LOG_VERBOSE,
		"CodeView Signature:\n"
		"  Signature: %08X (%s)\n"
		"  File offset: %08X\n",
		sig.Signature,
		bla,
		sig.Filepos);
	ZeroMemory(bla,sizeof(bla));

	if ( (0x3031424E == sig.Signature) && (0x00 == sig.Filepos ) ) {

		log.append(LOG_DEBUG,"External Debug information assumed\n");
		if ( ! ReadFile(fh,(LPVOID)&ext,sizeof(ext),&in,NULL) ){
			log.append(LOG_ERROR,"Could not read external info header\n");
			return false;
		}
		log.append(LOG_VERBOSE,
			"CodeView External Header:\n"
			"  TimeStamp: %s"
			"  Unknown: %08X\n",
			ctime( (time_t*) &(ext.TimeStamp) ),
			ext.Unknown);

		while ( ReadFile(fh,(LPVOID)bla,1,&in,NULL) ) {
			if ( bla[0] == 0x00 ) break;
			fname += ( bla );
		}
		log.append(LOG_VERBOSE,"Debug Information in: %s\n",fname.c_str());

	} else if ( (0x3131424E == sig.Signature) && (0x00 != sig.Filepos ) ) {
		
		ReadDebug_CodeViewDir(fh,fileoffset + sig.Filepos);
		
	} else {
		// pedram
        //log.append(LOG_ERROR,"Unknown CodeView Signature\n");
		return false;
	}

	return true;
}


bool PEfile::ReadDebug_CodeViewDir(HANDLE hFile, DWORD fileoffset) {
	DWORD									in;
	t_codeview_header						cvh;
	vector <t_codeview_directory_entry>		dir;

	SetFilePointer(hFile,fileoffset,NULL,FILE_BEGIN);

	if ( ! ReadFile(hFile,(LPVOID)&cvh,sizeof(cvh),&in,NULL) ){
		log.append(LOG_ERROR,"Could not read codeview header\n");
		return false;
	}
	
	log.append(LOG_VERBOSE,
		"CodeView Header:\n"
		"  Size of Header: %u\n"
		"  Size of Entry: %u\n"
		"  Number of Entries: %u\n"
		"  Offset of next Directory: %08X\n"
		"  Flags: %08X\n",
		cvh.HeaderSize,
		cvh.EntrySize,
		cvh.NumberOfEntries,
		cvh.NextDirectoryOffset,
		cvh.Flags);
    /*

    >>>>>>>>>>>> HERE

	entrycnt = cvh.NumberOfEntries;
	while ( entrycnt > 0 ) {
		if ( ! ReadFile(hFile,(LPVOID)&entry,sizeof(entry),&in,NULL) ) {

	*/
	return true;
}


bool PEfile::ReadDebug_FPO(DWORD fileoffset) {
	DWORD					in;
	t_image_fpo_data		fpo;

	SetFilePointer(fh,fileoffset,NULL,FILE_BEGIN);

	if ( ! ReadFile(fh,(LPVOID)&fpo,sizeof(fpo),&in,NULL) ){
		log.append(LOG_ERROR,"Could not read FPO data\n");
		return false;
	}

	log.append(LOG_VERBOSE,
		"FPO Data:\n"
		"  Offset Start: %08X\n"
		"  Number of bytes in function: %u\n"
		"  Number of bytes in locales: %u\n"
		"  Number of bytes in parameters: %u\n"
		"  Number of bytes in prolog: %u\n"
		"  Number of Registers saved: %u\n"
		"  Function has SEH: %s\n"
		"  Function allocates EBP: %s\n"
		"  Reserved: %08X\n"
		"  Frame Type: %08X\n",
		fpo.ulOffStart,
		fpo.cbProcSize,
		fpo.cdwLocals*4,
		fpo.cdwParams*4,
		fpo.cbProlog,
		fpo.cbRegs,
		fpo.fHasSEH==1?"yes":"no",
		fpo.fUseBP==1?"yes":"no",
		fpo.reserved,
		fpo.cbFrame);

	return true;
}


bool PEfile::ReadDebug_Misc(DWORD fileoffset) {
	DWORD					in;
	t_image_debug_misc		misc;

	SetFilePointer(fh,fileoffset,NULL,FILE_BEGIN);

	if ( ! ReadFile(fh,(LPVOID)&misc,sizeof(misc),&in,NULL) ){
		log.append(LOG_ERROR,"Could not read Misc data\n");
		return false;
	}

	log.append(LOG_VERBOSE,"Misc Debug Information:\n"
		"  Type: %08X\n"
		"  Length: %u\n"
		"  Unicode: %s\n"
		"  Reserved: %02X%02X%02X\n",
		misc.DataType,
		misc.Length,
		misc.Unicode==1?"yes":"no",
		misc.Reserved[0], misc.Reserved[1], misc.Reserved[2]);

	if ( misc.DataType == IMAGE_DEBUG_MISC_EXENAME ) {
		char	*exename = new char[misc.Length];

		if ( ! ReadFile(fh,(LPVOID)exename,misc.Length,&in,NULL) ){
			log.append(LOG_ERROR,
				"Could not read in Misc Debug info\n");
			return false;
		}

		if (misc.Unicode) {
			char	*exename2 = new char [misc.Length];

			utilUnicodeToAnsi((WCHAR*)exename,exename2);
			delete (exename);
			exename = exename2;
		}

		log.append(LOG_DEBUG,"Exename: '%s'\n",exename);
		debug_name = exename;
		delete(exename);
	}
	
	return true;
}
			

bool PEfile::PopulateExport(HANDLE hProcess) {
	DWORD						export_tab;
	DWORD						remaining_size;
	DWORD						in;
	t_export_directory_entry	ex;
	t_pecoff_export				*et;

	DWORD		ExportAddressTable;
	DWORD		NamePointerRVA;
	DWORD		OrdinalTableRVA;
	DWORD		name_ord_cnt;
	
	WORD		otemp;
	DWORD		ntemp;
	string		NameTemp;
	DWORD		etemp;
	string		ForwardTemp;
	

	log.append(LOG_DEBUG,"----PopulateExport()----\n");

	if ( 0 == datadir->Export.RVA ) {
		log.append(LOG_DEBUG,"PopulateExport(): Module has no Export entry\n");
		return true;
	}

	export_tab = winpe->ImageBase + datadir->Export.RVA;
	remaining_size = datadir->Export.Size;
	log.append(LOG_DEBUG,"Looking for the export table at 0x%08X\n",export_tab);

	if ( ! ReadProcessMemory(hProcess,(LPCVOID)export_tab,&ex,sizeof(ex),&in) ){
		log.append(LOG_ERROR,
			"PopulateExport(): Could not read process memory at 0x%08X\n",
			export_tab);
		return false;
	} else {
		log.append(LOG_DEBUG,
			"PopulateExport(): %u bytes export table entry in\n",in);
		remaining_size -= sizeof(ex);
	}

	log.append(LOG_VERBOSE,
		"Export entry:\n"
		"  Characteristics: %08X\n"
		"  Time Stamp: %s"
		"  Version: %u.%u\n"
		"  Name RVA: 0x%08X\n"
		"  Ordinal Bias: %u\n"
		"  Number of Functions: %u\n"
		"  Number of Names: %u\n"
		"  Address of Functions: 0x%08X\n"
		"  Address of Names: 0x%08X\n"
		"  Address of Ordinals: 0x%08X\n",
		ex.Characteristics,
		ctime((long *)&(ex.TimeStamp)),
		ex.MajorVersion, ex.MiniorVersion,
		ex.NameRVA,
		ex.OrdinalBias,
		ex.NumberOfFunctions,
		ex.NumberOfNames,
		ex.AddressOfFunctions,
		ex.AddressOfNames,
		ex.AddressOfOrdinals);	
	
	ProcessStrCpy(hProcess,(DWORD)(winpe->ImageBase + ex.NameRVA),&internal_name);
	log.append(LOG_VERBOSE,"Internal DLL name: '%s'\n",internal_name.c_str());

	
	ExportAddressTable = winpe->ImageBase + ex.AddressOfFunctions;
	NamePointerRVA = winpe->ImageBase + ex.AddressOfNames;
	OrdinalTableRVA = winpe->ImageBase + ex.AddressOfOrdinals;
	
	name_ord_cnt = ex.NumberOfNames;	// Names and ordinals are __required__ to be the same
	
	while (name_ord_cnt > 0) {
		//
		// Ordinal and Name pointer tables run in parallel
		//
		if ( ! ReadProcessMemory(
			hProcess,
			(LPCVOID)OrdinalTableRVA,
			&otemp,
			sizeof(otemp),
			NULL) ){
			
			log.append(LOG_ERROR,
				"PopulateExport(): Failed to read process memory at 0x%08X\n",
				OrdinalTableRVA);
			return false;
		} 
		log.append(LOG_DEBUG,"Ordinal entry: %u\n",otemp);
		OrdinalTableRVA += sizeof(otemp);
		
		if ( ! ReadProcessMemory(
			hProcess,
			(LPCVOID)NamePointerRVA,
			&ntemp,
			sizeof(ntemp),
			NULL) ){
			
			log.append(LOG_ERROR,
				"PopulateExport(): Failed to read process memory at 0x%08X\n",
				NamePointerRVA);
			return false;
		} 
		log.append(LOG_DEBUG,"Correspondig Name RVA entry: %08X\n",ntemp);
		NamePointerRVA += sizeof(ntemp);
		
		//
		// Now see what's the name to it
		//
		if ( 0 != ntemp ) {
			if ( ! ProcessStrCpy(hProcess, winpe->ImageBase + ntemp, &NameTemp) ) {
				log.append(LOG_ERROR,
					"PopulateExport(): Failed to read process memory at 0x%08X\n",
					winpe->ImageBase + ntemp);
				return false;
			}
			log.append(LOG_DEBUG,"Corresponding Name: '%s'\n",NameTemp.c_str());
		} else {
			NameTemp = "";
		}
		
		//
		// The ordinal (without any fixup) is an index in the Export Address Table
		//
		if ( ! ReadProcessMemory(
			hProcess,
			(LPCVOID)(ExportAddressTable + (4*otemp)),
			&etemp,
			sizeof(etemp),
			NULL) ){
			log.append(LOG_ERROR,
				"PopulateExport(): Failed to read process memory at 0x%08X\n",
				(ExportAddressTable + (4*otemp)));
			return false;
		} 
		
		//
		// If the export address is NOT within the export section it's a real 
		// export, otherwise it's forwarded
		//
		if ( 0 != etemp ) {
			
			if ( 
				(etemp > datadir->Export.RVA)
				&&
				(etemp < (datadir->Export.RVA + datadir->Export.Size))
				){
				
				log.append(LOG_DEBUG,"Corresponding Address is a FORWARDER RVA: %08X\n",etemp);
				
				if ( ! ProcessStrCpy(hProcess, (winpe->ImageBase + etemp),&ForwardTemp) ) {
					log.append(LOG_ERROR,
						"PopulateExport(): Failed to read process memory at 0x%08X\n",
						winpe->ImageBase + etemp);
					return false;
				}
				
				if ( NULL == (et = new (t_pecoff_export)) ){
					log.append(LOG_ERROR,"PopulateExport(): Failed to allocate"
						" %u bytes for export entry\n",sizeof(t_pecoff_export));
					return false;
				}
				
				et->Address = 0x0;
				et->Name = NameTemp;
				et->Ordinal = otemp + ex.OrdinalBias;
				et->Forwarded = true;
				et->ForwardName = ForwardTemp;
				exports.push_back(et);
				
			} else {
				
				log.append(LOG_DEBUG,"Corresponding Address: %08X\n",
					winpe->ImageBase+etemp);
				
				if ( NULL == (et = new (t_pecoff_export)) ){
					log.append(LOG_ERROR,"PopulateExport(): Failed to allocate"
						" %u bytes for export entry\n",sizeof(t_pecoff_export));
					return false;
				}
				
				et->Address = winpe->ImageBase+etemp;
				et->Name = NameTemp;
				et->Ordinal = otemp + ex.OrdinalBias;
				et->Forwarded = false;
				et->ForwardName = "";
				exports.push_back(et);
			}
			
		} else {
			
			log.append(LOG_DEBUG,"Export has address of 0x00 - unused\n");
		}
		
		name_ord_cnt--;
	}

	return true;
}


bool PEfile::PopulateImport(HANDLE hProcess) {
	DWORD						import_tab;
	DWORD						remaining_size;
	t_image_import_descriptor	imp;
	DWORD						in;
	PEcoff_import				*import;
	DWORD						ft, oft;
	DWORD						oimage_thunk;
	DWORD						image_thunk;
	t_pecoff_import_func		*import_func;
	char						ordinal_buffer[20];
	DWORD						name_addr;


	log.append(LOG_DEBUG,"----PopulateImport(%s)----\n",internal_name.c_str());

	if ( 0 == datadir->Import.RVA ) {
		log.append(LOG_DEBUG,"PopulateImport(): Image has no import directory\n");
		return true;
	}

	import_tab = winpe->ImageBase + datadir->Import.RVA;
	remaining_size = datadir->Import.Size;

	do {
		
		if ( ! ReadProcessMemory(
				hProcess,
				(LPCVOID)import_tab,
				&imp,
				sizeof(t_image_import_descriptor),
				&in) ){
			log.append(LOG_ERROR,"PopulateImport(): Failed to read memory"
				" at 0x%08X with Image Import Descriptor\n",import_tab);
			return false;
		}
		remaining_size -= sizeof(t_image_import_descriptor);
		import_tab += sizeof(t_image_import_descriptor);

		if ( ! (
			(imp.FirstThunk == 0)
			&& (imp.OriginalFirstThunk == 0)
			&& (imp.NameRVA == 0)
			&& (imp.ForwarderChain == 0)
			&& (imp.TimeStamp == 0) )
			){
			//
			// Good to go
			//
			log.append(LOG_VERBOSE,
				"Image Import Descriptor:\n"
				"  Original First Thunk: 0x%08X\n"
				"  Time Stamp: 0x%08X\n"
				"  Forwarder Chain: 0x%08X\n"
				"  Name RVA: 0x%08X\n"
				"  First Thunk: 0x%08X\n",
				imp.OriginalFirstThunk,
				imp.TimeStamp,
				imp.ForwarderChain,
				imp.NameRVA,
				imp.FirstThunk);

			if ( NULL == (import=new(PEcoff_import)) ){
				log.append(LOG_ERROR,"PopulateImport(): Failed to allocate %u bytes\n",
					sizeof(PEcoff_import));
				return false;
			}

			ProcessStrCpy(hProcess, 
				winpe->ImageBase + imp.NameRVA, 
				&(import->Name));

			log.append(LOG_DEBUG,"Processing imports from %s...\n",
				import->Name.c_str());

			ft = winpe->ImageBase + imp.FirstThunk;
			oft = winpe->ImageBase + imp.OriginalFirstThunk;

			do {
				if ( NULL == (import_func=new(t_pecoff_import_func)) ){
					log.append(LOG_ERROR,"PopulateImport(): Failed to allocate %u bytes\n",
						sizeof(t_pecoff_import_func));
					return false;
				}

				if ( ! ReadProcessMemory(
					hProcess,
					(LPCVOID)oft,
					&oimage_thunk,
					sizeof(oimage_thunk),
					&in) ){

					log.append(LOG_ERROR,"PopulateImport(): Failed to read process "
						"memory at 0x%08X\n",oft);
					return false;
				}
				oft += sizeof(oimage_thunk);

				log.append(LOG_DEBUG,"oft image_thunk: %08X\n",oimage_thunk);

				if ( ! ReadProcessMemory(
					hProcess,
					(LPCVOID)ft,
					&image_thunk,
					sizeof(image_thunk),
					&in) ){

					log.append(LOG_ERROR,"PopulateImport(): Failed to read process "
						"memory at 0x%08X\n",oft);
					return false;
				}
				ft += sizeof(image_thunk);

				log.append(LOG_DEBUG,"ft image_thunk: %08X\n",image_thunk);

				//
				// early breakout
				//
				if ( (image_thunk == 0) && (oimage_thunk == 0) ) break;

				//
				// Check to see if we got a name to it
				//
				if ( (oimage_thunk & 0x80000000) != 0 ) {
					//
					// import is only by ordinal
					//
					sprintf(ordinal_buffer,"#%u", (oimage_thunk & 0x7FFFFFFF));
					import_func->Name = ordinal_buffer;
				} else {
					//
					// Skip the hint field, we don't care
					//
					name_addr = winpe->ImageBase + oimage_thunk + 2;
					ProcessStrCpy(hProcess,name_addr,&(import_func->Name));
				}
				
				//
				// Address might not be resolved yet
				//
				if ( oimage_thunk != image_thunk ) {
					import_func->Address = image_thunk;
				} else {
					import_func->Address = 0x00000000;
				}
				

				log.append(LOG_DEBUG,"0x%08X %s\n",
					import_func->Address, 
					import_func->Name.c_str());

				//
				// add to vector
				//
				import->functions.push_back(import_func);

			} while ( (image_thunk != 0) && (oimage_thunk != 0) );

			log.append(LOG_VERBOSE,"%u imports for %s processed\n",
				import->functions.size(),import->Name.c_str());

			if ( image_thunk != oimage_thunk ) {
				log.append(LOG_WARNING,
					"PopulateImport(): image thunk = %08X, original image thunk = %08X",
					image_thunk,oimage_thunk);
			}

			//
			// This import is processed, add to the imports vector
			//
			imports.push_back(import);

		} else /* terminating NULL entry */ {
			//
			// terminate loop when NULL entry in array is found
			//
			log.append(LOG_DEBUG,"Terminating Image Import Descriptor found\n");
			break;
		}

	} while ( remaining_size > sizeof(t_image_import_descriptor) );

	log.append(LOG_VERBOSE,"%u imported modules for %s processed\n",
				imports.size(),internal_name.c_str());

	log.append(LOG_DEBUG,
		"Terminated import directory with remaining size = %u\n",
		remaining_size);

	return true;
}


bool PEfile::PopulateExportByFile(HANDLE  fh) {
	DWORD						export_tab;
	DWORD						remaining_size;
	DWORD						in;
	t_export_directory_entry	ex;
	t_pecoff_export				*et;

	DWORD		ExportAddressTable;
	DWORD		NamePointerRVA;
	DWORD		OrdinalTableRVA;
	DWORD		name_ord_cnt;
	
	WORD		otemp;
	DWORD		ntemp;
	string		NameTemp;
	DWORD		etemp;
	string		ForwardTemp;
	

	log.append(LOG_DEBUG,"----PopulateExportByFile()----\n");

	if ( 0 == datadir->Export.RVA ) {
		log.append(LOG_DEBUG,"PopulateExportByFile(): Module has no Export entry\n");
		return true;
	}

	export_tab = RVA2Offset(datadir->Export.RVA);
	remaining_size = datadir->Export.Size;
	log.append(LOG_DEBUG,"Looking for the export table at 0x%08X\n",export_tab);

	SetFilePointer(fh,export_tab,NULL,FILE_BEGIN);
	if ( ! ReadFile(fh,&ex,sizeof(ex),&in,NULL) ){
		log.append(LOG_ERROR,
			"PopulateExportByFile(): Could not read 0x%08X\n",
			export_tab);
		return false;
	} else {
		log.append(LOG_DEBUG,
			"PopulateExportByFile(): %u bytes export table entry in\n",in);
		remaining_size -= sizeof(ex);
	}

	log.append(LOG_VERBOSE,
		"Export entry:\n"
		"  Characteristics: %08X\n"
		"  Time Stamp: %s"
		"  Version: %u.%u\n"
		"  Name RVA: 0x%08X\n"
		"  Ordinal Bias: %u\n"
		"  Number of Functions: %u\n"
		"  Number of Names: %u\n"
		"  Address of Functions: 0x%08X\n"
		"  Address of Names: 0x%08X\n"
		"  Address of Ordinals: 0x%08X\n",
		ex.Characteristics,
		ctime((long *)&(ex.TimeStamp)),
		ex.MajorVersion, ex.MiniorVersion,
		ex.NameRVA,
		ex.OrdinalBias,
		ex.NumberOfFunctions,
		ex.NumberOfNames,
		ex.AddressOfFunctions,
		ex.AddressOfNames,
		ex.AddressOfOrdinals);	
	
	FileStrCpy(fh,RVA2Offset(ex.NameRVA),&internal_name);
	log.append(LOG_VERBOSE,"Internal DLL name: '%s'\n",internal_name.c_str());

	
	ExportAddressTable = RVA2Offset(ex.AddressOfFunctions);
	NamePointerRVA = RVA2Offset(ex.AddressOfNames);
	OrdinalTableRVA = RVA2Offset(ex.AddressOfOrdinals);
	
	name_ord_cnt = ex.NumberOfNames;	// Names and ordinals are __required__ to be the same
	
	while (name_ord_cnt > 0) {
		//
		// Ordinal and Name pointer tables run in parallel
		//
		SetFilePointer(fh,OrdinalTableRVA,NULL,FILE_BEGIN);
		if ( ! ReadFile(fh,&otemp,sizeof(otemp),&in,NULL) ){
			log.append(LOG_ERROR,
				"PopulateExportbyFile(): Failed to read at 0x%08X\n",
				OrdinalTableRVA);
			return false;
		} 
		log.append(LOG_DEBUG,"Ordinal entry: %u\n",otemp);
		OrdinalTableRVA += sizeof(otemp);
		
		SetFilePointer(fh,NamePointerRVA,NULL,FILE_BEGIN);
		if ( ! ReadFile(fh,&ntemp,sizeof(ntemp),&in,NULL) ){
		
			log.append(LOG_ERROR,
				"PopulateExportbyfile(): Failed to read at 0x%08X\n",
				NamePointerRVA);
			return false;
		} 
		log.append(LOG_DEBUG,"Correspondig Name RVA entry: %08X\n",ntemp);
		NamePointerRVA += sizeof(ntemp);
		
		//
		// Now see what's the name to it
		//
		if ( 0 != ntemp ) {
			if ( ! FileStrCpy(fh, RVA2Offset(ntemp), &NameTemp) ) {
				log.append(LOG_ERROR,
					"PopulateExportByFile(): Failed to read at 0x%08X\n",
					ntemp);
				return false;
			}
			log.append(LOG_DEBUG,"Corresponding Name: '%s'\n",NameTemp.c_str());
		} else {
			NameTemp = "";
		}
		
		//
		// The ordinal (without any fixup) is an index in the Export Address Table
		//
		SetFilePointer(fh,(ExportAddressTable + (4*otemp)),NULL,FILE_BEGIN);
		if ( ! ReadFile(fh,&etemp,sizeof(etemp),&in,NULL) ){
		
			log.append(LOG_ERROR,
				"PopulateExportByFile(): Failed to read at 0x%08X\n",
				(ExportAddressTable + (4*otemp)));
			return false;
		} 
		
		//
		// If the export address is NOT within the export section it's a real 
		// export, otherwise it's forwarded
		//
		if ( 0 != etemp ) {
			
			if ( 
				(etemp > datadir->Export.RVA)
				&&
				(etemp < (datadir->Export.RVA + datadir->Export.Size))
				){
				
				log.append(LOG_DEBUG,"Corresponding Address is a FORWARDER RVA: %08X\n",etemp);
				
				if ( ! FileStrCpy(fh, RVA2Offset(etemp),&ForwardTemp) ) {
					log.append(LOG_ERROR,
						"PopulateExportByFile(): Failed to read at 0x%08X\n",
						etemp);
					return false;
				}
				
				if ( NULL == (et = new (t_pecoff_export)) ){
					log.append(LOG_ERROR,"PopulateExportByFile(): Failed to allocate"
						" %u bytes for export entry\n",sizeof(t_pecoff_export));
					return false;
				}
				
				et->Address = 0x0;
				et->Name = NameTemp;
				et->Ordinal = otemp + ex.OrdinalBias;
				et->Forwarded = true;
				et->ForwardName = ForwardTemp;
				exports.push_back(et);
				
			} else {
				
				log.append(LOG_DEBUG,"Corresponding Address: %08X\n",
					etemp);
				
				if ( NULL == (et = new (t_pecoff_export)) ){
					log.append(LOG_ERROR,"PopulateExportByFile(): Failed to allocate"
						" %u bytes for export entry\n",sizeof(t_pecoff_export));
					return false;
				}
				
				et->Address = etemp;
				et->Name = NameTemp;
				et->Ordinal = otemp + ex.OrdinalBias;
				et->Forwarded = false;
				et->ForwardName = "";
				exports.push_back(et);
			}
			
		} else {
			
			log.append(LOG_DEBUG,"Export has address of 0x00 - unused\n");
		}
		
		name_ord_cnt--;
	}

	return true;
}


bool PEfile::PopulateImportByFile(HANDLE fh) {
	DWORD						import_tab;
	DWORD						remaining_size;
	t_image_import_descriptor	imp;
	DWORD						in;
	PEcoff_import				*import;
	DWORD						ft, oft;
	DWORD						oimage_thunk;
	DWORD						image_thunk;
	t_pecoff_import_func		*import_func;
	char						ordinal_buffer[20];
	DWORD						name_addr;


	log.append(LOG_DEBUG,"----PopulateImport(%s)----\n",internal_name.c_str());

	if ( 0 == datadir->Import.RVA ) {
		log.append(LOG_DEBUG,"PopulateImport(): Image has no import directory\n");
		return true;
	}

	import_tab = RVA2Offset(datadir->Import.RVA);
	remaining_size = datadir->Import.Size;

	do {
		
		SetFilePointer(fh,import_tab,NULL,FILE_BEGIN);
		if ( ! ReadFile(fh,&imp,sizeof(t_image_import_descriptor),&in,NULL) ){
		
			log.append(LOG_ERROR,"PopulateImportByFile(): Failed to read "
				" at 0x%08X with Image Import Descriptor\n",import_tab);
			return false;
		}
		remaining_size -= sizeof(t_image_import_descriptor);
		import_tab += sizeof(t_image_import_descriptor);

		if ( ! (
			(imp.FirstThunk == 0)
			&& (imp.OriginalFirstThunk == 0)
			&& (imp.NameRVA == 0)
			&& (imp.ForwarderChain == 0)
			&& (imp.TimeStamp == 0) )
			){
			//
			// Good to go
			//
			log.append(LOG_VERBOSE,
				"Image Import Descriptor:\n"
				"  Original First Thunk: 0x%08X\n"
				"  Time Stamp: 0x%08X\n"
				"  Forwarder Chain: 0x%08X\n"
				"  Name RVA: 0x%08X\n"
				"  First Thunk: 0x%08X\n",
				imp.OriginalFirstThunk,
				imp.TimeStamp,
				imp.ForwarderChain,
				imp.NameRVA,
				imp.FirstThunk);

			if ( NULL == (import=new(PEcoff_import)) ){
				log.append(LOG_ERROR,"PopulateImportByFile(): Failed to allocate %u bytes\n",
					sizeof(PEcoff_import));
				return false;
			}

			FileStrCpy(fh, 
				RVA2Offset(imp.NameRVA), 
				&(import->Name));

			log.append(LOG_DEBUG,"Processing imports from %s...\n",
				import->Name.c_str());

			ft = RVA2Offset(imp.FirstThunk);
			oft = RVA2Offset(imp.OriginalFirstThunk);

			do {
				if ( NULL == (import_func=new(t_pecoff_import_func)) ){
					log.append(LOG_ERROR,"PopulateImportByFile(): Failed to allocate %u bytes\n",
						sizeof(t_pecoff_import_func));
					return false;
				}

				SetFilePointer(fh,oft,NULL,FILE_BEGIN);
				if ( ! ReadFile(fh,&oimage_thunk,sizeof(oimage_thunk),&in,NULL) ){

					log.append(LOG_ERROR,"PopulateImportByFile(): Failed to read  "
						"at 0x%08X\n",oft);
					return false;
				}
				oft += sizeof(oimage_thunk);

				log.append(LOG_DEBUG,"oft image_thunk: %08X\n",oimage_thunk);

				SetFilePointer(fh,ft,NULL,FILE_BEGIN);
				if ( ! ReadFile(fh,&image_thunk,sizeof(image_thunk),&in,NULL) ){
				
					log.append(LOG_ERROR,"PopulateImportByFile(): Failed to read "
						"at 0x%08X\n",oft);
					return false;
				}
				ft += sizeof(image_thunk);

				log.append(LOG_DEBUG,"ft image_thunk: %08X\n",image_thunk);

				//
				// early breakout
				//
				if ( (image_thunk == 0) && (oimage_thunk == 0) ) break;

				//
				// Check to see if we got a name to it
				//
				if ( (oimage_thunk & 0x80000000) != 0 ) {
					//
					// import is only by ordinal
					//
					sprintf(ordinal_buffer,"#%u", (oimage_thunk & 0x7FFFFFFF));
					import_func->Name = ordinal_buffer;
				} else {
					//
					// Skip the hint field, we don't care
					//
					name_addr = RVA2Offset(oimage_thunk + 2);
					FileStrCpy(fh,name_addr,&(import_func->Name));
				}
				
				//
				// Address might not be resolved yet
				//
				if ( oimage_thunk != image_thunk ) {
					import_func->Address = image_thunk;
				} else {
					import_func->Address = 0x00000000;
				}
				

				log.append(LOG_DEBUG,"0x%08X %s\n",
					import_func->Address, 
					import_func->Name.c_str());

				//
				// add to vector
				//
				import->functions.push_back(import_func);

			} while ( (image_thunk != 0) && (oimage_thunk != 0) );

			log.append(LOG_VERBOSE,"%u imports for %s processed\n",
				import->functions.size(),import->Name.c_str());

			if ( image_thunk != oimage_thunk ) {
				log.append(LOG_WARNING,
					"PopulateImportByFile(): image thunk = %08X, original image thunk = %08X",
					image_thunk,oimage_thunk);
			}

			//
			// This import is processed, add to the imports vector
			//
			imports.push_back(import);

		} else /* terminating NULL entry */ {
			//
			// terminate loop when NULL entry in array is found
			//
			log.append(LOG_DEBUG,"Terminating Image Import Descriptor found\n");
			break;
		}

	} while ( remaining_size > sizeof(t_image_import_descriptor) );

	log.append(LOG_VERBOSE,"%u imported modules for %s processed\n",
				imports.size(),internal_name.c_str());

	log.append(LOG_DEBUG,
		"Terminated import directory with remaining size = %u\n",
		remaining_size);

	return true;
}


bool PEfile::FileStrCpy(HANDLE fileh, DWORD offset, string *str) {
	DWORD		fpsave, in;
	char		c[2];
	string		rstr;
	bool		zerofound = false;
	
	fpsave=SetFilePointer(fileh,0,NULL,FILE_CURRENT);

	// 
	// according to MSDN (http://msdn.microsoft.com/library/en-us/fileio/base/setfilepointer.asp)
	// there is a return value of INVALID_SET_FILE_POINTER but this is not defined in any
	// of the include files; great! Hence the zerofound variable.
	//
	SetFilePointer(fileh,offset,NULL,FILE_BEGIN);
		
	c[1]='\0';
	while ( ReadFile(fileh,c,sizeof(char),&in,NULL) ) {
		
		if (c[0]=='\0') {
			zerofound = true;
			break;
		} else {
			rstr += c;
		}
	}

	if (zerofound)
		*str = rstr;
	else
		*str = "";

	SetFilePointer(fileh,fpsave,NULL,FILE_BEGIN);
	return zerofound;
}