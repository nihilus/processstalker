#ifndef __PECOFF_HPP__
#define __PECOFF_HPP__

#include <stdio.h>
#include <windows.h>

#include <vector>
#include <string>

#include "log.hpp"

using namespace std;


#define PECOFF_MAGIC_PE		0x10B
#define PECOFF_MAGIC_PEPLUS	0x20B

extern char *DebugTypes[];
#define DEBUG_TYPE_NAME(a)		(a<10?DebugTypes[a]:"(invalid)")


#pragma pack(1)

typedef struct __COFF_HEADER {
	WORD	machine;
	WORD	NumberOfSections;
	DWORD	TimeStamp;
	DWORD	PointerToSymbolTable;
	DWORD	NumberOfSymbols;
	WORD	SizeOfOptionalHeader;
	WORD	Characteristics;
} t_coff_header;

typedef struct __OPTIONAL_HEADER_PE {
	WORD	Magic;
	BYTE	LinkerMajor;
	BYTE	LinkerMinor;
	DWORD	SizeOfCode;
	DWORD	SizeOfInitializedData;
	DWORD	SizeOfUninitializedData;
	DWORD	AddressOfEntryPoint;
	DWORD	BaseOfCode;
	DWORD	BaseOfData;
} t_optional_header_pe;

typedef struct __OPTIONAL_HEADER_PEPLUS {
	WORD	Magic;
	BYTE	LinkerMajor;
	BYTE	LinkerMinor;
	DWORD	SizeOfCode;
	DWORD	SizeOfInitializedData;
	DWORD	SizeOfUninitializedData;
	DWORD	AddressOfEntryPoint;
	DWORD	BaseOfCode;
} t_optional_header_peplus;

typedef struct __OPTIONAL_WINDOWS_PE {
	DWORD	ImageBase;
	DWORD	SectionAlignment;
	DWORD	FileAlignment;
	WORD	OperatingSystemMajor;
	WORD	OperatingSystemMinor;
	WORD	ImageVersionMajor;
	WORD	ImageVersionMinor;
	WORD	SubsystemMajor;
	WORD	SubsystemMinor;
	DWORD	Reserved;
	DWORD	SizeOfImage;
	DWORD	SizeOfHeaders;
	DWORD	Checksum;
	WORD	Subsystem;
	WORD	DLLCharacteristics;
	DWORD	SizeOfStackReserve;
	DWORD	SizeOfStackCommit;
	DWORD	SizeOfHeapReserve;
	DWORD	SizeOfHeapCommit;
	DWORD	LoaderFlags;
	DWORD	NumberOfRVAAndSizes;
} t_optional_windows_pe;

typedef struct __OPTIONAL_WINDOWS_PEPLUS {
	DWORD	ImageBase[2];
	DWORD	SectionAlignment;
	DWORD	FileAlignment;
	WORD	OperatingSystemMajor;
	WORD	OperatingSystemMinor;
	WORD	ImageVersionMajor;
	WORD	ImageVersionMinor;
	WORD	SubsystemMajor;
	WORD	SubsystemMinor;
	DWORD	Reserved;
	DWORD	SizeOfImage;
	DWORD	SizeOfHeaders;
	DWORD	Checksum;
	WORD	Subsystem;
	WORD	DLLCharacteristics;
	DWORD	SizeOfStackReserve[2];
	DWORD	SizeOfStackCommit[2];
	DWORD	SizeOfHeapReserve[2];
	DWORD	SizeOfHeapCommit[2];
	DWORD	LoaderFlags;
	DWORD	NumberOfRVAAndSizes;
} t_optional_windows_peplus;

typedef struct __IMAGE_DATA_DIRECTORY {
	DWORD	RVA;
	DWORD	Size;
} t_image_data_directory;

typedef struct __DATA_DIRECTORIES {
		t_image_data_directory	Export;
		t_image_data_directory	Import;
		t_image_data_directory	Resource;
		t_image_data_directory	Exception;
		t_image_data_directory	Certificate;
		t_image_data_directory	Base_relocation;
		t_image_data_directory	Debug;
		t_image_data_directory	Architecture;
		t_image_data_directory	GlobalPtr;
		t_image_data_directory	ThreadLocalStorage;
		t_image_data_directory	LoadConfig;
		t_image_data_directory	BoundImport;
		t_image_data_directory	ImportAddress;
		t_image_data_directory	DelayImport;
		t_image_data_directory	COMplus;
		t_image_data_directory	Reserved;
} t_data_directories;

typedef struct __SECTION_HEADERS {
	BYTE	Name[8];
	DWORD	VirtualSize;
	DWORD	VirtualAddress;
	DWORD	SizeOfRawData;
	DWORD	PointerToRawData;
	DWORD	PointerToRelocations;
	DWORD	PointerToLineNumbers;
	WORD	NumberOfRelocations;
	WORD	NumberOfLineNumbers;
	DWORD	Characteristics;
} t_section_header;

typedef struct __EXPORT_DIRECTORY_ENTRY {
	DWORD	Characteristics;
	DWORD	TimeStamp;
	WORD	MajorVersion;
	WORD	MiniorVersion;
	DWORD	NameRVA;
	DWORD	OrdinalBias;
	DWORD	NumberOfFunctions;
	DWORD	NumberOfNames;
	DWORD	AddressOfFunctions;
	DWORD	AddressOfNames;
	DWORD	AddressOfOrdinals;
} t_export_directory_entry;

//
// Import
//

typedef struct __IMAGE_IMPORT_DESCRIPTOR {
	DWORD	OriginalFirstThunk;
	DWORD	TimeStamp;
	DWORD	ForwarderChain;
	DWORD	NameRVA;
	DWORD	FirstThunk;
} t_image_import_descriptor;

//
// Debug symbol stuff
//

typedef struct __IMAGE_DEBUG_DIRECTORY {
	DWORD	Characteristics;  
	DWORD	TimeDateStamp;  
	WORD	MajorVersion;  
	WORD	MinorVersion;  
	DWORD	Type;  
	DWORD	SizeOfData;  
	DWORD	AddressOfRawData;  
	DWORD	PointerToRawData;
} t_image_debug_directory;

typedef struct __IMAGE_COFF_SYMBOLS_HEADER {
    DWORD   NumberOfSymbols;
    DWORD   LvaToFirstSymbol;
    DWORD   NumberOfLinenumbers;
    DWORD   LvaToFirstLinenumber;
    DWORD   RvaToFirstByteOfCode;
    DWORD   RvaToLastByteOfCode;
    DWORD   RvaToFirstByteOfData;
    DWORD   RvaToLastByteOfData;
} t_image_coff_symbols;

typedef struct __FPO_DATA {
    DWORD       ulOffStart;             // offset 1st byte of function code
    DWORD       cbProcSize;             // # bytes in function
    DWORD       cdwLocals;              // # bytes in locals/4
    WORD        cdwParams;              // # bytes in params/4
    WORD        cbProlog : 8;           // # bytes in prolog
    WORD        cbRegs   : 3;           // # regs saved
    WORD        fHasSEH  : 1;           // TRUE if SEH in func
    WORD        fUseBP   : 1;           // TRUE if EBP has been allocated
    WORD        reserved : 1;           // reserved for future use
    WORD        cbFrame  : 2;           // frame type
} t_image_fpo_data;

typedef struct __IMAGE_DEBUG_MISC {
    DWORD       DataType;               // type of misc data
    DWORD       Length;                 // total length of record, rounded to four
                                        // byte multiple.
    BOOLEAN     Unicode;                // TRUE if data is unicode string
    BYTE        Reserved[ 3 ];
    //BYTE        Data[ 1 ];			// Actual data (commented out to be read seperately)
} t_image_debug_misc;

typedef struct __CODEVIEW_SIGNATURE {
	DWORD		Signature;
	DWORD		Filepos;
} t_codeview_signature;

typedef struct __CODEVIEW_EXTERNAL {
	DWORD		TimeStamp;
	DWORD		Unknown;
} t_codeview_external;

typedef struct __CODEVIEW_HEADER {
	WORD		HeaderSize;
	WORD		EntrySize;
	DWORD		NumberOfEntries;
	DWORD		NextDirectoryOffset;
	DWORD		Flags;
} t_codeview_header;

typedef struct __CODEVIEW_DIRECTORY_ENTRY {
	WORD		SubsectionType;
	WORD		iMod;
	DWORD		FileOffset;
	DWORD		Size;
} t_codeview_directory_entry;

#pragma pack(8)

//
// structs that don't need to be packed tightly
//
typedef struct __PECOFF_EXPORT {
	DWORD	Address;
	WORD	Ordinal;
	string	Name;
	bool	Forwarded;
	string	ForwardName;
} t_pecoff_export;

typedef struct __PECOFF_IMPORT_FUNC {
	DWORD	Address;
	string	Name;
} t_pecoff_import_func;

//
//
// A class to handle the import mess
//
//
class PEcoff_import {
public:
	string								Name;
	vector <t_pecoff_import_func *>		functions;

	PEcoff_import(void);
	~PEcoff_import(void);

	DWORD	FunctionByName(char *name);
	char	*FunctionByAddress(DWORD addr);
};


//
//
// THE main PEfile class
//
//
class PEfile {

public:
	//
	// member variable for logging
	//
	Logger		log;

	//
	// file info elements
	//
	WORD						peoffset;		// offset of PE header in file
	t_coff_header				coff;			// COFF header
	bool						peplus;			// PE32 (false) or PE32+ (true) header
	t_optional_header_pe		*pe;			// pointer to PE32/PE32+ Header
	t_optional_windows_pe		*winpe;			// Windows specific PE32/PE32+ header
	t_data_directories			*datadir;		// Data Directory Tables	
	vector <t_section_header*>	section;		// Section Header table

	//
	// populated data
	//
	vector <t_pecoff_export*>	exports;		// the exported functions of this module if any
	string						internal_name;	// for DLLs, how it was called at compile time
	string						debug_name;		// When there was a MISC debug info section
	vector <PEcoff_import*>		imports;		// the imported modules and their functions if any

	//
	// Constructor
	//
	PEfile(void);
	PEfile(HANDLE handle);
	~PEfile(void);

	//
	// File
	//
	bool PEOpen(char *fname);
	bool PEOpen(HANDLE handle);
	void PEClose(void);

	//
	// Parsing
	//
	bool parse(void);

	//
	// Information population
	//
	bool PopulateByProcess(HANDLE hProcess);
	bool PopulateByFile(void);

	//
	// Easy access to import and export symbols
	// ImportByName can also handle module specification such as "Kernel32.dll:HeapCreate"
	//
	DWORD	ImportByName(char *name);
	DWORD	ExportByName(char *name);

	//
	// Public because they are useful (*huray, I'm useful*)
	//
	DWORD ProcessStrlen(HANDLE hProcess, DWORD address);
	bool ProcessStrCpy(HANDLE hProcess, DWORD address, string *dest);

protected:

	HANDLE		fh;
	
private:

	DWORD RVA2Offset(DWORD rva);

	bool ReadDOS(void);
	bool ReadCOFF(void);
	bool ReadPE32(void);
	bool ReadSectionHeaders(void);
	bool ReadDebug(void);
	bool ReadDebug_COFF(DWORD fileoffset);
	bool ReadDebug_CodeView(DWORD fileoffset);
	bool ReadDebug_CodeViewDir(HANDLE hFile, DWORD fileoffset);	// this is seperated to later support dbg files
	bool ReadDebug_FPO(DWORD fileoffset);
	bool ReadDebug_Misc(DWORD fileoffset);

	bool PopulateExport(HANDLE hProcess);
	bool PopulateImport(HANDLE hProcess);

	bool PopulateExportByFile(HANDLE fh);
	bool PopulateImportByFile(HANDLE fh);

	bool FileStrCpy(HANDLE fileh,DWORD offset,string *str);
};

#endif __PECOFF_HPP__