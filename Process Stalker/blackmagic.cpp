#include <stdio.h>
#include <string>
#include <windows.h>

#include "blackmagic.hpp"

// ntdll instance
HINSTANCE hNTDLL=0;

//
// some magic functions we need 
//

// NtQueryObject
typedef DWORD (WINAPI * NTQUERYOBJECT)(DWORD,DWORD,DWORD ,DWORD ,DWORD);
NTQUERYOBJECT lpNtQueryObject=NULL;
// NtQueryInformationThread
typedef NTSTATUS (WINAPI * NTQUERYINFORMATIONTHREAD)(HANDLE,THREADINFOCLASS,PVOID,ULONG,PULONG);
NTQUERYINFORMATIONTHREAD lpNtQueryInformationThread = NULL;



bool InitBlackmagic(void) {
	
	if ( NULL == (hNTDLL=LoadLibrary("ntdll.dll")) ){
		return false;
	}

	if ( NULL == (lpNtQueryObject = 
		(NTQUERYOBJECT)GetProcAddress(hNTDLL,"NtQueryObject")) ){
		return false;
	}

	if ( NULL == (lpNtQueryInformationThread =
		(NTQUERYINFORMATIONTHREAD)GetProcAddress(hNTDLL,"NtQueryInformationThread")) ){
		return false;
	}

	return true;
}


bool Exorcism(void) {

	if ( NULL != hNTDLL ) 
		FreeLibrary(hNTDLL);

	return true;
}


bool ReadThreadBasicInformation(HANDLE hThread, THREAD_BASIC_INFORMATION *basics) {
	THREADINFOCLASS				tic;
	ULONG						ret;
	NTSTATUS					rv;

	tic = ThreadBasicInformation;
	rv=lpNtQueryInformationThread(hThread,tic, basics, sizeof(THREAD_BASIC_INFORMATION),&ret);

	if ( 0 == rv ) 
		return true;
	else 
		return false;
}

//
// Stolen from some posting
//

#define DUPLICATEHANDLE_CURRENTPROCESS (HANDLE) -1
#define ObjectNameInformation 1

bool utilUnicodeToAnsi(WCHAR *szW, char *szA)
{
    WideCharToMultiByte(CP_ACP, 0, szW, -1, szA, lstrlenW(szW)+2, NULL, NULL);
    return true;
}

bool GetHandleName(HANDLE hProcess, HANDLE xhandle,char *szRetBuff, DWORD dwRetBufSize) {
    HANDLE	hDest;
	bool	worked = false;
	WCHAR	Space[1024];

    if (hProcess != INVALID_HANDLE_VALUE)
    {
        if (!DuplicateHandle (hProcess, xhandle,
			DUPLICATEHANDLE_CURRENTPROCESS,
			&hDest, 0, false, DUPLICATE_SAME_ACCESS) )
        {
            //CloseHandle(hProcess);
            return false;
        }
     
        memset(Space,0,sizeof(Space));
        lpNtQueryObject((DWORD) hDest,ObjectNameInformation,(DWORD) Space,sizeof(Space), NULL);
        if (*Space)
        {
			worked = true;
            utilUnicodeToAnsi(Space+4,szRetBuff);
        }
		
		CloseHandle(hDest);
		return worked;
		
    }
    else
        return false;
}
