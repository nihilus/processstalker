#ifndef __BLACKMAGIC_HPP__
#define __BLACKMAGIC_HPP__

#include <windows.h>

#pragma pack(1)

//
// Windows magics - some of the stuff is stolen from wine
//
 
typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING {
  USHORT Length;        /* bytes */
  USHORT MaximumLength; /* bytes */
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _CLIENT_ID
{
   HANDLE UniqueProcess;
   HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _PEB_LDR_DATA
{
    ULONG               Length;
    BOOLEAN             Initialized;
    PVOID               SsHandle;
    LIST_ENTRY          InLoadOrderModuleList;
    LIST_ENTRY          InMemoryOrderModuleList;
    LIST_ENTRY          InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB
{
    BYTE                         Reserved1[2];       /*  00 */
    BYTE                         BeingDebugged;      /*  02 */
    BYTE                         Reserved2[5];       /*  03 */
    HMODULE                      ImageBaseAddress;   /*  08 */
    PPEB_LDR_DATA                LdrData;            /*  0c */
    DWORD						 ProcessParameters;  /*  10 */
    PVOID                        __pad_14;           /*  14 */
    HANDLE                       ProcessHeap;        /*  18 */
    BYTE                         __pad_1c[36];       /*  1c */
    DWORD		                 TlsBitmap;          /*  40 */
    ULONG                        TlsBitmapBits[2];   /*  44 */
    BYTE                         __pad_4c[24];       /*  4c */
    ULONG                        NumberOfProcessors; /*  64 */
    BYTE                         __pad_68[128];      /*  68 */
    PVOID                        Reserved3[59];      /*  e8 */
    ULONG                        SessionId;          /* 1d4 */
} PEB, *PPEB;

typedef struct _TEB
{
    NT_TIB          Tib;                        /* 000 */
    PVOID           EnvironmentPointer;         /* 01c */
    CLIENT_ID       ClientId;                   /* 020 */
    PVOID           ActiveRpcHandle;            /* 028 */
    PVOID           ThreadLocalStoragePointer;  /* 02c */
    PPEB            Peb;                        /* 030 */
    ULONG           LastErrorValue;             /* 034 */
    BYTE            __pad038[140];              /* 038 */
    ULONG           CurrentLocale;              /* 0c4 */
    BYTE            __pad0c8[1752];             /* 0c8 */
    PVOID           Reserved2[278];             /* 7a0 */
    UNICODE_STRING  StaticUnicodeString;        /* bf8 used by advapi32 */
    WCHAR           StaticUnicodeBuffer[261];   /* c00 used by advapi32 */
    PVOID           DeallocationStack;          /* e0c */
    PVOID           TlsSlots[64];               /* e10 */
    LIST_ENTRY      TlsLinks;                   /* f10 */
    PVOID           Reserved4[26];              /* f18 */
    PVOID           ReservedForOle;             /* f80 Windows 2000 only */
    PVOID           Reserved5[4];               /* f84 */
    PVOID           TlsExpansionSlots;          /* f94 */
} TEB, *PTEB;

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    MaxThreadInfoClass
} THREADINFOCLASS;

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS  ExitStatus;
    PVOID     TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG     AffinityMask;
    LONG      Priority;
    LONG      BasePriority;

} THREAD_BASIC_INFORMATION;

#pragma pack(4)


bool utilUnicodeToAnsi(WCHAR *szW, char *szA);
bool GetHandleName(HANDLE hProcess, HANDLE xhandle,char *szRetBuff, DWORD dwRetBufSize);

bool InitBlackmagic(void);
bool Exorcism(void);
bool ReadThreadBasicInformation(HANDLE hThread, THREAD_BASIC_INFORMATION *basics);

#endif __BLACKMAGIC_HPP__