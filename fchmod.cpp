#include "fchmod.h"

#define __builtin_ia32_sfence()
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <io.h>
#include <wchar.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stddef.h>
//#include <winternl.h>

// NT structures are undefined outside NT DDKs
typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectAllInformation,
    ObjectDataInformation
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS FAR* LPOBJECT_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _UNICODE_STRING FAR * LPUNICODE_STRING;

typedef struct _PUBLIC_OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG Reserved[10];    // reserved for internal use
 } PUBLIC_OBJECT_BASIC_INFORMATION, *PPUBLIC_OBJECT_BASIC_INFORMATION;

typedef struct _PUBLIC_OBJECT_BASIC_INFORMATION FAR *LPPUBLIC_OBJECT_BASIC_INFORMATION;

typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG Reserved [22];    // reserved for internal use
} PUBLIC_OBJECT_TYPE_INFORMATION, *PPUBLIC_OBJECT_TYPE_INFORMATION;

typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION FAR *LPPUBLIC_OBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION FAR *LPOBJECT_NAME_INFORMATION;

// NSTATUS codes are undefined outside NT DDKs
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                   ((NTSTATUS) 0x00000000)
#endif

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW           ((NTSTATUS) 0x80000005)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS) 0xC0000004)
#endif

#ifndef MIN
#define MIN(A, B) (((A) < (B)) ? (A) : (B))
#endif

#if _MSC_VER
#define NAKED __declspec(naked)
#else
//#define NAKED __attribute__ ((naked)) 
//#define NAKED __declspec(naked)
#define NAKED 
#if __GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1)
#define INTERRUPT __attribute__ ((interrupt))
struct interrupt_frame;
#endif
#endif

#define GetVxDServiceOrdinal(service)   service

#ifdef _MSC_VER
#define VxDCall(service) \
    _asm _emit 0xcd \
    _asm _emit 0x20 \
    _asm _emit (GetVxDServiceOrdinal(service) & 0xff) \
    _asm _emit (GetVxDServiceOrdinal(service) >> 8) & 0xff \
    _asm _emit (GetVxDServiceOrdinal(service) >> 16) & 0xff \
    _asm _emit (GetVxDServiceOrdinal(service) >> 24) & 0xff \

#define VxDJmp(service) \
    _asm _emit 0xcd \
    _asm _emit 0x20 \
    _asm _emit (GetVxDServiceOrdinal(service) & 0xff) \
    _asm _emit ((GetVxDServiceOrdinal(service) >> 8) & 0xff) | 0x80 \
    _asm _emit (GetVxDServiceOrdinal(service) >> 16) & 0xff \
    _asm _emit (GetVxDServiceOrdinal(service) >> 24) & 0xff \
	
#else

#define VxDStringifyX(X) #X
#define VxDStringify(X) VxDStringifyX(X)

#define VxDCall(service) \
    __asm__ volatile(\
		".byte 0xcd\n\t" \
		".byte 0x20\n\t" \
		".byte (" VxDStringify(GetVxDServiceOrdinal(service)) " & 0xff)\n\t" \
		".byte (" VxDStringify(GetVxDServiceOrdinal(service)) " >> 8) & 0xff\n\t" \
		".byte (" VxDStringify(GetVxDServiceOrdinal(service)) " >> 16) & 0xff\n\t" \
		".byte (" VxDStringify(GetVxDServiceOrdinal(service)) " >> 24) & 0xff\n\t" \
	)

#define VxDJmp(service) \
    __asm__ volatile(\
		".byte 0xcd\n\t" \
		".byte 0x20\n\t" \
		".byte (" VxDStringify(GetVxDServiceOrdinal(service)) " & 0xff)\n\t" \
		".byte ((" VxDStringify(GetVxDServiceOrdinal(service)) " >> 8) & 0xff) | 0x80\n\t" \
		".byte (" VxDStringify(GetVxDServiceOrdinal(service)) " >> 16) & 0xff\n\t" \
		".byte (" VxDStringify(GetVxDServiceOrdinal(service)) " >> 24) & 0xff\n\t" \
	)
	
#endif

#ifndef MAKEDWORD
#define MAKEDWORD(a, b)      ((DWORD)(((WORD)(a)) | ((DWORD)((WORD)(b))) << 16))
#endif

#ifndef HIDWORD
#define HIDWORD(l)          ((DWORD)((((ULONGLONG)(l)) >> 32) & 0xffffffff))
#endif

#ifndef LODWORD
#define LODWORD(l)          ((DWORD)(((ULONGLONG)(l)) & 0xffffffff))
#endif

#ifndef MAKEDWORD64
#define MAKEDWORD64(a, b, c) ((ULONGLONG)(((WORD)(a)) | ((DWORD)((WORD)(b))) << 16 | ((ULONGLONG)((DWORD)(c))) << 32))
#endif

#ifndef VOLUME_NAME_DOS
#define VOLUME_NAME_DOS 0x0
#endif

#ifndef VOLUME_NAME_GUID
#define VOLUME_NAME_GUID 0x1
#endif

#ifndef VOLUME_NAME_NONE
#define VOLUME_NAME_NONE 0x4
#endif

#ifndef VOLUME_NAME_NT
#define VOLUME_NAME_NT 0x2
#endif

#ifndef FILE_NAME_NORMALIZED
#define FILE_NAME_NORMALIZED 0x0
#endif

#ifndef FILE_NAME_OPENED
#define FILE_NAME_OPENED 0x8
#endif

#ifndef VER_PLATFORM_WIN32s
#define VER_PLATFORM_WIN32s 0
#endif

#ifndef VER_PLATFORM_WIN32_WINDOWS
#define VER_PLATFORM_WIN32_WINDOWS 1
#endif

#ifndef VER_PLATFORM_WIN32_NT
#define VER_PLATFORM_WIN32_NT 2
#endif

// CompareString and CompareStringW are undefined on NT 3.1
#ifndef CompareString
	#ifdef  UNICODE
		#define CompareString CompareStringW
	#else   /* UNICODE */
		#define CompareString CompareStringA
	#endif /* UNICODE */
	static inline int CompareStringA(LCID lcid, DWORD fdwStyle, LPCSTR lpString1, int cch1, LPCSTR lpString2, int cch2)
	{
		int lpString1Len = ((lpString1 == NULL) ? 0 : lstrlen(lpString1));
		int lpString2Len = ((lpString2 == NULL) ? 0 : lstrlen(lpString2));

		int cch1BufLength;
		int cch2BufLength;

		int i;
		int ret;

		LPWSTR string1;
		LPWSTR string2;

		if(cch1 < 0)
		{
			cch1BufLength = lpString1Len;
		}
		else
		{
			cch1BufLength = MIN(lpString1Len + 1, cch1);
		}

		if(cch2 < 0)
		{
			cch2BufLength = lpString2Len;
		}
		else
		{
			cch2BufLength = MIN(lpString2Len + 1, cch2);
		}

		string1 = (LPWSTR)LocalAlloc(LPTR, cch1BufLength * sizeof (WCHAR));

		if(string1 == NULL)
		{
			return 0;
		}

		string2 = (LPWSTR)LocalAlloc(LPTR, cch2BufLength * sizeof (WCHAR));

		if(string2 == NULL)
		{
			DWORD err = GetLastError();
			LocalFree(string1);
			SetLastError(err);

			return 0;
		}

		for(i = 0; i < cch1BufLength; i++)
		{
			string1[i] = lpString1[i];
		}

		for(i = 0; i < cch2BufLength; i++)
		{
			string2[i] = lpString2[i];
		}

		ret = CompareStringW(lcid, fdwStyle, string1, cch1, string2, cch2);

		LocalFree(string1);
		LocalFree(string2);

		return ret;
	}
#endif

// CSTR_EQUAL is undefined in NT 3.1 SDK
#ifndef CSTR_EQUAL
#define CSTR_EQUAL 2
#endif

typedef LONG NTSTATUS;

typedef struct _LOSVERSIONINFOEXW {
  DWORD dwOSVersionInfoSize;
  DWORD dwMajorVersion;
  DWORD dwMinorVersion;
  DWORD dwBuildNumber;
  DWORD dwPlatformId;
  WCHAR szCSDVersion[128];
  WORD  wServicePackMajor;
  WORD  wServicePackMinor;
  WORD  wSuiteMask;
  BYTE  wProductType;
  BYTE  wReserved;
} LOSVERSIONINFOEXW;

typedef struct _LOSVERSIONINFOEXA {
  DWORD dwOSVersionInfoSize;
  DWORD dwMajorVersion;
  DWORD dwMinorVersion;
  DWORD dwBuildNumber;
  DWORD dwPlatformId;
  CHAR  szCSDVersion[128];
  WORD  wServicePackMajor;
  WORD  wServicePackMinor;
  WORD  wSuiteMask;
  BYTE  wProductType;
  BYTE  wReserved;
} LOSVERSIONINFOEXA;

typedef struct _LOSVERSIONINFOA {
  DWORD dwOSVersionInfoSize;
  DWORD dwMajorVersion;
  DWORD dwMinorVersion;
  DWORD dwBuildNumber;
  DWORD dwPlatformId;
  CHAR  szCSDVersion[128];
} LOSVERSIONINFOA;

typedef struct _LOSVERSIONINFOW {
  DWORD dwOSVersionInfoSize;
  DWORD dwMajorVersion;
  DWORD dwMinorVersion;
  DWORD dwBuildNumber;
  DWORD dwPlatformId;
  WCHAR szCSDVersion[128];
} LOSVERSIONINFOW;

typedef LOSVERSIONINFOEXA *PLOSVERSIONINFOEXA;
typedef LOSVERSIONINFOEXA FAR * LPLOSVERSIONINFOEXA;

typedef LOSVERSIONINFOEXW LRTL_OSVERSIONINFOEXW;
typedef LOSVERSIONINFOEXW *PLOSVERSIONINFOEXW;
typedef LOSVERSIONINFOEXW *PLRTL_OSVERSIONINFOEXW;

typedef LOSVERSIONINFOEXW FAR * LPLOSVERSIONINFOEXW;
typedef LOSVERSIONINFOEXW FAR * LPLRTL_OSVERSIONINFOEXW;

typedef LOSVERSIONINFOA * PLOSVERSIONINFOA;
typedef LOSVERSIONINFOA FAR * LPLOSVERSIONINFOA;

typedef LOSVERSIONINFOW LRTL_OSVERSIONINFOW;
typedef LOSVERSIONINFOW * PLOSVERSIONINFOW;
typedef LOSVERSIONINFOW *PLRTL_OSVERSIONINFOW;

typedef LOSVERSIONINFOW FAR * LPLOSVERSIONINFOW;
typedef LOSVERSIONINFOW FAR * LPLRTL_OSVERSIONINFOW;

#pragma pack(1) 

typedef HANDLE LHTASK;

typedef struct _MODREF 
{ 
    struct _MODREF *pNextModRef;    // 00h 
    DWORD           un1;            // 04h 
    DWORD           un2;            // 08h 
    DWORD           un3;            // 0Ch 
    WORD            mteIndex;       // 10h 
    WORD            un4;            // 12h 
    DWORD           un5;            // 14h 
    PVOID           ppdb;           // 18h Pointer to process database 
    DWORD           un6;            // 1Ch 
    DWORD           un7;            // 20h 
    DWORD           un8;            // 24h 
} MODREF, *PMODREF; 
 
typedef struct _IMTE 
{ 
    DWORD           un1;            // 00h 
    PIMAGE_NT_HEADERS   pNTHdr;     // 04h 
    DWORD           un2;            // 08h 
    PSTR            pszFileName;    // 0Ch 
    PSTR            pszModName;     // 10h 
    WORD            cbFileName;     // 14h 
    WORD            cbModName;      // 16h 
    DWORD           un3;            // 18h 
    DWORD           cSections;      // 1Ch 
    DWORD           un5;            // 20h 
    DWORD           baseAddress;    // 24h 
    WORD            hModule16;      // 28h 
    WORD            cUsage;         // 2Ah 
    DWORD           un7;            // 2Ch 
    PSTR            pszFileName2;   // 30h 
    WORD            cbFileName2;    // 34h 
    DWORD           pszModName2;    // 36h 
    WORD            cbModName2;     // 3Ah 
} IMTE, *PIMTE; 
 
typedef struct _ENVIRONMENT_DATABASE 
{ 
PSTR    pszEnvironment;     // 00h Pointer to Environment 
DWORD   un1;                // 04h 
PSTR    pszCmdLine;         // 08h Pointer to command line 
PSTR    pszCurrDirectory;   // 0Ch Pointer to current directory 
LPSTARTUPINFOA pStartupInfo;// 10h Pointer to STARTUPINFOA struct 
HANDLE  hStdIn;             // 14h Standard Input 
HANDLE  hStdOut;            // 18h Standard Output 
HANDLE  hStdErr;            // 1Ch Standard Error 
DWORD   un2;                // 20h 
DWORD   InheritConsole;     // 24h 
DWORD   BreakType;          // 28h 
DWORD   BreakSem;           // 2Ch 
DWORD   BreakEvent;         // 30h 
DWORD   BreakThreadID;      // 34h 
DWORD   BreakHandlers;      // 38h 
} ENVIRONMENT_DATABASE, EDB, *PENVIRONMENT_DATABASE, *PEDB; 
 
typedef struct _HANDLE_TABLE_ENTRY 
{ 
    DWORD   flags;      // Valid flags depend on what type of object this is 
    PVOID   pObject;    // Pointer to the object that the handle refers to 
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY; 
 
typedef struct _HANDLE_TABLE 
{ 
    DWORD   cEntries;               // Max number of handles in table 
    HANDLE_TABLE_ENTRY array[1];    // An array (number is given by cEntries) 
} HANDLE_TABLE, *PHANDLE_TABLE; 
 
typedef struct _PDB95 {                 // Size = 0xC0 (from Kernel32) 
    DWORD   Type;                       //00 KERNEL32 object type (K32OBJ_PROCESS = 5) 
    DWORD   cReference;                 //04 Number of references to process 
    DWORD   Unknown1;                   //08 (always 0) 
    DWORD   pEvent;                     //0C Pointer to K32OBJ_EVENT (2) 
    DWORD   TerminationStatus;          //10 Returned by GetExitCodeProcess() 
    DWORD   Unknown2;                   //14 (always 0) 
    DWORD   DefaultHeap;                //18 Address of the default process heap 
    DWORD   MemoryContext;              //1C Pointer to the process's context (Returned by GetProcessHeap()) 
    DWORD   Flags;                      //20 Flags 
    DWORD   pPSP;                       //24 Linear address of PSP ? 
    WORD    PSPSelector;                //28 Selector for DOS PSP 
    WORD    MTEIndex;                   //2A *4 + ModuleList = IMTE 
    WORD    cThreads;                   //2C Number of threads belonging to this process 
    WORD    cNotTermThreads;            //2E Number of threads for this process that haven't yet been terminated 
    WORD    Unknown3;                   //30 (always 0) 
    WORD    cRing0Threads;              //32 Number of ring 0 threads 
    HANDLE  HeapHandle;                 //34 Heap to allocate handle tables out of (this seems to always be the KERNEL32 heap) 
    LHTASK   W16TDB;                     //38 Win16 Task Database selector 
    DWORD   MemMapFiles;                //3C Pointer to memory mapped file list 
    PEDB    pEDB;                       //40 Pointer to Environment Database 
    PHANDLE_TABLE pHandleTable;         //44 Pointer to process handle table 
    struct _PDB95* ParentPDB;            //48 Parent process database 
    PMODREF MODREFlist;                 //4C Pointer to module reference list 
    DWORD   ThreadList;                 //50 Pointer to list of threads owned by this process 
    DWORD   DebuggeeCB;                 //54 Debuggee Context block ? 
    DWORD   LocalHeapFreeHead;          //58 Pointer to head of free list in process heap 
    DWORD   InitialRing0ID;             //5C (always 0) 
    CRITICAL_SECTION CriticalSection;   //60 Defined in winnt.h (len=0x18) 
    DWORD   Unknow4[2];                 //78 (always 0) 
    DWORD   pConsole;                   //80 Pointer to console object for process (K32OBJ_CONSOLE = 9) 
    DWORD   tlsInUseBits1;              //84 Represents TLS status bits 0 - 31 
    DWORD   tlsInUseBits2;              //88 Represents TLS status bits 32 - 63 
    DWORD   ProcessDWORD;               //8C Retrieved by GetProcessDword() 
    struct _PDB95* ProcessGroup;         //90 Pointer to the master process (K32_OBJ_PROCESS = 5) 
    DWORD   pExeMODREF;                 //94 Pointer to EXE's MODREF 
    DWORD   TopExcFilter;               //98 Top Exception Filter 
    DWORD   PriorityClass;              //9C Base scheduling priority for process (8 = NORMAL) 
    DWORD   HeapList;                   //A0 Head of the list of process heaps 
    DWORD   HeapHandleList;             //A4 Pointer to head of heap handle block list 
    DWORD   HeapPointer;                //A8 Normally zero, but can pointer to a moveable handle block in the heap 
    DWORD   pConsoleProvider;           //AC Zero or process that owns the console we're using (K32OBJ_CONSOLE) 
    WORD    EnvironSelector;            //B0 Selector containing process environment 
    WORD    ErrorMode;                  //B2 Value set by SetErrorMode() 
    DWORD   pEventLoadFinished;         //B4 Pointer to event LoadFinished (K32OBJ_EVENT = 2) 
    WORD    UTState;                    //B8 
    DWORD   Unknown5[2];                //BA 
} PDB95, *PPDB95; 

typedef struct _PDB98 {                 // Size = 0xC4 (from Kernel32) 
    BYTE    Type;                       // 00 Kernel object type = K32OBJ_PROCESS (6) 
    BYTE    Unknown_A;                  // 01 (align ?) 
    WORD    cReference;                 // 02 Number of references to process 
    DWORD   Unknown_B;                  // 04 Pointer to ??? 
    DWORD   Unknown1;                   // 08 (zero) 
    DWORD   pEvent;                     // 0C Event for process waiting 
    DWORD   TerminationStatus;          // 10 GetExitCodeProcess 
    DWORD   Unknown2;                   // 14 May be used for private purposes 
    DWORD   DefaultHeap;                // 18 GetProcessHeap 
    DWORD   MemoryContext;              // 1C Pointer to process context 
    DWORD   Flags;                      // 20 Flags 
    DWORD   pPSP;                       // 24 Linear address of DOS PSP 
    WORD    PSPSelector;                // 28 Selector to DOS PSP 
    WORD    MTEIndex;                   // 2A Index into global module table 
    WORD    cThreads;                   // 2C Threads.ItemCount 
    WORD    cNotTermThreads;            // 2E Threads.ItemCount 
    WORD    Unknown3;                   // 30 (zero) 
    WORD    cRing0Threads;              // 32 Normally Threads.ItemCount (except kernel32) 
    HANDLE  HeapHandle;                 // 34 Kernel32 shared heap 
    DWORD   w16TDB;                     // 38 Win16 task database selector 
    DWORD   MemMappedFiles;             // 3C List of memory mapped files 
    PEDB    pEDB;                       // 40 Pointer to Environment Database 
    PHANDLE_TABLE pHandleTable;         // 44 Pointer to Handle Table 
    struct _PDB98* ParentPDB;            // 48 Pointer to parent process (PDB) 
    PMODREF MODREFList;                 // 4C Pointer to list of modules 
    DWORD   ThreadList;                 // 50 Pointer to list of threads 
    DWORD   DebuggeeCB;                 // 54 Debuggee context block 
    DWORD   LocalHeapFreeHead;          // 58 Free list for process default heap 
    DWORD   InitialRing0ID;             // 5C Meaning unknown 
    CRITICAL_SECTION CriticalSection;   // 60 For synchronizing threads 
    DWORD   Unknown4[3];                // 78 
    DWORD   pConsole;                   // 84 Output console 
    DWORD   tlsInUseBits1;              // 88 Status of TLS indexes  0 - 31 
    DWORD   tlsInUseBits2;              // 8C Status of TLS indexes 32 - 63 
    DWORD   ProcessDWORD;               // 90 Undocumented API GetProcessDword, meaning unknown 
    struct _PDB98* ProcessGroup;         // 94 Master process PDB (in debugging) 
    DWORD   pExeMODREF;                 // 98 Points to exe's module structure 
    DWORD   TopExcFilter;               // 9C SetUnhandledExceptionFilter 
    DWORD   PriorityClass;              // A0 PriorityClass (8 = NORMAL) 
    DWORD   HeapList;                   // A4 List of heaps 
    DWORD   HeapHandleList;             // A8 List of moveable memory blocks 
    DWORD   HeapPointer;                // AC Pointer to one moveable memory block, meaning unknown 
    DWORD   pConsoleProvider;           // B0 Console for DOS apps 
    WORD    EnvironSelector;            // B4 Environment database selector 
    WORD    ErrorMode;                  // B6 SetErrorMode 
    DWORD   pEventLoadFinished;         // B8 Signaled when the process has finished loading 
    WORD    UTState;                    // BC Universal thunking, meaning unknown 
    WORD    Unknown5;                   // BE (zero) 
    DWORD   Unknown6;                   // C0 
} PDB98, *PPDB98; 

typedef struct _PDBME {                 // Size = 0xC4 (from Kernel32) 
    BYTE    Type;                       // 00 Kernel object type = K32OBJ_PROCESS (6) 
    BYTE    Unknown_A;                  // 01 (align ?) 
    WORD    cReference;                 // 02 Number of references to process 
    DWORD   Unknown_B;                  // 04 Pointer to ??? 
    DWORD   Unknown1;                   // 08 (zero) 
    DWORD   pEvent;                     // 0C Event for process waiting 
    DWORD   TerminationStatus;          // 10 GetExitCodeProcess 
    DWORD   Unknown2;                   // 14 May be used for private purposes 
    DWORD   DefaultHeap;                // 18 GetProcessHeap 
    DWORD   MemoryContext;              // 1C Pointer to process context 
    DWORD   Flags;                      // 20 Flags 
    DWORD   pPSP;                       // 24 Linear address of DOS PSP 
    WORD    PSPSelector;                // 28 Selector to DOS PSP 
    WORD    MTEIndex;                   // 2A Index into global module table 
    WORD    cThreads;                   // 2C Threads.ItemCount 
    WORD    cNotTermThreads;            // 2E Threads.ItemCount 
    WORD    Unknown3;                   // 30 (zero) 
    WORD    cRing0Threads;              // 32 Normally Threads.ItemCount (except kernel32) 
    HANDLE  HeapHandle;                 // 34 Kernel32 shared heap 
    DWORD   w16TDB;                     // 38 Win16 task database selector 
    DWORD   MemMappedFiles;             // 3C List of memory mapped files 
    PEDB    pEDB;                       // 40 Pointer to Environment Database 
    PHANDLE_TABLE pHandleTable;         // 44 Pointer to Handle Table 
    struct _PDBME* ParentPDB;            // 48 Pointer to parent process (PDB) 
    PMODREF MODREFList;                 // 4C Pointer to list of modules 
    DWORD   ThreadList;                 // 50 Pointer to list of threads 
    DWORD   DebuggeeCB;                 // 54 Debuggee context block 
    DWORD   LocalHeapFreeHead;          // 58 Free list for process default heap 
    DWORD   InitialRing0ID;             // 5C Meaning unknown 
    CRITICAL_SECTION CriticalSection;   // 60 For synchronizing threads 
    DWORD   Unknown4[2];                // 78 
    DWORD   pConsole;                   // 80 Output console 
    DWORD   tlsInUseBits1;              // 84 Status of TLS indexes  0 - 31 
    DWORD   tlsInUseBits2;              // 88 Status of TLS indexes 32 - 63 
    DWORD   ProcessDWORD;               // 8C Undocumented API GetProcessDword, meaning unknown 
    DWORD   Unknown_C;                  // 90 Unknown 
    struct _PDBME* ProcessGroup;         // 94 Master process PDB (in debugging) 
    DWORD   pExeMODREF;                 // 98 Points to exe's module structure 
    DWORD   TopExcFilter;               // 9C SetUnhandledExceptionFilter 
    DWORD   PriorityClass;              // A0 PriorityClass (8 = NORMAL) 
    DWORD   HeapList;                   // A4 List of heaps 
    DWORD   HeapHandleList;             // A8 List of moveable memory blocks 
    DWORD   HeapPointer;                // AC Pointer to one moveable memory block, meaning unknown 
    DWORD   pConsoleProvider;           // B0 Console for DOS apps 
    WORD    EnvironSelector;            // B4 Environment database selector 
    WORD    ErrorMode;                  // B6 SetErrorMode 
    DWORD   pEventLoadFinished;         // B8 Signaled when the process has finished loading 
    WORD    UTState;                    // BC Universal thunking, meaning unknown 
    WORD    Unknown5;                   // BE (zero) 
    DWORD   Unknown6;                   // C0 
} PDBME, *PPDBME; 
 
typedef union _PROCESS_DATABASE {
	PDB95 pdb95;
	PDB98 pdb98;
	PDBME pdbME;
} PROCESS_DATABASE, *PPROCESS_DATABASE;

struct _TDB95;
struct _TDB98;
struct _TDBME;

typedef struct _TDBX95 { 
    struct _TDB98  *ptdb;             // 00 TDB 
    PDB98  *ppdb;             // 04 PDB 
    DWORD  ContextHandle;     // 08 R0 memory context 
    DWORD  un1;               // 0C 
    DWORD  TimeOutHandle;     // 10 
    DWORD  WakeParam;         // 14 
    DWORD  BlockHandle;       // 18 R0 semaphore on which thread will wait inside VWIN32 
    DWORD  BlockState;        // 1C 
    DWORD  SuspendCount;      // 20 Number of times SuspendThread() was called 
    DWORD  SuspendHandle;     // 24 
    DWORD  MustCompleteCount; // 28 Count of EnterMustComplete's minus LeaveMustComplete's 
    DWORD  WaitExFlags;       // 2C Flags 
    DWORD  SyncWaitCount;     // 30 
    DWORD  QueuedSyncFuncs;   // 34 
    DWORD  UserAPCList;       // 38 
    DWORD  KernAPCList;       // 3C 
    DWORD  pPMPSPSelector;    // 40 Pointer to protected mode PSP selector 
    DWORD  BlockedOnID;       // 44 
    DWORD  un2[7];            // 48 
    DWORD  TraceRefData;      // 64 
    DWORD  TraceCallBack;     // 68 
    DWORD  TraceEventHandle;  // 6C 
    WORD   TraceOutLastCS;    // 70 
    WORD   K16TDB;            // 72 Win16 TDB selector 
    WORD   K16PDB;            // 74 Win16 PSP selector 
    WORD   DosPDBSeg;         // 76 Real mode segment value of PSP 
    WORD   ExceptionCount;    // 78 
} TDBX95, *PTDBX95;  

typedef struct _TDBX98 { 
    DWORD  un0;                // 00 
    struct _TDB98  *ptdb;              // 04 R3 thread database 
    PDB98  *ppdb;              // 08 R3 process database 
    DWORD  ContextHandle;      // 0C R0 memory context 
    DWORD  Ring0Thread;        // 10 R0 thread control block [TCB *] 
    DWORD  WaitNodeList;       // 14 Anchor of things we're waiting on  [WAITNODE *] 
    DWORD  WaitFlags;          // 18 Blocking flags 
    DWORD  un1;                // 1C 
    DWORD  TimeOutHandle;      // 20 
    DWORD  WakeParam;          // 24 
    DWORD  BlockHandle;        // 28 R0 semaphore on which thread will wait inside VWIN32 
    DWORD  BlockState;         // 2C 
    DWORD  SuspendCount;       // 30 
    DWORD  SuspendHandle;      // 34 
    DWORD  MustCompleteCount;  // 38 Count of EnterMustComplete's minus LeaveMustComplete's 
    DWORD  WaitExFlags;        // 3C Flags 
    DWORD  SyncWaitCount;      // 40 
    DWORD  QueuedSyncFuncs;    // 44 
    DWORD  UserAPCList;        // 48 
    DWORD  KernAPCList;        // 4C 
    DWORD  pPMPSPSelector;     // 50 
    DWORD  BlockedOnID;        // 54 
} TDBX98, *PTDBX98; 

typedef struct _TDBXME {
	DWORD un0;
    DWORD  WaitNodeList;       // Anchor of things we're waiting on  [WAITNODE *] 
    DWORD  WaitFlags;          // Blocking flags 
	DWORD  Ring0Thread;        // R0 thread control block [TCB *] 
	DWORD  ContextHandle;      // R0 memory context 
	PDBME  *ppdb;              // R3 process database
	struct _TDBME  *ptdb;              // R3 thread database
    DWORD  SuspendCount;       //
    DWORD  SuspendHandle;      //
    DWORD  MustCompleteCount;  // Count of EnterMustComplete's minus LeaveMustComplete's
	DWORD  BlockState;         // 
	DWORD  BlockHandle;        // R0 semaphore on which thread will wait inside VWIN32
	DWORD  WakeParam;          //
	DWORD  TimeOutHandle;      //
	DWORD  un1;
	DWORD  unk1;
	DWORD  unk2;
	DWORD  unk3;
	DWORD  unk4;
	DWORD  unk5;
	DWORD  unk6;
	DWORD  unk7;
	DWORD  unk8;
	DWORD  pPMPSPSelector;
	DWORD  KernAPCList;
	DWORD  unk11; // UserAPCList
	DWORD  unk12;
	DWORD  unk13;
	DWORD  WaitExFlags;
} TDBXME, *PTDBXME;

typedef union _TDBX {
	TDBX95 tdbx95;
	TDBX98 tdbx98;
} TDBX, *PTDBX;

typedef struct _SEH 
{ 
    struct _SEH *pNext; 
    FARPROC     pfnHandler; 
} SEH, *PSEH; 
 
// This is semi-documented in the NTDDK.H file from the NT DDK 
typedef struct _TIB95 {         // Size = 0x34 
    PSEH    pvExcept;           // 00 Pointer to head of structured exception handling chain 
    PVOID   pvStackUserTop;     // 04 Max. address for stack 
    PVOID   pvStackUserBase;    // 08 Lowest page aligned addr. of stack 
    WORD    pvTDB;              // 0C Ptr to win-16 task database 
    WORD    pvThunksSS;         // 0E SS selector used for thunking to 16 bits 
    DWORD   SelmanList;         // 10 Pointer to selector manager list 
    PVOID   pvArbitrary;        // 14 Available for application use 
    struct _TIB95 *pTIBSelf;    // 18 Linear address of TIB structure 
    WORD    TIBFlags;           // 1C TIBF_WIN32 = 1, TIBF_TRAP = 2 
    WORD    Win16MutexCount;    // 1E Win16Lock 
    DWORD   DebugContext;       // 20 Pointer to debug context structure 
    DWORD   pCurrentPriority;   // 24 Pointer to DWORD containing current priority level 
    DWORD   pvQueue;            // 28 Message Queue selector 
    PVOID*  pvTLSArray;         // 2C Thread Local Storage (TLS) array 
    PVOID*  pProcess;           // 30 Pointer to owning process database (PDB) 
} TIB95, *PTIB95; 

typedef struct _TIB98 {        // Size = 0x38 
    PSEH    pvExcept;          // 00 Head of exception record list 
    PVOID   pvStackUserTop;    // 04 Top of user stack 
    PVOID   pvStackUserBase;   // 08 Base of user stack 
    WORD    pvTDB;             // 0C Ptr to win-16 task database 
    WORD    pvThunksSS;        // 0E SS selector used for thunking to 16 bits 
    DWORD   SelmanList;        // 10 Pointer to selector manager list 
    PVOID   pvArbitrary;       // 14 Available for application use 
    struct _TIB98 *pTIBSelf;   // 18 Linear address of TIB structure 
    WORD    TIBFlags;          // 1C TIBF_WIN32 = 1, TIBF_TRAP = 2 
    WORD    Win16MutexCount;   // 1E Win16Lock 
    DWORD   DebugContext;      // 20 Pointer to debug context structure 
    DWORD   pCurrentPriority;  // 24 Pointer to DWORD containing current priority level 
    DWORD   pvQueue;           // 28 Message Queue selector 
    PVOID   *pvTLSArray;       // 2C Thread Local Storage (TLS) array 
    PVOID   *pProcess;         // 30 Pointer to owning process database (PDB) 
    DWORD   Unknown;           // 34 Pointer to ??? 
} TIB98, *PTIB98; 

typedef TIB98   TIBME;
typedef TIBME   *PTIBME;

typedef union _TIB {
	TIB95 tib95;
	TIB98 tib98;
	TIBME tibME;
} TIB, *PTIB;

typedef struct _TDB95 {                // Size = 0x1D4 (from Kernel32) 
    DWORD      Type;                   // 00 Object type = K32OBJ_THREAD (6) 
    DWORD      cReference;             // 04 Reference count for thread 
    PPDB95     pProcess;               // 08 Pointer to PDB 
    DWORD      pSomeEvent;             // 0C Pointer to K32OBJ_EVENT 
    TIB95      tib;                    // 10-40 TIB 
    DWORD      Flags;                  // 44 Flags 
    DWORD      TerminationStatus;      // 48 Returned by GetExitCodeThread() 
    WORD       TIBSelector;            // 4C TIB selector 
    WORD       EmulatorSelector;       // 4E 80387 emulator state selector 
    DWORD      cHandles;               // 50 (always 0) 
    DWORD      WaitNodeList;           // 54 Pointer to event list 
    DWORD      un4;                    // 58 (0 or 2) 
    DWORD      Ring0Thread;            // 5C Pointer to ring0 THCB (Thread Control Block) 
    TDBX95     *pTDBX;                 // 60 Pointer to TDBX 
    DWORD      StackBase;              // 64 Lowest stack address 
    DWORD      TerminationStack;       // 68 ESP for thread termination 
    DWORD      EmulatorData;           // 6C Linear address for 80387 emulator data 
    DWORD      GetLastErrorCode;       // 70 Value returned by GetLastErrorCode() 
    DWORD      DebuggerCB;             // 74 Pointer do debugger data 
    DWORD      DebuggerThread;         // 78 If thread is being debugged contains a non-NULL value 
    PCONTEXT   ThreadContext;          // 7C Register context defined in WINNT.H 
    DWORD      Except16List;           // 80 (always 0) 
    DWORD      ThunkConnect;           // 84 (always 0) 
    DWORD      NegStackBase;           // 88 StackBase + NegStackBase 
    DWORD      CurrentSS;              // 8C 16-bit stack selector for thunking 
    DWORD      SSTable;                // 90 Pointer to memory block with 16-bit stack info for thunking 
    DWORD      ThunkSS16;              // 94 Selector for thunking 
    DWORD      TLSArray[64];           // 98 TLS array 
    DWORD      DeltaPriority;          // 198 Diference between priority of thread and priority class of the owning process 
    DWORD      un5[7];                 // 19C 
    DWORD      APISuspendCount;        // 1B8 Number of times SuspendThread() has been called 
    DWORD      un[6];                  // 1BC 
 
/* 
    // The retail version breaks off somewhere around here. 
    // All the remaining fields are most likely only in the debug version 
    DWORD      un5[7];                 // 19C (always 0) 
    DWORD      pCreateData16;          // 1B8 Pointer to struct with PProcessInfo and pStartupInfo (always 0) 
    DWORD      APISuspendCount;        // 1BC Number of times SuspendThread() has been called 
    DWORD      un6;                    // 1C0 
    DWORD      WOWChain;               // 1C4 (always 0) 
    WORD       wSSBig;                 // 1C8 32-bit stack selector (always 0) 
    WORD       un7;                    // 1CA 
    DWORD      lp16SwitchRec;          // 1CC 
    DWORD      un8[6];                 // 1D0 (always 0) 
    DWORD      pSomeCritSect1;         // 1E8 Pointer to K32OBJ_CRITICAL_SECTION 
    DWORD      pWin16Mutex;            // 1EC Pointer to Win16Mutex in KRNL386.EXE 
    DWORD      pWin32Mutex;            // 1F0 Pointer to Krn32Mutex in KERNEL32.DLL 
    DWORD      pSomeCritSect2;         // 1F4 Pointer to K32OBJ_CRITICAL_SECTION 
    DWORD      un9;                    // 1F8 (always 0) 
    DWORD      ripString;              // 1FC 
    DWORD      LastTlsSetValueEIP[64]; // 200 Parallel to TlsArray, contains EIP where TLS value was last set from 
*/ 
} TDB95, *PTDB95;

typedef struct _TDB98 {        // Size = 0x228 (from Kernel32) 
    WORD    Type;              // 00 K32 object type 
    WORD    cReference;        // 02 Reference count 
    DWORD   pSomeEvent;        // 04 K32 event object used when someone waits on the thread object 
    TIB98   tib;               // 08 Thread information block (TIB) 
    DWORD   Unknown;           // 40 
    DWORD   Flags;             // 44 Flags 
    DWORD   TerminationStatus; // 48 Exit code 
    WORD    TIBSelector;       // 4C Selector used in FS to point to TIB 
    WORD    EmulatorSelector;  // 4E Memory block for saving x87 state 
    DWORD   cHandles;          // 50 Handle count 
    DWORD   Ring0Thread;       // 54 R0 thread control block (TCB) 
    TDBX98  *pTDBX;            // 58 R0 thread database extension (TDBX) 
    DWORD   un1[109];          // 5C 
    DWORD   APISuspendCount;   // 210 Count of SuspendThread's minus ResumeThread's 
} TDB98, *PTDB98;

typedef struct _TDBME {        // Size = 0x228 (from Kernel32) 
    WORD    Type;              // 00 K32 object type 
    WORD    cReference;        // 02 Reference count 
    DWORD   pSomeEvent;        // 04 K32 event object used when someone waits on the thread object 
    TIB98   tib;               // 08 Thread information block (TIB) 
    DWORD   Unknown;           // 40 
    DWORD   Unknown2;          // 44 
    WORD    TIBSelector;       // 46 Selector used in FS to point to TIB 
    DWORD   TerminationStatus; // 48 Exit code 
    DWORD   Flags;             // 4C Flags 
    DWORD   cHandles;          // 50 Handle count 
    DWORD   Ring0Thread;       // 54 R0 thread control block (TCB) 
    DWORD   Unknown3;          // 58 Selector for ??? 
    DWORD   un1[109];          // 5C 
    DWORD   APISuspendCount;   // 210 Count of SuspendThread's minus ResumeThread's 
} TDBME, *PTDBME;
 
typedef union _THREAD_DATABASE {
	TDB95 tdb95;
	TDB98 tdb98;
	TDBME tdbME;
} THREAD_DATABASE, *PTHREAD_DATABASE;

typedef struct _K32ObjectHeader95 {
	DWORD dwType;
	DWORD dwRefCnt;
} K32ObjectHeader95, *PK32ObjectHeader95;

typedef struct _K32ObjectHeader98 {
	BYTE dwType;
	BYTE dwFlags;
	WORD dwRefCnt;
} K32ObjectHeader98, *PK32ObjectHeader98;

typedef struct _K32ObjectHeaderME {
	BYTE dwType;
	BYTE dwFlags;
	WORD dwRefCnt;
} K32ObjectHeaderME, *PK32ObjectHeaderME;

typedef struct _K32OBJBASE95 {            
    K32ObjectHeader95   header;         //00 KERNEL32 object header
    BYTE	payload[1];					//08 payload
} K32OBJBASE95, *PK32OBJBASE95; 

typedef struct _K32OBJBASE98 {                 // Size = 0xC4 (from Kernel32) 
    K32ObjectHeader98   header;         //00 KERNEL32 object header
    BYTE	payload[1];					// 04 payload
} K32OBJBASE98, *PK32OBJBASE98; 

typedef struct _K32OBJBASEME {                 // Size = 0xC4 (from Kernel32) 
    K32ObjectHeaderME   header;         //00 KERNEL32 object header
	BYTE	payload[1];					// 04 payload
} K32OBJBASEME, *PK32OBJBASEME; 
 
typedef union _K32OBJBASE {
	K32OBJBASE95 kobj95;
	K32OBJBASE98 kobj98;
	K32OBJBASEME kobjME;
} K32OBJBASE, *PK32OBJBASE;

typedef struct _K32OBJECT_NAME {
	struct _K32OBJECT_NAME *mystery; // -- points to another footer mystery, but doesn't seem to match the previous object created.
	PK32OBJBASE *pSelf;
	BYTE payload[1];
} K32OBJECT_NAME, *PK32OBJECT_NAME;

typedef K32OBJECT_NAME FAR * LPK32OBJECT_NAME;

typedef struct _K32LINKED_LIST_NODE {
	struct _K32LINKED_LIST_NODE FAR * pPrev;
	struct _K32LINKED_LIST_NODE FAR * pNext;
	LPVOID pObj;
} K32LINKED_LIST_NODE, *PK32LINKED_LIST_NODE;

typedef K32LINKED_LIST_NODE FAR * LPK32LINKED_LIST_NODE;

typedef struct _K32OBJ_EVENT95 {
	K32ObjectHeader95 header;
	PPDB95 pPdb; // 08 pdb pointer???
	PSECURITY_ATTRIBUTES pSecurityAttribues; // 0C always NULL for me
	BOOL bInitialState; // 10
	PK32OBJECT_NAME pFooter; // 14
	BOOL bManualReset; // 18
	PVOID mystery2; // 1C
	K32OBJECT_NAME footer; // 20
} K32OBJ_EVENT95, *PK32OBJ_EVENT95;

typedef struct _K32OBJ_EVENT98 {
	K32ObjectHeader98 header;
	PSECURITY_ATTRIBUTES pSecurityAttribues; // 0C always NULL for me
	BOOL bInitialState; // 10
	PK32OBJECT_NAME pFooter; // 14
	DWORD mystery1; // 18
	DWORD mystery2; // 1C
	DWORD mystery3; // 1C
	DWORD mystery4; // 1C
} K32OBJ_EVENT98, *PK32OBJ_EVENT98;

typedef struct _EVENTME {
	K32ObjectHeaderME header;
	PSECURITY_ATTRIBUTES pSecurityAttribues; // 0C always NULL for me
	BOOL bInitialState; // 10
	PK32OBJECT_NAME pFooter; // 14
	DWORD mystery1; // 18
	DWORD mystery2; // 1C
	DWORD mystery3; // 1C
	DWORD mystery4; // 1C
} K32OBJ_EVENTME, *PK32OBJ_EVENTME;

typedef union _K32OBJ_EVENT {
	K32OBJ_EVENT95 event95;
	K32OBJ_EVENT98 event98;
	K32OBJ_EVENTME eventME;
} K32OBJ_EVENT, *PK32OBJ_EVENT;

typedef struct _K32OBJ_FILE_OBJECT_95 {
	K32ObjectHeader95 header;
	PPDB95 pPdb;
	PK32OBJ_EVENT95 pSomeEvent;
	WORD hExtendedFileHandle;
	WORD reserved;
	DWORD dwModeAndFlags; // delete on close = 0xFFFFFFFF, if dos file handle (hExtendedFileHandle <= 0x200) then mode and flags word
	char pszFullPath[1];
} K32OBJ_FILE_OBJECT_95, *PK32OBJ_FILE_OBJECT_95;

typedef struct _K32OBJ_FILE_OBJECT_98 {
	K32ObjectHeader98 header;
	PK32OBJ_EVENT98 pSomeEvent;
	WORD hExtendedFileHandle;
	WORD reserved;
	DWORD dwModeAndFlags; // delete on close = 0xFFFFFFFF, if dos file handle (hExtendedFileHandle <= 0x200) then mode and flags word
	char pszFullPath[1];
} K32OBJ_FILE_OBJECT_98, *PK32OBJ_FILE_OBJECT_98;

typedef struct _K32OBJ_FILE_OBJECT_ME {
	K32ObjectHeaderME header;
	PK32OBJ_EVENTME pSomeEvent;
	WORD hExtendedFileHandle;
	WORD reserved;
	DWORD dwModeAndFlags; // delete on close = 0xFFFFFFFF, if dos file handle (hExtendedFileHandle <= 0x200) then mode and flags word
	char pszFullPath[1];
} K32OBJ_FILE_OBJECT_ME, *PK32OBJ_FILE_OBJECT_ME;

typedef union _K32OBJ_FILE_OBJECT {
	K32OBJ_FILE_OBJECT_95 fileObject95;
	K32OBJ_FILE_OBJECT_98 fileObject98;
	K32OBJ_FILE_OBJECT_ME fileObjectME;
} K32OBJ_FILE_OBJECT, *PK32OBJ_FILE_OBJECT;

#define WIN95_K32OBJ_SEMAPHORE            0x1
#define WIN95_K32OBJ_EVENT                0x2
#define WIN95_K32OBJ_MUTEX                0x3
#define WIN95_K32OBJ_CRITICAL_SECTION     0x4
#define WIN95_K32OBJ_PROCESS              0x5
#define WIN95_K32OBJ_THREAD               0x6
#define WIN95_K32OBJ_FILE                 0x7
#define WIN95_K32OBJ_CHANGE               0x8
#define WIN95_K32OBJ_CONSOLE              0x9
#define WIN95_K32OBJ_SCREEN_BUFFER        0xA
#define WIN95_K32OBJ_MEM_MAPPED_FILE      0xB
#define WIN95_K32OBJ_SERIAL               0xC
#define WIN95_K32OBJ_DEVICE_IOCTL         0xD
#define WIN95_K32OBJ_PIPE                 0xE
#define WIN95_K32OBJ_MAILSLOT             0xF
#define WIN95_K32OBJ_TOOLHELP_SNAPSHOT    0x10
#define WIN95_K32OBJ_SOCKET               0x11

#define WIN98_K32OBJ_SEMAPHORE            0x1
#define WIN98_K32OBJ_EVENT                0x2
#define WIN98_K32OBJ_MUTEX                0x3
#define WIN98_K32OBJ_CRITICAL_SECTION     0x4
//#define                0x5
#define WIN98_K32OBJ_PROCESS              0x6
#define WIN98_K32OBJ_THREAD               0x7
#define WIN98_K32OBJ_FILE                 0x8
#define WIN98_K32OBJ_CHANGE               0x9
#define WIN98_K32OBJ_CONSOLE              0xA
//#define              0xB
#define WIN98_K32OBJ_SCREEN_BUFFER        0xC
#define WIN98_K32OBJ_MEM_MAPPED_FILE      0xD
#define WIN98_K32OBJ_SERIAL               0xE
#define WIN98_K32OBJ_DEVICE_IOCTL         0xF
#define WIN98_K32OBJ_PIPE                 0x10
#define WIN98_K32OBJ_MAILSLOT             0x11
#define WIN98_K32OBJ_TOOLHELP_SNAPSHOT    0x12
#define WIN98_K32OBJ_SOCKET               0x13

#define WINME_K32OBJ_SEMAPHORE            0x1
#define WINME_K32OBJ_EVENT                0x2
#define WINME_K32OBJ_MUTEX                0x3
#define WINME_K32OBJ_CRITICAL_SECTION     0x4
//#define                0x5
#define WINME_K32OBJ_PROCESS              0x6
#define WINME_K32OBJ_THREAD               0x7
#define WINME_K32OBJ_FILE                 0x8
#define WINME_K32OBJ_CHANGE               0x9
#define WINME_K32OBJ_CONSOLE              0xA
//#define              0xB
#define WINME_K32OBJ_SCREEN_BUFFER        0xC
#define WINME_K32OBJ_MEM_MAPPED_FILE      0xD
#define WINME_K32OBJ_SERIAL               0xE
#define WINME_K32OBJ_DEVICE_IOCTL         0xF
#define WINME_K32OBJ_PIPE                 0x10
#define WINME_K32OBJ_MAILSLOT             0x11
#define WINME_K32OBJ_TOOLHELP_SNAPSHOT    0x12
#define WINME_K32OBJ_SOCKET               0x13

#pragma pack()

typedef DWORD (WINAPI * PGetFinalPathNameByHandleW)(HANDLE hFile, LPWSTR lpszFilePath, DWORD cchFilePath, DWORD dwFlags);
typedef DWORD (WINAPI * PGetFinalPathNameByHandleA)(HANDLE hFile, LPSTR  lpszFilePath, DWORD  cchFilePath, DWORD  dwFlags);
typedef DWORD (WINAPI * PGetFinalPathNameByHandleT)(HANDLE hFile, LPTSTR  lpszFilePath, DWORD  cchFilePath, DWORD  dwFlags);

typedef DWORD (WINAPI FAR * LPGetFinalPathNameByHandleW)(HANDLE hFile, LPWSTR lpszFilePath, DWORD cchFilePath, DWORD dwFlags);
typedef DWORD (WINAPI FAR * LPGetFinalPathNameByHandleA)(HANDLE hFile, LPSTR  lpszFilePath, DWORD  cchFilePath, DWORD  dwFlags);
typedef DWORD (WINAPI FAR * LPGetFinalPathNameByHandleT)(HANDLE hFile, LPTSTR lpszFilePath, DWORD cchFilePath, DWORD dwFlags);

typedef NTSTATUS (WINAPI * PNtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
typedef NTSTATUS (WINAPI FAR * LPNtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);

typedef DWORD (WINAPI * PGetMappedFileNameA)(HANDLE hProcess, LPVOID lpv, LPSTR lpFilename, DWORD nSize);
typedef DWORD (WINAPI * PGetMappedFileNameW)(HANDLE hProcess, LPVOID lpv, LPWSTR lpFilename, DWORD nSize);
typedef DWORD (WINAPI * PGetMappedFileNameT)(HANDLE hProcess, LPVOID lpv, LPTSTR lpFilename, DWORD nSize);

typedef DWORD (WINAPI FAR * LPGetMappedFileNameA)(HANDLE hProcess, LPVOID lpv, LPSTR lpFilename, DWORD nSize);
typedef DWORD (WINAPI FAR * LPGetMappedFileNameW)(HANDLE hProcess, LPVOID lpv, LPWSTR lpFilename, DWORD nSize);
typedef DWORD (WINAPI FAR * LPGetMappedFileNameT)(HANDLE hProcess, LPVOID lpv, LPTSTR lpFilename, DWORD nSize);

typedef NTSTATUS (WINAPI *PRtlGetVersion)(PLRTL_OSVERSIONINFOW lpVersionInfo);
typedef NTSTATUS (WINAPI FAR *LPRtlGetVersion)(PLRTL_OSVERSIONINFOW lpVersionInfo);

typedef NTSTATUS (WINAPI *PRtlGetVersionEX)(PLRTL_OSVERSIONINFOEXW lpVersionInfo);
typedef NTSTATUS (WINAPI FAR *LPRtlGetVersionEX)(PLRTL_OSVERSIONINFOEXW lpVersionInfo);

typedef BOOL (WINAPI *PGetVersionEXA)(LPLOSVERSIONINFOA lpVersionInformation);
typedef BOOL (WINAPI FAR *LPGetVersionEXA)(LPLOSVERSIONINFOA lpVersionInformation);

typedef BOOL (WINAPI *PGetVersionEXEXA)(LPLOSVERSIONINFOEXA lpVersionInformation);
typedef BOOL (WINAPI FAR *LPGetVersionEXEXA)(LPLOSVERSIONINFOEXA lpVersionInformation);

typedef unsigned short *string_t;	/* character string */
typedef unsigned short sfn_t;		/* system file number */
typedef unsigned long pos_t;		/* file position */
#if defined(_MSC_VER)
typedef unsigned int pid_t;			/* process ID of requesting task */
#endif
typedef void FAR *ubuffer_t;		/* ptr to user data buffer */
typedef unsigned char uid_t;		/* user ID for this request */

#ifndef rh_t
	typedef void *rh_t;		/* resource handle */
#endif
#ifndef fh_t
	typedef void *fh_t;		/* file handle */
#endif
#ifndef fsdwork_t
	typedef int fsdwork_t[16];	/* provider work space */
#endif

/** dos_time - DOS time & date format */

typedef struct dos_time dos_time;
struct dos_time {
	unsigned short	dt_time;
	unsigned short	dt_date;
};	/* dos_time */

typedef struct volfunc volfunc, *vfunc_t;
typedef struct hndlfunc hndlfunc, *hfunc_t;

/* Parsed path structures are defined later in this file. */
typedef struct PathElement PathElement;
typedef struct ParsedPath ParsedPath;
typedef ParsedPath *path_t;

/** ParsedPath - structure of an IFSMgr parsed pathname */

struct PathElement {
	unsigned short	pe_length;
	unsigned short	pe_unichars[1];
}; /* PathElement */

struct ParsedPath {
	unsigned short	pp_totalLength;
	unsigned short	pp_prefixLength;
	struct PathElement pp_elements[1];
}; /* ParsedPath */

/** _QWORD - 64-bit data type
 *  A struct used to return 64-bit data types to C callers
 *  from the qwUniToBCS & qwUniToBCS rotuines.  These
 *  'routines' are just alias' for UntoToBCS & UniToBCSPath
 *  routines and do not exist as separate entities.  Both
 *  routines always return a 64-bit result.  The lower
 *  32-bits are a length.  The upper 32-bits are flags.
 *  Typically, the flag returned indicates whether a mapping
 *  resulted in a loss on information in the UNICODE to BCS
 *  translation (i.e. a unicode char was converted to an '_').
 */

typedef struct _QWORD _QWORD;
struct _QWORD {
	unsigned long	ddLower;
	unsigned long	ddUpper;
}; /* _QWORD */

#ifndef _ULONGLONG_
#define _ULONGLONG_
#if (!defined (_MAC) && (!defined(MIDL_PASS) || defined(__midl)) && (!defined(_M_IX86) || (defined(_INTEGRAL_MAX_BITS) && _INTEGRAL_MAX_BITS >= 64)))
typedef __int64 LONGLONG;
typedef unsigned __int64 ULONGLONG;

#define MAXLONGLONG                      (0x7fffffffffffffff)
#else

#if defined(_MAC) && defined(_MAC_INT_64)
typedef __int64 LONGLONG;
typedef unsigned __int64 ULONGLONG;

#define MAXLONGLONG                      (0x7fffffffffffffff)
#else
typedef double LONGLONG;
typedef double ULONGLONG;
#endif //_MAC and int64

#endif

typedef LONGLONG *PLONGLONG;
typedef ULONGLONG *PULONGLONG;

#endif

typedef struct event event, *pevent;

typedef union {
	ubuffer_t		aux_buf;
	unsigned long	aux_ul;
	dos_time		aux_dt;
	vfunc_t			aux_vf;
	hfunc_t			aux_hf;
	void			*aux_ptr;
	string_t		aux_str;
	path_t			aux_pp;
	unsigned int	aux_ui;
} aux_t;

struct ioreq {
	unsigned int	ir_length;	/* length of user buffer (eCX) */
	unsigned char	ir_flags;	/* misc. status flags (AL) */
	uid_t			ir_user;	/* user ID for this request */
	sfn_t			ir_sfn;		/* System File Number of file handle */
	pid_t			ir_pid;		/* process ID of requesting task */
	path_t			ir_ppath;	/* unicode pathname */
	aux_t			ir_aux1;	/* secondary user data buffer (CurDTA) */
	ubuffer_t		ir_data;	/* ptr to user data buffer (DS:eDX) */
	unsigned short	ir_options;	/* request handling options */
	short			ir_error;	/* error code (0 if OK) */
	rh_t			ir_rh;		/* resource handle */
	fh_t			ir_fh;		/* file (or find) handle */
	pos_t			ir_pos;		/* file position for request */
	aux_t			ir_aux2;	/* misc. extra API parameters */
	aux_t			ir_aux3;	/* misc. extra API parameters */
	pevent			ir_pev;		/* ptr to IFSMgr event for async requests */
	fsdwork_t		ir_fsd;		/* Provider work space */
};	/* ioreq */

typedef struct ioreq ioreq, *pioreq;

typedef	int	_cdecl IFSFunc(pioreq pir);
typedef IFSFunc *pIFSFunc;

#define NUM_HNDLMISC	8

typedef struct volfunc volfunc;
typedef struct hndlmisc hndlmisc;
typedef struct hndlfunc hndlfunc;

struct hndlfunc {
	pIFSFunc	hf_read;	/* file read handler function */
	pIFSFunc	hf_write;	/* file write handler function */
	hndlmisc	*hf_misc;	/* ptr to misc. function vector */
};	/* hndlfunc */


struct hndlmisc {
	short		hm_version;			/* IFS version # */
	char		hm_revision;		/* IFS interface revision # */
	char		hm_size;			/* # of entries in table */
	pIFSFunc	hm_func[NUM_HNDLMISC];
};	/* hndlmisc */

#define NUM_VOLFUNC	15

struct volfunc {
	short		vfn_version;		/* IFS version # */
	char		vfn_revision;		/* IFS interface revision # */
	char		vfn_size;			/* # of entries in table */
	pIFSFunc	vfn_func[NUM_VOLFUNC];/* volume base function handlers */
};	/* volfunc */

struct fhandle;
struct shres;

typedef struct shres { 
	WORD sr_sig;
	BYTE sr_serial;
	BYTE sr_idx;
	struct shres *sr_next;
	DWORD sr_rh;
	struct volfunc *sr_func;
	DWORD sr_inUse;
	WORD sr_uword;
	WORD sr_HndCnt;
	BYTE sr_UNCCnt;
	BYTE sr_DrvCnt;
	BYTE sr_rtype;
	BYTE sr_flags;
	DWORD sr_ProID;
	void* sr_VolInfo;
	struct fhandle* sr_fhandleHead;
	DWORD sr_LockPid;
	DWORD sr_LockSavFunc;
	BYTE sr_LockType;
	BYTE sr_PhysUnit;
	WORD sr_LockFlags;
	DWORD sr_LockOwner;
	WORD sr_LockWaitCnt;
	WORD sr_LockReadCnt;
	WORD sr_LockWriteCnt;
	BYTE sr_flags2;
	BYTE sr_reserved;
	void* sr_pnv;
} shres, *pshres;

typedef struct hlockinfo {
	struct hndlfunc hl;
	DWORD hl_lock;
	DWORD hl_flags;
	DWORD hl_pathlen;
	unsigned short hl_pathname[1];
} hlockinfo, *phlockinfo;

typedef struct fhandle {
	struct hndlfunc fh_hf;
	fh_t fh_fh;
	shres * fh_psr;
	void * fh_pSFT;
	DWORD fh_position;
	WORD fh_devflags;
	BYTE fh_hflag;
	BYTE fh_type;
	WORD fh_ref_count;
	WORD fh_mode;
	hlockinfo* fh_hlockinfo;
	void* fh_prev;
	void* fh_next;
	WORD fh_sfn;
	WORD fh_mmsfn;
	DWORD fh_pid;
	DWORD fh_ntid;
	WORD fh_fhFlags;
	WORD fh_InCloseCnt;
} fhandle, *pfhandle;

typedef void* HVM;

typedef struct ifsreq {
	ioreq ifs_ir;
	fhandle* ifs_pfn;
	DWORD ifs_psft;
	shres * ifs_psr;
	DWORD ifs_pdb;
	DWORD ifs_proid;
	BYTE ifs_func;
	BYTE ifs_drv;
	BYTE ifs_hflag;
	BYTE ifs_nflags;
	void* ifs_pbuffer;
	HVM ifs_VMHandle;
	void* ifs_PV;
	BYTE ifs_crs[48];
} ifsreq, *pifsreq;

typedef	int	_cdecl IFSFileHookFunc( pIFSFunc pfn, int fn, int Drive, int ResType, int CodePage, pioreq pir );
typedef	IFSFileHookFunc	*pIFSFileHookFunc;
typedef	pIFSFileHookFunc	*ppIFSFileHookFunc;

#define HM_SEEK			0			/* Seek file handle */
#define HM_CLOSE		1			/* close handle */
#define HM_COMMIT		2			/* commit buffered data for handle*/
#define HM_FILELOCKS	3			/* lock/unlock byte range */
#define HM_FILETIMES	4			/* get/set file modification time */
#define HM_PIPEREQUEST	5			/* named pipe operations */
#define HM_HANDLEINFO	6			/* get/set file information */
#define HM_ENUMHANDLE	7			/* enum filename from handle, lock info */

/** IFS Function IDs passed to IFSMgr_CallProvider */

#define IFSFN_READ			0		/* read a file */
#define IFSFN_WRITE			1		/* write a file */
#define IFSFN_FINDNEXT		2		/* LFN handle based Find Next */
#define IFSFN_FCNNEXT		3		/* Find Next Change Notify */

#define IFSFN_SEEK			10		/* Seek file handle */
#define IFSFN_CLOSE			11		/* close handle */
#define IFSFN_COMMIT		12		/* commit buffered data for handle*/
#define IFSFN_FILELOCKS		13		/* lock/unlock byte range */
#define IFSFN_FILETIMES		14		/* get/set file modification time */
#define IFSFN_PIPEREQUEST	15		/* named pipe operations */
#define IFSFN_HANDLEINFO	16		/* get/set file information */
#define IFSFN_ENUMHANDLE	17		/* enum file handle information */
#define IFSFN_FINDCLOSE		18		/* LFN find close */
#define IFSFN_FCNCLOSE		19		/* Find Change Notify Close */

#define IFSFN_CONNECT		30		/* connect or mount a resource */
#define IFSFN_DELETE		31		/* file delete */
#define IFSFN_DIR			32		/* directory manipulation */
#define IFSFN_FILEATTRIB	33		/* DOS file attribute manipulation */
#define IFSFN_FLUSH			34		/* flush volume */
#define IFSFN_GETDISKINFO	35		/* query volume free space */
#define IFSFN_OPEN			36		/* open file */
#define IFSFN_RENAME		37		/* rename path */
#define IFSFN_SEARCH		38		/* search for names */
#define IFSFN_QUERY			39		/* query resource info (network only) */
#define IFSFN_DISCONNECT	40		/* disconnect from resource (net only) */
#define IFSFN_UNCPIPEREQ	41		/* UNC path based named pipe operations */
#define IFSFN_IOCTL16DRIVE	42		/* drive based 16 bit IOCTL requests */
#define IFSFN_GETDISKPARMS	43		/* get DPB */
#define IFSFN_FINDOPEN		44		/* open	an LFN file search */
#define IFSFN_DASDIO		45		/* direct volume access */

/**	Resource types passed in on the File Hook: */
#define IFSFH_RES_UNC		0x01	/* UNC resource */
#define IFSFH_RES_NETWORK	0x08	/* Network drive connection */
#define IFSFH_RES_LOCAL		0x10	/* Local drive */
#define IFSFH_RES_CFSD		0x80	/* Character FSD */

/** Values for ir_flags for HM_ENUMHANDLE call: */
#define ENUMH_GETFILEINFO	0		/* get fileinfo by handle */
#define ENUMH_GETFILENAME	1		/* get filename associated with handle */
#define ENUMH_GETFINDINFO	2		/* get info for resuming */
#define ENUMH_RESUMEFIND	3		/* resume find operation */
#define ENUMH_RESYNCFILEDIR	4		/* resync dir entry info for file */
#ifdef	MAPCACHE
#define ENUMH_MAPCACHEBLOCK	5		/* map a cache block within a file */
#endif

#define VFN_DELETE			0		/* file delete */
#define VFN_DIR				1		/* directory manipulation */
#define VFN_FILEATTRIB		2		/* DOS file attribute manipulation */
#define VFN_FLUSH			3		/* flush volume */
#define VFN_GETDISKINFO		4		/* query volume free space */
#define VFN_OPEN			5		/* open file */
#define VFN_RENAME			6		/* rename path */
#define VFN_SEARCH			7		/* search for names */
#define VFN_QUERY			8		/* query resource info (network only) */
#define VFN_DISCONNECT		9		/* disconnect from resource (net only) */
#define VFN_UNCPIPEREQ		10		/* UNC path based named pipe operations */
#define VFN_IOCTL16DRIVE	11		/* drive based 16 bit IOCTL requests */
#define VFN_GETDISKPARMS	12		/* get DPB */
#define VFN_FINDOPEN		13		/* open	an LFN file search */
#define VFN_DASDIO			14		/* direct volume access */

#define R0_OPENCREATFILE		0xD500	/* Open/Create a file */
#define R0_OPENCREAT_IN_CONTEXT	0xD501	/* Open/Create file in current context */
#define R0_READFILE				0xD600	/* Read a file, no context */
#define R0_WRITEFILE			0xD601	/* Write to a file, no context */
#define R0_READFILE_IN_CONTEXT	0xD602	/* Read a file, in thread context */
#define R0_WRITEFILE_IN_CONTEXT	0xD603	/* Write to a file, in thread context */
#define R0_CLOSEFILE			0xD700	/* Close a file */
#define R0_GETFILESIZE			0xD800	/* Get size of a file */
#define R0_FINDFIRSTFILE		0x4E00	/* Do a LFN FindFirst operation */
#define R0_FINDNEXTFILE			0x4F00	/* Do a LFN FindNext operation */
#define R0_FINDCLOSEFILE		0xDC00	/* Do a LFN FindClose operation */
#define R0_FILEATTRIBUTES		0x4300	/* Get/Set Attributes of a file */
#define R0_RENAMEFILE			0x5600	/* Rename a file */
#define R0_DELETEFILE			0x4100	/* Delete a file */
#define R0_LOCKFILE				0x5C00	/* Lock/Unlock a region in a file */
#define R0_GETDISKFREESPACE		0x3600	/* Get disk free space */
#define R0_READABSOLUTEDISK		0xDD00	/* Absolute disk read */
#define R0_WRITEABSOLUTEDISK	0xDE00	/* Absolute disk write */
#define R0_HANDLETOPATH			0xEC00	/* Get the full path from a file handle */
#define R0_MAPCACHEBLOCK		0xED00	/* Map a vcache cache block owned by vfat */
#define R0_GETVOLLOCKLEVEL		0xEE00	/* Get the vol lock level & permissions */


#define Interrupt 5 /* interrupt 3 will make debugging more difficult */

#if defined _MSC_VER
#pragma optimize("", off)
#else
#pragma GCC push_options
#pragma GCC optimize ("O0")
#endif
#if defined _MSC_VER
	#if _MSC_VER >= 1400
#include <intrin.h>
_inline PTIB getTIB(void)
{
#ifdef _M_IX86
	return (PTIB)__readfsdword(0x18);
#elif _M_AMD64
	return (PTIB)__readgsqword(0x30);
#else
#error unsupported architecture
#endif
}
	#elif _MSC_VER >= 1300
#include <WinNT.h>
_inline PTIB getTIB(void)
{
#ifdef _M_IX86
	return (PTIB)__readfsdword(0x18);
#elif _M_AMD64
	return (PTIB)__readgsqword(0x30);
#else
#error unsupported architecture
#endif
}
	#else
#pragma warning( disable : 4035 )
NAKED PTIB getTIB(VOID)
{
	__asm
	{
		mov EAX, FS:[18h]
		ret
	}
}
#pragma warning( default : 4035 )
	#endif
#else
PTIB getTIB(VOID)
{
	register PTIB pTIB;

#if defined(_M_AMD64)
	__asm__ volatile ("movq %%gs:0x30, %0" : "=r" (pTIB));
#elif defined(_M_IX86)
	__asm__ volatile ("movl %%fs:0x18, %0" : "=r" (pTIB));
#else
#error unsupported architecture
#endif
	return pTIB;
}
#endif

#if defined _MSC_VER && _MSC_VER >= 1300
	#ifdef _M_IX86
		typedef struct KDESCRIPTOR
		{
			USHORT Pad[1];
			USHORT Limit;
			PVOID Base;
		} KDESCRIPTOR;
	#elif _M_AMD64
		typedef struct KDESCRIPTOR
		{
			USHORT Pad[3];
			USHORT Limit;
			PVOID Base;
		} KDESCRIPTOR;
	#else
		#error unsupported architecture
	#endif
#endif

#if defined _MSC_VER
	#if _MSC_VER >= 1400
		#include <intrin.h>
	#elif _MSC_VER >= 1300
		#include <WinNT.h>
	#endif
	#if _MSC_VER >= 1300
		_inline PVOID getIDT(void)
		{
			KDESCRIPTOR descr;
			__sidt(&descr.Limit);
			return (PVOID)descr.Base;
		}
	#else
		_inline PVOID getIDT(void)
		{
			#ifdef _M_IX86
				DWORD idt;
				WORD limit;

				_asm push edx
				_asm push dx
				_asm sidt [esp] ;reads IDT into the stack
				_asm pop dx
				_asm mov limit, dx
				_asm pop edx
				_asm mov idt, edx
			#elif _M_AMD64
				ULONGLONG idt;
				WORD limit;

				_asm push rdx
				_asm push dx
				_asm sidt [rsp]
				_asm pop dx
				_asm mov limit, dx
				_asm pop rdx
				_asm mov idt, rdx
			#else
				#error unsupported architecture
			#endif
			return (PVOID)idt;
		}
	#endif
#else
PVOID getIDT(void)
{
#if defined(_M_AMD64)
	ULONGLONG idt;
	WORD limit;

    __asm__ volatile(
                    "pushq %%rdx\n\t"
                    "pushw %%dx\n\t"
                    "sidt (%%rsp) #reads IDT into the stack\n\t"
                    "popw %%dx\n\t"
                    "movw %%dx,%1\n\t"
                    "popq %%rdx\n\t"
                    "movq %%rdx,%0\n\t"
                    : "=m"(idt), "=m"(limit)
    );
#elif defined(_M_IX86)
	DWORD idt;
	WORD limit;

    __asm__ volatile(
				"pushl %%edx\n\t"
				"pushw %%dx\n\t"
				"sidt (%%esp) #reads IDT into the stack\n\t"
				"popw %%dx\n\t"
				"movw %%dx, %1\n\t"
				"popl %%edx\n\t"
				"movl %%edx, %0\n\t"
                    : "=m"(idt), "=m"(limit)
    );
#else
#error unsupported architecture
#endif
	return (PVOID)idt;
}
#endif

static PBOOL getRing0HandleHookRet;
static PDWORD getRing0HandleHookExtendedFileHandle;
static PVOID *getRing0HandleHookpHandleBuf;
static PDWORD getRing0HandleHookpFilePos;

typedef	int	_cdecl IFSFileHookFunc( pIFSFunc pfn, int fn, int Drive, int ResType, int CodePage, pioreq pir );
typedef	IFSFileHookFunc	*pIFSFileHookFunc;
typedef	pIFSFileHookFunc	*ppIFSFileHookFunc;

static ppIFSFileHookFunc IFSMgr_InstallFileSystemApiHook(pIFSFileHookFunc func)
{
	ppIFSFileHookFunc r = NULL;
#if defined(_M_AMD64)
	#ifdef _MSC_VER
	_asm {
		mov rax, func
		push rax
	};
	#else
	__asm__ volatile (
		"movq %0, %%rax\n\t"
		"pushq %%rax\n\t"
		: : "m" (func)
	);
	#endif
#elif defined(_M_IX86)
	#ifdef _MSC_VER
	_asm {
		mov eax, func
		push eax
	};
	#else
	__asm__ volatile (
		"movl %0, %%eax\n\t"
		"pushl %%eax\n\t"
		: : "m" (func)
	);
	#endif
#else
#error unsupported architecture
#endif
	VxDCall(0x00400067);
#if defined(_M_AMD64)
	#ifdef _MSC_VER
	_asm {
		pop rcx
		mov r, rax
	};
	#else
	__asm__ volatile (
		"popq %%rcx\n\t"
		"movq %%rax, %0\n\t"
		: "=m" (r)
	);
	#endif
#elif defined(_M_IX86)
	#ifdef _MSC_VER
	_asm {
		pop ecx
		mov r, eax
	};
	#else
	__asm__ volatile (
		"popl %%ecx\n\t"
		"movl %%eax, %0\n\t"
		: "=m" (r)
	);
	#endif
#else
#error unsupported architecture
#endif
	return r;
}

static ppIFSFileHookFunc IFSMgr_RemoveFileSystemApiHook(pIFSFileHookFunc func)
{
	ppIFSFileHookFunc r = NULL;
#if defined(_M_AMD64)
	#ifdef _MSC_VER
	_asm {
		mov rax, func
		push rax
	};
	#else
	__asm__ volatile (
		"movq %0, %%rax\n\t"
		"pushq %%rax\n\t"
		: : "m" (func)
	);
	#endif
#elif defined(_M_IX86)
	#ifdef _MSC_VER
	_asm {
		mov eax, func
		push eax
	};
	#else
	__asm__ volatile (
		"movl %0, %%eax\n\t"
		"pushl %%eax\n\t"
		: : "m" (func)
	);
	#endif
#else
#error unsupported architecture
#endif
	VxDCall(0x00400068);
#if defined(_M_AMD64)
	#ifdef _MSC_VER
	_asm {
		pop rcx
		mov r, rax
	};
	#else
	__asm__ volatile (
		"popq %%rcx\n\t"
		"movq %%rax, %0\n\t"
		: "=m" (r)
	);
	#endif
#elif defined(_M_IX86)
	#ifdef _MSC_VER
	_asm {
		pop ecx
		mov r, eax
	};
	#else
	__asm__ volatile (
		"popl %%ecx\n\t"
		"movl %%eax, %0\n\t"
		: "=m" (r)
	);
	#endif
#else
#error unsupported architecture
#endif
	return r;
}


static LPVOID IFSMgr_GetHeap(DWORD allocSize)
{
	LPVOID r = NULL;
#if defined(_M_AMD64)
	#ifdef _MSC_VER
	_asm {
		mov rax, allocSize
		push rax
	};
	#else
	__asm__ volatile (
		"movq %0, %%rax\n\t"
		"pushq %%rax\n\t"
		: : "m" (allocSize)
	);
	#endif
#elif defined(_M_IX86)
	#ifdef _MSC_VER
	_asm {
		mov eax, allocSize
		push eax
	};
	#else
	__asm__ volatile (
		"movl %0, %%eax\n\t"
		"pushl %%eax\n\t"
		: : "m" (allocSize)
	);
	#endif
#else
#error unsupported architecture
#endif
	VxDCall(0x0040000D);
#if defined(_M_AMD64)
	#ifdef _MSC_VER
	_asm {
		pop rcx
		mov r, rax
	};
	#else
	__asm__ volatile (
		"popq %%rcx\n\t"
		"movq %%rax, %0\n\t"
		: "=m" (r)
	);
	#endif
#elif defined(_M_IX86)
	#ifdef _MSC_VER
	_asm {
		pop ecx
		mov r, eax
	};
	#else
	__asm__ volatile (
		"popl %%ecx\n\t"
		"movl %%eax, %0\n\t"
		: "=m" (r)
	);
	#endif
#else
#error unsupported architecture
#endif
	return r;
}

static void IFSMgr_RetHeap(LPVOID pMemPtr)
{
#if defined(_M_AMD64)
	#ifdef _MSC_VER
	_asm {
		mov rax, pMemPtr
		push rax
	};
	#else
	__asm__ volatile (
		"movq %0, %%rax\n\t"
		"pushq %%rax\n\t"
		: : "m" (pMemPtr)
	);
	#endif
#elif defined(_M_IX86)
	#ifdef _MSC_VER
	_asm {
		mov eax, pMemPtr
		push eax
	};
	#else
	__asm__ volatile (
		"movl %0, %%eax\n\t"
		"pushl %%eax\n\t"
		: : "m" (pMemPtr)
	);
	#endif
#else
#error unsupported architecture
#endif
	VxDCall(0x0040000E);
#if defined(_M_AMD64)
	#ifdef _MSC_VER
	_asm {
		pop rcx
	}
	#else
	__asm__ volatile (
		"popq %rcx\n\t"
	);
	#endif
#elif defined(_M_IX86)
	#ifdef _MSC_VER
	_asm {
		pop ecx
	}
	#else
	__asm__ volatile (
		"popl %ecx\n\t"
	);
	#endif
#else
#error unsupported architecture
#endif
	return;
}

static BOOL IFSMgr_Win32_Get_Ring0_Handle(DWORD handle, PVOID *pHandleBuf, PDWORD pFilePos)
{
	BOOL r = FALSE;

#if defined(_M_AMD64)
	#ifdef _MSC_VER
	_asm {
		mov rax, handle
		mov rbx, rax
	}
	#else
	__asm__ volatile (
		"movq %0, %%rax\n\t"
		"movq %%rax, %%rbx\n\t"
		: 
		: "m" (handle)
		: "eax", "ebx"
	);
	#endif
#elif defined(_M_IX86)
	#ifdef _MSC_VER
	_asm {
		mov eax, handle
		mov ebx, eax
	}
	#else
	__asm__ volatile (
		"movl %0, %%eax\n\t"
		"movl %%eax, %%ebx\n\t"
		: 
		: "m" (handle)
		: "eax", "ebx"
	);
	#endif
#else
#error unsupported architecture
#endif
	VxDCall(0x00400033);
#if defined(_M_AMD64)
	#ifdef _MSC_VER
	_asm {
		mov rax, pHandleBuf
		mov [rax], rbx
		mov rax, pFilePos
		mov [rax], rdx
		setnb al
		and rax, 1
		mov r, rax
	}
	#else
	__asm__ volatile (
		"movq %0, %%rax\n\t"
		"movq %%rbx, (%%rax)\n\t"
		"movq %1, %%rax\n\t"
		"movq %%rdx, (%%rax)\n\t"
		"setnbb %%al\n\t"
		"andq $1, %%rax\n\t" 
		"movq %%rax, %2\n\t" 
		: "+m" (pHandleBuf), "+m" (pFilePos), "=m" (r) : : "eax"
	);
	#endif
#elif defined(_M_IX86)
	#ifdef _MSC_VER
	_asm {
		mov eax, pHandleBuf
		mov [eax], ebx
		mov eax, pFilePos
		mov [eax], edx
		setnb al
		and eax, 1
		mov r, eax
	}
	#else
	__asm__ volatile (
		"movl %0, %%eax\n\t"
		"movl %%ebx, (%%eax)\n\t"
		"movl %1, %%eax\n\t"
		"movl %%edx, (%%eax)\n\t"
		"setnbb %%al\n\t"
		"andl $1, %%eax\n\t" 
		"movl %%eax, %2\n\t" 
		: "+m" (pHandleBuf), "+m" (pFilePos), "=m" (r) : : "eax"
	);
	#endif
#else
#error unsupported architecture
#endif

	return r;
}

#pragma pack(push, 1)
typedef struct GetPathAsciiData {
	ppIFSFileHookFunc oldFunc;
	BOOL called;
	LPVOID handleBuf;
	BOOL error;
	BYTE dataBuf[4];
	struct ParsedPath outPath;
	WCHAR outBuffer[MAX_PATH];
	BYTE out[MAX_PATH + 3];
	int Drive;
	int ResType;
	int CodePage;
} GetPathAsciiData, *PGetPathAsciiData;

typedef struct GetPathUnicodeData {
	ppIFSFileHookFunc oldFunc;
	BOOL called;
	LPVOID handleBuf;
	BOOL error;
	BYTE dataBuf[4];
	struct ParsedPath outPath;
	WCHAR outBuffer[MAX_PATH];
	WCHAR out[MAX_PATH + 3];
	int Drive;
	int ResType;
	int CodePage;
} GetPathUnicodeData, *PGetPathUnicodeData;
#pragma pack(pop)

size_t sizeofGetPathAscii = 0;
size_t sizeofGetPathUnicode = 0;

#ifdef _M_IX86
	DWORD offLdPData;
#elif _M_AMD64
	ULONGLONG offLdPData;
#else
	#error unsupported architecture
#endif

DWORD page;
DWORD func1;
DWORD func2;
DWORD func3;
LPVOID memBlock;

pIFSFileHookFunc pFunc;
LPVOID fileSystemApiHandle = NULL;
ppIFSFileHookFunc oldFunc;
PGetPathAsciiData pData;
PGetPathUnicodeData pUnicodeData;

static int	_cdecl getPathAscii( pIFSFunc pfn, int fn, int Drive, int ResType, int CodePage, pioreq pir )
{
	PGetPathAsciiData pData;
	ppIFSFileHookFunc *pOldFunc;
	PBOOL pCalled;
	LPVOID *pHandleBuf;
	DWORD ret;
	BYTE (*pDataBuf)[4];
	WCHAR (*pOutBuffer)[MAX_PATH];
	unsigned char (*pOut)[MAX_PATH + 3];
	path_t pOutPath;
	ifsreq origifsr;
	pioreq origir;
	pIFSFunc        enumFunc;
    ifsreq          ifsr;
	int i;
	BYTE *porigir;
	BYTE *ppir;
	_QWORD unitobcsResult;
	_QWORD *pUnitobcsResult;
	struct PathElement *pp_elements;
	unsigned char *pOutBuf;
	DWORD outBufSize;
	DWORD outBufStart;

#if defined(_M_AMD64)
	#ifdef _MSC_VER
	_asm mov rax, 0x00000000
	_asm mov pData, rax
	#else
	__asm__ volatile (
		"movq $0, %%rax\n\t"
		"movq %%rax, %0\n\t"
		: "=m" (pData)
	);
	#endif
#elif defined(_M_IX86)
	#ifdef _MSC_VER
	_asm mov eax, 0x00000000
	_asm mov pData, eax
	#else
	__asm__ volatile (
		"movl $0, %%eax\n\t"
		"movl %%eax, %0\n\t"
		: "=m" (pData)
	);
	#endif
#else
#error unsupported architecture
#endif

	pOldFunc = &pData->oldFunc;
	pCalled = &pData->called;
	pHandleBuf = &pData->handleBuf;
	pDataBuf = &pData->dataBuf;
	pOutPath = &pData->outPath;
	pOutBuffer = &pData->outBuffer;
	pOut = &pData->out;

	ret = (*(*(*pOldFunc)))(pfn, fn, Drive, ResType, CodePage, pir);

	if(*pCalled == 1 && *pHandleBuf == ((ifsreq*)pir)->ifs_pfn)
	{
		*pCalled = 2;

		origir = (pioreq) &origifsr;
		//memcpy( &origifsr, pir, sizeof( ifsreq ));
		for(i = 0, porigir = (BYTE *)&origifsr, ppir = (BYTE *)pir; i < sizeof( ifsreq ); i++, porigir++, ppir++)
		{
			*porigir = *ppir;
		}
//FilemonGetFullPath( origir->ir_fh, fullpathname, Drive, ResType, CodePage, origir );
            
        //
        // Send a query file name request
        //
        //memcpy( &ifsr, origir, sizeof( ifsreq ));
		for(i = 0, porigir = (BYTE *)&ifsr, ppir = (BYTE *)origir; i < sizeof( ifsreq ); i++, porigir++, ppir++)
		{
			*porigir = *ppir;
		}

		outBufStart = 0;
		pOutBuf = &pData->out[0];

		if((ResType & IFSFH_RES_NETWORK) != 0)
		{
			ifsr.ifs_ir.ir_options = 0;
			ifsr.ifs_ir.ir_flags = 0;
			ifsr.ifs_ir.ir_ppath = pOutPath;
			enumFunc = ifsr.ifs_psr->sr_func->vfn_func[VFN_QUERY];

			if((*(*(*pOldFunc)))(enumFunc, IFSFN_QUERY, 
										Drive, ResType, CodePage, 
											(pioreq) &ifsr) == 0)
			{
				pData->Drive = Drive;
				pData->ResType = ResType;
				pData->CodePage = CodePage;

				pUnitobcsResult = &unitobcsResult;
				pp_elements = pOutPath->pp_elements;

				outBufSize = MAX_PATH;

				if(Drive != 0xFFFFFFFF)
				{
					pData->out[outBufStart] = Drive + 'A' - 1;
					outBufStart++;
					pData->out[outBufStart] = ':';
					outBufStart++;
				}
				pOutBuf = &pData->out[outBufStart];

#if defined(_M_AMD64)
				#ifdef _MSC_VER
				_asm push CodePage
				_asm push outBufSize
				_asm push pp_elements
				_asm push pOutBuf
				#else
				__asm__ volatile( 
					"pushq %0\n\t"
					"pushq %1\n\t"
					"pushq %2\n\t"
					"pushq %3\n\t"
					: : "m" (CodePage), "m" (outBufSize), "m" (pp_elements), "m" (pOutBuf)
				);
				#endif
#elif defined(_M_IX86)
				#ifdef _MSC_VER
				_asm push CodePage
				_asm push outBufSize
				_asm push pp_elements
				_asm push pOutBuf
				#else
				__asm__ volatile( 
					"pushl %0\n\t"
					"pushl %1\n\t"
					"pushl %2\n\t"
					"pushl %3\n\t"
					: : "m" (CodePage), "m" (outBufSize), "m" (pp_elements), "m" (pOutBuf)
				);
				#endif
#else
#error unsupported architecture
#endif
				
				VxDCall(0x00400041);
#if defined(_M_AMD64)
				#ifdef _MSC_VER
				_asm mov rcx, pUnitobcsResult
				_asm mov [rcx], rax
				_asm mov [rcx + 4], rdx

				_asm pop rax
				_asm pop rax
				_asm pop rax
				_asm pop rax
				#else
				__asm__ volatile( 
					"movq %0, %%rcx\n\t"
					"movq %%rax, (%%rcx)\n\t"
					"movq %%rdx, 4(%%rcx)\n\t"

					"popq %%rax\n\t"
					"popq %%rax\n\t"
					"popq %%rax\n\t"
					"popq %%rax\n\t"
					: "+m" (pUnitobcsResult)
				);
				#endif
#elif defined(_M_IX86)
				#ifdef _MSC_VER
				_asm mov ecx, pUnitobcsResult
				_asm mov [ecx], eax
				_asm mov [ecx + 4], edx

				_asm pop eax
				_asm pop eax
				_asm pop eax
				_asm pop eax
				#else
				__asm__ volatile( 
					"movl %0, %%ecx\n\t"
					"movl %%eax, (%%ecx)\n\t"
					"movl %%edx, 4(%%ecx)\n\t"

					"popl %%eax\n\t"
					"popl %%eax\n\t"
					"popl %%eax\n\t"
					"popl %%eax\n\t"
					: "+m" (pUnitobcsResult)
				);
				#endif
#else
#error unsupported architecture
#endif

				pData->out[outBufStart + unitobcsResult.ddLower] = 0;
				outBufStart = outBufStart + unitobcsResult.ddLower;
				pOutBuf = &pData->out[outBufStart];

				for(i = 0; i < sizeof pData->outPath; i++)
				{
					((char *)(&pData->outPath))[i] = '\0';
				}
				for(i = 0; i < sizeof pData->outBuffer; i++)
				{
					((char *)(&pData->outBuffer))[i] = '\0';
				}
			}
			else
			{
				pData->error = TRUE;
			}
		}

		for(i = 0, porigir = (BYTE *)&ifsr, ppir = (BYTE *)origir; i < sizeof( ifsreq ); i++, porigir++, ppir++)
		{
			*porigir = *ppir;
		}

		ifsr.ifs_ir.ir_flags = ENUMH_GETFILENAME;
        ifsr.ifs_ir.ir_ppath = pOutPath;
		enumFunc = ifsr.ifs_pfn->fh_hf.hf_misc->hm_func[HM_ENUMHANDLE];

        if(!pData->error && (*(*(*pOldFunc)))(enumFunc, IFSFN_ENUMHANDLE, 
                                    Drive, ResType, CodePage, 
                                        (pioreq) &ifsr) == 0)
		{
			pData->Drive = Drive;
			pData->ResType = ResType;
			pData->CodePage = CodePage;

			pUnitobcsResult = &unitobcsResult;
			pp_elements = pOutPath->pp_elements;

			outBufSize = MAX_PATH;

			if((ResType & IFSFH_RES_NETWORK) == 0 && Drive != 0xFFFFFFFF)
			{
				pData->out[outBufStart] = Drive + 'A' - 1;
				outBufStart++;
				pData->out[outBufStart] = ':';
				outBufStart++;
				pOutBuf = &pData->out[outBufStart];
			}

#if defined(_M_AMD64)
			#ifdef _MSC_VER
			_asm push CodePage
			_asm push outBufSize
			_asm push pp_elements
			_asm push pOutBuf
			#else
			__asm__ volatile (
				"pushq %0\n\t"
				"pushq %1\n\t"
				"pushq %2\n\t"
				"pushq %3\n\t"
				: : "m" (CodePage), "m" (outBufSize), "m" (pp_elements), "m" (pOutBuf)
			);
			#endif
#elif defined(_M_IX86)
			#ifdef _MSC_VER
			_asm push CodePage
			_asm push outBufSize
			_asm push pp_elements
			_asm push pOutBuf
			#else
			__asm__ volatile (
				"pushl %0\n\t"
				"pushl %1\n\t"
				"pushl %2\n\t"
				"pushl %3\n\t"
				: : "m" (CodePage), "m" (outBufSize), "m" (pp_elements), "m" (pOutBuf)
			);
			#endif
#else
#error unsupported architecture
#endif
			
			VxDCall(0x00400041);
#if defined(_M_AMD64)
			#ifdef _MSC_VER
			_asm mov rcx, pUnitobcsResult
			_asm mov [rcx], rax
			_asm mov [rcx + 4], rdx

			_asm pop rax
			_asm pop rax
			_asm pop rax
			_asm pop rax
			#else
			__asm__ volatile (
				"movq %0, %%rcx\n\t"
				"movq %%rax, (%%rcx)\n\t"
				"movq %%rdx, 4(%%rcx)\n\t"

				"popq %%rax\n\t"
				"popq %%rax\n\t"
				"popq %%rax\n\t"
				"popq %%rax\n\t"
				: "+m" (pUnitobcsResult)
			);
			#endif
#elif defined(_M_IX86)
			#ifdef _MSC_VER
			_asm mov ecx, pUnitobcsResult
			_asm mov [ecx], eax
			_asm mov [ecx + 4], edx

			_asm pop eax
			_asm pop eax
			_asm pop eax
			_asm pop eax
			#else
			__asm__ volatile (
				"movl %0, %%ecx\n\t"
				"movl %%eax, (%%ecx)\n\t"
				"movl %%edx, 4(%%ecx)\n\t"

				"popl %%eax\n\t"
				"popl %%eax\n\t"
				"popl %%eax\n\t"
				"popl %%eax\n\t"
				: "+m" (pUnitobcsResult)
			);
			#endif
#else
#error unsupported architecture
#endif

			pData->out[outBufStart + unitobcsResult.ddLower ] = 0;

			*pCalled = 3;
		}
		else
		{
			pData->error = TRUE;
		}
	}
	if(!*pCalled)
	{
		*pCalled = 1;

#if defined(_M_AMD64)
		#ifdef _MSC_VER
		_asm mov rax, pDataBuf
		_asm mov rsi, [rax]
		_asm mov rax, pHandleBuf
		_asm mov rbx, [rax]
		_asm mov rcx, 4
		_asm mov rdx, 0
		_asm mov rax, 0x0D602
		#else
		__asm__ volatile (
			"movq %0, %%rax\n\t"
			"movq (%%rax), %%rsi\n\t"
			"movq %1, %%rax\n\t"
			"movq (%%rax), %%rbx\n\t"
			"movq $4, %%rcx\n\t"
			"movq $0, %%rdx\n\t"
			"movq $0x0D602, %%rax\n\t"
			: : "m" (pDataBuf), "m" (pHandleBuf)
		);
		#endif
#elif defined(_M_IX86)
		#ifdef _MSC_VER
		_asm mov eax, pDataBuf
		_asm mov esi, [eax]
		_asm mov eax, pHandleBuf
		_asm mov ebx, [eax]
		_asm mov ecx, 4
		_asm mov edx, 0
		_asm mov eax, 0x0D602
		#else
		__asm__ volatile (
			"movl %0, %%eax\n\t"
			"movl (%%eax), %%esi\n\t"
			"movl %1, %%eax\n\t"
			"movl (%%eax), %%ebx\n\t"
			"movl $4, %%ecx\n\t"
			"movl $0, %%edx\n\t"
			"movl $0x0D602, %%eax\n\t"
			: : "m" (pDataBuf), "m" (pHandleBuf)
		);
		#endif
#else
#error unsupported architecture
#endif
		
		VxDCall(0x00400032);
	}

	return ret;
	//return 0;
}

static DWORD _cdecl getPathAsciiEnd()
{
    return 0;
}

#pragma warning(disable : 4101)
static int	_cdecl getPathAsciiOffsets( pIFSFunc pfn, int fn, int Drive, int ResType, int CodePage, pioreq pir )
{
	PGetPathAsciiData pData;
	ppIFSFileHookFunc *pOldFunc;
	PBOOL pCalled;
	LPVOID *pHandleBuf;
	DWORD ret;
	BYTE (*pDataBuf)[4];
	WCHAR (*pOutBuffer)[MAX_PATH];
	unsigned char (*pOut)[MAX_PATH + 3];
	path_t pOutPath;
	ifsreq origifsr;
	pioreq origir;
	pIFSFunc        enumFunc;
    ifsreq          ifsr;
	int i;
	BYTE *porigir;
	BYTE *ppir;
	_QWORD unitobcsResult;
	_QWORD *pUnitobcsResult;
	struct PathElement *pp_elements;
	unsigned char *pOutBuf;
	DWORD outBufSize;
	DWORD outBufStart;

	#if _MSC_VER
ldPData:
		#ifdef _M_IX86
			_asm mov eax, 0x00000000
			_asm mov pData, eax

			_asm mov eax, offset ldPData
			_asm mov offLdPData, eax
		#elif _M_AMD64
			_asm mov rax, 0x00000000
			_asm mov pData, rax

			_asm mov rax, offset ldPData
			_asm mov offLdPData, rax
		#else
			#error unsupported architecture
		#endif	
	#else
		__asm__ volatile (
			"ldPData:\n\t"
		#ifdef _M_IX86
			"movl $0x00000000, %%eax\n\t"
			"movl %%eax, %0\n\t"

			"movl $ldPData, %%eax\n\t"
			"movl %%eax, %1\n\t"
		#elif _M_AMD64
			"movq $0x00000000, %%rax\n\t"
			"movq %%rax, %0\n\t"

			"movq $ldPData, %%rax\n\t"
			"movq %%rax, %1\n\t"
		#else
			#error unsupported architecture
		#endif
	
		: "=m"(pData), "=m"(offLdPData)
	);
	#endif

	#ifdef _M_IX86
		offLdPData -= (DWORD)getPathAsciiOffsets;
	#elif _M_AMD64
		offLdPData -= (ULONGLONG)getPathAsciiOffsets;
	#else
		#error unsupported architecture
	#endif

	return 0;
}
#pragma warning(default : 4101)

static int	_cdecl getPathUnicode( pIFSFunc pfn, int fn, int Drive, int ResType, int CodePage, pioreq pir )
{
	PGetPathUnicodeData pUnicodeData;
	ppIFSFileHookFunc *pOldFunc;
	PBOOL pCalled;
	LPVOID *pHandleBuf;
	DWORD ret;
	BYTE (*pDataBuf)[4];
	WCHAR (*pOut)[MAX_PATH + 3];
	path_t pOutPath;
	ifsreq origifsr;
	pioreq origir;
	pIFSFunc        enumFunc;
    ifsreq          ifsr;
	int i;
	//int j;
	BYTE *porigir;
	BYTE *ppir;
	DWORD outBufSize;
	DWORD outBufStart;
	struct PathElement *pp_element;
	LPVOID parsedPathEnd;
	LPVOID pathElementEnd;
/*struct PathElement {
	unsigned short	pe_length;
	unsigned short	pe_unichars[1];
};

struct ParsedPath {
	unsigned short	pp_totalLength;
	unsigned short	pp_prefixLength;
	struct PathElement pp_elements[1];
};*/

#if defined(_M_AMD64)
	#ifdef _MSC_VER
	_asm mov rax, 0x00000000
	_asm mov pUnicodeData, rax
	#else
	__asm__ volatile (
		"movq $0x00000000, %%rax\n\t"
		"movq %%rax, %0\n\t"
		: "=m" (pUnicodeData)
	);
	#endif
#elif defined(_M_IX86)
	#ifdef _MSC_VER
	_asm mov eax, 0x00000000
	_asm mov pUnicodeData, eax
	#else
	__asm__ volatile (
		"movl $0x00000000, %%eax\n\t"
		"movl %%eax, %0\n\t"
		: "=m" (pUnicodeData)
	);
	#endif
#else
#error unsupported architecture
#endif

	pOldFunc = &pUnicodeData->oldFunc;
	pCalled = &pUnicodeData->called;
	pHandleBuf = &pUnicodeData->handleBuf;
	pDataBuf = &pUnicodeData->dataBuf;
	pOutPath = &pUnicodeData->outPath;
	pOut = &pUnicodeData->out;

	ret = (*(*(*pOldFunc)))(pfn, fn, Drive, ResType, CodePage, pir);

	if(*pCalled == 1 && *pHandleBuf == ((ifsreq*)pir)->ifs_pfn)
	{
		*pCalled = 2;

		origir = (pioreq) &origifsr;
		//memcpy( &origifsr, pir, sizeof( ifsreq ));
		for(i = 0, porigir = (BYTE *)&origifsr, ppir = (BYTE *)pir; i < sizeof( ifsreq ); i++, porigir++, ppir++)
		{
			*porigir = *ppir;
		}
//FilemonGetFullPath( origir->ir_fh, fullpathname, Drive, ResType, CodePage, origir );
            
        //
        // Send a query file name request
        //
        //memcpy( &ifsr, origir, sizeof( ifsreq ));
		for(i = 0, porigir = (BYTE *)&ifsr, ppir = (BYTE *)origir; i < sizeof( ifsreq ); i++, porigir++, ppir++)
		{
			*porigir = *ppir;
		}

		outBufStart = 0;

		if((ResType & IFSFH_RES_NETWORK) != 0)
		{
			ifsr.ifs_ir.ir_options = 0;
			ifsr.ifs_ir.ir_flags = 0;
			ifsr.ifs_ir.ir_ppath = pOutPath;
			enumFunc = ifsr.ifs_psr->sr_func->vfn_func[VFN_QUERY];

			if((*(*(*pOldFunc)))(enumFunc, IFSFN_QUERY, 
										Drive, ResType, CodePage, 
											(pioreq) &ifsr) == 0)
			{
				pUnicodeData->Drive = Drive;
				pUnicodeData->ResType = ResType;
				pUnicodeData->CodePage = CodePage;

				outBufSize = MAX_PATH;

				if(Drive != 0xFFFFFFFF)
				{
					pUnicodeData->out[outBufStart] = Drive + (WCHAR)'A' - 1;
					outBufStart++;
					pUnicodeData->out[outBufStart] = (WCHAR)':';
					outBufStart++;
				}

				if(pOutPath)
				{
					/*for(i = 0; i < pOutPath->pp_totalLength && outBufStart < sizeof pUnicodeData->out / sizeof pUnicodeData->out[0] - 1; i++)
					{
						for(j = 0; j < pOutPath->pp_elements[i].pe_length && outBufStart < sizeof pUnicodeData->out / sizeof pUnicodeData->out[0] - 1; j++)
						{
							pUnicodeData->out[outBufStart] = pOutPath->pp_elements[i].pe_unichars[j];
							outBufStart++;
						}
					}*/
					/*for(j = 0; j < pOutPath->pp_elements[0].pe_length && outBufStart < sizeof pUnicodeData->out / sizeof pUnicodeData->out[0] - 1; j++)
					{
						pUnicodeData->out[outBufStart] = pOutPath->pp_elements[0].pe_unichars[i];
						outBufStart++;
					}*/
					pp_element = &pOutPath->pp_elements[0];
					#ifdef _M_IX86
						parsedPathEnd = (LPVOID)((DWORD)pOutPath + pOutPath->pp_totalLength);
					#elif _M_AMD64
						parsedPathEnd = (LPVOID)((ULONGLONG)pOutPath + pOutPath->pp_totalLength);
					#else
						#error unsupported architecture
					#endif
					while((LPVOID)pp_element < parsedPathEnd && outBufStart < sizeof pUnicodeData->out / sizeof pUnicodeData->out[0] - 1)
					{
						#ifdef _M_IX86
							pathElementEnd = (LPVOID)((DWORD)pp_element + pp_element->pe_length);
						#elif _M_AMD64
							pathElementEnd = (LPVOID)((ULONGLONG)pp_element + pp_element->pe_length);
						#else
							#error unsupported architecture
						#endif

						pUnicodeData->out[outBufStart] = (WCHAR)'\\';
						outBufStart++;
						for(i = 0; (unsigned int)i < pp_element->pe_length / sizeof pp_element->pe_unichars[0] - 1 && outBufStart < sizeof pUnicodeData->out / sizeof pUnicodeData->out[0] - 1; i++)
						{
							pUnicodeData->out[outBufStart] = pp_element->pe_unichars[i];
							outBufStart++;
						}

						pp_element = (struct PathElement *)pathElementEnd;
					}
				}

				if(outBufStart < sizeof pUnicodeData->out / sizeof pUnicodeData->out[0])
				{
					pUnicodeData->out[outBufStart] = (WCHAR)'\0';
				}

				for(i = 0; i < sizeof pUnicodeData->outPath; i++)
				{
					((char *)(&pUnicodeData->outPath))[i] = '\0';
				}
				for(i = 0; i < sizeof pUnicodeData->outBuffer; i++)
				{
					((char *)(&pUnicodeData->outBuffer))[i] = '\0';
				}
			}
			else
			{
				pUnicodeData->error = TRUE;
			}
		}

		for(i = 0, porigir = (BYTE *)&ifsr, ppir = (BYTE *)origir; i < sizeof( ifsreq ); i++, porigir++, ppir++)
		{
			*porigir = *ppir;
		}

		ifsr.ifs_ir.ir_flags = ENUMH_GETFILENAME;
        ifsr.ifs_ir.ir_ppath = pOutPath;
		enumFunc = ifsr.ifs_pfn->fh_hf.hf_misc->hm_func[HM_ENUMHANDLE];

        if(!pUnicodeData->error && (*(*(*pOldFunc)))(enumFunc, IFSFN_ENUMHANDLE, 
                                    Drive, ResType, CodePage, 
                                        (pioreq) &ifsr) == 0)
		{
			pUnicodeData->Drive = Drive;
			pUnicodeData->ResType = ResType;
			pUnicodeData->CodePage = CodePage;

			outBufSize = MAX_PATH;

			if((ResType & IFSFH_RES_NETWORK) == 0 && Drive != 0xFFFFFFFF)
			{
				pUnicodeData->out[outBufStart] = Drive + (WCHAR)'A' - 1;
				outBufStart++;
				pUnicodeData->out[outBufStart] = (WCHAR)':';
				outBufStart++;
			}

			if(pOutPath)
			{
				/*for(i = 0; i < pOutPath->pp_totalLength && outBufStart < sizeof pUnicodeData->out / sizeof pUnicodeData->out[0] - 1; i++)
				{
					for(j = 0; j < pOutPath->pp_elements[i].pe_length && outBufStart < sizeof pUnicodeData->out / sizeof pUnicodeData->out[0] - 1; j++)
					{
						pUnicodeData->out[outBufStart] = pOutPath->pp_elements[i].pe_unichars[j];
						outBufStart++;
					}
				}*/
				/*for(j = 0; j < pOutPath->pp_elements[0].pe_length && outBufStart < sizeof pUnicodeData->out / sizeof pUnicodeData->out[0] - 1; j++)
				{
					pUnicodeData->out[outBufStart] = pOutPath->pp_elements[0].pe_unichars[j];
					outBufStart++;
				}*/
				pp_element = &pOutPath->pp_elements[0];
				#ifdef _M_IX86
					parsedPathEnd = (LPVOID)((DWORD)pOutPath + pOutPath->pp_totalLength);
				#elif _M_AMD64
					parsedPathEnd = (LPVOID)((ULONGLONG)pOutPath + pOutPath->pp_totalLength);
				#else
					#error unsupported architecture
				#endif
				while((LPVOID)pp_element < parsedPathEnd && outBufStart < sizeof pUnicodeData->out / sizeof pUnicodeData->out[0] - 1)
				{
					#ifdef _M_IX86
						pathElementEnd = (LPVOID)((DWORD)pp_element + pp_element->pe_length);
					#elif _M_AMD64
						pathElementEnd = (LPVOID)((ULONGLONG)pp_element + pp_element->pe_length);
					#else
						#error unsupported architecture
					#endif

					pUnicodeData->out[outBufStart] = (WCHAR)'\\';
					outBufStart++;
					for(i = 0; (unsigned int)i < pp_element->pe_length / sizeof pp_element->pe_unichars[0] - 1 && outBufStart < sizeof pUnicodeData->out / sizeof pUnicodeData->out[0] - 1; i++)
					{
						pUnicodeData->out[outBufStart] = pp_element->pe_unichars[i];
						outBufStart++;
					}

					pp_element = (struct PathElement *)pathElementEnd;
				}
			}

			*pCalled = 3;
		}
		else
		{
			pUnicodeData->error = TRUE;
		}
	}
	if(!*pCalled)
	{
		*pCalled = 1;

#if defined(_M_AMD64)
		#ifdef _MSC_VER
		_asm mov rax, pDataBuf
		_asm mov rsi, [rax]
		_asm mov rax, pHandleBuf
		_asm mov rbx, [rax]
		_asm mov rcx, 4
		_asm mov rdx, 0
		_asm mov rax, 0x0D602
		#else
		__asm__ volatile (
			"movq %0, %%rax\n\t"
			"movq (%%rax), %%rsi\n\t"
			"movq %1, %%rax\n\t"
			"movq (%%rax), %%rbx\n\t"
			"movq $4, %%rcx\n\t"
			"movq $0, %%rdx\n\t"
			"movq $0x0D602, %%rax\n\t"
			: : "m"(pDataBuf), "m"(pHandleBuf)
		);
		#endif
#elif defined(_M_IX86)
		#ifdef _MSC_VER
		_asm mov eax, pDataBuf
		_asm mov esi, [eax]
		_asm mov eax, pHandleBuf
		_asm mov ebx, [eax]
		_asm mov ecx, 4
		_asm mov edx, 0
		_asm mov eax, 0x0D602
		#else
		__asm__ volatile (
			"movl %0, %%eax\n\t"
			"movl (%%eax), %%esi\n\t"
			"movl %1, %%eax\n\t"
			"movl (%%eax), %%ebx\n\t"
			"movl $4, %%ecx\n\t"
			"movl $0, %%edx\n\t"
			"movl $0x0D602, %%eax\n\t"
			: : "m"(pDataBuf), "m"(pHandleBuf)
		);
		#endif
#else
#error unsupported architecture
#endif
		
		VxDCall(0x00400032);
	}

	return ret;
	//return 0;
}

static DWORD _cdecl getPathUnicodeEnd()
{
    return 0;
}

#pragma warning(disable : 4101)
static int	_cdecl getPathUnicodeOffsets( pIFSFunc pfn, int fn, int Drive, int ResType, int CodePage, pioreq pir )
{
	PGetPathUnicodeData pUnicodeData;
	ppIFSFileHookFunc *pOldFunc;
	PBOOL pCalled;
	LPVOID *pHandleBuf;
	DWORD ret;
	BYTE (*pDataBuf)[4];
	WCHAR (*pOut)[MAX_PATH + 3];
	path_t pOutPath;
	ifsreq origifsr;
	pioreq origir;
	pIFSFunc        enumFunc;
    ifsreq          ifsr;
	int i;
	//int j;
	BYTE *porigir;
	BYTE *ppir;
	DWORD outBufSize;
	DWORD outBufStart;
	struct PathElement *pp_element;
	LPVOID parsedPathEnd;

#if defined(_M_AMD64)
	#if _MSC_VER
ldPData:
	_asm mov rax, 0x00000000
	_asm mov pUnicodeData, rax

	_asm mov rax, offset ldPData
	_asm mov offLdPData, rax
	#else
	__asm__ volatile (
		"lpPData:\n\t"
		"movq $0x00000000, %%rax\n\t"
		"movq %%rax, %0\n\t"

		"movq $lpPData, %%rax\n\t"
		"movq %%rax, %1\n\t"
		: "=m"(pUnicodeData), "=m"(offLdPData)
	);
	#endif
#elif defined(_M_IX86)
	#if _MSC_VER
ldPData:
	_asm mov eax, 0x00000000
	_asm mov pUnicodeData, eax

	_asm mov eax, offset ldPData
	_asm mov offLdPData, eax
	#else
	__asm__ volatile (
		"lpPData:\n\t"
		"movl $0x00000000, %%eax\n\t"
		"movl %%eax, %0\n\t"

		"movl $lpPData, %%eax\n\t"
		"movl %%eax, %1\n\t"
		: "=m"(pUnicodeData), "=m"(offLdPData)
	);
	#endif
#else
#error unsupported architecture
#endif

	#ifdef _M_IX86
		offLdPData -= (DWORD)getPathUnicodeOffsets;
	#elif _M_AMD64
		offLdPData -= (ULONGLONG)getPathUnicodeOffsets;
	#else
		#error unsupported architecture
	#endif

	return 0;
}
#pragma warning(default : 4101)

static PDWORD ring0ExtendedHandleToInfoPHandle;
static LPVOID ring0FileIOBuf = NULL;

#if _MSC_VER
NAKED void WINAPI ring0InstallIFSHookAscii(void)
#elif (__GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1))
INTERRUPT void WINAPI ring0InstallIFSHookAscii(struct interrupt_frame *frame)
#else
void WINAPI ring0InstallIFSHookAscii(void)
#endif
{
#if defined(_M_AMD64)
	#ifdef _MSC_VER
	_asm push rax
	_asm push rcx
	_asm push rdx
	_asm push rbx
	_asm push rbp
	_asm push rsi
	_asm push rdi
	#elif __GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1)
	#else
	__asm__ volatile (
		"pushq %rax\n\t"
		"pushq %rcx\n\t"
		"pushq %rdx\n\t"
		"pushq %rbx\n\t"
		"pushq %rbp\n\t"
		"pushq %rsi\n\t"
		"pushq %rdi\n\t"
	);
	#endif
#elif defined(_M_IX86)
	#ifdef _MSC_VER
	_asm pushad
	#elif __GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1)
	#else
	__asm__("pushal\n\t");
	#endif
#else
#error unsupported architecture
#endif

	#ifdef _M_IX86
		sizeofGetPathAscii = (DWORD)getPathAsciiEnd - (DWORD)getPathAscii;
	#elif _M_AMD64
		sizeofGetPathAscii = (ULONGLONG)getPathAsciiEnd - (ULONGLONG)getPathAscii;
	#else
		#error unsupported architecture
	#endif

	//fileSystemApiHandle = (LPVOID)GlobalAlloc(GPTR, sizeofGetPathAscii);
	//page = PageAllocate(22, PG_SYS, 0, 0, 0, 0xFFFFFFFF, &memBlock, PAGEZEROINIT | PAGEUSEALIGN  | PAGECONTIG | PAGEFIXED);

	#ifdef _M_IX86
		memBlock = IFSMgr_GetHeap(4 * ((sizeofGetPathAscii + 3) / 4) + sizeof (GetPathAsciiData));
	#elif _M_AMD64
		memBlock = IFSMgr_GetHeap(8 * ((sizeofGetPathAscii + 7) / 8) + sizeof (GetPathAsciiData));
	#else
		#error unsupported architecture
	#endif

	if(memBlock == NULL)
	{
		pData->oldFunc = NULL;
	}
	else
	{
		memcpy((char *)memBlock, (char *)getPathAscii, sizeofGetPathAscii);
		getPathAsciiOffsets(NULL, 0, 0, 0, 0, NULL);
		offLdPData++;
		#ifdef _M_IX86
			*(DWORD *)((DWORD)memBlock + offLdPData) = (DWORD)memBlock + (4 * ((sizeofGetPathAscii + 3) / 4));
		#elif _M_AMD64
			*(ULONGLONG *)((ULONGLONG)memBlock + offLdPData) = (ULONGLONG)memBlock + (8 * ((sizeofGetPathAscii + 7) / 8));
		#else
			#error unsupported architecture
		#endif
		#ifdef _M_IX86
			pData = (PGetPathAsciiData)((DWORD)memBlock + (4 * ((sizeofGetPathAscii + 3) / 4)));
		#elif _M_AMD64
			pData = (PGetPathAsciiData)((ULONGLONG)memBlock + (8 * ((sizeofGetPathAscii + 7) / 8)));
		#else
			#error unsupported architecture
		#endif
		pData->called = FALSE;
		pData->error = FALSE;
		pData->handleBuf = fileSystemApiHandle;

		#if _MSC_VER
		_asm jmp short $+2
		#else
		__asm__ volatile(
			"jmp rel1\n\t"
			"rel1:\n\t"
		);
		#endif

		pData->oldFunc = (ppIFSFileHookFunc)IFSMgr_InstallFileSystemApiHook((pIFSFileHookFunc)memBlock);
	}

#if defined(_M_AMD64)
	#if _MSC_VER
	_asm pop rdi
	_asm pop rsi
	_asm pop rbp
	_asm pop rbx
	_asm pop rdx
	_asm pop rcx
	_asm pop rax
	_asm iretd
	#elif __GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1)
	#else
	__asm__ volatile(
		"popq %rdi\n\t"
		"popq %rsi\n\t"
		"popq %rbp\n\t"
		"popq %rbx\n\t"
		"popq %rdx\n\t"
		"popq %rcx\n\t"
		"popq %rax\n\t"
		"add $0x24, %rsp\n\t"
		"pop %rbx\n\t"
		"pop %rbp\n\t"
		"iret\n\t"
	);
	#endif
#elif defined(_M_IX86)
	#if _MSC_VER
	_asm popad
	_asm iretd
	#elif __GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1)
	#else
	__asm__ volatile(
		"popal\n\t"
		"add $0x24, %esp\n\t"
		"pop %ebx\n\t"
		"pop %ebp\n\t"
		"iret\n\t"
	);
	#endif
#else
#error unsupported architecture
#endif
}

#if _MSC_VER
NAKED void WINAPI ring0UninstallIFSFileHookAscii(void)
#elif (__GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1))
INTERRUPT void WINAPI ring0UninstallIFSFileHookAscii(struct interrupt_frame *frame)
#else
void WINAPI ring0UninstallIFSFileHookAscii(void)
#endif
{
#if defined(_M_AMD64)
	#ifdef _MSC_VER
	_asm push rax
	_asm push rcx
	_asm push rdx
	_asm push rbx
	_asm push rbp
	_asm push rsi
	_asm push rdi
	#elif __GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1)
	#else
	__asm__ volatile (
		"pushq %rax\n\t"
		"pushq %rcx\n\t"
		"pushq %rdx\n\t"
		"pushq %rbx\n\t"
		"pushq %rbp\n\t"
		"pushq %rsi\n\t"
		"pushq %rdi\n\t"
	);
	#endif
#elif defined(_M_IX86)
	#ifdef _MSC_VER
	_asm pushad
	#elif __GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1)
	#else
	__asm__("pushal\n\t");
	#endif
#else
#error unsupported architecture
#endif

	if(pData->oldFunc && memBlock)
	{
		IFSMgr_RemoveFileSystemApiHook((pIFSFileHookFunc)memBlock);
	}

	if(memBlock)
	{
		IFSMgr_RetHeap(memBlock);
	}

#if defined(_M_AMD64)
	#if _MSC_VER
	_asm pop rdi
	_asm pop rsi
	_asm pop rbp
	_asm pop rbx
	_asm pop rdx
	_asm pop rcx
	_asm pop rax
	_asm iretd
	#elif __GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1)
	#else
	__asm__ volatile(
		"popq %rdi\n\t"
		"popq %rsi\n\t"
		"popq %rbp\n\t"
		"popq %rbx\n\t"
		"popq %rdx\n\t"
		"popq %rcx\n\t"
		"popq %rax\n\t"
		"add $0x4, %rsp\n\t"
		"pop %rbp\n\t"
		"iret\n\t"
	);
	#endif
#elif defined(_M_IX86)
	#if _MSC_VER
	_asm popad
	_asm iretd
	#elif __GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1)
	#else
	__asm__ volatile(
		"popal\n\t"
		"add $0x4, %esp\n\t"
		"pop %ebp\n\t"
		"iret\n\t"
	);
	#endif
#else
#error unsupported architecture
#endif
}

#if _MSC_VER
NAKED void WINAPI ring0InstallIFSHookUnicode(void)
#elif (__GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1))
INTERRUPT void WINAPI ring0InstallIFSHookUnicode(struct interrupt_frame *frame)
#else
void WINAPI ring0InstallIFSHookUnicode(void)
#endif
{
#if defined(_M_AMD64)
	#ifdef _MSC_VER
	_asm push rax
	_asm push rcx
	_asm push rdx
	_asm push rbx
	_asm push rbp
	_asm push rsi
	_asm push rdi
	#elif __GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1)
	#else
	__asm__ volatile (
		"pushq %rax\n\t"
		"pushq %rcx\n\t"
		"pushq %rdx\n\t"
		"pushq %rbx\n\t"
		"pushq %rbp\n\t"
		"pushq %rsi\n\t"
		"pushq %rdi\n\t"
	);
	#endif
#elif defined(_M_IX86)
	#ifdef _MSC_VER
	_asm pushad
	#elif __GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1)
	#else
	__asm__("pushal\n\t");
	#endif
#else
#error unsupported architecture
#endif

	#ifdef _M_IX86
		sizeofGetPathUnicode = (DWORD)getPathUnicodeEnd - (DWORD)getPathUnicode;
	#elif _M_AMD64
		sizeofGetPathUnicode = (ULONGLONG)getPathUnicodeEnd - (ULONGLONG)getPathUnicode;
	#else
		#error unsupported architecture
	#endif

	//fileSystemApiHandle = (LPVOID)GlobalAlloc(GPTR, sizeofGetPathAscii);
	//page = PageAllocate(22, PG_SYS, 0, 0, 0, 0xFFFFFFFF, &memBlock, PAGEZEROINIT | PAGEUSEALIGN  | PAGECONTIG | PAGEFIXED);

	#ifdef _M_IX86
		memBlock = IFSMgr_GetHeap(4 * ((sizeofGetPathUnicode + 3) / 4) + sizeof (GetPathUnicodeData));
	#elif _M_AMD64
		memBlock = IFSMgr_GetHeap(8 * ((sizeofGetPathUnicode + 7) / 8) + sizeof (GetPathUnicodeData));
	#else
		#error unsupported architecture
	#endif
	

	if(memBlock == NULL)
	{
		pUnicodeData->oldFunc = NULL;
	}
	else
	{
		memcpy((char *)memBlock, (char *)getPathUnicode, sizeofGetPathUnicode);
		getPathUnicodeOffsets(NULL, 0, 0, 0, 0, NULL);
		offLdPData++;
		#ifdef _M_IX86
			*(DWORD *)((DWORD)memBlock + offLdPData) = (DWORD)memBlock + (4 * ((sizeofGetPathUnicode + 3) / 4));
		#elif _M_AMD64
			*(DWORD *)((ULONGLONG)memBlock + offLdPData) = (ULONGLONG)memBlock + (8 * ((sizeofGetPathUnicode + 7) / 8));
		#else
			#error unsupported architecture
		#endif
		#ifdef _M_IX86
			pUnicodeData = (PGetPathUnicodeData)((DWORD)memBlock + (4 * ((sizeofGetPathUnicode + 3) / 4)));
		#elif _M_AMD64
			pUnicodeData = (PGetPathUnicodeData)((ULONGLONG)memBlock + (8 * ((sizeofGetPathUnicode + 7) / 8)));
		#else
			#error unsupported architecture
		#endif
		pUnicodeData->called = FALSE;
		pUnicodeData->error = FALSE;
		pUnicodeData->handleBuf = fileSystemApiHandle;

		#if _MSC_VER
		_asm jmp short $+2
		#else
		__asm__ volatile(
			"jmp rel2\n\t"
			"rel2:\n\t"
		);
		#endif

		pUnicodeData->oldFunc = (ppIFSFileHookFunc)IFSMgr_InstallFileSystemApiHook((pIFSFileHookFunc)memBlock);
	}

#if defined(_M_AMD64)
	#if _MSC_VER
	_asm pop rdi
	_asm pop rsi
	_asm pop rbp
	_asm pop rbx
	_asm pop rdx
	_asm pop rcx
	_asm pop rax
	_asm iretd
	#elif __GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1)
	#else
	__asm__ volatile (
		"popq %rdi\n\t"
		"popq %rsi\n\t"
		"popq %rbp\n\t"
		"popq %rbx\n\t"
		"popq %rdx\n\t"
		"popq %rcx\n\t"
		"popq %rax\n\t"
		"add $0x24, %rsp\n\t"
		"pop %rbx\n\t"
		"pop %rbp\n\t"
		"iret\n\t"
	);
	#endif
#elif defined(_M_IX86)
	#if _MSC_VER
	_asm popad
	_asm iretd
	#elif __GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1)
	#else
	__asm__ volatile (
		"popal\n\t"
		"add $0x24, %esp\n\t"
		"pop %ebx\n\t"
		"pop %ebp\n\t"
		"iret\n\t"
	);
	#endif
#else
#error unsupported architecture
#endif
}

#if _MSC_VER
NAKED void WINAPI ring0UninstallIFSFileHookUnicode(void)
#elif (__GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1))
INTERRUPT void WINAPI ring0UninstallIFSFileHookUnicode(struct interrupt_frame *frame)
#else
void WINAPI ring0UninstallIFSFileHookUnicode(void)
#endif
{
#if defined(_M_AMD64)
	#ifdef _MSC_VER
	_asm push rax
	_asm push rcx
	_asm push rdx
	_asm push rbx
	_asm push rbp
	_asm push rsi
	_asm push rdi
	#elif __GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1)
	#else
	__asm__ volatile (
		"pushq %rax\n\t"
		"pushq %rcx\n\t"
		"pushq %rdx\n\t"
		"pushq %rbx\n\t"
		"pushq %rbp\n\t"
		"pushq %rsi\n\t"
		"pushq %rdi\n\t"
	);
	#endif
#elif defined(_M_IX86)
	#ifdef _MSC_VER
	_asm pushad
	#elif __GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1)
	#else
	__asm__("pushal\n\t");
	#endif
#else
#error unsupported architecture
#endif

	if(pUnicodeData->oldFunc && memBlock)
	{
		IFSMgr_RemoveFileSystemApiHook((pIFSFileHookFunc)memBlock);
	}

	if(memBlock)
	{
		IFSMgr_RetHeap(memBlock);
	}

#if defined(_M_AMD64)
	#if _MSC_VER
	_asm pop rdi
	_asm pop rsi
	_asm pop rbp
	_asm pop rbx
	_asm pop rdx
	_asm pop rcx
	_asm pop rax
	_asm iretd
	#elif (__GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1))
	#else
	__asm__(
		"popq %rdi\n\t"
		"popq %rsi\n\t"
		"popq %rbp\n\t"
		"popq %rbx\n\t"
		"popq %rdx\n\t"
		"popq %rcx\n\t"
		"popq %rax\n\t"
		"add $0x4, %rsp\n\t"
		"pop %rbp\n\t"
		"iret\n\t"
	);
	#endif
#elif defined(_M_IX86)
	#if _MSC_VER
	_asm popad
	_asm iretd
	#elif (__GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1))
	#else
	__asm__(
		"popal\n\t"
		"add $0x4, %esp\n\t"
		"pop %ebp\n\t"
		"iret\n\t"
	);
	#endif
#else
#error unsupported architecture
#endif
}

#if _MSC_VER
static NAKED void WINAPI getRing0HandleHook(void)
#elif (__GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1))
static INTERRUPT void WINAPI getRing0HandleHook(struct interrupt_frame *frame)
#else
static void WINAPI getRing0HandleHook(void)
#endif
{
#if defined(_M_AMD64)
	#ifdef _MSC_VER
	_asm push rax
	_asm push rcx
	_asm push rdx
	_asm push rbx
	_asm push rbp
	_asm push rsi
	_asm push rdi
	#elif __GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1)
	#else
	__asm__ volatile (
		"pushq %rax\n\t"
		"pushq %rcx\n\t"
		"pushq %rdx\n\t"
		"pushq %rbx\n\t"
		"pushq %rbp\n\t"
		"pushq %rsi\n\t"
		"pushq %rdi\n\t"
	);
	#endif
#elif defined(_M_IX86)
	#ifdef _MSC_VER
	_asm pushad
	#elif __GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1)
	#else
	__asm__("pushal\n\t");
	#endif
#else
#error unsupported architecture
#endif

	*getRing0HandleHookRet = IFSMgr_Win32_Get_Ring0_Handle(*getRing0HandleHookExtendedFileHandle, getRing0HandleHookpHandleBuf, getRing0HandleHookpFilePos);

#if defined(_M_AMD64)
	#if _MSC_VER
	_asm pop rdi
	_asm pop rsi
	_asm pop rbp
	_asm pop rbx
	_asm pop rdx
	_asm pop rcx
	_asm pop rax
	_asm iretd
	#elif (__GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1))
	#else
	__asm__(
		"popq %rdi\n\t"
		"popq %rsi\n\t"
		"popq %rbp\n\t"
		"popq %rbx\n\t"
		"popq %rdx\n\t"
		"popq %rcx\n\t"
		"popq %rax\n\t"
		"add $0xc, %rsp\n\t"
		"pop %rbx\n\t"
		"pop %rbp\n\t"
		"iret\n\t"
	);
	#endif
#elif defined(_M_IX86)
	#if _MSC_VER
	_asm popad
	_asm iretd
	#elif (__GNUC__ > 7 || (__GNUC__  == 7 && __GNUC_MINOR__ >= 1))
	#else
	__asm__(
		"popal\n\t"
		"add $0xc, %esp\n\t"
		"pop %ebx\n\t"
		"pop %ebp\n\t"
		"iret\n\t"
	);
	#endif
#else
#error unsupported architecture
#endif
}
#if defined _MSC_VER
#ifdef _DEBUG
#pragma optimize("", off)
#else
#pragma optimize("", on)
#endif
#else
#pragma GCC pop_options
#endif

class GetWindowsFchmodFuncs
{
	private: 
		static int numInstances;
		static HMODULE hKernel32;
		static HMODULE hNtDll;
		static HMODULE hPsapi;
		static FARPROC fpGetFinalPathNameByHandleA;
		static FARPROC fpGetFinalPathNameByHandleW;
		static FARPROC fpGetFinalPathNameByHandleT;
		static FARPROC fpGetMappedFileNameA;
		static FARPROC fpGetMappedFileNameW;
		static FARPROC fpGetMappedFileNameT;
		static FARPROC fpNtQueryObject;
		static FARPROC fpGetVersion;
		static FARPROC fpGetVersionEx;
		static FARPROC fpRtlGetVersion;
		static BOOL zIsNt;
		static BOOL zIsWin32s;
		static DWORD majorVersion;
		static DWORD minorVersion;
		static DWORD build;
		static DWORD platformId;
		static BOOL OSWin9x;
		static BOOL OSWin95;
		static BOOL OSWin98;
		static BOOL OSWinME;
		static CRITICAL_SECTION csgetRing0Handle;
		static CRITICAL_SECTION csring0ExtendedHandleToPath;
		#ifdef _M_IX86
		static DWORD obsfucator;
		#elif _M_AMD64
		static ULONGLONG obsfucator;
		#else
			#error unsupported architecture
		#endif
		static PTIB pTib;
		static PTHREAD_DATABASE pTdb;
		static PPROCESS_DATABASE pPdb;

		static BOOL ring0ExtendedHandleToPathAscii(LPVOID handleBuf, BYTE *buf, size_t bufSize)
		{
			#ifdef _M_IX86
				DWORD idt;
			#elif _M_AMD64
				ULONGLONG idt;
			#else
				#error unsupported architecture
			#endif
			DWORD oldInt5;
			void *newInt5;
			BOOL success = FALSE;

			if(buf == NULL || handleBuf == NULL)
			{
				return FALSE;
			}

			sizeofGetPathAscii = (size_t)getPathAsciiEnd - (size_t)getPathAscii;

			EnterCriticalSection(&csring0ExtendedHandleToPath);
			#ifdef _M_IX86
				idt = (DWORD)getIDT();
			#elif _M_AMD64
				idt = (ULONGLONG)getIDT();
			#else
				#error unsupported architecture
			#endif

			#ifdef _M_IX86
				idt += (Interrupt*8)+4; /* reads a vector of the required interrupt (INT 5h) */
			#elif _M_AMD64
				idt += (Interrupt*16)+4; /* reads a vector of the required interrupt (INT 5h) */
			#else
				#error unsupported architecture
			#endif

			#ifdef _M_IX86
				oldInt5 = MAKEDWORD(*(WORD *)(idt - 4), *(WORD *)(idt + 2));/* reads an address of the old service of the required interrupt (INT 5h) */
			#elif _M_AMD64
				oldInt5 = MAKEDWORD64(*(WORD *)(idt - 4), *(WORD *)(idt + 2), *(DWORD *)(idt + 4));/* reads an address of the old service of the required interrupt (INT 5h) */
			#else
				#error unsupported architecture
			#endif

			newInt5 = (void *)ring0InstallIFSHookAscii;
			#ifdef _M_IX86
				*(WORD *)(idt - 4) = LOWORD((DWORD)newInt5);
				*(WORD *)(idt + 2) = HIWORD((DWORD)newInt5);
			#elif _M_AMD64
				*(WORD *)(idt - 4) = LOWORD(LODWORD((ULONGLONG)newInt5));
				*(WORD *)(idt + 2) = HIWORD(LODWORD((ULONGLONG)newInt5));
				*(DWORD *)(idt + 4) = HIDWORD((ULONGLONG)newInt5);
			#else
				#error unsupported architecture
			#endif

			fileSystemApiHandle = handleBuf;

			/* jump into Ring0 (the newly defined service INT 5h) */
			#if _MSC_VER
			_asm int Interrupt

			_asm nop
			#else
			__asm__ volatile(
				"int $" VxDStringify(Interrupt) "\n\t"

				"nop\n\t"
			);
			#endif

			if(!pData->oldFunc)
			{
				success = FALSE;
			}
			else
			{
				HANDLE fnul = INVALID_HANDLE_VALUE;
				if(pData->called < 1)
				{
					fnul = CreateFile(TEXT("NUL"), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL); // force file callback to be called in case it hasn't already.
				}
				while(pData->called < 3 && pData->error == FALSE)
				{
				}
				success = (pData->called >= 3 && pData->error == FALSE);
				if(success)
				{
					strncpy((char *)buf, (const char *)(pData->out), bufSize - 2);
					buf[bufSize - 1] = '\0';
				}
				if(fnul != INVALID_HANDLE_VALUE)
				{
					CloseHandle(fnul); // close our extra handle...
				}
			}

			newInt5 = (void *)ring0UninstallIFSFileHookAscii;
			#ifdef _M_IX86
				*(WORD *)(idt - 4) = LOWORD((DWORD)newInt5);
				*(WORD *)(idt + 2) = HIWORD((DWORD)newInt5);
			#elif _M_AMD64
				*(WORD *)(idt - 4) = LOWORD(LODWORD((ULONGLONG)newInt5));
				*(WORD *)(idt + 2) = HIWORD(LODWORD((ULONGLONG)newInt5));
				*(DWORD *)(idt + 4) = HIDWORD((ULONGLONG)newInt5);
			#else
				#error unsupported architecture
			#endif

			/* jump into Ring0 (the newly defined service INT 5h) */
			#if _MSC_VER
			_asm int Interrupt

			_asm nop
			#else
			__asm__ volatile(
				"int $" VxDStringify(Interrupt) "\n\t"

				"nop\n\t"
			);
			#endif

			/* restores int 5h */
			#ifdef _M_IX86
				*(WORD *)(idt - 4) = LOWORD((DWORD)oldInt5);
				*(WORD *)(idt + 2) = HIWORD((DWORD)oldInt5);
			#elif _M_AMD64
				*(WORD *)(idt - 4) = LOWORD(LODWORD((ULONGLONG)oldInt5));
				*(WORD *)(idt + 2) = HIWORD(LODWORD((ULONGLONG)oldInt5));
				*(DWORD *)(idt + 4) = HIDWORD((ULONGLONG)oldInt5);
			#else
				#error unsupported architecture
			#endif

			LeaveCriticalSection(&csring0ExtendedHandleToPath);

			return success;
		}

		static BOOL ring0ExtendedHandleToPathUnicode(LPVOID handleBuf, WCHAR *buf, size_t bufSize)
		{
			#ifdef _M_IX86
				DWORD idt;
			#elif _M_AMD64
				ULONGLONG idt;
			#else
				#error unsupported architecture
			#endif
			DWORD oldInt5;
			void *newInt5;
			BOOL success = FALSE;

			if(buf == NULL || handleBuf == NULL)
			{
				return FALSE;
			}

			sizeofGetPathUnicode = (size_t)getPathUnicodeEnd - (size_t)getPathUnicode;

			EnterCriticalSection(&csring0ExtendedHandleToPath);
			#ifdef _M_IX86
				idt = (DWORD)getIDT();
			#elif _M_AMD64
				idt = (ULONGLONG)getIDT();
			#else
				#error unsupported architecture
			#endif

			#ifdef _M_IX86
				idt += (Interrupt*8)+4; /* reads a vector of the required interrupt (INT 5h) */
			#elif _M_AMD64
				idt += (Interrupt*16)+4; /* reads a vector of the required interrupt (INT 5h) */
			#else
				#error unsupported architecture
			#endif

			#ifdef _M_IX86
				oldInt5 = MAKEDWORD(*(WORD *)(idt - 4), *(WORD *)(idt + 2));/* reads an address of the old service of the required interrupt (INT 5h) */
			#elif _M_AMD64
				oldInt5 = MAKEDWORD64(*(WORD *)(idt - 4), *(WORD *)(idt + 2), *(DWORD *)(idt + 4));/* reads an address of the old service of the required interrupt (INT 5h) */
			#else
				#error unsupported architecture
			#endif

			newInt5 = (void *)ring0InstallIFSHookUnicode;
			#ifdef _M_IX86
				*(WORD *)(idt - 4) = LOWORD((DWORD)newInt5);
				*(WORD *)(idt + 2) = HIWORD((DWORD)newInt5);
			#elif _M_AMD64
				*(WORD *)(idt - 4) = LOWORD(LODWORD((ULONGLONG)newInt5));
				*(WORD *)(idt + 2) = HIWORD(LODWORD((ULONGLONG)newInt5));
				*(DWORD *)(idt + 4) = HIDWORD((ULONGLONG)newInt5);
			#else
				#error unsupported architecture
			#endif

			fileSystemApiHandle = handleBuf;

			/* jump into Ring0 (the newly defined service INT 5h) */
			#if _MSC_VER
			_asm int Interrupt

			_asm nop
			#else
			__asm__ volatile(
				"int $" VxDStringify(Interrupt) "\n\t"

				"nop\n\t"
			);
			#endif

			if(!pUnicodeData->oldFunc)
			{
				success = FALSE;
			}
			else
			{
				HANDLE fnul = INVALID_HANDLE_VALUE;
				if(pUnicodeData->called < 1)
				{
					fnul = CreateFile(TEXT("NUL"), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL); // force file callback to be called in case it hasn't already.
				}
				while(pUnicodeData->called < 3 && pUnicodeData->error == FALSE)
				{
				}
				success = (pUnicodeData->called >= 3 && pUnicodeData->error == FALSE);
				if(success)
				{
					wcsncpy((WCHAR *)buf, (const WCHAR *)(pUnicodeData->out), bufSize - 2);
					buf[bufSize - 1] = (WCHAR)'\0';
				}
				if(fnul != INVALID_HANDLE_VALUE)
				{
					CloseHandle(fnul); // close our extra handle...
				}
			}

			newInt5 = (void *)ring0UninstallIFSFileHookUnicode;
			#ifdef _M_IX86
				*(WORD *)(idt - 4) = LOWORD((DWORD)newInt5);
				*(WORD *)(idt + 2) = HIWORD((DWORD)newInt5);
			#elif _M_AMD64
				*(WORD *)(idt - 4) = LOWORD(LODWORD((ULONGLONG)newInt5));
				*(WORD *)(idt + 2) = HIWORD(LODWORD((ULONGLONG)newInt5));
				*(DWORD *)(idt + 4) = HIDWORD((ULONGLONG)newInt5);
			#else
				#error unsupported architecture
			#endif

			/* jump into Ring0 (the newly defined service INT 5h) */
			#if _MSC_VER
			_asm int Interrupt

			_asm nop
			#else
			__asm__ volatile(
				"int $" VxDStringify(Interrupt) "\n\t"

				"nop\n\t"
			);
			#endif

			/* restores int 5h */
			#ifdef _M_IX86
				*(WORD *)(idt - 4) = LOWORD((DWORD)oldInt5);
				*(WORD *)(idt + 2) = HIWORD((DWORD)oldInt5);
			#elif _M_AMD64
				*(WORD *)(idt - 4) = LOWORD(LODWORD((ULONGLONG)oldInt5));
				*(WORD *)(idt + 2) = HIWORD(LODWORD((ULONGLONG)oldInt5));
				*(DWORD *)(idt + 4) = HIDWORD((ULONGLONG)oldInt5);
			#else
				#error unsupported architecture
			#endif

			LeaveCriticalSection(&csring0ExtendedHandleToPath);

			return success;
		}

		static BOOL getRing0Handle(DWORD extendedFileHandle, PVOID *pHandleBuf, PDWORD pFilePos)
		{
			#ifdef _M_IX86
				DWORD idt;
			#elif _M_AMD64
				ULONGLONG idt;
			#else
				#error unsupported architecture
			#endif
			DWORD oldInt5;
			void *newInt5;
			BOOL success = FALSE;

			if(pHandleBuf == NULL || pFilePos == NULL || extendedFileHandle < 0x200)
			{
				return FALSE;
			}

			EnterCriticalSection(&csgetRing0Handle);

			getRing0HandleHookRet = &success;
			getRing0HandleHookExtendedFileHandle = &extendedFileHandle;
			getRing0HandleHookpHandleBuf = pHandleBuf;
			getRing0HandleHookpFilePos = pFilePos;

			#ifdef _M_IX86
				idt = (DWORD)getIDT();
			#elif _M_AMD64
				idt = (ULONGLONG)getIDT();
			#else
				#error unsupported architecture
			#endif

			#ifdef _M_IX86
				idt += (Interrupt*8)+4; /* reads a vector of the required interrupt (INT 5h) */
			#elif _M_AMD64
				idt += (Interrupt*16)+4; /* reads a vector of the required interrupt (INT 5h) */
			#else
				#error unsupported architecture
			#endif

			#ifdef _M_IX86
				oldInt5 = MAKEDWORD(*(WORD *)(idt - 4), *(WORD *)(idt + 2));/* reads an address of the old service of the required interrupt (INT 5h) */
			#elif _M_AMD64
				oldInt5 = MAKEDWORD64(*(WORD *)(idt - 4), *(WORD *)(idt + 2), *(DWORD *)(idt + 4));/* reads an address of the old service of the required interrupt (INT 5h) */
			#else
				#error unsupported architecture
			#endif

			newInt5 = (void *)getRing0HandleHook;
			#ifdef _M_IX86
				*(WORD *)(idt - 4) = LOWORD((DWORD)newInt5);
				*(WORD *)(idt + 2) = HIWORD((DWORD)newInt5);
			#elif _M_AMD64
				*(WORD *)(idt - 4) = LOWORD(LODWORD((ULONGLONG)newInt5));
				*(WORD *)(idt + 2) = HIWORD(LODWORD((ULONGLONG)newInt5));
				*(DWORD *)(idt + 4) = HIDWORD((ULONGLONG)newInt5);
			#else
				#error unsupported architecture
			#endif

			// jump into Ring0 (the newly defined service INT 5h)
			#if _MSC_VER
			_asm int Interrupt

			_asm nop
			#else
			__asm__ volatile(
				"int $" VxDStringify(Interrupt) "\n\t"

				"nop\n\t"
			);
			#endif

			// restores int 5h
			#ifdef _M_IX86
				*(WORD *)(idt - 4) = LOWORD((DWORD)oldInt5);
				*(WORD *)(idt + 2) = HIWORD((DWORD)oldInt5);
			#elif _M_AMD64
				*(WORD *)(idt - 4) = LOWORD(LODWORD((ULONGLONG)oldInt5));
				*(WORD *)(idt + 2) = HIWORD(LODWORD((ULONGLONG)oldInt5));
				*(DWORD *)(idt + 4) = HIDWORD((ULONGLONG)oldInt5);
			#else
				#error unsupported architecture
			#endif

			LeaveCriticalSection(&csgetRing0Handle);

			return success;
		}

		static PK32OBJBASE Win32HandleToK32Object(HANDLE fh)
		{
			PK32OBJBASE ret = NULL;
			#ifdef _M_IX86
			DWORD idx = (DWORD)fh;
			#elif _M_AMD64
			ULONGLONG idx = (ULONGLONG)fh;
			#else
				#error unsupported architecture
			#endif

			if(fh && fh != INVALID_HANDLE_VALUE)
			{
				if(OSWin98 || OSWinME)
				{
					idx /= 4;
				}

				if(OSWinME)
				{
					ret = (PK32OBJBASE)(pPdb->pdbME.pHandleTable->array[idx].pObject);
				}
				else if(OSWin98)
				{
					ret = (PK32OBJBASE)(pPdb->pdb98.pHandleTable->array[idx].pObject);
				}
				else if(OSWin95)
				{
					ret = (PK32OBJBASE)(pPdb->pdb95.pHandleTable->array[idx].pObject);
				}
			}

			return ret;
		}

		static DWORD getExtendedFileHandle(PK32OBJBASE obj)
		{
			DWORD ret = 0;

			if(obj != NULL)
			{
				if(OSWinME)
				{
					if(obj->kobjME.header.dwType == WINME_K32OBJ_FILE)
					{
						ret = ((PK32OBJ_FILE_OBJECT_ME)obj)->hExtendedFileHandle;
					}
				}
				else if(OSWin98)
				{
					if(obj->kobj98.header.dwType == WIN98_K32OBJ_FILE)
					{
						ret = ((PK32OBJ_FILE_OBJECT_98)obj)->hExtendedFileHandle;
					}
				}
				else if(OSWin95)
				{
					if(obj->kobj95.header.dwType == WIN95_K32OBJ_FILE)
					{
						ret = ((PK32OBJ_FILE_OBJECT_95)obj)->hExtendedFileHandle;
					}
				}
			}

			return ret;
		}

	// converts
	// "\Device\HarddiskVolume3"                                -> "E:"
	// "\Device\HarddiskVolume3\Temp"                           -> "E:\Temp"
	// "\Device\HarddiskVolume3\Temp\transparent.jpeg"          -> "E:\Temp\transparent.jpeg"
	// "\Device\Harddisk1\DP(1)0-0+6\foto.jpg"                  -> "I:\foto.jpg"
	// "\Device\TrueCryptVolumeP\Data\Passwords.txt"            -> "P:\Data\Passwords.txt"
	// "\Device\Floppy0\Autoexec.bat"                           -> "A:\Autoexec.bat"
	// "\Device\CdRom1\VIDEO_TS\VTS_01_0.VOB"                   -> "H:\VIDEO_TS\VTS_01_0.VOB"
	// "\Device\Serial1"                                        -> "COM1"
	// "\Device\USBSER000"                                      -> "COM4"
	// "\Device\Mup\ComputerName\C$\Boot.ini"                   -> "\\ComputerName\C$\Boot.ini"
	// "\Device\LanmanRedirector\ComputerName\C$\Boot.ini"      -> "\\ComputerName\C$\Boot.ini"
	// "\Device\LanmanRedirector\ComputerName\Shares\Dance.m3u" -> "\\ComputerName\Shares\Dance.m3u"
	// returns an error for any other device type
	static DWORD GetTDosPathFromNtPath(LPCTSTR u16_NTPath, LPTSTR* ps_DosPath)
	{
		DWORD u32_Error;

		*ps_DosPath = NULL;
		size_t bufLen = 1;

		if (CompareString(GetThreadLocale(), NORM_IGNORECASE, u16_NTPath, 14, TEXT("\\Device\\Serial"), 14) == CSTR_EQUAL || // e.g. "Serial1"
			CompareString(GetThreadLocale(), NORM_IGNORECASE, u16_NTPath, 14, TEXT("\\Device\\UsbSer"), 14) == CSTR_EQUAL)   // e.g. "USBSER000"
		//if (_tcsnicmp(u16_NTPath, TEXT("\\Device\\Serial"), 14) == 0 || // e.g. "Serial1"
		//	_tcsnicmp(u16_NTPath, TEXT("\\Device\\UsbSer"), 14) == 0)   // e.g. "USBSER000"
		{
			HKEY h_Key; 
			if (u32_Error = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Hardware\\DeviceMap\\SerialComm"), 0, KEY_QUERY_VALUE, &h_Key))
				return u32_Error;

			BYTE u16_ComPort[50];

			DWORD u32_Type;
			DWORD u32_Size = sizeof(u16_ComPort); 
			if (u32_Error = RegQueryValueEx(h_Key, (LPTSTR)u16_NTPath, 0, &u32_Type, u16_ComPort, &u32_Size))
			{
				RegCloseKey(h_Key);
				return ERROR_UNKNOWN_PORT;
			}

			bufLen += lstrlen((TCHAR *)u16_ComPort);
			if(*ps_DosPath == NULL)
			{
				*ps_DosPath = (LPTSTR)LocalAlloc(LPTR, bufLen * sizeof (TCHAR));
				lstrcpy(*ps_DosPath, TEXT(""));
			}
			else
			{
				*ps_DosPath = (LPTSTR)LocalReAlloc((HANDLE)*ps_DosPath, bufLen * sizeof (TCHAR), LMEM_ZEROINIT);
			}
			lstrcat(*ps_DosPath, (TCHAR *)(u16_ComPort));
			RegCloseKey(h_Key);
			return 0;
		}

		if (CompareString(GetThreadLocale(), NORM_IGNORECASE, u16_NTPath, 25, TEXT("\\Device\\LanmanRedirector\\"), 25) == CSTR_EQUAL) // Win XP
		//if (_tcsnicmp(u16_NTPath, TEXT("\\Device\\LanmanRedirector\\"), 25) == 0) // Win XP
		{
			bufLen += lstrlen(TEXT("\\\\"));
			bufLen += lstrlen((u16_NTPath + 25));

			if(*ps_DosPath == NULL)
			{
				*ps_DosPath = (LPTSTR)LocalAlloc(LPTR, bufLen * sizeof (TCHAR));
				lstrcpy(*ps_DosPath, TEXT(""));
			}
			else
			{
				*ps_DosPath = (LPTSTR)LocalReAlloc((HANDLE)*ps_DosPath, bufLen * sizeof (TCHAR), LMEM_ZEROINIT);
			}
			lstrcat(*ps_DosPath, TEXT("\\\\"));
			lstrcat(*ps_DosPath, (u16_NTPath + 25));
			return 0;
		}

		if (CompareString(GetThreadLocale(), NORM_IGNORECASE, u16_NTPath, 12, TEXT("\\Device\\Mup\\"), 12) == CSTR_EQUAL) // Win 7
		//if (_tcsnicmp(u16_NTPath, TEXT("\\Device\\Mup\\"), 12) == 0) // Win 7
		{
			bufLen += lstrlen(TEXT("\\\\"));
			bufLen += lstrlen((u16_NTPath + 12));
			if(*ps_DosPath == NULL)
			{
				*ps_DosPath = (LPTSTR)LocalAlloc(LPTR, bufLen * sizeof (TCHAR));
				lstrcpy(*ps_DosPath, TEXT(""));
			}
			else
			{
				*ps_DosPath = (LPTSTR)LocalReAlloc((HANDLE)*ps_DosPath, bufLen * sizeof (TCHAR), LMEM_ZEROINIT);
			}
			lstrcat(*ps_DosPath, TEXT("\\\\"));
			lstrcat(*ps_DosPath, (u16_NTPath + 12));
			return 0;
		}

		TCHAR u16_Drives[300];
		if (!GetLogicalDriveStrings(300, u16_Drives))
			return GetLastError();

		TCHAR* u16_Drv = u16_Drives;
		while (u16_Drv[0])
		{
			TCHAR* u16_Next = u16_Drv + lstrlen(u16_Drv) + 1;
			u16_Drv[2] = 0; // the backslash is not allowed for QueryDosDevice()

			TCHAR u16_NtVolume[1000];
			u16_NtVolume[0] = 0;

			// may return multiple strings!
			// returns very weird strings for network shares
			if (!QueryDosDevice(u16_Drv, u16_NtVolume, sizeof(u16_NtVolume) / sizeof u16_NtVolume[0]))
				return GetLastError();

			int s32_Len = (int)lstrlen(u16_NtVolume);
			if (s32_Len > 0 && CompareString(GetThreadLocale(), NORM_IGNORECASE, u16_NtVolume, s32_Len, u16_NTPath, s32_Len) == CSTR_EQUAL)
			//if (s32_Len > 0 && _tcsnicmp(u16_NTPath, u16_NtVolume, s32_Len) == 0)
			{
				bufLen += lstrlen(u16_Drv);
				bufLen += lstrlen((u16_NTPath + s32_Len));
				if(*ps_DosPath == NULL)
				{
					*ps_DosPath = (LPTSTR)LocalAlloc(LPTR, bufLen * sizeof (TCHAR));
					lstrcpy(*ps_DosPath, TEXT(""));
				}
				else
				{
					*ps_DosPath = (LPTSTR)LocalReAlloc((HANDLE)*ps_DosPath, bufLen * sizeof (TCHAR), LMEM_ZEROINIT);
				}
				lstrcat(*ps_DosPath, u16_Drv);
				lstrcat(*ps_DosPath, (u16_NTPath + s32_Len));
				return 0;
			}

			u16_Drv = u16_Next;
		}
		return ERROR_BAD_PATHNAME;
	}

	static DWORD GetWDosPathFromNtPath(LPCWSTR u16_NTPath, LPWSTR* ps_DosPath)
	{
		DWORD u32_Error;

		*ps_DosPath = NULL;
		size_t bufLen = 1;

		if (CompareStringW(GetThreadLocale(), NORM_IGNORECASE, u16_NTPath, 14, L"\\Device\\Serial", 14) == CSTR_EQUAL || // e.g. "Serial1"
			CompareStringW(GetThreadLocale(), NORM_IGNORECASE, u16_NTPath, 14, L"\\Device\\UsbSer", 14) == CSTR_EQUAL)   // e.g. "USBSER000"
		//if (_tcsnicmp(u16_NTPath, TEXT("\\Device\\Serial"), 14) == 0 || // e.g. "Serial1"
		//	_tcsnicmp(u16_NTPath, TEXT("\\Device\\UsbSer"), 14) == 0)   // e.g. "USBSER000"
		{
			HKEY h_Key; 
			if (u32_Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Hardware\\DeviceMap\\SerialComm", 0, KEY_QUERY_VALUE, &h_Key))
				return u32_Error;

			BYTE u16_ComPort[50];

			DWORD u32_Type;
			DWORD u32_Size = sizeof(u16_ComPort); 
			if (u32_Error = RegQueryValueExW(h_Key, (LPWSTR)u16_NTPath, 0, &u32_Type, u16_ComPort, &u32_Size))
			{
				RegCloseKey(h_Key);
				return ERROR_UNKNOWN_PORT;
			}

			bufLen += lstrlenW((WCHAR *)u16_ComPort);
			if(*ps_DosPath == NULL)
			{
				*ps_DosPath = (LPWSTR)LocalAlloc(LPTR, bufLen * sizeof (WCHAR));
				lstrcpyW(*ps_DosPath, L"");
			}
			else
			{
				*ps_DosPath = (LPWSTR)LocalReAlloc((HANDLE)*ps_DosPath, bufLen * sizeof (WCHAR), LMEM_ZEROINIT);
			}
			lstrcatW(*ps_DosPath, (WCHAR *)(u16_ComPort));
			RegCloseKey(h_Key);
			return 0;
		}

		if (CompareStringW(GetThreadLocale(), NORM_IGNORECASE, u16_NTPath, 25, L"\\Device\\LanmanRedirector\\", 25) == CSTR_EQUAL) // Win XP
		//if (_tcsnicmp(u16_NTPath, TEXT("\\Device\\LanmanRedirector\\"), 25) == 0) // Win XP
		{
			bufLen += lstrlenW(L"\\\\");
			bufLen += lstrlenW((u16_NTPath + 25));

			if(*ps_DosPath == NULL)
			{
				*ps_DosPath = (LPWSTR)LocalAlloc(LPTR, bufLen * sizeof (WCHAR));
				lstrcpyW(*ps_DosPath, L"");
			}
			else
			{
				*ps_DosPath = (LPWSTR)LocalReAlloc((HANDLE)*ps_DosPath, bufLen * sizeof (WCHAR), LMEM_ZEROINIT);
			}
			lstrcatW(*ps_DosPath, L"\\\\");
			lstrcatW(*ps_DosPath, (u16_NTPath + 25));
			return 0;
		}

		if (CompareStringW(GetThreadLocale(), NORM_IGNORECASE, u16_NTPath, 12, L"\\Device\\Mup\\", 12) == CSTR_EQUAL) // Win 7
		//if (_tcsnicmp(u16_NTPath, TEXT("\\Device\\Mup\\"), 12) == 0) // Win 7
		{
			bufLen += lstrlenW(L"\\\\");
			bufLen += lstrlenW((u16_NTPath + 12));
			if(*ps_DosPath == NULL)
			{
				*ps_DosPath = (LPWSTR)LocalAlloc(LPTR, bufLen * sizeof (WCHAR));
				lstrcpyW(*ps_DosPath, L"");
			}
			else
			{
				*ps_DosPath = (LPWSTR)LocalReAlloc((HANDLE)*ps_DosPath, bufLen * sizeof (WCHAR), LMEM_ZEROINIT);
			}
			lstrcatW(*ps_DosPath, L"\\\\");
			lstrcatW(*ps_DosPath, (u16_NTPath + 12));
			return 0;
		}

		WCHAR u16_Drives[300];
		if (!GetLogicalDriveStringsW(300, u16_Drives))
			return GetLastError();

		WCHAR* u16_Drv = u16_Drives;
		while (u16_Drv[0])
		{
			WCHAR* u16_Next = u16_Drv + lstrlenW(u16_Drv) + 1;
			u16_Drv[2] = 0; // the backslash is not allowed for QueryDosDevice()

			WCHAR u16_NtVolume[1000];
			u16_NtVolume[0] = 0;

			// may return multiple strings!
			// returns very weird strings for network shares
			if (!QueryDosDeviceW(u16_Drv, u16_NtVolume, sizeof(u16_NtVolume) / sizeof u16_NtVolume[0]))
				return GetLastError();

			int s32_Len = (int)lstrlenW(u16_NtVolume);
			if (s32_Len > 0 && CompareStringW(GetThreadLocale(), NORM_IGNORECASE, u16_NtVolume, s32_Len, u16_NTPath, s32_Len) == CSTR_EQUAL)
			//if (s32_Len > 0 && _tcsnicmp(u16_NTPath, u16_NtVolume, s32_Len) == 0)
			{
				bufLen += lstrlenW(u16_Drv);
				bufLen += lstrlenW((u16_NTPath + s32_Len));
				if(*ps_DosPath == NULL)
				{
					*ps_DosPath = (LPWSTR)LocalAlloc(LPTR, bufLen * sizeof (WCHAR));
					lstrcpyW(*ps_DosPath, L"");
				}
				else
				{
					*ps_DosPath = (LPWSTR)LocalReAlloc((HANDLE)*ps_DosPath, bufLen * sizeof (WCHAR), LMEM_ZEROINIT);
				}
				lstrcatW(*ps_DosPath, u16_Drv);
				lstrcatW(*ps_DosPath, (u16_NTPath + s32_Len));
				return 0;
			}

			u16_Drv = u16_Next;
		}
		return ERROR_BAD_PATHNAME;
	}

	static DWORD GetADosPathFromNtPath(LPCSTR u16_NTPath, LPSTR* ps_DosPath)
	{
		DWORD u32_Error;

		*ps_DosPath = NULL;
		size_t bufLen = 1;

		if (CompareStringA(GetThreadLocale(), NORM_IGNORECASE, u16_NTPath, 14, "\\Device\\Serial", 14) == CSTR_EQUAL || // e.g. "Serial1"
			CompareStringA(GetThreadLocale(), NORM_IGNORECASE, u16_NTPath, 14, "\\Device\\UsbSer", 14) == CSTR_EQUAL)   // e.g. "USBSER000"
		//if (_tcsnicmp(u16_NTPath, "\\Device\\Serial", 14) == 0 || // e.g. "Serial1"
		//	_tcsnicmp(u16_NTPath, "\\Device\\UsbSer", 14) == 0)   // e.g. "USBSER000"
		{
			HKEY h_Key; 
			if (u32_Error = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Hardware\\DeviceMap\\SerialComm", 0, KEY_QUERY_VALUE, &h_Key))
				return u32_Error;

			BYTE u16_ComPort[50];

			DWORD u32_Type;
			DWORD u32_Size = sizeof(u16_ComPort); 
			if (u32_Error = RegQueryValueExA(h_Key, (LPSTR)u16_NTPath, 0, &u32_Type, u16_ComPort, &u32_Size))
			{
				RegCloseKey(h_Key);
				return ERROR_UNKNOWN_PORT;
			}

			bufLen += lstrlenA((CHAR *)u16_ComPort);
			if(*ps_DosPath == NULL)
			{
				*ps_DosPath = (LPSTR)LocalAlloc(LPTR, bufLen * sizeof (CHAR));
				lstrcpyA(*ps_DosPath, "");
			}
			else
			{
				*ps_DosPath = (LPSTR)LocalReAlloc((HANDLE)*ps_DosPath, bufLen * sizeof (CHAR), LMEM_ZEROINIT);
			}
			lstrcatA(*ps_DosPath, (CHAR *)(u16_ComPort));
			RegCloseKey(h_Key);
			return 0;
		}

		if (CompareStringA(GetThreadLocale(), NORM_IGNORECASE, u16_NTPath, 25, "\\Device\\LanmanRedirector\\", 25) == CSTR_EQUAL) // Win XP
		//if (_tcsnicmp(u16_NTPath, "\\Device\\LanmanRedirector\\", 25) == 0) // Win XP
		{
			bufLen += lstrlenA("\\\\");
			bufLen += lstrlenA((u16_NTPath + 25));

			if(*ps_DosPath == NULL)
			{
				*ps_DosPath = (LPSTR)LocalAlloc(LPTR, bufLen * sizeof (CHAR));
				lstrcpyA(*ps_DosPath, "");
			}
			else
			{
				*ps_DosPath = (LPSTR)LocalReAlloc((HANDLE)*ps_DosPath, bufLen * sizeof (CHAR), LMEM_ZEROINIT);
			}
			lstrcatA(*ps_DosPath, "\\\\");
			lstrcatA(*ps_DosPath, (u16_NTPath + 25));
			return 0;
		}

		if (CompareStringA(GetThreadLocale(), NORM_IGNORECASE, u16_NTPath, 12, "\\Device\\Mup\\", 12) == CSTR_EQUAL) // Win 7
		//if (_tcsnicmp(u16_NTPath, "\\Device\\Mup\\", 12) == 0) // Win 7
		{
			bufLen += lstrlenA("\\\\");
			bufLen += lstrlenA((u16_NTPath + 12));
			if(*ps_DosPath == NULL)
			{
				*ps_DosPath = (LPSTR)LocalAlloc(LPTR, bufLen * sizeof (CHAR));
				lstrcpyA(*ps_DosPath, "");
			}
			else
			{
				*ps_DosPath = (LPSTR)LocalReAlloc((HANDLE)*ps_DosPath, bufLen * sizeof (CHAR), LMEM_ZEROINIT);
			}
			lstrcatA(*ps_DosPath, "\\\\");
			lstrcatA(*ps_DosPath, (u16_NTPath + 12));
			return 0;
		}

		CHAR u16_Drives[300];
		if (!GetLogicalDriveStringsA(300, u16_Drives))
			return GetLastError();

		CHAR* u16_Drv = u16_Drives;
		while (u16_Drv[0])
		{
			CHAR* u16_Next = u16_Drv + lstrlenA(u16_Drv) + 1;
			u16_Drv[2] = 0; // the backslash is not allowed for QueryDosDevice()

			CHAR u16_NtVolume[1000];
			u16_NtVolume[0] = 0;

			// may return multiple strings!
			// returns very weird strings for network shares
			if (!QueryDosDeviceA(u16_Drv, u16_NtVolume, sizeof(u16_NtVolume) / sizeof u16_NtVolume[0]))
				return GetLastError();

			int s32_Len = (int)lstrlenA(u16_NtVolume);
			if (s32_Len > 0 && CompareStringA(GetThreadLocale(), NORM_IGNORECASE, u16_NtVolume, s32_Len, u16_NTPath, s32_Len) == CSTR_EQUAL)
			//if (s32_Len > 0 && _tcsnicmp(u16_NTPath, u16_NtVolume, s32_Len) == 0)
			{
				bufLen += lstrlenA(u16_Drv);
				bufLen += lstrlenA((u16_NTPath + s32_Len));
				if(*ps_DosPath == NULL)
				{
					*ps_DosPath = (LPSTR)LocalAlloc(LPTR, bufLen * sizeof (CHAR));
					lstrcpyA(*ps_DosPath, "");
				}
				else
				{
					*ps_DosPath = (LPSTR)LocalReAlloc((HANDLE)*ps_DosPath, bufLen * sizeof (CHAR), LMEM_ZEROINIT);
				}
				lstrcatA(*ps_DosPath, u16_Drv);
				lstrcatA(*ps_DosPath, (u16_NTPath + s32_Len));
				return 0;
			}

			u16_Drv = u16_Next;
		}
		return ERROR_BAD_PATHNAME;
	}

	public:

		GetWindowsFchmodFuncs()
		{
			if(numInstances == 0)
			{
				BOOL success = FALSE;

				hNtDll = LoadLibrary(TEXT("NTDLL"));
				hKernel32 = LoadLibrary(TEXT("KERNEL32"));
				hPsapi = LoadLibrary(TEXT("PSAPI"));

				if(hNtDll != 0)
				{
					fpNtQueryObject = GetProcAddress(hNtDll, "NtQueryObject");
					fpRtlGetVersion = GetProcAddress(hNtDll, TEXT("RtlGetVersion"));
					if(fpRtlGetVersion != NULL)
					{
						zIsNt = TRUE;
						zIsWin32s = FALSE;
					}
				}

				if(hKernel32 != 0)
				{
					fpGetFinalPathNameByHandleA = GetProcAddress(hKernel32, "GetFinalPathNameByHandleA");
					fpGetFinalPathNameByHandleW = GetProcAddress(hKernel32, "GetFinalPathNameByHandleW");

					if(fpGetFinalPathNameByHandleA == NULL)
					{
						fpGetFinalPathNameByHandleA = GetProcAddress(hKernel32, "GetFinalPathNameByHandle");
					}

					#ifdef  UNICODE
						fpGetFinalPathNameByHandleT = fpGetFinalPathNameByHandleW;
					#else   /* UNICODE */
						fpGetFinalPathNameByHandleT = fpGetFinalPathNameByHandleA;
					#endif /* UNICODE */

					fpGetMappedFileNameA = GetProcAddress(hKernel32, "GetMappedFileNameA");

					if(fpGetMappedFileNameA == NULL)
					{
						fpGetMappedFileNameA = GetProcAddress(hKernel32, "K32GetMappedFileNameA");

						if(fpGetMappedFileNameA == NULL)
						{
							fpGetMappedFileNameA = GetProcAddress(hKernel32, "GetMappedFileName");

							if(fpGetMappedFileNameA == NULL)
							{
								fpGetMappedFileNameA = GetProcAddress(hKernel32, "K32GetMappedFileName");
							}
						}
					}

					fpGetMappedFileNameW = GetProcAddress(hKernel32, "GetMappedFileNameW");

					if(fpGetMappedFileNameW == NULL)
					{
						fpGetMappedFileNameW = GetProcAddress(hKernel32, "K32GetMappedFileNameW");
					}

					#ifdef  UNICODE
						fpGetMappedFileNameT = fpGetMappedFileNameW;
					#else   /* UNICODE */
						fpGetMappedFileNameT = fpGetMappedFileNameA;
					#endif /* UNICODE */

					fpGetVersionEx = GetProcAddress(hKernel32, TEXT("GetVersionExA"));

					if(fpGetVersionEx == NULL)
					{
						fpGetVersionEx = GetProcAddress(hKernel32, TEXT("GetVersionEx"));
					}

					fpGetVersion = GetProcAddress(hKernel32, TEXT("GetVersion"));
				}

				if(hPsapi != NULL && fpGetMappedFileNameA == NULL && fpGetMappedFileNameW == NULL)
				{
					fpGetMappedFileNameA = GetProcAddress(hPsapi, "GetMappedFileNameA");

					if(fpGetMappedFileNameA == NULL)
					{
						fpGetMappedFileNameA = GetProcAddress(hPsapi, "K32GetMappedFileNameA");

						if(fpGetMappedFileNameA == NULL)
						{
							fpGetMappedFileNameA = GetProcAddress(hPsapi, "GetMappedFileName");

							if(fpGetMappedFileNameA == NULL)
							{
								fpGetMappedFileNameA = GetProcAddress(hPsapi, "K32GetMappedFileName");
							}
						}
					}

					fpGetMappedFileNameW = GetProcAddress(hPsapi, "GetMappedFileNameW");

					if(fpGetMappedFileNameW == NULL)
					{
						fpGetMappedFileNameW = GetProcAddress(hPsapi, "K32GetMappedFileNameW");
					}

					#ifdef  UNICODE
						fpGetMappedFileNameT = fpGetMappedFileNameW;
					#else   /* UNICODE */
						fpGetMappedFileNameT = fpGetMappedFileNameA;
					#endif /* UNICODE */
				}

				if(!zIsNt)
				{
					DWORD v = GetVersion();
					zIsNt = !(v & 0x80000000);
					zIsWin32s = ((!zIsNt) && (DWORD)(LOBYTE(LOWORD(v))) <= 3);
				}

				if(!success && fpRtlGetVersion != NULL)
				{
					LRTL_OSVERSIONINFOEXW osversioninfo;
					memset(&osversioninfo, '\0', sizeof (LRTL_OSVERSIONINFOEXW));
					osversioninfo.dwOSVersionInfoSize = sizeof (LRTL_OSVERSIONINFOEXW);
					NTSTATUS status = ((LPRtlGetVersionEX)fpRtlGetVersion)(&osversioninfo);
					if(status == STATUS_SUCCESS)
					{
						success = TRUE;
						majorVersion = osversioninfo.dwMajorVersion;
						minorVersion = osversioninfo.dwMinorVersion;
						build = osversioninfo.dwBuildNumber;
						platformId = osversioninfo.dwPlatformId;
					}
				}

				if(!success && fpGetVersionEx != NULL)
				{
					LOSVERSIONINFOEXA versionInformation;
					memset(&versionInformation, '\0', sizeof (LOSVERSIONINFOEXA));
					versionInformation.dwOSVersionInfoSize = sizeof (LOSVERSIONINFOEXA);
					success = ((LPGetVersionEXEXA)fpGetVersionEx)(&versionInformation);
					if(success)
					{
						majorVersion = versionInformation.dwMajorVersion;
						minorVersion = versionInformation.dwMinorVersion;
						build = versionInformation.dwBuildNumber;
						platformId = versionInformation.dwPlatformId;
					}
				}

				if(!success && fpRtlGetVersion != NULL)
				{
					LRTL_OSVERSIONINFOW osversioninfo;
					memset(&osversioninfo, '\0', sizeof (LRTL_OSVERSIONINFOW));
					osversioninfo.dwOSVersionInfoSize = sizeof (LRTL_OSVERSIONINFOW);
					NTSTATUS status = ((LPRtlGetVersion)fpRtlGetVersion)(&osversioninfo);
					if(status == STATUS_SUCCESS)
					{
						HKEY hKeyCurrentVersion = 0;
						HKEY hKeyProductOptions = 0;
						
						success = TRUE;
						majorVersion = osversioninfo.dwMajorVersion;
						minorVersion = osversioninfo.dwMinorVersion;
						build = osversioninfo.dwBuildNumber;
						platformId = osversioninfo.dwPlatformId;
					}
				}

				if(!success && fpGetVersionEx != NULL)
				{
					LOSVERSIONINFOA versionInformation;
					memset(&versionInformation, '\0', sizeof (LOSVERSIONINFOA));
					versionInformation.dwOSVersionInfoSize = sizeof (LOSVERSIONINFOA);
					success = ((LPGetVersionEXA)fpGetVersionEx)(&versionInformation);
					if(success)
					{
						// for win32S, GetVersionEx returns the version of win32s, so a separate call to GetVersion will be required.
						if(zIsWin32s || versionInformation.dwMajorVersion < 3)
						{
							DWORD dwVersion = GetVersion();
							
							majorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
							minorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

							build = 0;
							if(dwVersion < 0x80000000)
							{
								build = (DWORD)(HIWORD(dwVersion));
							}
							
							platformId = 0;
						}
						else
						{
							majorVersion = versionInformation.dwMajorVersion;
							minorVersion = versionInformation.dwMinorVersion;
							build = versionInformation.dwBuildNumber;
							platformId = versionInformation.dwPlatformId;
						}
					}
				}

				if(!success)
				{
					DWORD dwVersion = 0;
					dwVersion = GetVersion();

					majorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
					minorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

					if(dwVersion < 0x80000000)
					{
						build = (DWORD)(HIWORD(dwVersion));
					}
					
					platformId = 0;
					
					if(majorVersion >= 3 && minorVersion == 0x0a && zIsWin32s)
					{
						platformId = 0;
					}
					else if(majorVersion >= 3 && (minorVersion == 0x0a || minorVersion == 0x32 || minorVersion == 0x33))
					{
						platformId = 2;
					}
					else if(majorVersion >= 4 && zIsNt)
					{
						platformId = 2;
					}
					else if(majorVersion >= 4)
					{
						platformId = 1;
					}
					else
					{
						platformId = 0;
					}
				}

				OSWin9x = platformId == VER_PLATFORM_WIN32_WINDOWS;
				OSWin95 = (OSWin9x && majorVersion == 4 && minorVersion < 3) ? TRUE : FALSE;
				OSWin98 = (OSWin9x && majorVersion == 4 && (minorVersion >= 3 && minorVersion <= 10)) ? TRUE : FALSE;
				OSWinME = (OSWin9x && majorVersion == 4 && minorVersion >= 90) ? TRUE : FALSE;

				InitializeCriticalSection(&csgetRing0Handle);
				InitializeCriticalSection(&csring0ExtendedHandleToPath);

				if(OSWin9x)
				{
					pTib = getTIB();

					if(pTib)
					{
						if(OSWin95)
						{
							#ifdef _M_IX86
								pTdb = (PTHREAD_DATABASE)((DWORD)pTib - offsetof(struct _TDB95, tib));
							#elif _M_AMD64
								pTdb = (PTHREAD_DATABASE)((ULONGLONG)pTib - offsetof(struct _TDB95, tib));
							#else
								#error unsupported architecture
							#endif
						}
						else if(OSWin98)
						{
							#ifdef _M_IX86
							pTdb = (PTHREAD_DATABASE)((DWORD)pTib - offsetof(struct _TDB98, tib));
							#elif _M_AMD64
							pTdb = (PTHREAD_DATABASE)((ULONGLONG)pTib - offsetof(struct _TDB98, tib));
							#else
								#error unsupported architecture
							#endif
						}
						else if(OSWinME)
						{
							#ifdef _M_IX86
							pTdb = (PTHREAD_DATABASE)((DWORD)pTib - offsetof(struct _TDBME, tib));
							#elif _M_AMD64
							pTdb = (PTHREAD_DATABASE)((ULONGLONG)pTib - offsetof(struct _TDBME, tib));
							#else
								#error unsupported architecture
							#endif
						}
						else
						{
							pTdb = NULL;
						}
					}

					if(pTdb)
					{
						#ifdef _M_IX86
							DWORD tid = GetCurrentThreadId();
							obsfucator = ((DWORD)pTdb ^ tid);
						#elif _M_AMD64
							ULONGLONG tid = GetCurrentThreadId();
							obsfucator = ((ULONGLONG)pTdb ^ tid);
						#else
							#error unsupported architecture
						#endif
					}

					if(pTdb && obsfucator)
					{
						#ifdef _M_IX86
						DWORD pid = GetCurrentProcessId();
						pPdb = (PPROCESS_DATABASE)(pid ^ obsfucator);
						#elif _M_AMD64
						ULONGLONG pid = GetCurrentProcessId();
						pPdb = (PPROCESS_DATABASE)(pid ^ obsfucator);
						#else
							#error unsupported architecture
						#endif
					}
				}
			}

			numInstances++;
		}

		~GetWindowsFchmodFuncs()
		{
			numInstances--;
			if(numInstances == 0)
			{
				if(hPsapi != 0)
				{
					FreeLibrary(hPsapi);
					hPsapi = 0;
				}

				if(hNtDll != 0)
				{
					FreeLibrary(hNtDll);
					hNtDll = 0;
				}

				if(hKernel32 != 0)
				{
					FreeLibrary(hKernel32);
					hKernel32 = 0;
				}
				
				fpGetFinalPathNameByHandleA = NULL;
				fpGetFinalPathNameByHandleW = NULL;
				fpGetVersion = NULL;
				fpGetVersionEx = NULL;
				fpRtlGetVersion = NULL;

			}
		}

		static LPCSTR GetAPathByHandle(int fd)
		{
			LPSTR name = NULL;

			#ifndef q4_WCE
				HANDLE h = (HANDLE) _get_osfhandle(fd);
			#else
				HANDLE h = (HANDLE)fd;
			#endif //q4_WCE

			if(fpGetFinalPathNameByHandleA)
			{
				DWORD bufSize = 0;
				CHAR t;
				LPSTR ntPath = NULL;

				bufSize = ((LPGetFinalPathNameByHandleA)fpGetFinalPathNameByHandleA)(h, &t, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_NT);
				if(bufSize == 0)
				{
					return NULL;
				}
				else
				{
					ntPath = (LPSTR)LocalAlloc(LPTR, (bufSize + 1) * sizeof (CHAR));

					if(ntPath == 0)
					{
						return NULL;
					}
					else
					{
						if(((LPGetFinalPathNameByHandleA)fpGetFinalPathNameByHandleA)(h, ntPath, (bufSize + 1), FILE_NAME_NORMALIZED | VOLUME_NAME_NT) == 0)
						{
							LocalFree(ntPath);
							return NULL;
						}
						else
						{
							if(GetADosPathFromNtPath(ntPath, &name) != 0)
							{
								if(name != NULL)
								{
									LocalFree(name);
									name = NULL;
								}
							}
							LocalFree((HANDLE)ntPath);
						}
					}
				}
			}
			else if(fpNtQueryObject)
			{
				BYTE buf[sizeof (OBJECT_NAME_INFORMATION) / sizeof (BYTE) + MAX_PATH * sizeof (WCHAR) / sizeof (BYTE) + 2 * sizeof (WCHAR) / sizeof (BYTE)];
				size_t bufSize = sizeof buf / sizeof buf[0];

				ULONG returnLength;
				NTSTATUS ret = ((LPNtQueryObject)fpNtQueryObject)(h, ObjectNameInformation, buf, bufSize, &returnLength);

				if(ret == STATUS_SUCCESS)
				{
					int i;
					POBJECT_NAME_INFORMATION info = (POBJECT_NAME_INFORMATION)buf;
					LPSTR ntPath = NULL;

					ntPath = (LPSTR)LocalAlloc(LPTR, (info->Name.Length + 1) * sizeof (CHAR));
					if(ntPath != NULL)
					{
						for(i = 0; i < info->Name.Length; i++)
						{
							ntPath[i] = (char)(info->Name.Buffer[i] & 0xFF);
						}

						if(GetADosPathFromNtPath(ntPath, &name) != 0)
						{
							if(name != NULL)
							{
								LocalFree(name);
								name = NULL;
							}
						}
						LocalFree((HANDLE)ntPath);
						ntPath = NULL;
					}
				}
			}
			else if(fpGetMappedFileNameA != NULL)
			{
				DWORD dwFileSizeHi = 0;
				DWORD dwFileSizeLo = GetFileSize(h, &dwFileSizeHi);
				HANDLE hFileMap = 0;

				if(dwFileSizeLo == 0 && dwFileSizeHi == 0)
				{
					return NULL;
				}

				hFileMap = CreateFileMapping(h, NULL, PAGE_READONLY, 0, 1, NULL);

				if(hFileMap == NULL)
				{
					DWORD errNo = GetLastError();
					return NULL;
				}

				LPVOID pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

				if(pMem == NULL)
				{
					CloseHandle(hFileMap);
					return NULL;
				}

				CHAR pszFilename[MAX_PATH+1];

				if(((LPGetMappedFileNameA)fpGetMappedFileNameA)(GetCurrentProcess(), pMem, pszFilename, MAX_PATH))
				{
					if(GetADosPathFromNtPath(pszFilename, &name) != 0)
					{
						if(name != NULL)
						{
							LocalFree(name);
							name = NULL;
						}
					}
				}

				UnmapViewOfFile(pMem);
				CloseHandle(hFileMap);
			}
			else if(OSWin9x) // if 9X fall back to interrupt hack to chain to IFSMgr VXDCall to read the file handle path
			{
				BYTE path[MAX_PATH + 1];
				PK32OBJBASE pObj = Win32HandleToK32Object(h);
				DWORD hExtendedHandle = (pObj) ? getExtendedFileHandle(pObj) : 0;
				PVOID handleBuf;
				DWORD filePos;
				BOOL getHandleSuccess = (hExtendedHandle) ? getRing0Handle(hExtendedHandle, &handleBuf, &filePos) : FALSE;
				BOOL getRing0ExtendedHandleToPathSuccess = (getHandleSuccess) ? ring0ExtendedHandleToPathAscii(handleBuf, path, sizeof path / sizeof path[0]) : FALSE;

				if(getRing0ExtendedHandleToPathSuccess)
				{
					name = (LPSTR)LocalAlloc(LPTR, (MIN(strlen((LPCSTR)&path[0]), MAX_PATH) + 1) * sizeof (CHAR));
					if(name)
					{
						strncpy(name, (LPCSTR)path, MIN(strlen((LPCSTR)&path[0]), MAX_PATH));
					}
				}
			}

			return name;
		}

		static WCHAR* GetWPathByHandle(int fd)
		{
			LPWSTR name = NULL;

			#ifndef q4_WCE
				HANDLE h = (HANDLE) _get_osfhandle(fd);
			#else
				HANDLE h = (HANDLE)fd;
			#endif //q4_WCE

			if(fpGetFinalPathNameByHandleW)
			{
				DWORD bufSize = 0;
				WCHAR t;
				LPWSTR ntPath = NULL;

				bufSize = ((LPGetFinalPathNameByHandleW)fpGetFinalPathNameByHandleW)(h, &t, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_NT);
				if(bufSize == 0)
				{
					return NULL;
				}
				else
				{
					ntPath = (LPWSTR)LocalAlloc(LPTR, (bufSize + 1) * sizeof (WCHAR));

					if(ntPath == 0)
					{
						return NULL;
					}
					else
					{
						if(((LPGetFinalPathNameByHandleW)fpGetFinalPathNameByHandleW)(h, ntPath, (bufSize + 1), FILE_NAME_NORMALIZED | VOLUME_NAME_NT) == 0)
						{
							LocalFree(ntPath);
							return NULL;
						}
						else
						{
							if(GetWDosPathFromNtPath(ntPath, &name) != 0)
							{
								if(name != NULL)
								{
									LocalFree(name);
									name = NULL;
								}
							}
							LocalFree((HANDLE)ntPath);
						}
					}
				}
			}
			else if(fpNtQueryObject)
			{
				BYTE buf[sizeof (OBJECT_NAME_INFORMATION) / sizeof (BYTE) + MAX_PATH * sizeof (WCHAR) / sizeof (BYTE) + 2 * sizeof (WCHAR) / sizeof (BYTE)];
				size_t bufSize = sizeof buf / sizeof buf[0];

				ULONG returnLength;
				NTSTATUS ret = ((LPNtQueryObject)fpNtQueryObject)(h, ObjectNameInformation, buf, bufSize, &returnLength);

				if(ret == STATUS_SUCCESS)
				{
					POBJECT_NAME_INFORMATION info = (POBJECT_NAME_INFORMATION)buf;
					LPWSTR ntPath = NULL;

					ntPath = (LPWSTR)LocalAlloc(LPTR, (info->Name.Length + 1) * sizeof (WCHAR));
					if(ntPath != NULL)
					{
						lstrcpyW(ntPath, info->Name.Buffer);

						if(GetWDosPathFromNtPath(ntPath, &name) != 0)
						{
							if(name != NULL)
							{
								LocalFree(name);
								name = NULL;
							}
						}
						LocalFree((HANDLE)ntPath);
						ntPath = NULL;
					}
				}
			}
			else if(fpGetMappedFileNameW != NULL)
			{
				DWORD dwFileSizeHi = 0;
				DWORD dwFileSizeLo = GetFileSize(h, &dwFileSizeHi);
				HANDLE hFileMap = 0;

				if(dwFileSizeLo == 0 && dwFileSizeHi == 0)
				{
					return NULL;
				}

				hFileMap = CreateFileMapping(h, NULL, PAGE_READONLY, 0, 1, NULL);

				if(hFileMap == NULL)
				{
					DWORD errNo = GetLastError();
					return NULL;
				}

				LPVOID pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

				if(pMem == NULL)
				{
					CloseHandle(hFileMap);
					return NULL;
				}

				WCHAR pszFilename[MAX_PATH+1];

				if(((LPGetMappedFileNameW)fpGetMappedFileNameW)(GetCurrentProcess(), pMem, pszFilename, MAX_PATH))
				{
					if(GetWDosPathFromNtPath(pszFilename, &name) != 0)
					{
						if(name != NULL)
						{
							LocalFree(name);
							name = NULL;
						}
					}
				}

				UnmapViewOfFile(pMem);
				CloseHandle(hFileMap);
			}
			else if(OSWin9x) // if 9X fall back to interrupt hack to chain to IFSMgr VXDCall to read the file handle path
			{
				WCHAR path[MAX_PATH + 1];
				PK32OBJBASE pObj = Win32HandleToK32Object(h);
				DWORD hExtendedHandle = (pObj) ? getExtendedFileHandle(pObj) : 0;
				PVOID handleBuf;
				DWORD filePos;
				BOOL getHandleSuccess = (hExtendedHandle) ? getRing0Handle(hExtendedHandle, &handleBuf, &filePos) : FALSE;
				BOOL getRing0ExtendedHandleToPathSuccess = (getHandleSuccess) ? ring0ExtendedHandleToPathUnicode(handleBuf, path, sizeof path / sizeof path[0]) : FALSE;

				if(getRing0ExtendedHandleToPathSuccess)
				{
					name = (LPWSTR)LocalAlloc(LPTR, (MIN(wcslen(path), MAX_PATH) + 1) * sizeof (WCHAR));
					if(name)
					{
						wcsncpy(name, path, MIN(wcslen(path), MAX_PATH));
					}
				}
			}

			return name;
		}

		static LPCTSTR GetTPathByHandle(int fd)
		{
			LPTSTR name = NULL;

			#ifndef q4_WCE
				HANDLE h = (HANDLE) _get_osfhandle(fd);
			#else
				HANDLE h = (HANDLE)fd;
			#endif //q4_WCE

			if(fpGetFinalPathNameByHandleT)
			{
				DWORD bufSize = 0;
				TCHAR t;
				LPTSTR ntPath = NULL;

				bufSize = ((LPGetFinalPathNameByHandleT)fpGetFinalPathNameByHandleT)(h, &t, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_NT);
				if(bufSize == 0)
				{
					return NULL;
				}
				else
				{
					ntPath = (LPTSTR)LocalAlloc(LPTR, (bufSize + 1) * sizeof (TCHAR));

					if(ntPath == 0)
					{
						return NULL;
					}
					else
					{
						if(((LPGetFinalPathNameByHandleT)fpGetFinalPathNameByHandleT)(h, ntPath, (bufSize + 1), FILE_NAME_NORMALIZED | VOLUME_NAME_NT) == 0)
						{
							LocalFree(ntPath);
							return NULL;
						}
						else
						{
							if(GetTDosPathFromNtPath(ntPath, &name) != 0)
							{
								if(name != NULL)
								{
									LocalFree(name);
									name = NULL;
								}
							}
							LocalFree((HANDLE)ntPath);
						}
					}
				}
			}
			else if(fpNtQueryObject)
			{
				BYTE buf[sizeof (OBJECT_NAME_INFORMATION) / sizeof (BYTE) + MAX_PATH * sizeof (WCHAR) / sizeof (BYTE) + 2 * sizeof (WCHAR) / sizeof (BYTE)];
				size_t bufSize = sizeof buf / sizeof buf[0];

				ULONG returnLength;
				NTSTATUS ret = ((LPNtQueryObject)fpNtQueryObject)(h, ObjectNameInformation, buf, bufSize, &returnLength);

				if(ret == STATUS_SUCCESS)
				{
					int i;
					POBJECT_NAME_INFORMATION info = (POBJECT_NAME_INFORMATION)buf;
					LPTSTR ntPath = NULL;

					ntPath = (LPTSTR)LocalAlloc(LPTR, (info->Name.Length + 1) * sizeof (TCHAR));
					if(ntPath != NULL)
					{
						#ifdef  UNICODE
						lstrcpyW(ntPath, info->Name.Buffer);
						#else
						for(i = 0; i < info->Name.Length; i++)
						{
							ntPath[i] = (char)(info->Name.Buffer[i] & 0xFF);
						}
						#endif /* UNICODE */

						if(GetTDosPathFromNtPath(ntPath, &name) != 0)
						{
							if(name != NULL)
							{
								LocalFree(name);
								name = NULL;
							}
						}
						LocalFree((HANDLE)ntPath);
						ntPath = NULL;
					}
				}
			}
			else if(fpGetMappedFileNameT != NULL)
			{
				DWORD dwFileSizeHi = 0;
				DWORD dwFileSizeLo = GetFileSize(h, &dwFileSizeHi);
				HANDLE hFileMap = 0;

				if(dwFileSizeLo == 0 && dwFileSizeHi == 0)
				{
					return NULL;
				}

				hFileMap = CreateFileMapping(h, NULL, PAGE_READONLY, 0, 1, NULL);

				if(hFileMap == NULL)
				{
					DWORD errNo = GetLastError();
					return NULL;
				}

				LPVOID pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

				if(pMem == NULL)
				{
					CloseHandle(hFileMap);
					return NULL;
				}

				TCHAR pszFilename[MAX_PATH+1];

				if(((LPGetMappedFileNameT)fpGetMappedFileNameT)(GetCurrentProcess(), pMem, pszFilename, MAX_PATH))
				{
					if(GetTDosPathFromNtPath(pszFilename, &name) != 0)
					{
						if(name != NULL)
						{
							LocalFree(name);
							name = NULL;
						}
					}
				}

				UnmapViewOfFile(pMem);
				CloseHandle(hFileMap);
			}
			else if(OSWin9x) // if 9X fall back to interrupt hack to chain to IFSMgr VXDCall to read the file handle path
			{
				TCHAR path[MAX_PATH + 1];
				PK32OBJBASE pObj = Win32HandleToK32Object(h);
				DWORD hExtendedHandle = (pObj) ? getExtendedFileHandle(pObj) : 0;
				PVOID handleBuf;
				DWORD filePos;
				BOOL getHandleSuccess = (hExtendedHandle) ? getRing0Handle(hExtendedHandle, &handleBuf, &filePos) : FALSE;
				#ifdef  UNICODE
					BOOL getRing0ExtendedHandleToPathSuccess = (getHandleSuccess) ? ring0ExtendedHandleToPathUnicode(handleBuf, &path[0], sizeof path / sizeof path[0]) : FALSE;
				#else   /* UNICODE */
					BOOL getRing0ExtendedHandleToPathSuccess = (getHandleSuccess) ? ring0ExtendedHandleToPathAscii(handleBuf, (LPBYTE)(&path[0]), sizeof path / sizeof path[0]) : FALSE;
				#endif /* UNICODE */

				if(getRing0ExtendedHandleToPathSuccess)
				{
					name = (LPTSTR)LocalAlloc(LPTR, (MIN(_tcslen(path), MAX_PATH) + 1) * sizeof (TCHAR));
					if(name)
					{
						_tcsncpy(name, path, MIN(_tcslen(path), MAX_PATH));
					}
				}
			}

			return name;
		}
};

int GetWindowsFchmodFuncs::numInstances = 0;
HMODULE GetWindowsFchmodFuncs::hKernel32 = 0;
HMODULE GetWindowsFchmodFuncs::hNtDll = 0;
HMODULE GetWindowsFchmodFuncs::hPsapi = 0;
FARPROC GetWindowsFchmodFuncs::fpGetFinalPathNameByHandleA = NULL;
FARPROC GetWindowsFchmodFuncs::fpGetFinalPathNameByHandleW = NULL;
FARPROC GetWindowsFchmodFuncs::fpGetFinalPathNameByHandleT = NULL;
FARPROC GetWindowsFchmodFuncs::fpGetMappedFileNameA = NULL;
FARPROC GetWindowsFchmodFuncs::fpGetMappedFileNameW = NULL;
FARPROC GetWindowsFchmodFuncs::fpGetMappedFileNameT = NULL;
FARPROC GetWindowsFchmodFuncs::fpNtQueryObject = NULL;
FARPROC GetWindowsFchmodFuncs::fpGetVersion = NULL;
FARPROC GetWindowsFchmodFuncs::fpGetVersionEx = NULL;
FARPROC GetWindowsFchmodFuncs::fpRtlGetVersion = NULL;
BOOL GetWindowsFchmodFuncs::zIsNt = FALSE;
BOOL GetWindowsFchmodFuncs::zIsWin32s = FALSE;
DWORD GetWindowsFchmodFuncs::majorVersion = 0;
DWORD GetWindowsFchmodFuncs::minorVersion = 0;
DWORD GetWindowsFchmodFuncs::build = 0;
DWORD GetWindowsFchmodFuncs::platformId = 0;
BOOL GetWindowsFchmodFuncs::OSWin9x = FALSE;
BOOL GetWindowsFchmodFuncs::OSWin95 = FALSE;
BOOL GetWindowsFchmodFuncs::OSWin98 = FALSE;
BOOL GetWindowsFchmodFuncs::OSWinME = FALSE;
CRITICAL_SECTION GetWindowsFchmodFuncs::csgetRing0Handle;
CRITICAL_SECTION GetWindowsFchmodFuncs::csring0ExtendedHandleToPath;
#ifdef _M_IX86
DWORD GetWindowsFchmodFuncs::obsfucator = 0;
#elif _M_AMD64
ULONGLONG GetWindowsFchmodFuncs::obsfucator = 0;
#else
	#error unsupported architecture
#endif
PTIB GetWindowsFchmodFuncs::pTib = NULL;
PTHREAD_DATABASE GetWindowsFchmodFuncs::pTdb = NULL;
PPROCESS_DATABASE GetWindowsFchmodFuncs::pPdb = NULL;

static GetWindowsFchmodFuncs _getWindowsFchmodFuncs;

int fchmod(int fd, int mode)
{
	// we don't support other flags, pretend to succeed.
	if((mode & ~(_S_IREAD | _S_IWRITE)) == mode)
	{
		return 0;
	}
	else
	{
		LPCWSTR filePath = GetWindowsFchmodFuncs::GetWPathByHandle(fd);
		
		if(filePath == NULL)
		{
			errno = ENOENT;
			return -1;
		}
		else
		{
			int ret = _wchmod(filePath, mode);
			
			LocalFree((HANDLE)filePath);
			
			return ret;
		}
	}
}
