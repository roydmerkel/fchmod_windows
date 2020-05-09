#include "fchmod.h"

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <io.h>
#include <wchar.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
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

typedef DWORD (WINAPI * PGetFinalPathNameByHandleW)(HANDLE hFile, LPWSTR lpszFilePath, DWORD cchFilePath, DWORD dwFlags);
typedef DWORD (WINAPI * PGetFinalPathNameByHandleA)(HANDLE hFile, LPSTR  lpszFilePath, DWORD  cchFilePath, DWORD  dwFlags);
typedef DWORD (WINAPI * PGetFinalPathNameByHandleT)(HANDLE hFile, LPTSTR  lpszFilePath, DWORD  cchFilePath, DWORD  dwFlags);

typedef DWORD (WINAPI FAR * LPGetFinalPathNameByHandleW)(HANDLE hFile, LPWSTR lpszFilePath, DWORD cchFilePath, DWORD dwFlags);
typedef DWORD (WINAPI FAR * LPGetFinalPathNameByHandleA)(HANDLE hFile, LPSTR  lpszFilePath, DWORD  cchFilePath, DWORD  dwFlags);
typedef DWORD (WINAPI FAR * LPGetFinalPathNameByHandleT)(HANDLE hFile, LPTSTR lpszFilePath, DWORD cchFilePath, DWORD dwFlags);

typedef LONG NTSTATUS;
typedef NTSTATUS (WINAPI * PNtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
typedef NTSTATUS (WINAPI FAR * LPNtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);

typedef DWORD (WINAPI * PGetMappedFileNameA)(HANDLE hProcess, LPVOID lpv, LPSTR lpFilename, DWORD nSize);
typedef DWORD (WINAPI * PGetMappedFileNameW)(HANDLE hProcess, LPVOID lpv, LPWSTR lpFilename, DWORD nSize);
typedef DWORD (WINAPI * PGetMappedFileNameT)(HANDLE hProcess, LPVOID lpv, LPTSTR lpFilename, DWORD nSize);

typedef DWORD (WINAPI FAR * LPGetMappedFileNameA)(HANDLE hProcess, LPVOID lpv, LPSTR lpFilename, DWORD nSize);
typedef DWORD (WINAPI FAR * LPGetMappedFileNameW)(HANDLE hProcess, LPVOID lpv, LPWSTR lpFilename, DWORD nSize);
typedef DWORD (WINAPI FAR * LPGetMappedFileNameT)(HANDLE hProcess, LPVOID lpv, LPTSTR lpFilename, DWORD nSize);

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
				hNtDll = LoadLibrary(TEXT("NTDLL"));
				hKernel32 = LoadLibrary(TEXT("KERNEL32"));
				hPsapi = LoadLibrary(TEXT("PSAPI"));

				if(hNtDll != 0)
				{
					fpNtQueryObject = GetProcAddress(hNtDll, "NtQueryObject");
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
				BYTE buf[sizeof (OBJECT_NAME_INFORMATION) / sizeof (BYTE) + MAX_PATH * sizeof (WCHAR) / sizeof (BYTE) + sizeof (WCHAR) / sizeof (BYTE)];
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
				BYTE buf[sizeof (OBJECT_NAME_INFORMATION) / sizeof (BYTE) + MAX_PATH * sizeof (WCHAR) / sizeof (BYTE) + sizeof (WCHAR) / sizeof (BYTE)];
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
				BYTE buf[sizeof (OBJECT_NAME_INFORMATION) / sizeof (BYTE) + MAX_PATH * sizeof (WCHAR) / sizeof (BYTE) + sizeof (WCHAR) / sizeof (BYTE)];
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

