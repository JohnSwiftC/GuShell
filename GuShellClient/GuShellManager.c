#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <process.h>


#define PORT "3000"

#define MESSAGESIZE 10000
#define RESPONSESIZE 20000
#define CLIENTAMOUNT 10

#pragma comment(lib, "Ws2_32.lib")

int main(int argc, char* argv[]);
int openSock(void);
int acceptClientOnSock(int sockfd);
int startConversationWithClient(int remoteDesk, char* messageBuf, char* responseBuf, size_t messageBufSize, size_t responseBufSize);
void handleNewConnectionProc(void* pID);
void printWelcomeMessage();

// These need to be top level for easy threading. DO NOT CHANGE AFTER STARTING NEW THREADS UNLESS BLOCKED AND ACTUALLY PLANNED OUT
HANDLE hClientListMutex;
volatile int clientList[CLIENTAMOUNT] = { NULL };
volatile int clientCount;


// Returns socket file desc. for our socket on machine.
int openSock(void) {
	int sockfd = -1;

	struct addrinfo hints, * p, * servinfo;

	// Clear Hints
	memset(&hints, 0, sizeof hints);

	//Fill Hints
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	getaddrinfo(NULL, PORT, &hints, &servinfo);

	// Honestly, I'm not sure how useful this loop is as the host, but I will do it anyway
	// Beej's network guide does this for host discovery on clients but not servers, idk tbh

	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			continue;
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			closesocket((SOCKET)sockfd);
			continue;
		}

		break;
	}

	// Also not sure where I got this from? I used it in my first little playground, not sure how useful this cast is.
	// Maybe wants const char * for timeout input but not the size of the string, but the size of DWORD??? idk.
	DWORD timeout = 1000;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout);

	if (listen(sockfd, 10) == -1) {
		return -1;
	}

	freeaddrinfo(servinfo);

	return sockfd;
}

// Accepts connection on socket that is open and listening
int acceptClientOnSock(int sockfd) {
	int remoteDesk = -1;
	struct sockaddr_storage clientAddr;
	int sin_size = sizeof clientAddr;
	char clientipv4[INET_ADDRSTRLEN];

	remoteDesk = accept(sockfd, (struct sockaddr*)&clientAddr, &sin_size);

	// Atrocious cast please clean this up
	inet_ntop(AF_INET, &(((struct sockaddr_in*)&clientAddr)->sin_addr), clientipv4, INET_ADDRSTRLEN);

	printf("%s%s\n", "Receiving connection from: ", clientipv4);

	return remoteDesk;
}

// Send and recv loop for a client.

int startConversationWithClient(int remoteDesk, char* messageBuf, char* responseBuf, size_t messageBufSize, size_t responseBufSize) {
	int bytesRecv = -1;

	// This must be called here because this function is blocking, and we cannot clear it in main.
	// We would like to get new connections even in conversation. See when it is called in main for details.
	ReleaseMutex(hClientListMutex);

	do {
		memset(messageBuf, 0, messageBufSize);
		memset(responseBuf, 0, responseBufSize);

		bytesRecv = recv(remoteDesk, responseBuf, sizeof responseBuf, 0);

		printf("%s", responseBuf);
	} while (bytesRecv >= 0);

	while (1 == 1) {

		memset(messageBuf, 0, messageBufSize);
		memset(responseBuf, 0, responseBufSize);

		gets_s(messageBuf, messageBufSize);

		// Check for exit command

		if (strcmp(messageBuf, "clientlist") == 0) {
			memset(messageBuf, 0, messageBufSize);
			memset(responseBuf, 0, responseBufSize);

			send(remoteDesk, "0", 1, 0);

			break;
		}

		strcat(messageBuf, "\r\n");

		send(remoteDesk, messageBuf, strlen(messageBuf), 0);

		do {
			memset(messageBuf, 0, messageBufSize);
			memset(responseBuf, 0, responseBufSize);

			bytesRecv = recv(remoteDesk, responseBuf, RESPONSESIZE, 0);

			printf("%s", responseBuf);
		} while (bytesRecv >= 0);

	}

	return 0;
}

void handleNewConnectionProc(void* arg) {

	int remoteDesk;
	int sockfd = (int)(uintptr_t)arg;

	if (sockfd == -1) {
		printf("Invalid socket passed to handleNewConnectionProc.");
		ExitProcess(1);
	}

	do {

		remoteDesk = acceptClientOnSock(sockfd);

		WaitForSingleObject(hClientListMutex, INFINITE);

		clientList[clientCount] = remoteDesk;
		clientCount++;

		ReleaseMutex(hClientListMutex);

	} while (clientCount != CLIENTAMOUNT);

	return;
}

void printWelcomeMessage() {
	printf("  _._     _,-'""`-._\n");
	printf(" (,-.`._,'(       |\\`-/|\n");
	printf("    `-.-' \\ )-`( , o o)\n");
	printf("          `-    \\`_`\"'-\n\n");
	printf("GuShell Manager - Lightweight and open source reverse shell manager\n");
	printf("Developed by JohnSwiftC\n\n");
}


int main(int argc, char* argv[]) {

	printWelcomeMessage();

	WSADATA WsaData;
	if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0) {
		printf("Error in WSAStartup.");
		ExitProcess(1);
	}

	hClientListMutex = CreateMutexW(NULL, FALSE, NULL);
	clientCount = 0;

	int remoteDesk;
	int sockfd;

	HANDLE hAcceptClientProcThread;

	// These are huge, just keep them on the heap or downsize them.
	char* messageBuf = (char*)malloc((MESSAGESIZE) * sizeof(char));
	char* responseBuf = (char*)malloc((RESPONSESIZE) * sizeof(char));

	memset(clientList, -1, sizeof clientList);

	if (messageBuf == NULL || responseBuf == NULL) {
		printf("Failed to allocate heap memory.");
		ExitProcess(1);
	}

	if ((sockfd = openSock()) == -1) {
		printf("Failed to open socket.\n");
		ExitProcess(1);
	}

	hAcceptClientProcThread = (HANDLE)_beginthread(handleNewConnectionProc, 0, (void*)(uintptr_t)sockfd);

	int i;
	int clientSelection;

	// Users fault if they overwrite this lol
	char commandBuf[50];
	while (1) {

		while (clientCount == 0) {
			continue;
		}

		printf("Select a client from the connected clients list: \n");

		WaitForSingleObject(hClientListMutex, INFINITE);

		for (i = 0; i < CLIENTAMOUNT; ++i) {
			if (clientList[i] == NULL || clientList[i] == -1) {
				break;
			}

			printf("Client %d\n", (i + 1));
		}

		ReleaseMutex(hClientListMutex);

		// We release here so that we can still take potential connections while the user is taking
		// their sweet time carefulling picking what client to interact with

		memset(commandBuf, 0, sizeof commandBuf);
		gets_s(commandBuf, sizeof commandBuf);
		clientSelection = atoi(commandBuf);

		if (clientSelection == 0 || clientSelection > clientCount) {
			continue;
		}

		WaitForSingleObject(hClientListMutex, INFINITE);

		// Hold the phone here, we access the shared data so we block, but where is the release? I added the release to the beginning
		// if the startConversationWithClient function so that we can still get new connections while using the shell.
		startConversationWithClient(clientList[clientSelection - 1], messageBuf, responseBuf, (size_t)MESSAGESIZE, (size_t)RESPONSESIZE);
	}

	free(messageBuf);
	free(responseBuf);

	WSACleanup();

	CloseHandle(hAcceptClientProcThread);

	return 0;
}