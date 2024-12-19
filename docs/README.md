# GuShell

> A lightweight open-source reverse shell client and listener built for Windows.

Hello! If you are looking to use GuShell, please take a look at the `Build` and `Usage` sections!
If you are contributing, feel free to look at the quick function docs. Thank you! 😆

## Build

> I personally have used **Visual Studio 2022** to build and test. I cannot provide clear build instructions outside of Visual Studio!

### Settings

In your project settings, ensure that in `Config Properties > Advanced` you select **Use Unicode Character Set**.

> There is a possibility that not following this could work, and the same is true for the other case. Refer to the `attemptRegistryPersistence`
> function for a case that might break based on the character set.

Under `Linker > Manifest`, ensure that you either set the option **highestAvailable** or **requireAdministrator** on the client.

> Ok, so here's the deal. If you include the **requireAdministrator** option, it will prompt the victim to start in administrator with a window.
> This, of course, might not be great. However, it allows the `attemptDefeatDefender` function to execute without issue, and for the `attemptRegistryPersistence`
> function to get `HKEY_LOCAL_MACHINE` values. There are no garuntees of these functions with the **highestAvailable** option. Use what is optimal for you.

### Macros

> Macros are _**VERY**_ important, do not skip this!

There are several macros to be defined or left alone in both the manager and client, they are listed here.

| Macro          | Description                                                                                                                                     |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `PORT`         | Port to connect over.                                                                                                                           |
| `LOCALTEST`    | If defined in the client, it will use the local address specified by `ADDRESS`. If not, it will use the public facing IP provided to `ADDRESS`. |
| `ADDRESS`      | Is to be defined twice in the client as seen in the source file. Replace each one accordingly.                                                  |
| `DEBUG_CLIENT` | If defined in the client, the client will not hide its window at run time. Disabled by default.                                                 |

There are other macros defined in the source, they are not crucial for operation. Ensure that if you change these, you ensure it does not harm communication.

## Usage

> Commands marked with an \* may not execute, you will maintain a connection and receive an error message.

> Commands marked with a \*\* are exclusive to the manager (most commands run off the client, and will be available on most listening software).

### Text Commands

> These commands must be typed out.

| Command        | Description                                                                                                                                                                        |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| clientlist\*\* | Returns user to the list of active clients.                                                                                                                                        |
| exit           | This command is not from GuShell, rather it is the command to terminate a shell process. GuShell is checking whether a process has been closed before it "pulls out" of the shell. |

### Utility Commands

> These commands are not to be typed out, just type the number prompted by the client for each command.

| Command                        | Description                                                                                                                                                                                                                                                                |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Drop Into Shell                | Creates a shell process on the victim machine that you can talk to. you will be prompted to then type the name of the shell process such as `cmd` or `powershell`. GuShell resumes normal communication after this process is killed by the user, see `startShellProcess`. |
| Attempt Defeat Defender\*      | Attempts to place a Regestry key `DisableAntiSpyware` to permanently disable Windows Defender. May fail due to low elevation.                                                                                                                                              |
| Attempt Registry Persistence\* | Attempts to place auto-start values in both the `HKEY_LOCAL_MACHINE` and `HKEY_CURRENT_USER` registry trees. One or both may fail due to low elevation.                                                                                                                    |

## Function Reference

> All functions are either included in `GuShell.c` or `GuShellManager.c`, sometimes with additional commenting.

##### `int openSock(void)` in `GuShellManager.c`

Opens a socket, binds to the socket, and starts listening on the socket as a server. Uses defined macros such as `PORT`.

Returns: The socket file descriptor of the created socket as `int`.

##### `int acceptClientOnSock(int sockfd)` in `GuShellManager.c`

> Do not use this function outside of where it is intended or there may be nasty side effects.

Intended to be used on a seperate thread to accept incoming connections on the input `sockfd`. Prints output upon incoming connection. Do not use this function elsewhere, it is specifically used in a seperate thread process which is responsible for adding new connections to the client list.

Returns: The socket of the newly established connection.

##### `int startConversationWithClient(int remoteDesk, char * messageBuf, char * responseBuf, size_t messageBufSize, size_t responseBufSize)` in `GuShellManager.c`

This function starts streaming communication between the host and client. Its parameters are the remote connection socket, a message buffer, the size of the message buffer, a response buffer, and the size of the response buffer.

This function releases a globally defined mutex. This is required because the `remoteDesk` input is learned through a shared resource in practice. Always lock the mutex before reading from the client list when calling this function.

This function is blocking. It is the function where the `clientlist` command is called. When this is called, the function returns and exits back to the main input loop.

Returns: Always returns the value `0`. Consider refactoring to `void`.

##### `void handleNewConnectionProc(void * arg)` in `GuShellManager.c`

> Intended to be ran as a thread process.

This function is ran in a thread and engages with a globally defined mutex. The function accepts new connections and places them in the client list. The argument is the sockfd opened with `openSock`.

##### `void printWelcomeMessage()` in `GuShellManager.c`

Prints a cute welcome message. Called in `main`.

##### `int main(int argc, char * argv[])` in `GuShellManager.c`

The manager's main function. It first starts with initializating winsock, creating the global mutex, and allocating a message and reply buffer. It then creates the socket, and the thread that handles new connections.

The main function then runs in an infinite loop that accepts user input, and then starts a conversation using `startConversationWithClient` given user input.

It cleans up before exiting.

##### `SOCKET connectToServer()` in `GuShell.c`

Connects to the manager with predefined macros.

Returns: Socket from the new connection.

##### `void startShellProcess(SOCKET * pSockfd, PROCESS_INFORMATION * pPinfo)` in `GuShell.c`

Requires a pointer to the socket and a pointer to a `PROCESS_INFORMATION` structure. Sends messages to the connected client on the socket input. Starts the shell process as indicated by the attacker, and then blocks until the child process is exited.

##### `void attemptDefeatDefender(SOCKET * pSockfd)` in `GuShell.c`

Requires a pointer to the socket. Attempts to place the `DisableAntiSpyware` registry value into the registry, disabling Windows Defender. This function requires administrator evelation, and will not succeed without it.

##### `void attemptRegistryPersistence(SOCKET * pSockfd)` in `GuShell.c`

Requires a pointer to the socket. Attempts to place the current process directory in the `HKEY_LOCAL_MACHINE` and the `HKEY_CURRENT_USER` autostart keys. This function may fail with one or both keys due to bad elevation.

##### `void cleanManagerInput(char * command, size_t size)` in `GuShell.c`

Cleans the `\r\n` off of manager commands when needed. These characters are typically needed for shell input. This is done inplace to the input `command` string.

##### `int main(int argc, char * argv[])` in `GuShell.c`

Main function for `GuShell.c`. Connects to the server, and then starts an infinite loop. When a command is successfully passed, it calls the associated function.
