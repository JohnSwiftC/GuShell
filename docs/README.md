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
