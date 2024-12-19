### GuShell
> A lightweight open-source reverse shell client and listener built for Windows.

Hello! If you are looking to use GuShell, please take a look at the 'Build' and 'Usage' sections!
If you are contributing, feel free to look at the quick function docs. Thank you! 😆

## Build
> I personally have used **Visual Studio 2022** to build and test. I cannot provide clear build instructions outside of Visual Studio!
# Settings
In your project settings, ensure that in 'Config Properties > Advanced' you select **Use Unicode Character Set**.
> There is a possibility that not following this could work, and the same is true for the other case. Refer to the 'attemptRegistryPersistence()'
> function for a case that might break based on the character set.
Under 'Linker > Manifest', ensure that you either set the option **highestAvailable** or **requireAdministrator** on the client.
> Ok, so here's the deal. If you include the **requireAdministrator** option, it will prompt the victim to start in administrator with a window.
> This, of course, might not be great. However, it allows the 'attemptDefeatDefender()' function to execute without issue, and for the 'attemptRegistryPersistence()'
> function to get 'HKEY_LOCAL_MACHINE' values. There are no garuntees of these functions with the **highestAvailable** option. Use what is optimal for you.
# Macros
> Macros are _**VERY**_ important, do not skip this!
There are several macros to be defined or left alone in both the manager and client, they are listed here.
Macro | Description
LOCALTEST | If defined in the client, it will use the local address specified by 'ADDRESS'. If not, it will use the public facing IP provided to 'ADDRESS'.
ADDRESS | Is to be defined twice in the client as seen in the source file. Replace each one accordingly.
DEBUG_CLIENT | If defined in the client, the client will not hide its window at run time. Disabled by default.
There are other macros defined in the source, they are not crucial for operation. Ensure that if you change these, you ensure it does not harm communication.
