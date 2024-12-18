# GuShell
Lightweight and open source reverse shell client and connection manager built for windows. (Named after a cat.)
# Features
- The manager is capable of managing several connections at once via the clientlist command!
- The shell, while built along side the manager, can likely be used with any listener with how it was made! (I have not tested this myself!)
- Drop into and out of shells (cmd, PowerShell, etc.) of your choice, move between several on the same machine.
# Purpose and Usage
This tool is built for educational purposes only, and out of my own curiousity. The only component currently included is the connection manager,
which should *seamlessly* integrate with the typical reverse shell (similar to nc). The client, which I have not built yet, will be built with the features
of changing between command line processes and executing custom code on the client machine (like a very similar tool, but in a lighter and jankier format).

As I said before, this is a fun project for those interested in learning low level concepts, development in cybersecurity, and networking! Contributions are heavily appreciated!

 * *For those in the back, GuShell.c is the victim machine, and GuShellManager.c, well, manages connections.*

**Commands**
- clientlist > Shows connected client list
- exit > typical command to exit most used shells like PowerShell and cmd. Others may be different or not have one at all.
# Build
Please, please, please, use Visual Studio. That is what I used, and I personally just open a blank C++ project and smack a Source.c in there.
CHECK DEFINED MACROS!!! THEY ARE IMPORTANT!!!

**In Visual Studio, go to the Manifest Settings in the Linker settings! Set UAC Execution Level to either "Highest Possible" (recommended) or "Require Admin"**
This will potentially be useful when executing some commands down the line!
# Starting Points
- Check for dropped client connections
- Give it some more style!
- Stop user from shooting themselves in the foot (they can do it a lot!)
# Want to Learn?
Go check out **Beej's Networking Guide!** This is a great point to start learning about sockets and networking,
and while it might not get everything, especially on Windows, its a good spot to start!
https://beej.us/guide/bgnet/
