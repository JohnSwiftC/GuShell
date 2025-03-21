# GuShell

**LATEST UPDATE: UAC Bypass!**

**All source files can be found in `GuShellClient`.**

UPDATE: Finally easy to build! Just clone and build solution as Release, look at video linked below. Also, a problem with the manager was fixed. It now works even when compiled with compiler optimizations! (On by default)
> Lightweight and open source reverse shell client and connection manager built for Windows. (Named after a cat.)

> There are now two versions of the client! `GuShellPebWalk.c` uses a peb walk to get API calls!
> Implementation is closely modeled by this very nice blog post, but I made some changes to their implementation.
> https://fareedfauzi.github.io/2024/07/13/PEB-Walk.html

Find documentation, build settings, and commands here! https://johnswiftc.github.io/GuShell/#/
Easy build tutorial if you are still lost, https://www.youtube.com/watch?v=v0s6J8l7FcE

> Check out https://docsify.js.org/#/ for great GitHub pages, its how I'm making mine! ❤️
# Features
- The manager is capable of managing several connections at once via the clientlist command!
- The shell, while built along side the manager, can likely be used with any listener with how it was made.
- Drop into and out of shells (cmd, PowerShell, etc.) of your choice, move between several on the same machine.
- Stop Defender.
- Persistence in Registry Autostart.
- Persistence in AppData files
- UAC Bypass.

# Warning!
This repo is for cybersecurity education only! I am making this out of interest in network programming, low level programming, malware reverse engineering and general cybersecurity! I am not liable for people who attempt to use this tool outside of what I have made it for. Thank you!
# Want to Learn?
Go check out **Beej's Networking Guide!** This is a great point to start learning about sockets and networking,
and while it might not get everything, especially on Windows, its a good spot to start!
https://beej.us/guide/bgnet/

Also, I have a [blog](https://johnswiftc.github.io/) to yap in when I get bored now.
