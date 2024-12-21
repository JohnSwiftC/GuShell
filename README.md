# GuShell
**HUGE NOTE:** I CURRENTLY RECOMMEND THE PEBWALK VERSION FOR USE. I LOWKEY HAVE NOT TESTED THE OTHER ONE WITH NEW FEATURES. IT WORKS I PROMISE PROBABLY. (Will make stable branch soon.)

> Lightweight and open source reverse shell client and connection manager built for Windows. (Named after a cat.)

> There are now two versions of the client! `GuShellPebWalk.c` uses a peb walk to get API calls!
> Implementation is closely modeled by this very nice blog post, but I made some changes to their implementation.
> https://fareedfauzi.github.io/2024/07/13/PEB-Walk.html

Find documentation, build settings, and commands here! https://johnswiftc.github.io/GuShell/#/

> Check out https://docsify.js.org/#/ for great GitHub pages, its how I'm making mine! ❤️
# Features
- The manager is capable of managing several connections at once via the clientlist command!
- The shell, while built along side the manager, can likely be used with any listener with how it was made.
- Drop into and out of shells (cmd, PowerShell, etc.) of your choice, move between several on the same machine.
- Stop Defender.
- Persistence in Registry Autostart.
# Want to Learn?
Go check out **Beej's Networking Guide!** This is a great point to start learning about sockets and networking,
and while it might not get everything, especially on Windows, its a good spot to start!
https://beej.us/guide/bgnet/
