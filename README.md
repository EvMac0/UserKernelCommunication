## Alternate communication between kernel driver and user mode app WITHOUT:
1) system threads
2) IRP, IOCTL
3) sockets

#### Motivation:
Try to hide our communication from anti-cheats/anti-viruses.

Communication must haven't driver device and using asm shellcode.
Based on shared memory!

My solution:
1) Create user-mode app with two thread. First thread - main thread, second - sleep thread
2) Create FileMapping and fill data of the sleep thread
3) Load driver with test sign or buy cert or sign your driver with leaked cert
4) Driver allocates memory and fill asm shellcode
4) Kernel driver gets data from the FileMapping, find sleep user-mode thread and hijack ret address in stack of this thread
5) Now, user-mode thread hijacked to our asm shellcode
6) Unload your driver and clear all traces

Worked on:
Win7+ x64

PatchGuard compitable on all Windows 10 versions!


#### How to detect it?
Scan all user-mode threads and walk through their stacks
If ret address in stack is located in unknown memory, that maybe PatchGuard or using this method
