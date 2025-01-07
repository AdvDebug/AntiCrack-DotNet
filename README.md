# AntiCrack DotNet
A .NET Project which Contains some useful techniques to detect debugging and other harmful actions and bypass methods which can be used by crackers to analyze your assembly. (also feel free to open an issue for adding additional anti-debugging features, etc) with syscall support.

![image](https://github.com/user-attachments/assets/a49389e4-105b-41d4-8f3a-4d5851022c79)


## Anti Debugging
* NtUserGetForegroundWindow (looks for bad active window names to check if it's a known debugger)

* Debugger.IsAttached

* Hide Threads From Debugger

* IsDebuggerPresent

* PEB.BeingDebugged

* PEB.NtGlobalFlag

* NtSetDebugFilterState

* Page Guard Breakpoints Detection

* NtQueryInformationProcess: ProcessDebugFlags, ProcessDebugPort, ProcessDebugObjectHandle

* NtClose: Invalid Handle, Protected Handle

* Parent Process Checking (Checks if parent are explorer.exe or cmd.exe)

* Detection of Hardware Breakpoints

* FindWindow (looks for bad window names)

* GetTickCount

* OutputDebugString

* Crashing Non-Managed Debuggers with a Debugger Breakpoint

* OllyDbg Format String Exploit

* Patching DbgUiRemoteBreakin and DbgBreakPoint (Anti-Debugger Attaching)

## Anti Virtualization

* Detecting Any.run

* Detecting Triage

* Detecting Qemu.

* Detecting Parallels.

* Detecting Sandboxie

* Detecting Comodo Container

* Detecting Qihoo360 Sandbox

* Detecting Cuckoo Sandbox

* Detecting VirtualBox and VMware

* Detecting HyperV

* Detecting Emulation

* Checking For Blacklisted Usernames

* Detecting KVM

* Detecting Wine

* Checking For Known Bad VM File Locations

* Checking For Known Bad Process Names

* Checking For Ports on the system (useful if the VM or the sandbox have no ports connected)

* Checking for devices created by VMs or Sandboxes

* Checking if AVX x64/x86 instructions are properly implemented to see if we are in an emulator.

* Checking for RDRAND x64/x86 instruction to see if it's properly implemented which could indicate an emulator.

* Checking for flags manipulation (for x64 and x86) checks to see if it's correctly handled.

## Anti Dll Injection

* Taking Advantage of Binary Image Signature Mitigation Policy to prevent injecting Non-Microsoft Binaries.

* Checking if any injected libraries are present (simple dlls path whitelist check)

* Thread Injection Detection

* Using PEB to change the main module info of the program which is main module name and module base address at runtime.

* Detecting process hollowing in our program by checking suspicious image base address.

## Other Detections
* Detecting if Unsigned Drivers are Allowed to Load

* Detecting if Test-Signed Drivers are Allowed to Load

* Detecting if Kernel Debugging are Enabled on the System

* Detecting if Secure Boot are Enabled on the System

* Detecting if Virtualization-Based Security is Enabled.

* Detecting if Memory Integrity Protection is Enabled.

* Detecting if the current assembly has been invoked.

## Hooks Detection
* Detecting Most Anti Anti-Debugging Hooking Methods on Common Anti-Debugging Functions by checking for Bad Instructions on Functions Addresses and it detects user-mode anti anti-debuggers like scyllahide, and it can also detect some sandboxes which uses hooking to monitor application behaviour/activity (like <a href="https://github.com/sandboxie-plus/Sandboxie">Sandboxie/Sandboxie Plus</a>, <a href="https://www.hybrid-analysis.com">Hybrid Analysis</a>, <a href="https://cuckoosandbox.org/index.html">Cuckoo Sandbox</a>, and a lot of other online malware analysis websites/applications).

* Basic detection for stealthy page guard hooking.

* Detecting CLR Functions Hooking (like harmony hooks).

# Notice
This Project are created for educational purposes only, also this project are licensed under MIT License. you can use the code however you please, just please use it responsibly (NOT for malware) (e.g. you are developing an anti-cheat).
