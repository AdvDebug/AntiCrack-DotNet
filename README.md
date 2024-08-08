# AntiCrack DotNet
A C# Project which Contains some Anti-Cracking, anti memory injection techniques, etc. (also feel free to open an issue for adding additional anti-debugging features, etc)

![Damn](https://github.com/AdvDebug/AntiCrack-DotNet/assets/90452585/db8a12aa-b3c6-47db-bb72-6db6894567c7)

## Anti Debugging
* GetForegroundWindow (looks for bad active window names to check if it's a known debugger)

* Debugger.IsAttached

* Hide Threads From Debugger

* IsDebuggerPresent

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

* Making Sandboxie Crash Your Application (no longer works)

* Checking for devices created by VMs or Sandboxes

## Anti Dll Injection
* Patching LoadLibraryA

* Patching LoadLibraryW

* Taking Advantage of Binary Image Signature Mitigation Policy to prevent injecting Non-Microsoft Binaries.

* Checking if any injected libraries are present (simple dlls path whitelist check)

## Other Detections
* Detecting if Unsigned Drivers are Allowed to Load

* Detecting if Test-Signed Drivers are Allowed to Load

* Detecting if Kernel Debugging are Enabled on the System

* Detecting if Secure Boot are Enabled on the System

* Detecting if Virtualization-Based Security is Enabled.

* Detecting if Memory Integrity Protection is Enabled.

* Detecting if the current assembly has been invoked.

## Hooks Detection
* Detecting Most Anti Anti-Debugging Hooking Methods on Common Anti-Debugging Functions by checking for Bad Instructions on Functions Addresses and it detects user-mode anti anti-debuggers like scyllahide, and it can also detect some sandboxes which uses hooking to monitor application behaviour/activity (like <a href="https://github.com/sandboxie-plus/Sandboxie">Sandboxie/Sandboxie Plus</a>, <a href="https://www.hybrid-analysis.com">Hybrid Analysis</a>, <a href="https://cuckoosandbox.org/">Cuckoo Sandbox</a>, and a lot of other online malware analysis websites/applications).

* Detecting CLR Functions Hooking (like harmony hooks). (works only under x86)

# Notice
This Project are created for educational purposes only, also this project are licensed under MIT License.
