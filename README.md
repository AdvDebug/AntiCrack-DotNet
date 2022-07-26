# AntiCrack DotNet
A C# Project which Contains the Most Advanced Anti-Cracking Methods Ever Made in C#.

<img width="960" alt="AntiCrackDotNet_1 2" src="https://user-images.githubusercontent.com/90452585/180578537-d3817dc7-6398-4c3b-b7aa-a46d6a604d45.PNG">

## Anti Debugging
* GetForegroundWindow (looks for bad active window names to check if it's a known debugger)

* Debugger.IsAttached

* Hide Threads From Debugger

* IsDebuggerPresent

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

* Making Sandboxie Crash Your Application (this exploit no longer works, it's patched by sandboxie, that's what i get for making things public :), now it works only with older versions of sandboxie)

## Anti Dll Injection
* Patching LoadLibraryA

* Patching LoadLibraryW

* Taking Advantage of Binary Image Signature Mitigation Policy to prevent injecting Non-Microsoft Binaries.

## Other Detections
* Detecting if Unsigned Drivers are Allowed to Load

* Detecting if Test-Signed Drivers are Allowed to Load

* Detecting if Kernel Debugging are Enabled on the System

## Hooks Detection
* Detecting Most Anti Anti-Debugging Hooking Methods on Common Anti-Debugging Functions by checking for Bad Instructions on Functions Addresses (Most Effective on x64)

# Notice
This Project are created for educational purposes only, also this project are licensed under MIT License.
