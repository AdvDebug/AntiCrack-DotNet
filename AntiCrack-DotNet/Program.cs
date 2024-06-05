using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;

namespace AntiCrack_DotNet
{
    class Program
    {
        private class ConsoleConfig
        {
            public static void SetDefaultColors()
            {
                Console.BackgroundColor = ConsoleColor.Black;
                Console.ForegroundColor = ConsoleColor.White;
                Console.Clear();
            }

            public static void SetTitle(string title)
            {
                Console.Title = title;
            }

            public static void DisplayHeader(string header)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"\n------ {header} ------\n");
                Console.ForegroundColor = ConsoleColor.White;
            }

            public static void DisplayFooter()
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("---------------------------------------------------------\n");
                Console.ForegroundColor = ConsoleColor.White;
            }

            public static void DisplayResult(string text, bool result, string info = "")
            {
                Console.Write(text);
                if (result)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write("[Bad] ");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write("[Good] ");
                }
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine(info);
                Console.ForegroundColor = ConsoleColor.White;
            }

            public static void DisplayResult(string text, string result, string info = "")
            {
                Console.Write(text);
                switch (result)
                {
                    case "[Bad]":
                    case "Failed":
                        Console.ForegroundColor = ConsoleColor.Red;
                        break;
                    case "Skipped":
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        break;
                    default:
                        Console.ForegroundColor = ConsoleColor.Green;
                        break;
                }
                Console.WriteLine($"{result} {info}");
                Console.ForegroundColor = ConsoleColor.White;
            }
        }

        private static void ExecuteAntiDebuggingTricks()
        {
            ConsoleConfig.DisplayHeader("Executing Anti Debugging Tricks");
            ConsoleConfig.DisplayResult("GetForegroundWindow (Looking For Bad Active Debugger Window): ", AntiDebug.GetForegroundWindowAntiDebug(), "Checks if a debugger window is in the foreground.");
            ConsoleConfig.DisplayResult("Debugger.IsAttached: ", AntiDebug.DebuggerIsAttached(), "Checks if a managed debugger is attached.");
            ConsoleConfig.DisplayResult("Hide Threads From Debugger..... ", AntiDebug.HideThreadsAntiDebug(), "Attempts to hide threads from the debugger.");
            ConsoleConfig.DisplayResult("IsDebuggerPresent: ", AntiDebug.IsDebuggerPresentCheck(), "Checks if a debugger is present.");
            ConsoleConfig.DisplayResult("NtSetDebugFilterState Check: ", AntiDebug.NtSetDebugFilterStateAntiDebug(), "Sets the debug filter state.");
            ConsoleConfig.DisplayResult("Page Guard Breakpoints Detection Check: ", AntiDebug.PageGuardAntiDebug(), "Detects page guard breakpoints.");
            ConsoleConfig.DisplayResult("NtQueryInformationProcess ProcessDebugFlags: ", AntiDebug.NtQueryInformationProcessCheck_ProcessDebugFlags(), "Queries process debug flags.");
            ConsoleConfig.DisplayResult("NtQueryInformationProcess ProcessDebugPort: ", AntiDebug.NtQueryInformationProcessCheck_ProcessDebugPort(), "Queries process debug port.");
            ConsoleConfig.DisplayResult("NtQueryInformationProcess ProcessDebugObjectHandle: ", AntiDebug.NtQueryInformationProcessCheck_ProcessDebugObjectHandle(), "Queries process debug object handle.");
            ConsoleConfig.DisplayResult("NtClose (Invalid Handle): ", AntiDebug.NtCloseAntiDebug_InvalidHandle(), "Tests NtClose with an invalid handle.");
            ConsoleConfig.DisplayResult("NtClose (Protected Handle): ", AntiDebug.NtCloseAntiDebug_ProtectedHandle(), "Tests NtClose with a protected handle.");
            ConsoleConfig.DisplayResult("Parent Process (Checking if the parent process is cmd.exe or explorer.exe): ", AntiDebug.ParentProcessAntiDebug(), "Checks if the parent process is a known process.");
            ConsoleConfig.DisplayResult("Hardware Registers Breakpoints Detection: ", AntiDebug.HardwareRegistersBreakpointsDetection(), "Detects hardware register breakpoints.");
            ConsoleConfig.DisplayResult("FindWindow (Looking For Bad Debugger Windows): ", AntiDebug.FindWindowAntiDebug(), "Finds windows with debugger-related titles.");
            ConsoleConfig.DisplayResult("GetTickCount Anti Debug: ", "Skipped", "Unreliable for real anti-debug use.");
            ConsoleConfig.DisplayResult("OutputDebugString Anti Debug: ", "Skipped", "Unreliable for real anti-debug use.");
            ConsoleConfig.DisplayResult("Trying To Crash Non-Managed Debuggers with a Debugger Breakpoint..... ", "Skipped");
            Console.WriteLine("Executing OllyDbg Format String Exploit.....");
            AntiDebug.OllyDbgFormatStringExploit();
            ConsoleConfig.DisplayResult("Patching DbgUiRemoteBreakin and DbgBreakPoint To Prevent Debugger Attaching..... ", AntiDebug.AntiDebugAttach(), "Patches functions to prevent debugger attaching.");
            ConsoleConfig.DisplayFooter();
        }

        private static void ExecuteAntiVirtualizationTricks()
        {
            ConsoleConfig.DisplayHeader("Executing Anti Virtualization Tricks");
            ConsoleConfig.DisplayResult("Checking For Sandboxie Module in Current Process: ", AntiVirtualization.IsSandboxiePresent(), "Checks if Sandboxie is present.");
            ConsoleConfig.DisplayResult("Checking For Comodo Sandbox Module in Current Process: ", AntiVirtualization.IsComodoSandboxPresent(), "Checks if Comodo Sandbox is present.");
            ConsoleConfig.DisplayResult("Checking For Cuckoo Sandbox Module in Current Process: ", AntiVirtualization.IsCuckooSandboxPresent(), "Checks if Cuckoo Sandbox is present.");
            ConsoleConfig.DisplayResult("Checking For Qihoo360 Sandbox Module in Current Process: ", AntiVirtualization.IsQihoo360SandboxPresent(), "Checks if Qihoo360 Sandbox is present.");
            ConsoleConfig.DisplayResult("Checking If The Program is Emulated: ", AntiVirtualization.IsEmulationPresent(), "Checks if the program is emulated.");
            ConsoleConfig.DisplayResult("Checking For Blacklisted Usernames: ", AntiVirtualization.CheckForBlacklistedNames(), "Checks if the username is blacklisted.");
            ConsoleConfig.DisplayResult("Checking if the Program is running under wine using dll exports detection: ", AntiVirtualization.IsWinePresent(), "Checks if the program is running under Wine.");
            ConsoleConfig.DisplayResult("Checking For VirtualBox and VMware: ", AntiVirtualization.CheckForVMwareAndVirtualBox(), "Checks if the program is running in VirtualBox or VMware.");
            ConsoleConfig.DisplayResult("Checking For KVM: ", AntiVirtualization.CheckForKVM(), "Checks if the program is running in KVM.");
            ConsoleConfig.DisplayResult("Checking For HyperV: ", AntiVirtualization.CheckForHyperV(), "Checks if the program is running in HyperV.");
            ConsoleConfig.DisplayResult("Checking For Known Bad VM File Locations: ", AntiVirtualization.BadVMFilesDetection(), "Detects known bad VM file locations.");
            ConsoleConfig.DisplayResult("Checking For Known Bad Process Names: ", AntiVirtualization.BadVMProcessNames(), "Detects known bad VM process names.");
            ConsoleConfig.DisplayResult("Checking For Ports (useful to detect VMs which have no ports connected): ", AntiVirtualization.PortConnectionAntiVM(), "Checks for VM port connections.");
            Console.WriteLine("Trying To Crash Sandboxie if Present......");
            ConsoleConfig.DisplayResult("Checking for devices created by VMs or Sandboxes: ", AntiVirtualization.CheckDevices(), "Checks for VM or sandbox devices.");
            AntiVirtualization.CrashingSandboxie();
            ConsoleConfig.DisplayFooter();
        }

        private static void ExecuteAntiDllInjectionTricks()
        {
            ConsoleConfig.DisplayHeader("Executing Anti DLL Injection Tricks");
            ConsoleConfig.DisplayResult("Patching and Changing LoadLibraryA Page Protection To Prevent DLL Injection..... ", AntiDllInjection.PatchLoadLibraryA(), "Patches LoadLibraryA to prevent DLL injection.");
            ConsoleConfig.DisplayResult("Patching and Changing LoadLibraryW Page Protection To Prevent DLL Injection..... ", AntiDllInjection.PatchLoadLibraryW(), "Patches LoadLibraryW to prevent DLL injection.");
            ConsoleConfig.DisplayResult("Taking Advantage of Binary Image Signature Mitigation Policy to Prevent Non-Microsoft Binaries From Being Injected..... ", AntiDllInjection.BinaryImageSignatureMitigationAntiDllInjection(), "Enforces binary image signature mitigation policy.");
            ConsoleConfig.DisplayResult("Checking if any injected libraries are present (simple DLL path whitelist check): ", AntiDllInjection.IsInjectedLibrary(), "Checks for injected libraries.");
            ConsoleConfig.DisplayFooter();
        }

        private static void ExecuteOtherDetectionTricks()
        {
            ConsoleConfig.DisplayHeader("Executing Other Detection Tricks");
            ConsoleConfig.DisplayResult("Detecting if Unsigned Drivers are Allowed to Load: ", OtherChecks.IsUnsignedDriversAllowed(), "Checks if unsigned drivers are allowed.");
            ConsoleConfig.DisplayResult("Detecting if Test-Signed Drivers are Allowed to Load: ", OtherChecks.IsTestSignedDriversAllowed(), "Checks if test-signed drivers are allowed.");
            ConsoleConfig.DisplayResult("Detecting if Kernel Debugging is Enabled on the System: ", OtherChecks.IsKernelDebuggingEnabled(), "Checks if kernel debugging is enabled.");
            ConsoleConfig.DisplayResult("Detecting if Secure Boot is Enabled on the System: ", OtherChecks.IsSecureBootEnabled(), "Checks if secure boot is enabled.");
            ConsoleConfig.DisplayFooter();
        }

        private static void ExecuteHooksDetectionTricks()
        {
            ConsoleConfig.DisplayHeader("Executing Hooks Detection Tricks");
            ConsoleConfig.DisplayResult("Detecting Hooks on Common WinAPI Functions by checking for Bad Instructions on Functions Addresses (Most Effective on x64): ", HooksDetection.DetectHooksOnCommonWinAPIFunctions(null, null), "Detects hooks on common WinAPI functions.");
            ConsoleConfig.DisplayFooter();
        }

        static void Main(string[] args)
        {
            ConsoleConfig.SetDefaultColors();
            ConsoleConfig.SetTitle("AntiCrack DotNet");
            while (true)
            {
                ExecuteAntiDebuggingTricks();
                ExecuteAntiVirtualizationTricks();
                ExecuteAntiDllInjectionTricks();
                ExecuteOtherDetectionTricks();
                ExecuteHooksDetectionTricks();
                Console.WriteLine("Press Enter to run again or Ctrl+C to exit...");
                Console.ReadLine();
            }
        }
    }
}
