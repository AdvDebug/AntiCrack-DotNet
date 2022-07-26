using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;

namespace AntiCrack_DotNet
{
    class Program
    {
        public static void DisplayCheckResult(string Text, bool Result)
        {
            if (Result == true)
            {
                Console.Write(Text);
                Console.ForegroundColor = ConsoleColor.DarkRed;
                Console.Write("[Bad]" + "\n\n");
                Console.ForegroundColor = ConsoleColor.White;
            }
            else
            {
                Console.Write(Text);
                Console.ForegroundColor = ConsoleColor.DarkGreen;
                Console.Write("[Good]" + "\n\n");
                Console.ForegroundColor = ConsoleColor.White;
            }
        }

        public static void DisplayCheckResult(string Text, string Result)
        {
            if (Result == "[Bad]" || Result == "Failed")
            {
                Console.Write(Text);
                Console.ForegroundColor = ConsoleColor.DarkRed;
                Console.Write(Result + "\n\n");
                Console.ForegroundColor = ConsoleColor.White;
            }
            else if (Result == "Skipped")
            {
                Console.Write(Text);
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.Write($"[{Result}]" + "\n\n");
                Console.ForegroundColor = ConsoleColor.White;
            }
            else
            {
                Console.Write(Text);
                Console.ForegroundColor = ConsoleColor.DarkGreen;
                Console.Write(Result + "\n\n");
                Console.ForegroundColor = ConsoleColor.White;
            }
        }

        private static void ExecuteAntiDebuggingTricks()
        {
            Console.WriteLine("----------------------------------Executing Anti Debugging Tricks-------------------------------------------------------");
            DisplayCheckResult("GetForegroundWindow (Looking For Bad Active Debugger Window): ", AntiDebug.GetForegroundWindowAntiDebug());
            DisplayCheckResult("Debugger.IsAttached: ", AntiDebug.DebuggerIsAttached());
            DisplayCheckResult("Hide Threads From Debugger..... ", AntiDebug.HideThreadsAntiDebug());
            DisplayCheckResult("IsDebuggerPresent: ", AntiDebug.IsDebuggerPresentCheck());
            DisplayCheckResult("NtQueryInformationProcess ProcessDebugFlags: ", AntiDebug.NtQueryInformationProcessCheck_ProcessDebugFlags());
            DisplayCheckResult("NtQueryInformationProcess ProcessDebugPort: ", AntiDebug.NtQueryInformationProcessCheck_ProcessDebugPort());
            DisplayCheckResult("NtQueryInformationProcess ProcessDebugObjectHandle: ", AntiDebug.NtQueryInformationProcessCheck_ProcessDebugObjectHandle());
            DisplayCheckResult("NtClose (Invalid Handle): ", AntiDebug.NtCloseAntiDebug_InvalidHandle());
            DisplayCheckResult("NtClose (Protected Handle): ", AntiDebug.NtCloseAntiDebug_ProtectedHandle());
            DisplayCheckResult("Parent Process (Checking if the parent process are cmd.exe or explorer.exe): ", AntiDebug.ParentProcessAntiDebug());
            DisplayCheckResult("Hardware Registers Breakpoints Detection: ", AntiDebug.HardwareRegistersBreakpointsDetection());
            DisplayCheckResult("FindWindow (Looking For Bad Debugger Windows): ", AntiDebug.FindWindowAntiDebug());
            DisplayCheckResult("GetTickCount Anti Debug: ", "Skipped"); //it's unreliable for real anti-debug use
            DisplayCheckResult("OutputDebugString Anti Debug: ", "Skipped"); //it's unreliable for real anti-debug use
            DisplayCheckResult("Trying To Crash Non-Managed Debuggers with a Debugger Breakpoint..... ", "Skipped");
            //AntiDebug.DebugBreakAntiDebug(); //Not that useful, easily bypassable, and delays execution.
            Console.Write("Executing OllyDbg Format String Exploit.....\n\n");
            AntiDebug.OllyDbgFormatStringExploit();
            DisplayCheckResult("Patching DbgUiRemoteBreakin and DbgBreakPoint To Prevent Debugger Attaching..... ", AntiDebug.AntiDebugAttach());
            Console.WriteLine("------------------------------------------------------------------------------------------------------------------------\n\n");
        }

        private static void ExecuteAntiVirtualizationTricks()
        {
            Console.WriteLine("----------------------------------Executing Anti Virtualization Tricks--------------------------------------------------");
            DisplayCheckResult("Checking For Sandboxie Module in Current Process: ", AntiVirtualization.IsSandboxiePresent());
            DisplayCheckResult("Checking For Comodo Sandbox Module in Current Process: ", AntiVirtualization.IsComodoSandboxPresent());
            DisplayCheckResult("Checking For Cuckoo Sandbox Module in Current Process: ", AntiVirtualization.IsCuckooSandboxPresent());
            DisplayCheckResult("Checking For Qihoo360 Sandbox Module in Current Process: ", AntiVirtualization.IsQihoo360SandboxPresent());
            DisplayCheckResult("Checking If The Program are Emulated: ", AntiVirtualization.IsEmulationPresent());
            DisplayCheckResult("Checking For Blacklisted Usernames: ", AntiVirtualization.CheckForBlacklistedNames());
            DisplayCheckResult("Checking if the Program are running under wine using dll exports detection: ", AntiVirtualization.IsWinePresent());
            DisplayCheckResult("Checking For VirtualBox and VMware: ", AntiVirtualization.CheckForVMwareAndVirtualBox());
            DisplayCheckResult("Checking For KVM: ", AntiVirtualization.CheckForKVM());
            DisplayCheckResult("Checking For HyperV: ", AntiVirtualization.CheckForHyperV());
            DisplayCheckResult("Checking For Known Bad VM File Locations: ", AntiVirtualization.BadVMFilesDetection());
            DisplayCheckResult("Checking For Known Bad Process Names: ", AntiVirtualization.BadVMProcessNames());
            DisplayCheckResult("Checking For Ports (useful to detect VMs which have no ports connected): ", AntiVirtualization.PortConnectionAntiVM());
            Console.Write("Trying To Crash Sandboxie if Present......\n\n");
            AntiVirtualization.CrashingSandboxie();
            Console.WriteLine("------------------------------------------------------------------------------------------------------------------------\n\n");
        }

        private static void ExecuteAntiDllInjectionTricks()
        {
            Console.WriteLine("----------------------------------Executing Anti Dll Injection Tricks---------------------------------------------------");
            DisplayCheckResult("Patching LoadLibraryA To Prevent Dll Injection..... ", AntiDllInjection.PatchLoadLibraryA());
            DisplayCheckResult("Patching LoadLibraryW To Prevent Dll Injection..... ", AntiDllInjection.PatchLoadLibraryW());
            DisplayCheckResult("Taking Advantage of Binary Image Signature Mitigation Policy to Prevent Non-Microsoft Binaries From Being Injected..... ", AntiDllInjection.BinaryImageSignatureMitigationAntiDllInjection());
            Console.WriteLine("------------------------------------------------------------------------------------------------------------------------\n\n");
        }

        private static void ExecuteOtherDetectionTricks()
        {
            Console.WriteLine("----------------------------------Executing Other Detection Tricks-----------------------------------------------------\n");
            DisplayCheckResult("Detecting if Unsigned Drivers are Allowed to Load: ", OtherChecks.IsUnsignedDriversAllowed());
            DisplayCheckResult("Detecting if Test-Signed Drivers are Allowed to Load: ", OtherChecks.IsTestSignedDriversAllowed());
            DisplayCheckResult("Detecting if Kernel Debugging are Enabled on the System: ", OtherChecks.IsKernelDebuggingEnabled());
            Console.WriteLine("------------------------------------------------------------------------------------------------------------------------\n\n");
        }

        private static void ExecuteHooksDetectionTricks()
        {
            Console.WriteLine("----------------------------------Executing Hooks Detection Tricks------------------------------------------------------");
            DisplayCheckResult("Detecting Most Anti Anti-Debugging Hooking Methods on Common Anti-Debugging Functions by checking for Bad Instructions on Functions Addresses (Most Effective on x64): ", HooksDetection.DetectBadInstructionsOnCommonAntiDebuggingFunctions());
            Console.WriteLine("------------------------------------------------------------------------------------------------------------------------\n\n");
        }

        static void Main(string[] args)
        {
            Console.Title = "AntiCrack DotNet";
            for (;;)
            {
                ExecuteAntiDebuggingTricks();
                ExecuteAntiVirtualizationTricks();
                ExecuteAntiDllInjectionTricks();
                ExecuteOtherDetectionTricks();
                ExecuteHooksDetectionTricks();
                Console.ReadLine();
            }
        }
    }
}