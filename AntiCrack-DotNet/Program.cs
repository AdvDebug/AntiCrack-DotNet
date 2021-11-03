using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace AntiCrack_DotNet
{
    class Program
    {
        private static void ExecuteAntiDebuggingTricks()
        {
            Console.WriteLine("----------------------------------Executing Anti Debugging Tricks-------------------------------------------------------");
            Console.WriteLine("Debugger.IsAttached: " + AntiDebug.DebuggerIsAttached() + "\n");
            Console.WriteLine("Hide Threads From Debugger.... " + AntiDebug.HideThreadsAntiDebug() + "\n");
            Console.WriteLine("IsDebuggerPresent: " + AntiDebug.IsDebuggerPresentCheck() + "\n");
            Console.WriteLine("CheckRemoteDebuggerPresent / NtQueryInformationProcess: " + AntiDebug.CheckRemoteDebuggerPresentCheck() + "\n");
            Console.WriteLine("CloseHandle Anti Debug: " + AntiDebug.CloseHandleAntiDebug() + "\n");
            Console.WriteLine("Looking For Bad Debuggers Windows (FindWindow): " + AntiDebug.FindWindowAntiDebug() + "\n");
            Console.WriteLine("GetTickCount Anti Debug: " + "Skipped" + "\n");
            Console.WriteLine("OutputDebugString Anti Debug: " + "Skipped" + "\n");
            Console.WriteLine("Executing OllyDbg Format String Exploit.....\n");
            Console.WriteLine("Trying To Crash Non-Managed Debuggers with a Debugger Breakpoint.....\n");
            AntiDebug.DebugBreakAntiDebug();
            Console.WriteLine("Patching DbgUiRemoteBreakIn To Prevent Debugger Attaching..... " + AntiDebug.PatchingDbgUiRemoteBreakin() + "\n");
            Console.WriteLine("------------------------------------------------------------------------------------------------------------------------\n\n");
        }

        private static void ExecuteAntiVirtualizationTricks()
        {
            Console.WriteLine("----------------------------------Executing Anti Virtualization Tricks--------------------------------------------------");
            Console.WriteLine("Checking For Sandboxie Module in Current Process: " + AntiVirtualization.IsSandboxiePresent() + "\n");
            Console.WriteLine("Checking For Comodo Sandbox in Current Process: " + AntiVirtualization.IsComodoSandboxPresent() + "\n");
            Console.WriteLine("Checking For Cuckoo Sandbox Module in Current Process: " + AntiVirtualization.IsCuckooSandboxPresent() + "\n");
            Console.WriteLine("Checking For Qihoo360 Sandbox Module in Current Process: " + AntiVirtualization.IsQihoo360SandboxPresent() + "\n");
            Console.WriteLine("Checking If The Program are Emulated: " + AntiVirtualization.IsEmulationPresent() + "\n");
            Console.WriteLine("Checking For Blacklisted Usernames: " + AntiVirtualization.CheckForBlacklistedNames() + "\n");
            Console.WriteLine("Checking if the Program are running under wine using dll exports detection: " + AntiVirtualization.IsWinePresent() + "\n");
            Console.WriteLine("Checking For VirtualBox and VMware: " + AntiVirtualization.CheckForVMwareAndVirtualBox() + "\n");
            Console.WriteLine("Checking For KVM: " + AntiVirtualization.CheckForKVM() + "\n");
            Console.WriteLine("Checking For HyperV: " + AntiVirtualization.CheckForHyperV() + "\n");
            Console.WriteLine("Trying To Crash Sandboxie if Present......");
            AntiVirtualization.CrashingSandboxie();
            Console.WriteLine("------------------------------------------------------------------------------------------------------------------------\n\n");
        }
        
        private static void ExecuteAntiDllInjectionTricks()
        {
            Console.WriteLine("----------------------------------Executing Anti Dll Injection Tricks---------------------------------------------------");
            Console.WriteLine("Patching LoadLibraryA To Prevent Dll Injection..... " + AntiDllInjection.PatchLoadLibraryA() + "\n");
            Console.WriteLine("Patching LoadLibraryW To Prevent Dll Injection..... " + AntiDllInjection.PatchLoadLibraryW() + "\n");
            Console.WriteLine("------------------------------------------------------------------------------------------------------------------------\n\n");
        }

        static void Main(string[] args)
        {
            Console.Title = "AntiCrack DotNet";
            ExecuteAntiDebuggingTricks();
            ExecuteAntiVirtualizationTricks();
            ExecuteAntiDllInjectionTricks();
            AntiDebug.OllyDbgFormatStringExploit();
            Console.ReadLine();
        }
    }
}
