using System;
using System.Reflection;
using System.Globalization;

namespace AntiCrack_DotNet
{
    internal sealed class Program
    {
        private sealed class ConsoleConfig
        {
            public static bool IsHooksEnabled = true;
            public static bool IsAntiDebugChecksEnabled = true;
            public static bool IsAntiVirtualizationChecksEnabled = true;
            public static bool IsAntiInjectionEnabled = true;
            public static bool IsOtherDetectionChecksEnabled = true;
            public static bool IsAntiHookChecksEnabled = true;

            public static void ProcessArgs(string[] args)
            {
                if (args != null && args.Length != 0)
                {
                    foreach (string arg in args)
                    {
                        string lower_arg = CultureInfo.CurrentCulture.TextInfo.ToLower(arg);
                        switch (lower_arg)
                        {
                            case "--disable-hooks":
                                IsHooksEnabled = false;
                                break;
                            case "--disable-antidebug":
                                IsAntiDebugChecksEnabled = false;
                                break;
                            case "--disable-antivirtualization":
                                IsAntiVirtualizationChecksEnabled = false;
                                break;
                            case "--disable-antiinjection":
                                IsAntiInjectionEnabled = false;
                                break;
                            case "--disable-otherdetections":
                                IsOtherDetectionChecksEnabled = false;
                                break;
                            case "--disable-hooksdetection":
                                IsAntiHookChecksEnabled = false;
                                break;
                        }
                    }
                }
            }

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

            public static void DisplayResult(string text, bool result, bool SwapResult, string Info = "")
            {
                Console.Write(text);
                if (result)
                {
                    if (SwapResult)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write("[Good] ");
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.Write("[Bad] ");
                    }
                }
                else
                {
                    if (SwapResult)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.Write("[Bad] ");
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write("[Good] ");
                    }
                }
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine(Info);
                Console.ForegroundColor = ConsoleColor.White;

            }

            public static void DisplayResult(string text, string result, string Info = "")
            {
                Console.Write(text);
                string lower_result = CultureInfo.CurrentCulture.TextInfo.ToLower(result);
                switch (lower_result)
                {
                    case "[bad]":
                    case "failed":
                        Console.ForegroundColor = ConsoleColor.Red;
                        break;
                    case "skipped":
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        break;
                    default:
                        Console.ForegroundColor = ConsoleColor.Green;
                        break;
                }

                if (lower_result.Contains("failed") || lower_result.Contains("success") || lower_result.Contains("skipped") || lower_result.Contains("bad"))
                {
                    Console.WriteLine($"[Operation Result = {result}] {Info}");
                }
                else
                {
                    Console.WriteLine($"{result} {Info}");
                }
                Console.ForegroundColor = ConsoleColor.White;
            }

            public static void SyscallPrompt()
            {
                string Arch = IntPtr.Size == 8 ? "[x64 Environment]" : "[x86 Environment]";
                SetTitle($"AntiCrack DotNet {Arch} | Syscall Mode: Undetermined");
                Console.Write("Do you want to use syscalls for some of the detections? (Y/N): ");
                string Response = Console.ReadLine().ToLower();
                Console.Clear();
                if (Response == "y" || Response == "yes")
                {
                    syscall = true;
                    SetTitle($"AntiCrack DotNet {Arch} | Syscall Mode: {syscall}");
                    Syscalls.InitSyscall();
                    Syscalls.BuildNumber = Syscalls.GetBuildNumber(false, true);
                    if (!Syscalls.IsBuildNumberSaved())
                    {
                        Console.ForegroundColor = ConsoleColor.DarkRed;
                        Console.WriteLine("your system build number is not saved, we will try to get the most common syscall number used across platforms or dynamically get the syscalls and work with what we got.");
                        Console.ForegroundColor = ConsoleColor.White;
                    }
                }
                else
                {
                    SetTitle($"AntiCrack DotNet {Arch} | Syscall Mode: {syscall}");
                }
            }
        }

        private static bool syscall = false;

        private static void ExecuteHooks()
        {
            if (!ConsoleConfig.IsHooksEnabled)
                return;
            ConsoleConfig.DisplayHeader("Executing Hooks");
            ConsoleConfig.DisplayResult("Prevent unauthorized retrieval of .NET functions pointer: ", Hooks.PreventUnauthorizedFunctionPointerRetrieval(true, new MethodInfo[] { typeof(Utils).GetMethod("GetPointer", BindingFlags.Public | BindingFlags.Static) }, null), true, "Prevents unauthorized retrieval of .NET functions pointer to prevent raw memory modifications of functions at runtime by whitelisting our own function to get the pointer for the other checks. you should use, test, and modify it carefully based on your needs if you wanna use it in real-world apps or games.");
            ConsoleConfig.DisplayFooter();
        }

        private static void ExecuteAntiDebuggingTricks()
        {
            if (!ConsoleConfig.IsAntiDebugChecksEnabled)
                return;
            ConsoleConfig.DisplayHeader("Executing Anti Debugging Tricks");
            ConsoleConfig.DisplayResult("NtUserGetForegroundWindow (Looking For Bad Active Debugger Windows): ", AntiDebug.NtUserGetForegroundWindowAntiDebug(), false, "Checks if a debugger window is in the foreground.");
            ConsoleConfig.DisplayResult("Debugger.IsAttached: ", AntiDebug.DebuggerIsAttached(), false, "Checks if a managed debugger is attached.");
            ConsoleConfig.DisplayResult("Hide Threads From Debugger..... ", AntiDebug.HideThreadsAntiDebug(), "Attempts to hide threads from the debugger.");
            ConsoleConfig.DisplayResult("IsDebuggerPresent: ", AntiDebug.IsDebuggerPresentCheck(), false, "Checks if a debugger is present.");
            ConsoleConfig.DisplayResult("Checking for the BeingDebugged flag from the PEB directly: ", AntiDebug.BeingDebuggedCheck(), false, "Checks for the BeingDebugged flag from PEB instead of IsDebuggerPresent.");
            ConsoleConfig.DisplayResult("Checking for the NtGlobalFlag from the PEB directly: ", AntiDebug.NtGlobalFlagCheck(), false, "Checks for the NtGlobalFlag from the PEB.");
            ConsoleConfig.DisplayResult("NtSetDebugFilterState Check: ", AntiDebug.NtSetDebugFilterStateAntiDebug(), false, "Sets the debug filter state.");
            ConsoleConfig.DisplayResult("Page Guard Breakpoints Detection Check: ", AntiDebug.PageGuardAntiDebug(), false, "Detects page guard breakpoints.");
            ConsoleConfig.DisplayResult("NtQueryInformationProcess ProcessDebugFlags: ", AntiDebug.NtQueryInformationProcessCheck_ProcessDebugFlags(syscall), false, "Queries process debug flags.");
            ConsoleConfig.DisplayResult("NtQueryInformationProcess ProcessDebugPort: ", AntiDebug.NtQueryInformationProcessCheck_ProcessDebugPort(syscall), false, "Queries process debug port.");
            ConsoleConfig.DisplayResult("NtQueryInformationProcess ProcessDebugObjectHandle: ", AntiDebug.NtQueryInformationProcessCheck_ProcessDebugObjectHandle(syscall), false, "Queries process debug object handle.");
            ConsoleConfig.DisplayResult("NtClose (Invalid Handle): ", AntiDebug.NtCloseAntiDebug_InvalidHandle(syscall), false, "Tests NtClose with an invalid handle.");
            ConsoleConfig.DisplayResult("NtClose (Protected Handle): ", AntiDebug.NtCloseAntiDebug_ProtectedHandle(syscall), false, "Tests NtClose with a protected handle.");
            ConsoleConfig.DisplayResult("Parent Process (Checking if the parent process is cmd.exe or explorer.exe): ", AntiDebug.ParentProcessAntiDebug(syscall), false, "Checks if the parent process is a known process.");
            ConsoleConfig.DisplayResult("Hardware Registers Breakpoints Detection: ", AntiDebug.HardwareRegistersBreakpointsDetection(), false, "Detects hardware register breakpoints.");
            ConsoleConfig.DisplayResult("FindWindow (Looking For Bad Debugger Windows): ", AntiDebug.FindWindowAntiDebug(), false, "Finds windows with debugger-related titles.");
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
            if (!ConsoleConfig.IsAntiVirtualizationChecksEnabled)
                return;
            ConsoleConfig.DisplayHeader("Executing Anti Virtualization Tricks");
            ConsoleConfig.DisplayResult("Checking For Any.run: ", AntiVirtualization.AnyRunCheck(), false, "Checks if Any.run is present through crypto id.");
            ConsoleConfig.DisplayResult("Checking For Triage: ", AntiVirtualization.TriageCheck(), false, "Checks if Triage is present through disk.");
            ConsoleConfig.DisplayResult("Checking For Qemu: ", AntiVirtualization.CheckForQemu(), false, "Checks if running under Qemu.");
            ConsoleConfig.DisplayResult("Checking For Parallels: ", AntiVirtualization.CheckForParallels(), false, "Checks if running under Parallels.");
            ConsoleConfig.DisplayResult("Checking For Sandboxie Module in Current Process: ", AntiVirtualization.IsSandboxiePresent(), false, "Checks if Sandboxie is present.");
            ConsoleConfig.DisplayResult("Checking For Comodo Sandbox Module in Current Process: ", AntiVirtualization.IsComodoSandboxPresent(), false, "Checks if Comodo Sandbox is present.");
            ConsoleConfig.DisplayResult("Checking For Cuckoo Sandbox Module in Current Process: ", AntiVirtualization.IsCuckooSandboxPresent(), false, "Checks if Cuckoo Sandbox is present.");
            ConsoleConfig.DisplayResult("Checking For Qihoo360 Sandbox Module in Current Process: ", AntiVirtualization.IsQihoo360SandboxPresent(), false, "Checks if Qihoo360 Sandbox is present.");
            ConsoleConfig.DisplayResult("Checking For Blacklisted Usernames: ", AntiVirtualization.CheckForBlacklistedNames(), false, "Checks if the username is blacklisted.");
            ConsoleConfig.DisplayResult("Checking if the Program is running under wine using dll exports detection: ", AntiVirtualization.IsWinePresent(), false, "Checks if the program is running under Wine.");
            ConsoleConfig.DisplayResult("Checking For VirtualBox and VMware: ", AntiVirtualization.CheckForVMwareAndVirtualBox(), false, "Checks if the program is running in VirtualBox or VMware.");
            ConsoleConfig.DisplayResult("Checking For KVM: ", AntiVirtualization.CheckForKVM(), false, "Checks if the program is running in KVM.");
            ConsoleConfig.DisplayResult("Checking For HyperV: ", AntiVirtualization.CheckForHyperV(), false, "Checks if the program is running in HyperV.");
            ConsoleConfig.DisplayResult("Checking For Known Bad VM File Locations: ", AntiVirtualization.BadVMFilesDetection(), false, "Detects known bad VM file locations.");
            ConsoleConfig.DisplayResult("Checking For Known Bad Process Names: ", AntiVirtualization.BadVMProcessNames(), false, "Detects known bad VM process names.");
            ConsoleConfig.DisplayResult("Checking for devices created by VMs or Sandboxes: ", AntiVirtualization.CheckDevices(), false, "Checks for VM or sandbox devices.");
            ConsoleConfig.DisplayResult("Checking if the program is emulated using a timing check: ", AntiVirtualization.Generic.EmulationTimingCheck(), false, "Checks if the program is emulated using a timing check.");
            ConsoleConfig.DisplayResult("Checking For Ports (useful to detect VMs which have no ports connected): ", AntiVirtualization.Generic.PortConnectionAntiVM(), false, "Checks for VM port connections.");
            ConsoleConfig.DisplayResult("Checking for AVX instructions not being implemented properly: ", AntiVirtualization.Generic.AVXInstructions(), false, "Checks to see if the AVX instructions are properly implemented to see if we are running in a virtual/emulated CPU.");
            ConsoleConfig.DisplayResult("Checking for RDRAND instruction not being implemented/misconfigured: ", AntiVirtualization.Generic.RDRANDInstruction(), false, "Checks to see if the RDRAND instruction is supported and properly implemented which some emulators don't.");
            ConsoleConfig.DisplayResult("Checking if the instructions that control the RFlags (or EFlags) register are handled correctly: ", AntiVirtualization.Generic.FlagsManipulationInstructions(), false, "Verifies if the RFlags (or EFlags) register manipulations are correct, which may indicate an emulator.");
            ConsoleConfig.DisplayFooter();
        }

        private static void ExecuteAntiInjectionTricks()
        {
            if (!ConsoleConfig.IsAntiInjectionEnabled)
                return;
            ConsoleConfig.DisplayHeader("Executing Anti Injection Tricks");
            ConsoleConfig.DisplayResult("Taking Advantage of Binary Image Signature Mitigation Policy to Prevent Non-Microsoft Binaries From Being Injected..... ", AntiInjection.SetDllLoadPolicy(), "Enforces binary image signature mitigation policy.");
            ConsoleConfig.DisplayResult("Checking for Injected Threads: ", AntiInjection.CheckInjectedThreads(syscall, true), false, "Checks for injected threads that it's start address is neither committed nor from image, or not in modules range.");
            ConsoleConfig.DisplayResult("Changing the main module info: ", AntiInjection.ChangeModuleInfo(null, Spoofs.ModuleName | Spoofs.BaseAddress | Spoofs.AddressOfEntryPoint | Spoofs.SizeOfImage | Spoofs.ImageMagic | Spoofs.NotExecutableNorDll | Spoofs.ExecutableSectionName | Spoofs.ExecutableSectionRawSize | Spoofs.ExecutableSectionRawPointer | Spoofs.ClearExecutableSectionCharacteristics | Spoofs.ExecutableSectionVirtualSize), true, "Changes the main module info including module name, base address, etc to prevent modifications, runtime lookups or some kinds of dumping.");
            ConsoleConfig.DisplayResult("Changing the CLR module ImageMagic: ", AntiInjection.ChangeCLRModuleImageMagic(), true, "Changes the CLR module image magic in the memory of the process to try to prevent (some) external processes/software from retrieving some critical info about our assemblies while still being functional by making it seem like debugger exports is missing. (only if the module is present. if it's not present or this is AOT compiled then this will fail)");
            ConsoleConfig.DisplayResult("Checks for suspicious image base address (process hollowing): ", AntiInjection.CheckForSuspiciousBaseAddress(), false, "Checks for suspicious image base address by comparing it with the one in the main module.");
            ConsoleConfig.DisplayFooter();
        }

        private static void ExecuteOtherDetectionTricks()
        {
            if (!ConsoleConfig.IsOtherDetectionChecksEnabled)
                return;
            ConsoleConfig.DisplayHeader("Executing Other Detection Tricks");
            ConsoleConfig.DisplayResult("Detecting if Unsigned Drivers are Allowed to Load: ", OtherChecks.IsUnsignedDriversAllowed(syscall), false, "Checks if unsigned drivers are allowed.");
            ConsoleConfig.DisplayResult("Detecting if Test-Signed Drivers are Allowed to Load: ", OtherChecks.IsTestSignedDriversAllowed(syscall), false, "Checks if test-signed drivers are allowed.");
            ConsoleConfig.DisplayResult("Detecting if Kernel Debugging is Enabled on the System: ", OtherChecks.IsKernelDebuggingEnabled(syscall), false, "Checks if kernel debugging is enabled.");
            ConsoleConfig.DisplayResult("Detecting if Secure Boot is Enabled on the System: ", OtherChecks.IsSecureBootEnabled(syscall), true, "Checks if secure boot is enabled.");
            ConsoleConfig.DisplayResult("Detecting if Virtualization-Based Security is Enabled: ", OtherChecks.IsVirtualizationBasedSecurityEnabled(), true, "Checks if VBS is enabled.");
            ConsoleConfig.DisplayResult("Detecting if Memory Integrity Protection is Enabled: ", OtherChecks.IsMemoryIntegrityEnabled(), true, "Checks if Memory Integrity is enabled.");
            ConsoleConfig.DisplayResult("Detecting if the current assembly has been invoked by another one: ", OtherChecks.IsInvokedAssembly(true), false, "Checks to see if the assembly has been invoked.");
            ConsoleConfig.DisplayFooter();
        }

        private static void ExecuteHooksDetectionTricks()
        {
            if (!ConsoleConfig.IsAntiHookChecksEnabled)
                return;
            ConsoleConfig.DisplayHeader("Executing Hooks Detection Tricks");
            ConsoleConfig.DisplayResult("Detecting hooks on common WinApi functions by checking for bad instructions on functions addresses: ", HooksDetection.DetectHooks(), false, "Detects hooks on common WinAPI functions.");
            ConsoleConfig.DisplayResult("Basic Detection for Stealthy Page Guard hooking on common WinApi Functions: ", HooksDetection.DetectGuardPagesHooks(syscall), false, "Detects hooks that depends on Page Guard exception handling.");
            ConsoleConfig.DisplayResult("Detecting Hooks on CLR Functions: ", HooksDetection.DetectCLRHooks(), false, "Detects hooks on CLR Functions.");
            ConsoleConfig.DisplayFooter();
        }

        public static void Main(string[] args)
        {
            ConsoleConfig.ProcessArgs(args);
            ConsoleConfig.SetDefaultColors();
            ConsoleConfig.SyscallPrompt();
            ExecuteHooks();
            while (true)
            {
                ExecuteAntiDebuggingTricks();
                ExecuteAntiVirtualizationTricks();
                ExecuteAntiInjectionTricks();
                ExecuteOtherDetectionTricks();
                ExecuteHooksDetectionTricks();
                Console.WriteLine("Press Enter to run again or Ctrl+C to exit...");
                Console.ReadLine();
            }
        }
    }
}