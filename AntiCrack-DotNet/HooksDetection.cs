using System;
using System.IO;
using System.Reflection;
using System.Net.Sockets;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Linq;
using static AntiCrack_DotNet.Structs;
using System.Net;

namespace AntiCrack_DotNet
{
    public sealed class HooksDetection
    {
        public static object ProcessMethod { get; private set; }

        /// <summary>
        /// Detects hooks on common Windows API functions.
        /// </summary>
        /// <returns>Returns true if hooks are detected, otherwise false.</returns>
        public static bool DetectHooks()
        {
            string[] Libraries = { "kernel32.dll", "kernelbase.dll", "ntdll.dll", "user32.dll", "win32u.dll" };
            string[] CommonKernelLibFunctions = { "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetThreadContext", "CloseHandle", "OutputDebugStringA", "GetTickCount", "SetHandleInformation" };
            string[] CommonNtdllFunctions = { "NtQueryInformationProcess", "NtSetInformationThread", "NtClose", "NtGetContextThread", "NtQuerySystemInformation", "NtCreateFile", "NtCreateProcess", "NtCreateSection", "NtCreateThread", "NtYieldExecution", "NtCreateUserProcess", "NtAllocateVirtualMemory" };
            string[] CommonUser32Functions = { "FindWindowW", "FindWindowA", "FindWindowExW", "FindWindowExA", "GetForegroundWindow", "GetWindowTextLengthA", "GetWindowTextA", "BlockInput", "CreateWindowExW", "CreateWindowExA" };
            string[] CommonWin32uFunctions = { "NtUserBlockInput", "NtUserFindWindowEx", "NtUserQueryWindow", "NtUserGetForegroundWindow" };
            foreach (string Library in Libraries)
            {
                IntPtr hModule = Utils.LowLevelGetModuleHandle(Library);
                if (hModule != IntPtr.Zero)
                {
                    switch (Library)
                    {
                        case "kernel32.dll":
                            {
                                try
                                {
                                    foreach (string WinAPIFunction in CommonKernelLibFunctions)
                                    {
                                        IntPtr Function = Utils.GetFunctionExportAddress(hModule, WinAPIFunction);
                                        byte FunctionByte = Utils.InternalReadByte(Function);
                                        if (FunctionByte == 0x90 || FunctionByte == 0xE9)
                                        {
                                            return true;
                                        }
                                    }
                                }
                                catch
                                {
                                    continue;
                                }
                            }
                            break;
                        case "kernelbase.dll":
                            {
                                try
                                {
                                    foreach (string WinAPIFunction in CommonKernelLibFunctions)
                                    {
                                        IntPtr Function = Utils.GetFunctionExportAddress(hModule, WinAPIFunction);
                                        byte FunctionByte = Utils.InternalReadByte(Function);
                                        if (FunctionByte == 255 || FunctionByte == 0x90 || FunctionByte == 0xE9)
                                        {
                                            return true;
                                        }
                                    }
                                }
                                catch
                                {
                                    continue;
                                }
                            }
                            break;
                        case "ntdll.dll":
                            {
                                try
                                {
                                    foreach (string WinAPIFunction in CommonNtdllFunctions)
                                    {
                                        IntPtr Function = Utils.GetFunctionExportAddress(hModule, WinAPIFunction);
                                        byte FunctionByte = Utils.InternalReadByte(Function);
                                        if (FunctionByte == 255 || FunctionByte == 0x90 || FunctionByte == 0xE9)
                                        {
                                            return true;
                                        }
                                    }
                                }
                                catch
                                {
                                    continue;
                                }
                            }
                            break;
                        case "user32.dll":
                            {
                                try
                                {
                                    foreach (string WinAPIFunction in CommonUser32Functions)
                                    {
                                        IntPtr Function = Utils.GetFunctionExportAddress(hModule, WinAPIFunction);
                                        byte FunctionByte = Utils.InternalReadByte(Function);
                                        if (FunctionByte == 0x90 || FunctionByte == 0xE9)
                                        {
                                            return true;
                                        }
                                    }
                                }
                                catch
                                {
                                    continue;
                                }
                            }
                            break;
                        case "win32u.dll":
                            {
                                try
                                {
                                    foreach (string WinAPIFunction in CommonWin32uFunctions)
                                    {
                                        IntPtr Function = Utils.GetFunctionExportAddress(hModule, WinAPIFunction);
                                        byte FunctionByte = Utils.InternalReadByte(Function);
                                        if (FunctionByte == 255 || FunctionByte == 0x90 || FunctionByte == 0xE9)
                                        {
                                            return true;
                                        }
                                    }
                                }
                                catch
                                {
                                    continue;
                                }
                            }
                            break;
                    }
                }
            }
            return false;
        }

        /// <summary>
        /// Detects inline hooks on specified functions within a module.
        /// </summary>
        /// <param name="ModuleName">The name of the module to check for hooks.</param>
        /// <param name="Functions">The list of functions to check for hooks.</param>
        /// <returns>Returns true if hooks are detected, otherwise false.</returns>
        public static bool DetectInlineHooks(string ModuleName, string[] Functions)
        {
            if (ModuleName != null && Functions != null)
            {
                try
                {
                    foreach (string function in Functions)
                    {
                        IntPtr hModule = Utils.LowLevelGetModuleHandle(ModuleName);
                        IntPtr Function = Utils.GetFunctionExportAddress(hModule, function);
                        byte FunctionByte = Utils.InternalReadByte(Function);
                        if (FunctionByte == 255 || FunctionByte == 0x90 || FunctionByte == 0xE9)
                        {
                            return true;
                        }
                    }
                }
                catch { }
            }
            return false;
        }

        /// <summary>
        /// Detects potential guard page hooks on a specific memory address / function.
        /// </summary>
        /// <param name="pFunction">the address of the function.</param>
        /// <param name="Syscall">an indicator to whether or not to use syscalls for this check</param>
        /// <returns>Returns true if hooks are detected, otherwise false.</returns>
        public static bool DetectGuardPageHook(IntPtr pFunction, bool Syscall)
        {
            uint PAGE_GUARD = 0x100;
            Structs.MEMORY_BASIC_INFORMATION MBI = new Structs.MEMORY_BASIC_INFORMATION();
            
            if (Utils.GetVirtualMemoryQuery(Syscall, pFunction, ref MBI, out _))
            {
                if ((MBI.Protect & PAGE_GUARD) == PAGE_GUARD)
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Detects potential guard page hooks on common winapi functions.
        /// </summary>
        /// <param name="Syscall">an indicator to whether or not to use syscalls for this check</param>
        /// <returns>Returns true if hooks are detected, otherwise false.</returns>
        public static bool DetectGuardPagesHooks(bool Syscall)
        {
            string[] Libraries = { "kernel32.dll", "kernelbase.dll", "ntdll.dll", "user32.dll", "win32u.dll" };
            string[] CommonKernelLibFunctions = { "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetThreadContext", "CloseHandle", "OutputDebugStringA", "GetTickCount", "SetHandleInformation" };
            string[] CommonNtdllFunctions = { "NtQueryInformationProcess", "NtSetInformationThread", "NtClose", "NtGetContextThread", "NtQuerySystemInformation", "NtCreateFile", "NtCreateProcess", "NtCreateSection", "NtCreateThread", "NtYieldExecution", "NtCreateUserProcess", "NtAllocateVirtualMemory", "NtQueryInformationThread", "NtQueryVirtualMemory" };
            string[] CommonUser32Functions = { "FindWindowW", "FindWindowA", "FindWindowExW", "FindWindowExA", "GetForegroundWindow", "GetWindowTextLengthA", "GetWindowTextA", "BlockInput", "CreateWindowExW", "CreateWindowExA" };
            string[] CommonWin32uFunctions = { "NtUserBlockInput", "NtUserFindWindowEx", "NtUserQueryWindow", "NtUserGetForegroundWindow" };
            foreach (string Library in Libraries)
            {
                IntPtr hModule = Utils.LowLevelGetModuleHandle(Library);
                if (hModule != IntPtr.Zero)
                {
                    switch (Library)
                    {
                        case "kernel32.dll":
                            {
                                try
                                {
                                    foreach (string WinAPIFunction in CommonKernelLibFunctions)
                                    {
                                        IntPtr Function = Utils.GetFunctionExportAddress(hModule, WinAPIFunction);
                                        if (DetectGuardPageHook(Function, Syscall))
                                            return true;
                                    }
                                }
                                catch
                                {
                                    continue;
                                }
                            }
                            break;
                        case "kernelbase.dll":
                            {
                                try
                                {
                                    foreach (string WinAPIFunction in CommonKernelLibFunctions)
                                    {
                                        IntPtr Function = Utils.GetFunctionExportAddress(hModule, WinAPIFunction);
                                        if (DetectGuardPageHook(Function, Syscall))
                                            return true;
                                    }
                                }
                                catch
                                {
                                    continue;
                                }
                            }
                            break;
                        case "ntdll.dll":
                            {
                                try
                                {
                                    foreach (string WinAPIFunction in CommonNtdllFunctions)
                                    {
                                        IntPtr Function = Utils.GetFunctionExportAddress(hModule, WinAPIFunction);
                                        if (DetectGuardPageHook(Function, Syscall))
                                            return true;
                                    }
                                }
                                catch
                                {
                                    continue;
                                }
                            }
                            break;
                        case "user32.dll":
                            {
                                try
                                {
                                    foreach (string WinAPIFunction in CommonUser32Functions)
                                    {
                                        IntPtr Function = Utils.GetFunctionExportAddress(hModule, WinAPIFunction);
                                        if (DetectGuardPageHook(Function, Syscall))
                                            return true;
                                    }
                                }
                                catch
                                {
                                    continue;
                                }
                            }
                            break;
                        case "win32u.dll":
                            {
                                try
                                {
                                    foreach (string WinAPIFunction in CommonWin32uFunctions)
                                    {
                                        IntPtr Function = Utils.GetFunctionExportAddress(hModule, WinAPIFunction);
                                        if (DetectGuardPageHook(Function, Syscall))
                                            return true;
                                    }
                                }
                                catch
                                {
                                    continue;
                                }
                            }
                            break;
                    }
                }
            }
            return false;
        }

        /// <summary>
        /// Detects if an address is in range inside modules or not, used for compatibility.
        /// </summary>
        /// <param name="Address">The address to check for.</param>
        /// <returns>Returns true if the address is in no module, otherwise false.</returns>
        private static bool IsAddressInRange(IntPtr Address)
        {
            foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
            {
                IntPtr Base = module.BaseAddress;
                IntPtr End = IntPtr.Add(Base, module.ModuleMemorySize);
                if (Address.ToInt64() >= Base.ToInt64() && Address.ToInt64() < End.ToInt64())
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Detects hooks in common .NET methods.
        /// </summary>
        /// <returns>Returns true if hooks are detected, otherwise false.</returns>
        public static bool DetectCLRHooks()
        {
            try
            {
                if (!Utils.IsReflectionEnabled(true, true))
                    return false;
                if (IntPtr.Size == 4)
                {
                    MethodInfo[] ProcessMethods = typeof(Process).GetMethods();
                    MethodInfo[] AssemblyMethods = typeof(Assembly).GetMethods();
                    MethodInfo[] FileMethods = typeof(File).GetMethods();
                    MethodInfo[] SocketMethods = typeof(Socket).GetMethods();
                    MethodInfo[] MarshalMethods = typeof(Marshal).GetMethods();
                    MethodInfo[] StringMethods = typeof(string).GetMethods();
                    foreach (MethodInfo ProcessMethod in ProcessMethods)
                    {
                        try
                        {
                            IntPtr FP = Utils.GetPointer(ProcessMethod);
                            if (FP != IntPtr.Zero)
                            {
                                byte FirstByte = Utils.InternalReadByte(FP);
                                if (FirstByte == 0xE9 || FirstByte == 255)
                                {
                                    return true;
                                }
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }
                    foreach (MethodInfo AssemblyMethod in AssemblyMethods)
                    {
                        try
                        {
                            IntPtr FP = Utils.GetPointer(AssemblyMethod);
                            if (FP != IntPtr.Zero)
                            {
                                byte FirstByte = Utils.InternalReadByte(FP);
                                if (FirstByte == 0xE9 || FirstByte == 255)
                                    return true;
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }
                    foreach (MethodInfo FileMethod in FileMethods)
                    {
                        try
                        {
                            IntPtr FP = Utils.GetPointer(FileMethod);
                            if (FP != IntPtr.Zero)
                            {
                                byte FirstByte = Utils.InternalReadByte(FP);
                                if (FirstByte == 0xE9 || FirstByte == 255)
                                    return true;
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }
                    foreach (MethodInfo SocketMethod in SocketMethods)
                    {
                        try
                        {
                            IntPtr FP = Utils.GetPointer(SocketMethod);
                            if (FP != IntPtr.Zero)
                            {
                                byte FirstByte = Utils.InternalReadByte(FP);
                                if (FirstByte == 0xE9 || FirstByte == 255)
                                    return true;
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }
                    foreach (MethodInfo MarshalMethod in MarshalMethods)
                    {
                        try
                        {
                            IntPtr FP = Utils.GetPointer(MarshalMethod);
                            if (FP != IntPtr.Zero)
                            {
                                byte FirstByte = Utils.InternalReadByte(FP);
                                if (FirstByte == 0xE9 || FirstByte == 255)
                                    return true;
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }
                    foreach (MethodInfo StringMethod in StringMethods)
                    {
                        try
                        {
                            IntPtr FP = Utils.GetPointer(StringMethod);
                            if (FP != IntPtr.Zero)
                            {
                                byte FirstByte = Utils.InternalReadByte(FP);
                                if (FirstByte == 0xE9 || FirstByte == 255)
                                    return true;
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }
                    Assembly assembly = Assembly.GetExecutingAssembly();
                    foreach (Type type in assembly.GetTypes())
                    {
                        try
                        {
                            MethodInfo[] AllMethods = type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly);
                            var UserDefinedMethods = AllMethods.Where(method => !method.IsSpecialName).Where(method => method.DeclaringType.Assembly == assembly);
                            foreach (MethodInfo Method in UserDefinedMethods)
                            {
                                RuntimeHelpers.PrepareMethod(Method.MethodHandle);
                                IntPtr FP = Utils.GetPointer(Method);
                                if (FP != IntPtr.Zero)
                                {
                                    byte FirstByte = Utils.InternalReadByte(FP);
                                    if (FirstByte == 0xE9 || FirstByte == 255 || FirstByte == 0x90 || FirstByte == 144)
                                    {
                                        if (IsAddressInRange(FP))
                                            return true;
                                    }
                                }
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }
                }
                else if(IntPtr.Size == 8)
                {
                    MethodInfo[] ProcessMethods = typeof(Process).GetMethods();
                    MethodInfo[] AssemblyMethods = typeof(Assembly).GetMethods();
                    MethodInfo[] FileMethods = typeof(File).GetMethods();
                    MethodInfo[] SocketMethods = typeof(Socket).GetMethods();
                    MethodInfo[] MarshalMethods = typeof(Marshal).GetMethods();
                    MethodInfo[] StringMethods = typeof(string).GetMethods();
                    foreach (MethodInfo ProcessMethod in ProcessMethods)
                    {
                        try
                        {
                            IntPtr FP = Utils.GetPointer(ProcessMethod);
                            if (FP != IntPtr.Zero)
                            {
                                byte FirstByte = Utils.InternalReadByte(FP);
                                if (FirstByte == 0xE9 || FirstByte == 255)
                                {
                                    if (IsAddressInRange(FP))
                                        return true;
                                }
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }

                    foreach (MethodInfo AssemblyMethod in AssemblyMethods)
                    {
                        try
                        {
                            IntPtr FP = Utils.GetPointer(AssemblyMethod);
                            if (FP != IntPtr.Zero)
                            {
                                byte FirstByte = Utils.InternalReadByte(FP);
                                if (FirstByte == 0xE9 || FirstByte == 255)
                                {
                                    if (IsAddressInRange(FP))
                                        return true;
                                }
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }

                    foreach (MethodInfo FileMethod in FileMethods)
                    {
                        try
                        {
                            IntPtr FP = Utils.GetPointer(FileMethod);
                            if (FP != IntPtr.Zero)
                            {
                                byte FirstByte = Utils.InternalReadByte(FP);
                                if (FirstByte == 0xE9 || FirstByte == 255)
                                {
                                    if (IsAddressInRange(FP))
                                        return true;
                                }
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }

                    foreach (MethodInfo SocketMethod in SocketMethods)
                    {
                        try
                        {
                            IntPtr FP = Utils.GetPointer(SocketMethod);
                            if (FP != IntPtr.Zero)
                            {
                                byte FirstByte = Utils.InternalReadByte(FP);
                                if (FirstByte == 0xE9 || FirstByte == 255)
                                {
                                    if (IsAddressInRange(FP))
                                        return true;
                                }
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }

                    foreach (MethodInfo MarshalMethod in MarshalMethods)
                    {
                        try
                        {
                            IntPtr FP = Utils.GetPointer(MarshalMethod);
                            if (FP != IntPtr.Zero)
                            {
                                byte FirstByte = Utils.InternalReadByte(FP);
                                if (FirstByte == 0xE9 || FirstByte == 255)
                                {
                                    if (IsAddressInRange(FP))
                                        return true;
                                }
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }

                    foreach (MethodInfo StringMethod in StringMethods)
                    {
                        try
                        {
                            IntPtr FP = Utils.GetPointer(StringMethod);
                            if (FP != IntPtr.Zero)
                            {
                                byte FirstByte = Utils.InternalReadByte(FP);
                                if (FirstByte == 0xE9 || FirstByte == 255)
                                {
                                    if (IsAddressInRange(FP))
                                        return true;
                                }
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }

                    Assembly assembly = Assembly.GetExecutingAssembly();
                    foreach (Type type in assembly.GetTypes())
                    {
                        try
                        {
                            MethodInfo[] AllMethods = type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly);
                            var UserDefinedMethods = AllMethods.Where(method => !method.IsSpecialName).Where(method => method.DeclaringType.Assembly == assembly);
                            foreach (MethodInfo Method in UserDefinedMethods)
                            {
                                RuntimeHelpers.PrepareMethod(Method.MethodHandle);
                                IntPtr FP = Utils.GetPointer(Method);
                                if (FP != IntPtr.Zero)
                                {
                                    byte FirstByte = Utils.InternalReadByte(FP);
                                    if (FirstByte == 0xE9 || FirstByte == 255 || FirstByte == 0x90 || FirstByte == 144)
                                    {
                                        if (IsAddressInRange(FP))
                                            return true;
                                    }
                                }
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }
                }
            }
            catch
            {
                return false;
            }
            return false;
        }
    }
}