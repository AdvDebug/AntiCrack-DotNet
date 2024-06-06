using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Reflection;
using System.IO;
using System.Net.Sockets;

namespace AntiCrack_DotNet
{
    public class HooksDetection
    {
        [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern void RtlInitUnicodeString(out Structs.UNICODE_STRING DestinationString, string SourceString);

        [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern void RtlUnicodeStringToAnsiString(out Structs.ANSI_STRING DestinationString, Structs.UNICODE_STRING UnicodeString, bool AllocateDestinationString);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint LdrGetDllHandleEx(ulong Flags, [MarshalAs(UnmanagedType.LPWStr)] string DllPath, [MarshalAs(UnmanagedType.LPWStr)] string DllCharacteristics, Structs.UNICODE_STRING LibraryName, ref IntPtr DllHandle);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandleA(string Library);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string Function);

        [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern uint LdrGetProcedureAddressForCaller(IntPtr Module, Structs.ANSI_STRING ProcedureName, ushort ProcedureNumber, out IntPtr FunctionHandle, ulong Flags, IntPtr CallBack);

        private static IntPtr LowLevelGetModuleHandle(string Library)
        {
            if (IntPtr.Size == 4)
                return GetModuleHandleA(Library);
            IntPtr hModule = IntPtr.Zero;
            Structs.UNICODE_STRING UnicodeString = new Structs.UNICODE_STRING();
            RtlInitUnicodeString(out UnicodeString, Library);
            LdrGetDllHandleEx(0, null, null, UnicodeString, ref hModule);
            return hModule;
        }

        private static IntPtr LowLevelGetProcAddress(IntPtr hModule, string Function)
        {
            if (IntPtr.Size == 4)
                return GetProcAddress(hModule, Function);
            IntPtr FunctionHandle = IntPtr.Zero;
            Structs.UNICODE_STRING UnicodeString = new Structs.UNICODE_STRING();
            Structs.ANSI_STRING AnsiString = new Structs.ANSI_STRING();
            RtlInitUnicodeString(out UnicodeString, Function);
            RtlUnicodeStringToAnsiString(out AnsiString, UnicodeString, true);
            LdrGetProcedureAddressForCaller(hModule, AnsiString, 0, out FunctionHandle, 0, IntPtr.Zero);
            return FunctionHandle;
        }

        private static unsafe byte InternalReadByte(IntPtr ptr)
        {
            try
            {
                byte* ptr2 = (byte*)(void*)ptr;
                return *ptr2;
            }
            catch
            {

            }
            return 0;
        }

        public static bool DetectHooksOnCommonWinAPIFunctions(string ModuleName, string[] Functions)
        {
            string[] Libraries = { "kernel32.dll", "kernelbase.dll", "ntdll.dll", "user32.dll", "win32u.dll" };
            string[] CommonKernelLibFunctions = { "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetThreadContext", "CloseHandle", "OutputDebugStringA", "GetTickCount", "SetHandleInformation" };
            string[] CommonNtdllFunctions = { "NtQueryInformationProcess", "NtSetInformationThread", "NtClose", "NtGetContextThread", "NtQuerySystemInformation", "NtCreateFile", "NtCreateProcess", "NtCreateSection", "NtCreateThread", "NtYieldExecution", "NtCreateUserProcess" };
            string[] CommonUser32Functions = { "FindWindowW", "FindWindowA", "FindWindowExW", "FindWindowExA", "GetForegroundWindow", "GetWindowTextLengthA", "GetWindowTextA", "BlockInput", "CreateWindowExW", "CreateWindowExA" };
            string[] CommonWin32uFunctions = { "NtUserBlockInput", "NtUserFindWindowEx", "NtUserQueryWindow", "NtUserGetForegroundWindow" };
            foreach (string Library in Libraries)
            {
                IntPtr hModule = LowLevelGetModuleHandle(Library);
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
                                        IntPtr Function = LowLevelGetProcAddress(hModule, WinAPIFunction);
                                        byte FunctionByte = InternalReadByte(Function);
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
                                        IntPtr Function = LowLevelGetProcAddress(hModule, WinAPIFunction);
                                        byte FunctionByte = InternalReadByte(Function);
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
                                        IntPtr Function = LowLevelGetProcAddress(hModule, WinAPIFunction);
                                        byte FunctionByte = InternalReadByte(Function);
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
                                        IntPtr Function = LowLevelGetProcAddress(hModule, WinAPIFunction);
                                        byte FunctionByte = InternalReadByte(Function);
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
                                        IntPtr Function = LowLevelGetProcAddress(hModule, WinAPIFunction);
                                        byte FunctionByte = InternalReadByte(Function);
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
            if (ModuleName != null && Functions != null)
            {
                try
                {
                    foreach (string WinAPIFunction in Functions)
                    {
                        IntPtr hModule = LowLevelGetModuleHandle(ModuleName);
                        IntPtr Function = LowLevelGetProcAddress(hModule, WinAPIFunction);
                        byte FunctionByte = InternalReadByte(Function);
                        if (FunctionByte == 255 || FunctionByte == 0x90 || FunctionByte == 0xE9)
                        {
                            return true;
                        }
                    }
                }
                catch
                {

                }
            }
            return false;
        }

        public static bool DetectInlineHooks(string moduleName, string[] functions)
        {
            if (moduleName != null && functions != null)
            {
                try
                {
                    foreach (string function in functions)
                    {
                        IntPtr hModule = LowLevelGetModuleHandle(moduleName);
                        IntPtr Function = LowLevelGetProcAddress(hModule, function);
                        byte FunctionByte = InternalReadByte(Function);
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

        public static bool DetectCLRHooks()
        {
            if (IntPtr.Size == 4)
            {
                try
                {
                    MethodInfo[] ProcessMethods = typeof(Process).GetMethods();
                    MethodInfo[] AssemblyMethods = typeof(Assembly).GetMethods();
                    MethodInfo[] FileMethods = typeof(File).GetMethods();
                    MethodInfo[] SocketMethods = typeof(Socket).GetMethods();
                    MethodInfo[] MarshalMethods = typeof(Marshal).GetMethods();
                    MethodInfo[] StringMethods = typeof(string).GetMethods();
                    foreach (MethodInfo ProcessMethod in ProcessMethods)
                    {
                        byte FirstByte = InternalReadByte(ProcessMethod.MethodHandle.GetFunctionPointer());
                        if (FirstByte == 0xE9 || FirstByte == 255)
                        {
                            return true;
                        }
                    }

                    foreach (MethodInfo AssemblyMethod in AssemblyMethods)
                    {
                        byte FirstByte = InternalReadByte(AssemblyMethod.MethodHandle.GetFunctionPointer());
                        if (FirstByte == 0xE9 || FirstByte == 255)
                            return true;
                    }

                    foreach (MethodInfo FileMethod in FileMethods)
                    {
                        byte FirstByte = InternalReadByte(FileMethod.MethodHandle.GetFunctionPointer());
                        if (FirstByte == 0xE9 || FirstByte == 255)
                            return true;
                    }

                    foreach (MethodInfo SocketMethod in SocketMethods)
                    {
                        byte FirstByte = InternalReadByte(SocketMethod.MethodHandle.GetFunctionPointer());
                        if (FirstByte == 0xE9 || FirstByte == 255)
                            return true;
                    }

                    foreach (MethodInfo MarshalMethod in MarshalMethods)
                    {
                        byte FirstByte = InternalReadByte(MarshalMethod.MethodHandle.GetFunctionPointer());
                        if (FirstByte == 0xE9 || FirstByte == 255)
                            return true;
                    }

                    foreach (MethodInfo StringMethod in StringMethods)
                    {
                        byte FirstByte = InternalReadByte(StringMethod.MethodHandle.GetFunctionPointer());
                        if (FirstByte == 0xE9 || FirstByte == 255)
                            return true;
                    }

                    Type[] AllTypes = Assembly.GetExecutingAssembly().GetTypes();
                    foreach (Type type in AllTypes)
                    {
                        MethodInfo[] AllMethods = type.GetMethods();
                        foreach (MethodInfo Method in AllMethods)
                        {
                            byte FirstByte = InternalReadByte(Method.MethodHandle.GetFunctionPointer());
                            if (FirstByte == 0xE9 || FirstByte == 255)
                                return true;
                        }
                    }
                }
                catch
                {

                }
            }
            return false;
        }
    }
}