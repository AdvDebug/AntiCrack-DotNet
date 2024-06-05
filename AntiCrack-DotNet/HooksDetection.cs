using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;

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
                                        byte[] FunctionBytes = new byte[1];
                                        Marshal.Copy(Function, FunctionBytes, 0, 1);
                                        if (FunctionBytes[0] == 0x90 || FunctionBytes[0] == 0xE9)
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
                                        byte[] FunctionBytes = new byte[1];
                                        Marshal.Copy(Function, FunctionBytes, 0, 1);
                                        if (FunctionBytes[0] == 255 || FunctionBytes[0] == 0x90 || FunctionBytes[0] == 0xE9)
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
                                        byte[] FunctionBytes = new byte[1];
                                        Marshal.Copy(Function, FunctionBytes, 0, 1);
                                        if (FunctionBytes[0] == 255 || FunctionBytes[0] == 0x90 || FunctionBytes[0] == 0xE9)
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
                                        byte[] FunctionBytes = new byte[1];
                                        Marshal.Copy(Function, FunctionBytes, 0, 1);
                                        if (FunctionBytes[0] == 0x90 || FunctionBytes[0] == 0xE9)
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
                                        byte[] FunctionBytes = new byte[1];
                                        Marshal.Copy(Function, FunctionBytes, 0, 1);
                                        if (FunctionBytes[0] == 255 || FunctionBytes[0] == 0x90 || FunctionBytes[0] == 0xE9)
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
                        byte[] FunctionBytes = new byte[1];
                        Marshal.Copy(Function, FunctionBytes, 0, 1);
                        if (FunctionBytes[0] == 255 || FunctionBytes[0] == 0x90 || FunctionBytes[0] == 0xE9)
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

        // Additional detection method
        public static bool DetectInlineHooks(string moduleName, string[] functions)
        {
            if (moduleName != null && functions != null)
            {
                try
                {
                    foreach (string function in functions)
                    {
                        IntPtr moduleHandle = LowLevelGetModuleHandle(moduleName);
                        IntPtr functionHandle = LowLevelGetProcAddress(moduleHandle, function);
                        byte[] functionBytes = new byte[1];
                        Marshal.Copy(functionHandle, functionBytes, 0, 1);
                        if (functionBytes[0] == 0xCC || functionBytes[0] == 0xE9)
                        {
                            return true;
                        }
                    }
                }
                catch { }
            }
            return false;
        }
    }
}
