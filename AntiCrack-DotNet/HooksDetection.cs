using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace AntiCrack_DotNet
{
    public class HooksDetection
    {
        [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern void RtlInitUnicodeString(out Structs.UNICODE_STRING DestinationString, string SourceString);

        [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern void RtlUnicodeStringToAnsiString(out Structs.ANSI_STRING DestinationString, Structs.UNICODE_STRING UnicodeString, bool AllocateDestinationString);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint LdrGetDllHandle([MarshalAs(UnmanagedType.LPWStr)] string DllPath, [MarshalAs(UnmanagedType.LPWStr)] string DllCharacteristics, Structs.UNICODE_STRING LibraryName, ref IntPtr DllHandle);

        [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern uint LdrGetProcedureAddress(IntPtr Module, Structs.ANSI_STRING ProcedureName, ushort ProcedureNumber, out IntPtr FunctionHandle);

        private static IntPtr LowLevelGetModuleHandle(string Library)
        {
            IntPtr hModule = IntPtr.Zero;
            Structs.UNICODE_STRING UnicodeString = new Structs.UNICODE_STRING();
            RtlInitUnicodeString(out UnicodeString, Library);
            LdrGetDllHandle(null, null, UnicodeString, ref hModule);
            return hModule;
        }
        
        private static IntPtr LowLevelGetProcAddress(IntPtr hModule, string Function)
        {
            IntPtr FunctionHandle = IntPtr.Zero;
            Structs.UNICODE_STRING UnicodeString = new Structs.UNICODE_STRING();
            Structs.ANSI_STRING AnsiString = new Structs.ANSI_STRING();
            RtlInitUnicodeString(out UnicodeString, Function);
            RtlUnicodeStringToAnsiString(out AnsiString, UnicodeString, true);
            LdrGetProcedureAddress(hModule, AnsiString, 0, out FunctionHandle);
            return FunctionHandle;
        }

        public static bool DetectBadInstructionsOnCommonAntiDebuggingFunctions()
        {
            string[] Libraries = { "kernel32.dll", "kernelbase.dll", "ntdll.dll", "user32.dll", "win32u.dll" };
            string[] KernelLibAntiDebugFunctions = { "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetThreadContext", "CloseHandle", "OutputDebugStringA", "GetTickCount", "SetHandleInformation" };
            string[] NtdllAntiDebugFunctions = { "NtQueryInformationProcess", "NtSetInformationThread", "NtClose", "NtGetContextThread", "NtQuerySystemInformation" };
            string[] User32AntiDebugFunctions = { "FindWindowW", "FindWindowA", "FindWindowExW", "FindWindowExA", "GetForegroundWindow", "GetWindowTextLengthA", "GetWindowTextA", "BlockInput" };
            string[] Win32uAntiDebugFunctions = { "NtUserBlockInput", "NtUserFindWindowEx", "NtUserQueryWindow", "NtUserGetForegroundWindow" };
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
                                    foreach (string AntiDebugFunction in KernelLibAntiDebugFunctions)
                                    {
                                        IntPtr Function = LowLevelGetProcAddress(hModule, AntiDebugFunction);
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
                                    foreach (string AntiDebugFunction in KernelLibAntiDebugFunctions)
                                    {
                                        IntPtr Function = LowLevelGetProcAddress(hModule, AntiDebugFunction);
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
                                    foreach (string AntiDebugFunction in NtdllAntiDebugFunctions)
                                    {
                                        IntPtr Function = LowLevelGetProcAddress(hModule, AntiDebugFunction);
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
                                    foreach (string AntiDebugFunction in User32AntiDebugFunctions)
                                    {
                                        IntPtr Function = LowLevelGetProcAddress(hModule, AntiDebugFunction);
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
                                    foreach (string AntiDebugFunction in Win32uAntiDebugFunctions)
                                    {
                                        IntPtr Function = LowLevelGetProcAddress(hModule, AntiDebugFunction);
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
            return false;
        }
    }
}