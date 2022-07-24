using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace AntiCrack_DotNet
{
    public class HooksDetection
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string LibraryName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr Module, string Function);

        public static bool DetectBadInstructionsOnCommonAntiDebuggingFunctions()
        {
            string[] Libraries = { "kernel32.dll", "ntdll.dll", "user32.dll", "win32u.dll" };
            string[] Kernel32AntiDebugFunctions = { "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetThreadContext", "CloseHandle", "OutputDebugStringA", "GetTickCount", "SetHandleInformation" };
            string[] NtdllAntiDebugFunctions = { "NtQueryInformationProcess", "NtSetInformationThread", "NtClose", "NtGetContextThread", "NtQuerySystemInformation" };
            string[] User32AntiDebugFunctions = { "FindWindowW", "FindWindowA", "FindWindowExW", "FindWindowExA", "GetForegroundWindow", "GetWindowTextLengthA", "GetWindowTextA", "BlockInput" };
            string[] Win32uAntiDebugFunctions = { "NtUserBlockInput", "NtUserFindWindowEx", "NtUserQueryWindow", "NtUserGetForegroundWindow" };
            foreach (string Library in Libraries)
            {
                IntPtr hModule = GetModuleHandle(Library);
                if (hModule != IntPtr.Zero)
                {
                    switch (Library)
                    {
                        case "kernel32.dll":
                            {
                                try
                                {
                                    foreach (string AntiDebugFunction in Kernel32AntiDebugFunctions)
                                    {
                                        IntPtr Function = GetProcAddress(hModule, AntiDebugFunction);
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
                        case "ntdll.dll":
                            {
                                try
                                {
                                    foreach (string AntiDebugFunction in NtdllAntiDebugFunctions)
                                    {
                                        IntPtr Function = GetProcAddress(hModule, AntiDebugFunction);
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
                                        IntPtr Function = GetProcAddress(hModule, AntiDebugFunction);
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
                                        IntPtr Function = GetProcAddress(hModule, AntiDebugFunction);
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