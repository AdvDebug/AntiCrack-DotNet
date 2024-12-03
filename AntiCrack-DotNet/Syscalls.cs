using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Messaging;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;
using static AntiCrack_DotNet.Structs;

namespace AntiCrack_DotNet
{
    public sealed class Syscalls
    {
        #region WinApi

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, uint ZeroBits, ref uint RegionSize, uint AllocationType, uint Protect);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern void RtlInitUnicodeString(out Structs.UNICODE_STRING DestinationString, string SourceString);

        [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern void RtlUnicodeStringToAnsiString(out Structs.ANSI_STRING DestinationString, Structs.UNICODE_STRING UnicodeString, bool AllocateDestinationString);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint LdrGetDllHandleEx(ulong Flags, [MarshalAs(UnmanagedType.LPWStr)] string DllPath, [MarshalAs(UnmanagedType.LPWStr)] string DllCharacteristics, Structs.UNICODE_STRING LibraryName, ref IntPtr DllHandle);

        [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern uint LdrGetProcedureAddressForCaller(IntPtr Module, Structs.ANSI_STRING ProcedureName, ushort ProcedureNumber, out IntPtr FunctionHandle, ulong Flags, IntPtr CallBack);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandleA(string Library);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string Function);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int RtlGetVersion(ref Structs.OSVERSIONINFOEX versionInfo);

        #endregion

        #region Utils

        /// <summary>
        /// Searches for the syscall number from the function bytes.
        /// </summary>
        /// <param name="bytes">the bytes to search for the syscall.</param>
        /// <returns>The syscall byte.</returns>
        public static byte ExtractSyscallByte(byte[] bytes)
        {
            for (int i = 0; i < bytes.Length; i++)
            {
                if (bytes[i] == 0xB8)
                {
                    return bytes[i + 1];
                }
            }
            return 0;
        }

        private class Syscall
        {
            public string Name { get; set; }
            public List<(string BuildNumber, byte SyscallNumber)> BuildNumber { get; set; }
        }

        private static List<Syscall> syscalls = new List<Syscall>();

        /// <summary>
        /// Initializes the build numbers along with syscalls.
        /// </summary>
        public static void InitSyscallList()
        {
            syscalls = new List<Syscall>
            {
                new Syscall
                {
                    Name = "NtClose",
                    BuildNumber = new List<(string, byte)>
                    {
                        ("7601", 0xF),
                        ("9200", 0xF),
                        ("9600", 0xF),
                        ("10240", 0xF),
                        ("10586", 0xF),
                        ("14393", 0xF),
                        ("15063", 0xF),
                        ("16299", 0xF),
                        ("17134", 0xF),
                        ("17763", 0xF),
                        ("18362", 0xF),
                        ("18363", 0xF),
                        ("19041", 0xF),
                        ("19042", 0xF),
                        ("19043", 0xF),
                        ("19044", 0xF),
                        ("19045", 0xF),
                        ("22621", 0xF),
                        ("22631", 0xF),
                        ("25915", 0xF),
                        ("26000", 0xF)
                    }
                },
                new Syscall
                {
                    Name = "NtQueryInformationProcess",
                    BuildNumber = new List<(string, byte)>
                    {
                        ("7601", 0x16),
                        ("9200", 0x17),
                        ("9600", 0x18),
                        ("10240", 0x19),
                        ("10586", 0x19),
                        ("14393", 0x19),
                        ("15063", 0x19),
                        ("16299", 0x19),
                        ("17134", 0x19),
                        ("17763", 0x19),
                        ("18362", 0x19),
                        ("18363", 0x19),
                        ("19041", 0x19),
                        ("19042", 0x19),
                        ("19043", 0x19),
                        ("19044", 0x19),
                        ("19045", 0x19),
                        ("22621", 0x19),
                        ("22631", 0x19),
                        ("25915", 0x19),
                        ("26000", 0x19)
                    }
                },
                new Syscall
                {
                    Name = "NtQuerySystemInformation",
                    BuildNumber = new List<(string DisplayVersion, byte SyscallNumber)>
                    {
                        ("7601", 0x33),
                        ("9200", 0x34),
                        ("9600", 0x35),
                        ("10240", 0x36),
                        ("10586", 0x36),
                        ("14393", 0x36),
                        ("15063", 0x36),
                        ("16299", 0x36),
                        ("17134", 0x36),
                        ("17763", 0x36),
                        ("18362", 0x36),
                        ("18363", 0x36),
                        ("19041", 0x36),
                        ("19042", 0x36),
                        ("19043", 0x36),
                        ("19044", 0x36),
                        ("19045", 0x36),
                        ("22621", 0x36),
                        ("22631", 0x36),
                        ("25915", 0x36),
                        ("26000", 0x36)
                    }
                }
            };
        }

        /// <summary>
        /// Searches for the return value from the function bytes.
        /// </summary>
        /// <param name="bytes">the bytes to search for the ret value.</param>
        /// <returns>The return value byte.</returns>
        public static byte ExtractSyscallRetValue(byte[] bytes)
        {
            for (int i = 0; i < bytes.Length; i++)
            {
                if (bytes[i] == 0xC2)
                {
                    return bytes[i + 1];
                }
            }
            return 0;
        }

        /// <summary>
        /// Checks to see if the build number is already saved.
        /// </summary>
        /// <returns>An indicator to see if the build number is saved or not.</returns>
        public static bool IsBuildNumberSaved()
        {
            foreach (Syscall GetSyscalls in syscalls)
            {
                for (int i = 0; i < GetSyscalls.BuildNumber.Count; i++)
                {
                    if (GetSyscalls.BuildNumber[i].BuildNumber.ToLower() == BuildNumber)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        public static string BuildNumber = null;

        /// <summary>
        /// Searches for the build number in registry.
        /// </summary>
        /// <returns>The build number.</returns>
        private static string GetWindowsBuildNumberReg()
        {
            try
            {
                using (RegistryKey CurrentKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (CurrentKey != null)
                    {
                        object value = CurrentKey.GetValue("CurrentBuildNumber");
                        return value.ToString();
                    }
                }
            }
            catch
            {
                return null;
            }
            return null;
        }

        /// <summary>
        /// Searches for build number in WMI.
        /// </summary>
        /// <returns>The build number.</returns>
        private static string GetWindowsBuildNumberWMI()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject os in searcher.Get())
                    {
                        object build = os["BuildNumber"];
                        return build.ToString();
                    }
                }
            }
            catch
            {
                return null;
            }
            return null;
        }


        /// <summary>
        /// Gets the build number using RtlGetVersion WinAPI.
        /// </summary>
        /// <returns>The build number.</returns>
        private static string GetWindowsBuildNumberWinAPI()
        {
            OSVERSIONINFOEX VI = new OSVERSIONINFOEX();
            VI.dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEX));
            int status = RtlGetVersion(ref VI);
            if (status == 0)
            {
                return VI.dwBuildNumber.ToString();
            }
            return null;
        }


        /// <summary>
        /// Searches for the return value from the function bytes.
        /// </summary>
        /// <returns>returns if the build numbers have been tampered with.</returns>
        private static bool IsTampered(string WinAPI, string WMI, string Registry)
        {
            bool isMatch = (WinAPI == WMI) && (WMI == Registry);
            return !isMatch;
        }

        /// <summary>
        /// Searches for the return value from the function bytes.
        /// </summary>
        /// <returns>The most suitable build number.</returns>
        public static string GetMostMatching(string WinAPI, string WMI, string Registry)
        {
            if (Tampered)
            {
                if (WinAPI == WMI)
                {
                    return WinAPI;
                }
                else if (WinAPI == Registry)
                {
                    return WinAPI;
                }
                else if (WMI == Registry)
                {
                    return WMI;
                }
                else
                {
                    return WinAPI;
                }
            }
            else
            {
                return WinAPI;
            }
        }

        private static bool ShowedBefore = false;
        public static bool Tampered = false;

        /// <summary>
        /// Gets the system build number.
        /// </summary>
        /// <param name="ExitOnBuildNumberTamper">Exit if we found that the build number was tampered with.</param>
        /// <param name="OnlyShowOnTamper">Only print a console message that says that the function was tampered with. ExitOnBuildNumberTamper also needs to be enabled for this but the process won't die.</param>
        /// <returns>The current system build number.</returns>
        public static string GetBuildNumber(bool ExitOnBuildNumberTamper, bool OnlyShowOnTamper)
        {
            string WinAPI = GetWindowsBuildNumberWinAPI();
            string WMI = GetWindowsBuildNumberWMI();
            string Registry = GetWindowsBuildNumberReg();
            if (ExitOnBuildNumberTamper && IsTampered(WinAPI, WMI, Registry))
            {
                Tampered = true;
                if (OnlyShowOnTamper)
                {
                    if (!ShowedBefore)
                    {
                        Console.ForegroundColor = ConsoleColor.DarkRed;
                        Console.WriteLine("\nThe build number may have been tampered with. We will try to identify the most appropriate build number based on other detections and proceed with it, but there is a risk of incorrect syscalls...");
                        Console.ForegroundColor = ConsoleColor.White;
                        ShowedBefore = true;
                    }
                }
                else
                {
                    Environment.Exit(0);
                    unsafe
                    {
                        int* ptr = null;
                        *ptr = 42;
                    }
                    throw new Exception(new Random().Next(int.MinValue, int.MaxValue).ToString());
                }
            }
            return GetMostMatching(WinAPI, WMI, Registry);
        }

        /// <summary>
        /// Prepares the syscall code for the function provided.
        /// </summary>
        /// <param name="Library">the function library name.</param>
        /// <param name="Function">the function to get it's syscall code for.</param>
        /// <returns>An allocated memory to the syscall code.</returns>
        public static IntPtr SyscallCode(string Library, string Function)
        {
            try
            {
                bool Extract = true;
                byte SyscallNumber = 0x0;
                foreach (Syscall GetSyscalls in syscalls)
                {
                    if (GetSyscalls.Name.ToLower() == Function.ToLower())
                    {
                        for (int i = 0; i < GetSyscalls.BuildNumber.Count; i++)
                        {
                            if (GetSyscalls.BuildNumber[i].BuildNumber.ToLower() == BuildNumber)
                            {
                                Extract = false;
                                SyscallNumber = GetSyscalls.BuildNumber[i].SyscallNumber;
                                break;
                            }
                        }
                    }
                }
                IntPtr hModule = Utils.LowLevelGetModuleHandle(Library);
                IntPtr Address = Utils.LowLevelGetProcAddress(hModule, Function);
                if (Address != IntPtr.Zero)
                {
                    byte[] FunctionCode = new byte[40];
                    Utils.CopyMem(FunctionCode, Address);
                    if (Extract)
                    {
                        SyscallNumber = ExtractSyscallByte(FunctionCode);
                    }
                    if (SyscallNumber != 0)
                    {
                        byte[] Code = new byte[40];
                        if (IntPtr.Size == 8)
                        {
                            Code = new byte[] { 0x49, 0x89, 0xCA, 0xB8, SyscallNumber, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };
                        }
                        else
                        {
                            byte RetValue = ExtractSyscallRetValue(Code);
                            Code = new byte[] { 0xB8, SyscallNumber, 0x00, 0x00, 0x00, 0x64, 0xFF, 0x15, 0xC0, 0x00, 0x00, 0x00, 0xC2, RetValue, 0x00 };
                        }
                        IntPtr Allocated = IntPtr.Zero;
                        uint Length = (uint)Code.Length;
                        uint Status = NtAllocateVirtualMemory(new IntPtr(-1), ref Allocated, 0, ref Length, 0x1000, PAGE_EXECUTE_READWRITE);
                        if (Status == 0)
                        {
                            unsafe
                            {
                                fixed (byte* source = Code)
                                {
                                    Buffer.MemoryCopy(source, (void*)Allocated, Code.Length, Code.Length);
                                }
                            }
                            return Allocated;
                        }
                    }
                }
                return IntPtr.Zero;
            }
            catch
            {
                //this shouldn't happen in normal conditions
                Environment.Exit(0);
                unsafe
                {
                    int* ptr = null;
                    *ptr = 42;
                }
                return IntPtr.Zero;
            }
        }
        #endregion

        #region Syscalls Delegates

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint SysNtQueryInformationProcess(SafeHandle hProcess, uint ProcessInfoClass, out uint ProcessInfo, uint nSize, out uint ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint SysNtQueryInformationProcess2(SafeHandle hProcess, uint ProcessInfoClass, out IntPtr ProcessInfo, uint nSize, uint ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint SysNtQueryInformationProcess3(SafeHandle hProcess, uint ProcessInfoClass, ref Structs.PROCESS_BASIC_INFORMATION ProcessInfo, uint nSize, uint ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool SysNtClose(IntPtr Handle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint SysNtQuerySystemInformation(uint SystemInformationClass, ref Structs.SYSTEM_CODEINTEGRITY_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint SysNtQuerySystemInformation2(uint SystemInformationClass, ref Structs.SYSTEM_KERNEL_DEBUGGER_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint SysNtQuerySystemInformation3(uint SystemInformationClass, ref Structs.SYSTEM_SECUREBOOT_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        #endregion

        #region Syscalls

        private static uint PAGE_EXECUTE_READWRITE = 0x40;
        private static uint MEM_RELEASE = 0x00008000;

        public static uint SyscallNtQueryInformationProcess(SafeHandle hProcess, uint ProcessInfoClass, out uint ProcessInfo, uint nSize, out uint ReturnLength)
        {
            ProcessInfo = 0;
            ReturnLength = 0;
            IntPtr Syscall = SyscallCode("ntdll.dll", "NtQueryInformationProcess");
            if (Syscall != IntPtr.Zero)
            {
                SysNtQueryInformationProcess Executed = (SysNtQueryInformationProcess)Marshal.GetDelegateForFunctionPointer(Syscall, typeof(SysNtQueryInformationProcess));
                uint Result = Executed(hProcess, ProcessInfoClass, out ProcessInfo, nSize, out ReturnLength);
                VirtualFree(Syscall, 0, MEM_RELEASE);
                return Result;
            }
            return 0;
        }

        public static uint SyscallNtQueryInformationProcess(SafeHandle hProcess, uint ProcessInfoClass, out IntPtr ProcessInfo, uint nSize, uint ReturnLength)
        {
            ProcessInfo = IntPtr.Zero;
            ReturnLength = 0;
            IntPtr Syscall = SyscallCode("ntdll.dll", "NtQueryInformationProcess");
            if (Syscall != IntPtr.Zero)
            {
                SysNtQueryInformationProcess2 Executed = (SysNtQueryInformationProcess2)Marshal.GetDelegateForFunctionPointer(Syscall, typeof(SysNtQueryInformationProcess2));
                uint Result = Executed(hProcess, ProcessInfoClass, out ProcessInfo, nSize, ReturnLength);
                VirtualFree(Syscall, 0, MEM_RELEASE);
                return Result;
            }
            return 0;
        }

        public static uint SyscallNtQueryInformationProcess(SafeHandle hProcess, uint ProcessInfoClass, ref Structs.PROCESS_BASIC_INFORMATION ProcessInfo, uint nSize, uint ReturnLength)
        {
            ProcessInfo = new PROCESS_BASIC_INFORMATION();
            ReturnLength = 0;
            IntPtr Syscall = SyscallCode("ntdll.dll", "NtQueryInformationProcess");
            if (Syscall != IntPtr.Zero)
            {
                SysNtQueryInformationProcess3 Executed = (SysNtQueryInformationProcess3)Marshal.GetDelegateForFunctionPointer(Syscall, typeof(SysNtQueryInformationProcess3));
                uint Result = Executed(hProcess, ProcessInfoClass, ref ProcessInfo, nSize, ReturnLength);
                VirtualFree(Syscall, 0, MEM_RELEASE);
                return Result;
            }
            return 0;
        }

        public static bool SyscallNtClose(IntPtr Handle)
        {
            IntPtr Syscall = SyscallCode("ntdll.dll", "NtClose");
            if (Syscall != IntPtr.Zero)
            {
                SysNtClose Executed = (SysNtClose)Marshal.GetDelegateForFunctionPointer(Syscall, typeof(SysNtClose));
                bool Result = Executed(Handle);
                VirtualFree(Syscall, 0, MEM_RELEASE);
                return Result;
            }
            return false;
        }

        public static uint SyscallNtQuerySystemInformation(uint SystemInformationClass, ref Structs.SYSTEM_CODEINTEGRITY_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength)
        {
            ReturnLength = 0;
            IntPtr Syscall = SyscallCode("ntdll.dll", "NtQuerySystemInformation");
            if (Syscall != IntPtr.Zero)
            {
                SysNtQuerySystemInformation Executed = (SysNtQuerySystemInformation)Marshal.GetDelegateForFunctionPointer(Syscall, typeof(SysNtQuerySystemInformation));
                uint Result = Executed(SystemInformationClass, ref SystemInformation, SystemInformationLength, out ReturnLength);
                VirtualFree(Syscall, 0, MEM_RELEASE);
                return Result;
            }
            return 0;
        }

        public static uint SyscallNtQuerySystemInformation(uint SystemInformationClass, ref Structs.SYSTEM_KERNEL_DEBUGGER_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength)
        {
            ReturnLength = 0;
            IntPtr Syscall = SyscallCode("ntdll.dll", "NtQuerySystemInformation");
            if (Syscall != IntPtr.Zero)
            {
                SysNtQuerySystemInformation2 Executed = (SysNtQuerySystemInformation2)Marshal.GetDelegateForFunctionPointer(Syscall, typeof(SysNtQuerySystemInformation2));
                uint Result = Executed(SystemInformationClass, ref SystemInformation, SystemInformationLength, out ReturnLength);
                VirtualFree(Syscall, 0, MEM_RELEASE);
                return Result;
            }
            return 0;
        }

        public static uint SyscallNtQuerySystemInformation(uint SystemInformationClass, ref Structs.SYSTEM_SECUREBOOT_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength)
        {
            ReturnLength = 0;
            IntPtr Syscall = SyscallCode("ntdll.dll", "NtQuerySystemInformation");
            if (Syscall != IntPtr.Zero)
            {
                SysNtQuerySystemInformation3 Executed = (SysNtQuerySystemInformation3)Marshal.GetDelegateForFunctionPointer(Syscall, typeof(SysNtQuerySystemInformation3));
                uint Result = Executed(SystemInformationClass, ref SystemInformation, SystemInformationLength, out ReturnLength);
                VirtualFree(Syscall, 0, MEM_RELEASE);
                return Result;
            }
            return 0;
        }
        #endregion
    }
}