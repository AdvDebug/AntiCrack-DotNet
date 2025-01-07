using System;
using System.Collections.Generic;
using System.Management;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using static AntiCrack_DotNet.Structs;
using static AntiCrack_DotNet.Delegates;
using static AntiCrack_DotNet.Utils;
using System.Threading;

namespace AntiCrack_DotNet
{
    public sealed class Syscalls
    {
        #region WinApi

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
        /// Get the most common syscall number which is used across different builds.
        /// </summary>
        /// <param name="Function">the function name to search for the syscall.</param>
        /// <returns>The syscall byte.</returns>
        public static byte GetCommonSyscallByte(string Function)
        {
            foreach (Syscall GetSyscalls in syscalls)
            {
                if (GetSyscalls.Name.ToLower() == Function.ToLower())
                {
                    return GetSyscalls.CommonSyscall;
                }
            }
            return 0x00;
        }

        /// <summary>
        /// Searches for the syscall number from the function bytes.
        /// </summary>
        /// <param name="bytes">the bytes to search for the syscall.</param>
        /// <returns>The syscall byte.</returns>
        public static byte ExtractSyscallByte(byte[] bytes, string Function)
        {
            bool RetFoundFirst = false;
            for (int i = 0; i < bytes.Length; i++)
            {
                if (bytes[i] == 0xB8)
                {
                    if (RetFoundFirst || bytes[0] == 0xE9 || bytes[0] == 0x90)
                    {
                        byte Common = GetCommonSyscallByte(Function);
                        if(Common != 0x00)
                        {
                            return Common;
                        }
                    }
                    return bytes[i + 1];
                }

                if (bytes[i] == 0xC3 || bytes[i] == 0xC2)
                {
                    RetFoundFirst = true;
                }
            }
            return 0;
        }

        private sealed class Syscall
        {
            public string Name { get; set; }
            public List<(string BuildNumber, byte SyscallNumber)> BuildNumber { get; set; }
            public byte CommonSyscall { get; set; }
        }

        private static List<Syscall> syscalls = new List<Syscall>();

        /// <summary>
        /// Initializes the build numbers along with syscalls.
        /// </summary>
        public static void InitSyscall()
        {
            syscalls = new List<Syscall>
            {
                new Syscall
                {
                    CommonSyscall = 0xF,
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
                    CommonSyscall = 0x19,
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
                    CommonSyscall = 0x36,
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
                },
                new Syscall
                {
                    CommonSyscall = 0x23,
                    Name = "NtQueryVirtualMemory",
                    BuildNumber = new List<(string, byte)>
                    {
                        ("7601", 0x20),
                        ("9200", 0x21),
                        ("9600", 0x22),
                        ("10240", 0x23),
                        ("10586", 0x23),
                        ("14393", 0x23),
                        ("15063", 0x23),
                        ("16299", 0x23),
                        ("17134", 0x23),
                        ("17763", 0x23),
                        ("18362", 0x23),
                        ("18363", 0x23),
                        ("19041", 0x23),
                        ("19042", 0x23),
                        ("19043", 0x23),
                        ("19044", 0x23),
                        ("19045", 0x23),
                        ("22621", 0x23),
                        ("22631", 0x23),
                        ("25915", 0x23),
                        ("26000", 0x23)
                    }
                },
                new Syscall
                {
                    CommonSyscall = 0x25,
                    Name = "NtQueryInformationThread",
                    BuildNumber = new List<(string, byte)>
                    {
                        ("7601", 0x22),
                        ("9200", 0x23),
                        ("9600", 0x24),
                        ("10240", 0x25),
                        ("10586", 0x25),
                        ("14393", 0x25),
                        ("15063", 0x25),
                        ("16299", 0x25),
                        ("17134", 0x25),
                        ("17763", 0x25),
                        ("18362", 0x25),
                        ("18363", 0x25),
                        ("19041", 0x25),
                        ("19042", 0x25),
                        ("19043", 0x25),
                        ("19044", 0x25),
                        ("19045", 0x25),
                        ("22621", 0x25),
                        ("22631", 0x25),
                        ("25915", 0x25),
                        ("26000", 0x25)
                    }
                },
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
        /// <param name="OnlyShowOnTamper">Only print a console message that says that the function was tampered with.</param>
        /// <returns>The current system build number.</returns>
        public static string GetBuildNumber(bool ExitOnBuildNumberTamper, bool OnlyShowOnTamper)
        {
            string WinAPI = GetWindowsBuildNumberWinAPI();
            string WMI = GetWindowsBuildNumberWMI();
            string Registry = GetWindowsBuildNumberReg();
            if (IsTampered(WinAPI, WMI, Registry))
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
                else if(ExitOnBuildNumberTamper)
                {
                    ForceExit();
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
                IntPtr Address = GetFunctionExportAddress(Library, Function);
                if (Address != IntPtr.Zero)
                {
                    byte[] FunctionCode = new byte[40];
                    CopyMem(FunctionCode, Address, false);
                    if (Extract)
                    {
                        SyscallNumber = ExtractSyscallByte(FunctionCode, Function);
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
                        return AllocateCode(Code);
                    }
                }
                return IntPtr.Zero;
            }
            catch
            {
                //this shouldn't happen in normal conditions
                ForceExit();
                return IntPtr.Zero;
            }
        }

        #endregion

        #region Syscalls

        public static uint SyscallNtQueryInformationProcess(uint ProcessInfoClass, out uint ProcessInfo, uint nSize, out uint ReturnLength)
        {
            ProcessInfo = 0;
            ReturnLength = 0;
            IntPtr Syscall = SyscallCode("ntdll.dll", "NtQueryInformationProcess");
            if (Syscall != IntPtr.Zero)
            {
                try
                {
                    SysNtQueryInformationProcess Executed = (SysNtQueryInformationProcess)Marshal.GetDelegateForFunctionPointer(Syscall, typeof(SysNtQueryInformationProcess));
                    uint Result = Executed(new IntPtr(-1), ProcessInfoClass, out ProcessInfo, nSize, out ReturnLength);
                    FreeCode(Syscall);
                    return Result;
                }
                catch
                {
                    FreeCode(Syscall);
                }
            }
            return 0;
        }

        public static uint SyscallNtQueryInformationProcess(uint ProcessInfoClass, out IntPtr ProcessInfo, uint nSize, uint ReturnLength)
        {
            ProcessInfo = IntPtr.Zero;
            ReturnLength = 0;
            IntPtr Syscall = SyscallCode("ntdll.dll", "NtQueryInformationProcess");
            if (Syscall != IntPtr.Zero)
            {
                try
                {
                    SysNtQueryInformationProcess2 Executed = (SysNtQueryInformationProcess2)Marshal.GetDelegateForFunctionPointer(Syscall, typeof(SysNtQueryInformationProcess2));
                    uint Result = Executed(new IntPtr(-1), ProcessInfoClass, out ProcessInfo, nSize, ReturnLength);
                    FreeCode(Syscall);
                    return Result;
                }
                catch
                {
                    FreeCode(Syscall);
                }
            }
            return 0;
        }

        public static uint SyscallNtQueryInformationProcess(uint ProcessInfoClass, ref Structs.PROCESS_BASIC_INFORMATION ProcessInfo, uint nSize, uint ReturnLength)
        {
            ProcessInfo = new PROCESS_BASIC_INFORMATION();
            ReturnLength = 0;
            IntPtr Syscall = SyscallCode("ntdll.dll", "NtQueryInformationProcess");
            if (Syscall != IntPtr.Zero)
            {
                try
                {
                    SysNtQueryInformationProcess3 Executed = (SysNtQueryInformationProcess3)Marshal.GetDelegateForFunctionPointer(Syscall, typeof(SysNtQueryInformationProcess3));
                    uint Result = Executed(new IntPtr(-1), ProcessInfoClass, ref ProcessInfo, nSize, ReturnLength);
                    FreeCode(Syscall);
                    return Result;
                }
                catch
                {
                    FreeCode(Syscall);
                }
            }
            return 0;
        }

        public static bool SyscallNtClose(IntPtr Handle)
        {
            IntPtr Syscall = SyscallCode("ntdll.dll", "NtClose");
            if (Syscall != IntPtr.Zero)
            {
                try
                {
                    SysNtClose Executed = (SysNtClose)Marshal.GetDelegateForFunctionPointer(Syscall, typeof(SysNtClose));
                    bool Result = Executed(Handle);
                    FreeCode(Syscall);
                    return Result;
                }
                finally
                {
                    FreeCode(Syscall);
                }
            }
            return false;
        }

        public static uint SyscallNtQuerySystemInformation(uint SystemInformationClass, ref Structs.SYSTEM_CODEINTEGRITY_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength)
        {
            ReturnLength = 0;
            IntPtr Syscall = SyscallCode("ntdll.dll", "NtQuerySystemInformation");
            if (Syscall != IntPtr.Zero)
            {
                try
                {
                    SysNtQuerySystemInformation Executed = (SysNtQuerySystemInformation)Marshal.GetDelegateForFunctionPointer(Syscall, typeof(SysNtQuerySystemInformation));
                    uint Result = Executed(SystemInformationClass, ref SystemInformation, SystemInformationLength, out ReturnLength);
                    FreeCode(Syscall);
                    return Result;
                }
                catch
                {
                    FreeCode(Syscall);
                }
            }
            return 0;
        }

        public static uint SyscallNtQuerySystemInformation(uint SystemInformationClass, ref Structs.SYSTEM_KERNEL_DEBUGGER_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength)
        {
            ReturnLength = 0;
            IntPtr Syscall = SyscallCode("ntdll.dll", "NtQuerySystemInformation");
            if (Syscall != IntPtr.Zero)
            {
                try
                {
                    SysNtQuerySystemInformation2 Executed = (SysNtQuerySystemInformation2)Marshal.GetDelegateForFunctionPointer(Syscall, typeof(SysNtQuerySystemInformation2));
                    uint Result = Executed(SystemInformationClass, ref SystemInformation, SystemInformationLength, out ReturnLength);
                    FreeCode(Syscall);
                    return Result;
                }
                catch
                {
                    FreeCode(Syscall);
                }
            }
            return 0;
        }

        public static uint SyscallNtQuerySystemInformation(uint SystemInformationClass, ref Structs.SYSTEM_SECUREBOOT_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength)
        {
            ReturnLength = 0;
            IntPtr Syscall = SyscallCode("ntdll.dll", "NtQuerySystemInformation");
            if (Syscall != IntPtr.Zero)
            {
                try
                {
                    SysNtQuerySystemInformation3 Executed = (SysNtQuerySystemInformation3)Marshal.GetDelegateForFunctionPointer(Syscall, typeof(SysNtQuerySystemInformation3));
                    uint Result = Executed(SystemInformationClass, ref SystemInformation, SystemInformationLength, out ReturnLength);
                    FreeCode(Syscall);
                    return Result;
                }
                catch
                {
                    FreeCode(Syscall);
                }
            }
            return 0;
        }

        public static uint SyscallNtQueryVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, uint MemoryInformationClass, ref Structs.MEMORY_BASIC_INFORMATION MemoryInformation, uint MemoryInformationLength, out uint ReturnLength)
        {
            ReturnLength = 0;
            IntPtr Syscall = SyscallCode("ntdll.dll", "NtQueryVirtualMemory");
            if (Syscall != IntPtr.Zero)
            {
                try
                {
                    SysNtQueryVirtualMemory Executed = (SysNtQueryVirtualMemory)Marshal.GetDelegateForFunctionPointer(Syscall, typeof(SysNtQueryVirtualMemory));
                    uint Result = Executed(ProcessHandle, BaseAddress, MemoryInformationClass, ref MemoryInformation, MemoryInformationLength, out ReturnLength);
                    FreeCode(Syscall);
                    return Result;
                }
                catch
                {
                    FreeCode(Syscall);
                }
            }
            return 0;
        }

        public static int SyscallNtQueryInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, ref IntPtr ThreadInformation, uint ThreadInformationLength, IntPtr ReturnLength)
        {
            IntPtr Syscall = SyscallCode("ntdll.dll", "NtQueryInformationThread");
            if (Syscall != IntPtr.Zero)
            {
                try
                {
                    SysNtQueryInformationThread Executed = (SysNtQueryInformationThread)Marshal.GetDelegateForFunctionPointer(Syscall, typeof(SysNtQueryInformationThread));
                    int Result = Executed(ThreadHandle, ThreadInformationClass, ref ThreadInformation, ThreadInformationLength, ReturnLength);
                    FreeCode(Syscall);
                    return Result;
                }
                catch
                {
                    FreeCode(Syscall);
                }
            }
            return 1;
        }
        #endregion
    }
}