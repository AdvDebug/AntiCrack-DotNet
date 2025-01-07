using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using static AntiCrack_DotNet.Structs;

namespace AntiCrack_DotNet
{
    internal sealed class AntiInjection
    {

        #region WinApi

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lib);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr ModuleHandle, string Function);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(SafeHandle hProcess, IntPtr BaseAddress, byte[] Buffer, uint size, int NumOfBytes);

        [DllImport("kernelbase.dll", SetLastError = true)]
        public static extern bool SetProcessMitigationPolicy(int policy, ref Structs.PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY lpBuffer, int size);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtOpenThread(out IntPtr hThread, uint dwDesiredAccess, ref Structs.OBJECT_ATTRIBUTES ObjectAttributes, ref Structs.CLIENT_ID ClientID);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, ref IntPtr ThreadInformation, uint ThreadInformationLength, IntPtr ReturnLength);

        #endregion

        /// <summary>
        /// Checks if there are any injected libraries in the current process.
        /// </summary>
        /// <returns>Returns true if an injected library is detected, otherwise false.</returns>
        public static bool IsInjectedLibrary()
        {
            bool IsMalicious = false;
            string Windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLower();
            string ProgramData = Windows.Replace(@"\windows", @"\programdata");
            foreach (ProcessModule Module in Process.GetCurrentProcess().Modules)
            {
                string FileName = Module.FileName.ToLower();
                if (!FileName.StartsWith(Windows) && !FileName.StartsWith(ProgramData))
                    IsMalicious = true;

                if (FileName.StartsWith(Environment.CurrentDirectory.ToLower()))
                    IsMalicious = false;
            }
            return IsMalicious;
        }

        /// <summary>
        /// Sets the DLL load policy to only allow Microsoft-signed DLLs to be loaded.
        /// </summary>
        /// <returns>Returns "Success" if the policy was set successfully, otherwise "Failed".</returns>
        public static string SetDllLoadPolicy()
        {
            Structs.PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy = new Structs.PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
            {
                MicrosoftSignedOnly = 1
            };
            if (SetProcessMitigationPolicy(8, ref policy, Marshal.SizeOf(policy)))
                return "Success";
            return "Failed";
        }

        /// <summary>
        /// Detects if an address is in range inside modules or not.
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
        /// Detects if an address is in range inside modules or not.
        /// </summary>
        /// <param name="Syscall">Specifies whether we use syscalls for the check or not.</param>
        /// <param name="CheckModuleRange">Check if the threads start address is within modules range or not.</param>
        /// <returns>Returns true if no thread is injected, otherwise false.</returns>
        public static bool CheckInjectedThreads(bool Syscall, bool CheckModuleRange)
        {
            uint MEM_IMAGE = 0x1000000;
            uint MEM_COMMIT = 0x1000;
            int ThreadQuerySetWin32StartAddress = 9;
            uint THREAD_QUERY_INFORMATION = 0x0040;
            int PID = Process.GetCurrentProcess().Id;
            foreach (ProcessThread thread in Process.GetCurrentProcess().Threads)
            {
                CLIENT_ID CI = new CLIENT_ID
                {
                    UniqueProcess = (IntPtr)PID,
                    UniqueThread = (IntPtr)thread.Id
                };

                OBJECT_ATTRIBUTES Attributes = new OBJECT_ATTRIBUTES
                {
                    Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
                    RootDirectory = IntPtr.Zero,
                    ObjectName = IntPtr.Zero,
                    Attributes = 0,
                    SecurityDescriptor = IntPtr.Zero,
                    SecurityQualityOfService = IntPtr.Zero
                };

                IntPtr hThread = IntPtr.Zero;
                uint Status = NtOpenThread(out hThread, THREAD_QUERY_INFORMATION, ref Attributes, ref CI);
                if (Status == 0 || hThread != IntPtr.Zero)
                {
                    IntPtr StartAddress = IntPtr.Zero;
                    int QueryStatus = Syscall ? Syscalls.SyscallNtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, ref StartAddress, (uint)IntPtr.Size, IntPtr.Zero) : NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, ref StartAddress, (uint)IntPtr.Size, IntPtr.Zero);
                    Utils.CloseHandle(hThread);
                    if (QueryStatus == 0)
                    {
                        MEMORY_BASIC_INFORMATION MBI = new MEMORY_BASIC_INFORMATION();
                        if (Utils.GetVirtualMemoryQuery(Syscall, StartAddress, ref MBI, out _))
                        {
                            if (MBI.Type != MEM_IMAGE || MBI.State != MEM_COMMIT)
                            {
                                return true;
                            }

                            if (CheckModuleRange)
                            {
                                if (!IsAddressInRange(StartAddress))
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            return false;
        }

        /// <summary>
        /// Generate a random module name.
        /// </summary>
        /// <returns>the random module name.</returns>
        private static string GenerateRandomModule()
        {
            string Letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            Random random = new Random();
            int RandomLength = random.Next(6, 32);
            char[] NewModule = new char[RandomLength];
            for (int i = 0; i < RandomLength; i++)
            {
                NewModule[i] = Letters[random.Next(Letters.Length)];
            }
            return new string(NewModule);
        }

        /// <summary>
        /// Changes the module information at runtime to avoid modification.
        /// </summary>
        /// <param name="Module">The module name which we will change it's information, if left null, we get the main module of the process.</param>
        /// <param name="ChangeBaseAddress">An indicator to change the base address.</param>
        /// <param name="ChangeModuleName">An indicator to change the module name to something random.</param>
        /// <returns>Returns true if successfully changed the module info, otherwise false.</returns>
        public static bool ChangeModuleInfo(string Module, bool ChangeBaseAddress, bool ChangeModuleName)
        {
            try
            {
                if (!ChangeBaseAddress && !ChangeModuleName)
                    return false;
                string FinalModuleName = null;
                if (Module == null)
                {
                    string MainModule = Process.GetCurrentProcess().MainModule.ModuleName;
                    if (MainModule != null)
                        FinalModuleName = MainModule;
                }
                else
                {
                    FinalModuleName = Module;
                }
                string Fake = $"{GenerateRandomModule()}.dll";
                PEB Peb = Utils.GetPEB();
                _PEB_LDR_DATA Ldr = Marshal.PtrToStructure<_PEB_LDR_DATA>(Peb.Ldr);
                IntPtr f = Ldr.InMemoryOrderModuleList.Flink;
                int count = 0;
                while (count < 256)
                {
                    _LDR_DATA_TABLE_ENTRY TableEntry = Marshal.PtrToStructure<_LDR_DATA_TABLE_ENTRY>(f);
                    string ModuleName = Marshal.PtrToStringUni(TableEntry.FullDllName.Buffer);
                    if (ModuleName != null && ModuleName == FinalModuleName)
                    {
                        if (ChangeBaseAddress)
                        {
                            int RandomBaseAddress = new Random().Next(0x100000 / 0x1000, 0x7FFF000 / 0x1000) * 0x1000;
                            TableEntry.DllBase = (IntPtr)RandomBaseAddress;
                        }

                        if (ChangeModuleName)
                        {
                            IntPtr FakeDllBuffer = Marshal.StringToHGlobalUni(Fake);
                            TableEntry.FullDllName.Buffer = FakeDllBuffer;
                            TableEntry.FullDllName.Length = (ushort)(Fake.Length * 2);
                            TableEntry.FullDllName.MaximumLength = (ushort)((Fake.Length + 1) * 2);
                        }
                        Marshal.StructureToPtr(TableEntry, f, false);
                        return true;
                    }
                    f = TableEntry.InLoadOrderLinks.Flink;
                    count++;
                }
            }
            catch
            {
                
            }
            return false;
        }

        /// <summary>
        /// Detects ImageBaseAddress modification which could indicate code injection in our process (process hollowing).
        /// </summary>
        /// <returns>Returns true if the ImageBaseAddress is suspicious, otherwise false.</returns>
        public static bool CheckForSuspiciousBaseAddress()
        {
            try
            {
                PEB Peb = Utils.GetPEB();
                if (Peb.ImageBaseAddress != Process.GetCurrentProcess().MainModule.BaseAddress)
                    return true;
            }
            catch
            {

            }
            return false;
        }
    }
}