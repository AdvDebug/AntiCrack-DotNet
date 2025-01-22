using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using static AntiCrack_DotNet.Structs;

namespace AntiCrack_DotNet
{
    [Flags]
    public enum Spoofs
    {
        BaseAddress = 1 << 0,
        ModuleName = 1 << 1,
        AddressOfEntryPoint = 1 << 2,
        SizeOfImage = 1 << 3,
        NumberOfSections = 1 << 4,
        ImageMagic = 1 << 5,
        NotExecutableNorDll = 1 << 6,
        PESignature = 1 << 7,
        ExecutableSectionName = 1 << 8,
        ExecutableSectionRawSize = 1 << 9,
        ExecutableSectionRawPointer = 1 << 10,
        ClearExecutableSectionCharacteristics = 1 << 11,
        ExecutableSectionVirtualSize = 1 << 12,
    }

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
        private static string GenerateRandomString()
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

        private static bool IsFlagsSet(Spoofs SpoofOptions, Spoofs[] spoofs)
        {
            foreach (Spoofs spoofa in spoofs)
            {
                if (SpoofOptions.HasFlag(spoofa))
                    return true;
            }
            return false;
        }

        private static bool IsPE_FlagsSet(Spoofs SpoofOptions)
        {
            Spoofs[] spoofs = {
        Spoofs.AddressOfEntryPoint, Spoofs.SizeOfImage, Spoofs.ExecutableSectionRawSize,
        Spoofs.ExecutableSectionRawPointer, Spoofs.PESignature, Spoofs.ImageMagic,
        Spoofs.NotExecutableNorDll, Spoofs.NumberOfSections, Spoofs.ClearExecutableSectionCharacteristics,
        Spoofs.ExecutableSectionVirtualSize };
            return IsFlagsSet(SpoofOptions, spoofs);
        }

        /// <summary>
        /// Changes the module information at runtime to avoid modification/lookups.
        /// </summary>
        /// <param name="ModuleName">The module name which we will change it's information. if left null, we get the main module of the process.</param>
        /// <param name="SpoofOptions">The spoofing options to apply.</param>
        /// <returns>Returns true if successfully changed the module info, otherwise false.</returns>
        public static bool ChangeModuleInfo(string ModuleName, Spoofs SpoofOptions)
        {
            try
            {
                string FinalModuleName = ModuleName ?? Process.GetCurrentProcess().MainModule.ModuleName;
                if (string.IsNullOrEmpty(FinalModuleName))
                    return false;

                IntPtr hModule = Utils.LowLevelGetModuleHandle(FinalModuleName);
                if (hModule == IntPtr.Zero)
                    return false;

                string Fake = $"{GenerateRandomString()}.dll";
                PEB Peb = Utils.GetPEB();
                _PEB_LDR_DATA Ldr = Marshal.PtrToStructure<_PEB_LDR_DATA>(Peb.Ldr);
                IntPtr f = Ldr.InMemoryOrderModuleList.Flink;
                Random RandGen = new Random();

                for (int count = 0; count < 256 && f != IntPtr.Zero; count++)
                {
                    _LDR_DATA_TABLE_ENTRY TableEntry = Marshal.PtrToStructure<_LDR_DATA_TABLE_ENTRY>(f);
                    string ModuleNameBuffer = Marshal.PtrToStringUni(TableEntry.FullDllName.Buffer);

                    if (!string.IsNullOrEmpty(ModuleNameBuffer) && ModuleNameBuffer == FinalModuleName)
                    {
                        if (IsPE_FlagsSet(SpoofOptions))
                        {
                            Spoofs[] SectionSpoof = {
                        Spoofs.ExecutableSectionName, Spoofs.ExecutableSectionRawPointer,
                        Spoofs.ExecutableSectionRawSize, Spoofs.ClearExecutableSectionCharacteristics, Spoofs.ExecutableSectionVirtualSize};

                            IMAGE_DOS_HEADER dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(hModule);
                            IntPtr pNtHeaders = IntPtr.Add(hModule, dosHeader.e_lfanew);

                            if (IntPtr.Size == 8)
                            {
                                IMAGE_NT_HEADERS64 NtHeadersStruct = Marshal.PtrToStructure<IMAGE_NT_HEADERS64>(pNtHeaders);
                                if (SpoofOptions.HasFlag(Spoofs.AddressOfEntryPoint))
                                    NtHeadersStruct.OptionalHeader.AddressOfEntryPoint = (uint)RandGen.Next(0x1000, 0x2000);

                                if (SpoofOptions.HasFlag(Spoofs.NumberOfSections))
                                    NtHeadersStruct.FileHeader.NumberOfSections = (ushort)RandGen.Next(NtHeadersStruct.FileHeader.NumberOfSections, NtHeadersStruct.FileHeader.NumberOfSections + 99);

                                if (SpoofOptions.HasFlag(Spoofs.ImageMagic))
                                    NtHeadersStruct.OptionalHeader.Magic = (ushort)RandGen.Next(0, int.MaxValue);

                                if (SpoofOptions.HasFlag(Spoofs.SizeOfImage))
                                    NtHeadersStruct.OptionalHeader.SizeOfImage = (uint)RandGen.Next((int)NtHeadersStruct.OptionalHeader.SizeOfImage, (int)(NtHeadersStruct.OptionalHeader.SizeOfImage + 0x10000));

                                if (SpoofOptions.HasFlag(Spoofs.NotExecutableNorDll))
                                {
                                    ushort IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
                                    ushort IMAGE_FILE_DLL = 0x2000;
                                    NtHeadersStruct.FileHeader.Characteristics &= (ushort)~IMAGE_FILE_EXECUTABLE_IMAGE;
                                    NtHeadersStruct.FileHeader.Characteristics &= (ushort)~IMAGE_FILE_DLL;
                                }

                                if (SpoofOptions.HasFlag(Spoofs.PESignature))
                                    NtHeadersStruct.Signature = 0x4D5A0000;

                                if (IsFlagsSet(SpoofOptions, SectionSpoof))
                                {
                                    IntPtr pSectionHeaders = IntPtr.Add(pNtHeaders, sizeof(uint) + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)) + NtHeadersStruct.FileHeader.SizeOfOptionalHeader); //defined in here for now
                                    IntPtr pSectionHeader = pSectionHeaders;
                                    int SectionSize = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));

                                    for (int i = 0; i < NtHeadersStruct.FileHeader.NumberOfSections; i++)
                                    {
                                        IMAGE_SECTION_HEADER SectionHeader = Marshal.PtrToStructure<IMAGE_SECTION_HEADER>(pSectionHeader);
                                        uint IMAGE_SCN_CNT_CODE = 0x00000020;
                                        if ((SectionHeader.Characteristics & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE)
                                        {
                                            if (SpoofOptions.HasFlag(Spoofs.ExecutableSectionName))
                                                SectionHeader.Name = Encoding.ASCII.GetBytes($".{GenerateRandomString()}");

                                            if (SpoofOptions.HasFlag(Spoofs.ExecutableSectionRawPointer))
                                                SectionHeader.PointerToRawData = (uint)RandGen.Next(0, int.MaxValue);

                                            if (SpoofOptions.HasFlag(Spoofs.ExecutableSectionRawSize))
                                                SectionHeader.SizeOfRawData = (uint)RandGen.Next(0, int.MaxValue);

                                            if (SpoofOptions.HasFlag(Spoofs.ClearExecutableSectionCharacteristics))
                                                SectionHeader.Characteristics = 0;

                                            if (SpoofOptions.HasFlag(Spoofs.ExecutableSectionVirtualSize))
                                                SectionHeader.VirtualSize = (uint)RandGen.Next((int)SectionHeader.VirtualSize, (int)SectionHeader.VirtualSize + 0x10000);

                                            Utils.WriteStructToPtr(SectionHeader, pSectionHeader, true, true);
                                            break;
                                        }

                                        pSectionHeader = IntPtr.Add(pSectionHeader, SectionSize);
                                    }
                                }

                                Utils.WriteStructToPtr(NtHeadersStruct, pNtHeaders, true, true);
                            }
                            else
                            {
                                IMAGE_NT_HEADERS32 NtHeadersStruct = Marshal.PtrToStructure<IMAGE_NT_HEADERS32>(pNtHeaders);
                                if (SpoofOptions.HasFlag(Spoofs.AddressOfEntryPoint))
                                    NtHeadersStruct.OptionalHeader.AddressOfEntryPoint = (uint)RandGen.Next(0x1000, 0x2000);

                                if (SpoofOptions.HasFlag(Spoofs.NumberOfSections))
                                    NtHeadersStruct.FileHeader.NumberOfSections = (ushort)RandGen.Next(NtHeadersStruct.FileHeader.NumberOfSections, NtHeadersStruct.FileHeader.NumberOfSections + 99);

                                if (SpoofOptions.HasFlag(Spoofs.ImageMagic))
                                    NtHeadersStruct.OptionalHeader.Magic = (ushort)RandGen.Next(0, int.MaxValue);

                                if (SpoofOptions.HasFlag(Spoofs.SizeOfImage))
                                    NtHeadersStruct.OptionalHeader.SizeOfImage = (uint)RandGen.Next((int)NtHeadersStruct.OptionalHeader.SizeOfImage, (int)(NtHeadersStruct.OptionalHeader.SizeOfImage + 0x10000));

                                if (SpoofOptions.HasFlag(Spoofs.NotExecutableNorDll))
                                {
                                    ushort IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
                                    ushort IMAGE_FILE_DLL = 0x2000;
                                    NtHeadersStruct.FileHeader.Characteristics &= (ushort)~IMAGE_FILE_EXECUTABLE_IMAGE;
                                    NtHeadersStruct.FileHeader.Characteristics &= (ushort)~IMAGE_FILE_DLL;
                                }

                                if (SpoofOptions.HasFlag(Spoofs.PESignature))
                                    NtHeadersStruct.Signature = 0x4D5A0000;

                                if (IsFlagsSet(SpoofOptions, SectionSpoof))
                                {
                                    IntPtr pSectionHeaders = IntPtr.Add(pNtHeaders, sizeof(uint) + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)) + NtHeadersStruct.FileHeader.SizeOfOptionalHeader); //defined in here for now
                                    IntPtr pSectionHeader = pSectionHeaders;
                                    int SectionSize = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));

                                    for (int i = 0; i < NtHeadersStruct.FileHeader.NumberOfSections; i++)
                                    {
                                        IMAGE_SECTION_HEADER SectionHeader = Marshal.PtrToStructure<IMAGE_SECTION_HEADER>(pSectionHeader);
                                        uint IMAGE_SCN_CNT_CODE = 0x00000020;
                                        if ((SectionHeader.Characteristics & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE)
                                        {
                                            if (SpoofOptions.HasFlag(Spoofs.ExecutableSectionName))
                                                SectionHeader.Name = Encoding.ASCII.GetBytes($".{GenerateRandomString()}");

                                            if (SpoofOptions.HasFlag(Spoofs.ExecutableSectionRawPointer))
                                                SectionHeader.PointerToRawData = (uint)RandGen.Next(0, int.MaxValue);

                                            if (SpoofOptions.HasFlag(Spoofs.ExecutableSectionRawSize))
                                                SectionHeader.SizeOfRawData = (uint)RandGen.Next(0, int.MaxValue);

                                            if (SpoofOptions.HasFlag(Spoofs.ClearExecutableSectionCharacteristics))
                                                SectionHeader.Characteristics = 0;

                                            if (SpoofOptions.HasFlag(Spoofs.ExecutableSectionVirtualSize))
                                                SectionHeader.VirtualSize = (uint)RandGen.Next((int)SectionHeader.VirtualSize, (int)SectionHeader.VirtualSize + 0x10000);

                                            Utils.WriteStructToPtr(SectionHeader, pSectionHeader, true, true);
                                            break;
                                        }

                                        pSectionHeader = IntPtr.Add(pSectionHeader, SectionSize);
                                    }
                                }

                                Utils.WriteStructToPtr(NtHeadersStruct, pNtHeaders, true, true);
                            }
                        }

                        if (SpoofOptions.HasFlag(Spoofs.BaseAddress))
                        {
                            TableEntry.DllBase = (IntPtr)(RandGen.Next(0x100000 / 0x1000, 0x7FFF000 / 0x1000) * 0x1000);
                        }

                        if (SpoofOptions.HasFlag(Spoofs.ModuleName))
                        {
                            IntPtr FakeDllBuffer = Marshal.StringToHGlobalUni(Fake);
                            TableEntry.FullDllName.Buffer = FakeDllBuffer;
                            TableEntry.FullDllName.Length = (ushort)(Fake.Length * 2);
                            TableEntry.FullDllName.MaximumLength = (ushort)((Fake.Length + 1) * 2);
                        }

                        Utils.WriteStructToPtr(TableEntry, f, true, true);
                        return true;
                    }
                    f = TableEntry.InLoadOrderLinks.Flink;
                }
            }
            catch
            {
                return false;
            }
            return false;
        }

        /// <summary>
        /// Changes CLR Module ImageMagic to prevent critical info lookups.
        /// </summary>
        /// <returns>Returns true if successful, otherwise false.</returns>
        public static bool ChangeCLRModuleImageMagic()
        {
            string CLR = Utils.GetCurrentCLRModuleName();
            if (!string.IsNullOrEmpty(CLR))
            {
                return ChangeModuleInfo(CLR, Spoofs.ImageMagic);
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