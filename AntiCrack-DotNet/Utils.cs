using System;
using System.Runtime.InteropServices;
using System.Text;
using static AntiCrack_DotNet.Structs;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Globalization;
using static AntiCrack_DotNet.Delegates;
using System.Diagnostics;

namespace AntiCrack_DotNet
{
    public sealed class Utils
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

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandleA(string Library);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string Function);

        [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern uint LdrGetProcedureAddressForCaller(IntPtr Module, Structs.ANSI_STRING ProcedureName, ushort ProcedureNumber, out IntPtr FunctionHandle, ulong Flags, IntPtr CallBack);

        [DllImport("kernelbase.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern uint GetModuleFileName(IntPtr hModule, StringBuilder lpFileName, uint nSize);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtProtectVirtualMemory(IntPtr hProcess, ref IntPtr BaseAddress, ref UIntPtr RegionSize, uint NewProtect, out uint oldProtect);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQueryVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, uint MemoryInformationClass, ref Structs.MEMORY_BASIC_INFORMATION MemoryInformation, uint MemoryInformationLength, out uint ReturnLength);

        [DllImport("ntdll", SetLastError = true)]
        private static extern uint NtClose(IntPtr hObject);

        #endregion

        /// <summary>
        /// Gets the handle of a specified module using low-level functions.
        /// </summary>
        /// <param name="Library">The name of the library to get the handle for.</param>
        /// <returns>The handle to the module.</returns>
        public static IntPtr LowLevelGetModuleHandle(string Library)
        {
            if (IntPtr.Size == 4)
                return GetModuleHandleA(Library);
            IntPtr hModule = IntPtr.Zero;
            Structs.UNICODE_STRING UnicodeString = new Structs.UNICODE_STRING();
            RtlInitUnicodeString(out UnicodeString, Library);
            LdrGetDllHandleEx(0, null, null, UnicodeString, ref hModule);
            return hModule;
        }

        /// <summary>
        /// Gets the address of a specified function using low-level functions.
        /// </summary>
        /// <param name="hModule">The handle to the module.</param>
        /// <param name="Function">The name of the function to get the address for.</param>
        /// <returns>The address of the function.</returns>
        public static IntPtr LowLevelGetProcAddress(IntPtr hModule, string Function)
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

        /// <summary>
        /// Gets the export address of a function.
        /// </summary>
        /// <param name="Module">The module name.</param>
        /// <param name="Function">The name of the function to get the export address for.</param>
        /// <returns>The address of the function.</returns>
        public static IntPtr GetFunctionExportAddress(string Module, string Function)
        {
            IntPtr hModule = LowLevelGetModuleHandle(Module);
            try
            {
                IntPtr pDosHeader = hModule;
                IMAGE_DOS_HEADER dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(pDosHeader);
                IntPtr pNtHeaders = IntPtr.Add(pDosHeader, dosHeader.e_lfanew);
                dynamic NtHeadersStruct;
                if (IntPtr.Size == 8)
                    NtHeadersStruct = Marshal.PtrToStructure<IMAGE_NT_HEADERS64>(pNtHeaders);
                else
                    NtHeadersStruct = Marshal.PtrToStructure<IMAGE_NT_HEADERS32>(pNtHeaders);
                IMAGE_DATA_DIRECTORY EPData = NtHeadersStruct.OptionalHeader.DataDirectory;
                IntPtr pExportDirectory = IntPtr.Add(hModule, (int)EPData.VirtualAddress);
                IMAGE_EXPORT_DIRECTORY ED = Marshal.PtrToStructure<IMAGE_EXPORT_DIRECTORY>(pExportDirectory);
                IntPtr pAddressOfFunctions = IntPtr.Add(hModule, (int)ED.AddressOfFunctions);
                IntPtr pAddressOfNames = IntPtr.Add(hModule, (int)ED.AddressOfNames);
                IntPtr pAddressOfNameOrdinals = IntPtr.Add(hModule, (int)ED.AddressOfNameOrdinals);
                int NamesCount = (int)ED.NumberOfNames;
                for (int i = 0; i < NamesCount; i++)
                {
                    int FunctionNameRva = Marshal.ReadInt32(IntPtr.Add(pAddressOfNames, i * 4));
                    string FunctionName = Marshal.PtrToStringAnsi(IntPtr.Add(hModule, FunctionNameRva));
                    if (FunctionName == Function)
                    {
                        int FunctionOrdinal = Marshal.ReadInt16(IntPtr.Add(pAddressOfNameOrdinals, i * 2));
                        int FunctionRVA = Marshal.ReadInt32(IntPtr.Add(pAddressOfFunctions, FunctionOrdinal * 4));
                        return IntPtr.Add(hModule, FunctionRVA);
                    }
                }
            }
            catch
            {

            }
            return LowLevelGetProcAddress(hModule, Function);
        }

        /// <summary>
        /// Gets the export address of a function.
        /// </summary>
        /// <param name="hModule">The module handle.</param>
        /// <param name="Function">The name of the function to get the export address for.</param>
        /// <returns>The address of the function.</returns>
        public static IntPtr GetFunctionExportAddress(IntPtr hModule, string Function)
        {
            try
            {
                IntPtr pDosHeader = hModule;
                IMAGE_DOS_HEADER dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(pDosHeader);
                IntPtr pNtHeaders = IntPtr.Add(pDosHeader, dosHeader.e_lfanew);
                dynamic NtHeadersStruct;
                if (IntPtr.Size == 8)
                    NtHeadersStruct = Marshal.PtrToStructure<IMAGE_NT_HEADERS64>(pNtHeaders);
                else
                    NtHeadersStruct = Marshal.PtrToStructure<IMAGE_NT_HEADERS32>(pNtHeaders);
                IMAGE_DATA_DIRECTORY EPData = NtHeadersStruct.OptionalHeader.DataDirectory;
                IntPtr pExportDirectory = IntPtr.Add(hModule, (int)EPData.VirtualAddress);
                IMAGE_EXPORT_DIRECTORY ED = Marshal.PtrToStructure<IMAGE_EXPORT_DIRECTORY>(pExportDirectory);
                IntPtr pAddressOfFunctions = IntPtr.Add(hModule, (int)ED.AddressOfFunctions);
                IntPtr pAddressOfNames = IntPtr.Add(hModule, (int)ED.AddressOfNames);
                IntPtr pAddressOfNameOrdinals = IntPtr.Add(hModule, (int)ED.AddressOfNameOrdinals);
                int NamesCount = (int)ED.NumberOfNames;
                for (int i = 0; i < NamesCount; i++)
                {
                    int FunctionNameRva = Marshal.ReadInt32(IntPtr.Add(pAddressOfNames, i * 4));
                    string FunctionName = Marshal.PtrToStringAnsi(IntPtr.Add(hModule, FunctionNameRva));
                    if (FunctionName == Function)
                    {
                        int FunctionOrdinal = Marshal.ReadInt16(IntPtr.Add(pAddressOfNameOrdinals, i * 2));
                        int FunctionRVA = Marshal.ReadInt32(IntPtr.Add(pAddressOfFunctions, FunctionOrdinal * 4));
                        return IntPtr.Add(hModule, FunctionRVA);
                    }
                }
            }
            catch
            {

            }
            return LowLevelGetProcAddress(hModule, Function);
        }

        /// <summary>
        /// Writes the struct to a pointer.
        /// </summary>
        /// <param name="structure">The struct.</param>
        /// <param name="ptr">The pointer to the address that represents the struct.</param>
        /// <param name="fDeleteOld">An indicator to whether we should delete the old struct after writing or not.</param>
        /// <param name="ChangeMemoryProtection">An indicator to whether we should change the ptr memory protection before writing.</param>
        /// <returns>return true if successful, otherwise false.</returns>
        public static bool WriteStructToPtr<T>(T structure, IntPtr ptr, bool fDeleteOld, bool ChangeMemoryProtection)
        {
            try
            {
                if (ChangeMemoryProtection)
                {
                    uint Old = 0;
                    ProtectMemory(ptr, (UIntPtr)Marshal.SizeOf(structure), PAGE_EXECUTE_READWRITE, out Old);
                    Marshal.StructureToPtr(structure, ptr, fDeleteOld);
                    ProtectMemory(ptr, (UIntPtr)Marshal.SizeOf(structure), Old, out Old);
                    return true;
                }
                else
                {
                    Marshal.StructureToPtr(structure, ptr, fDeleteOld);
                    return true;
                }
            }
            catch
            {
                
            }
            return false;
        }

        public static string GetCurrentCLRModuleName()
        {
            string[] CLRs = { "clr.dll", "coreclr.dll" };
            foreach(ProcessModule module in Process.GetCurrentProcess().Modules)
            {
                foreach (string CLR in CLRs)
                {
                    if (module.ModuleName.ToLower() == CLR)
                    {
                        return module.ModuleName;
                    }
                }
            }
            return null;
        }

        /// <summary>
        /// Changes the page protection for an address.
        /// </summary>
        /// <param name="BaseAddress">The Address to change the protection for.</param>
        /// <param name="RegionSize">The size of the address.</param>
        /// <param name="NewProtect">The new protection to apply.</param>
        /// <param name="oldProtect">The old protection if you wanna set it back again.</param>
        /// <returns>return true if successfully did it's job, otherwise false.</returns>
        public static bool ProtectMemory(IntPtr BaseAddress, UIntPtr RegionSize, uint NewProtect, out uint oldProtect)
        {
            int Status = NtProtectVirtualMemory(new IntPtr(-1), ref BaseAddress, ref RegionSize, NewProtect, out oldProtect);
            if (Status == 0)
                return true;
            return false;
        }

        /// <summary>
        /// Reads a byte from a specified memory address.
        /// </summary>
        /// <param name="ptr">The memory address to read from.</param>
        /// <returns>The byte read from the memory address.</returns>
        public static byte InternalReadByte(IntPtr ptr)
        {
            unsafe
            {
                try
                {
                    byte* ptr2 = (byte*)(void*)ptr;
                    return *ptr2;
                }
                catch
                {
                    return 0;
                }
            }
        }

        /// <summary>
        /// Force exits the process even if hooked.
        /// </summary>
        public static void ForceExit()
        {
            Environment.Exit(0);
            unsafe
            {
                int* ptr = null;
                *ptr = 42;
            }
            throw new Exception(new Random().Next(int.MinValue, int.MaxValue).ToString());
        }

        /// <summary>
        /// copies memory from a byte array to an IntPtr.
        /// </summary>
        /// <param name="dst">The IntPtr destination in which the data will be copied to.</param>
        /// <param name="src">The byte array source in which the data will be copied from.</param>
        public static void CopyMem(IntPtr dst, byte[] src, bool ChangeProtection)
        {
            unsafe
            {
                fixed (byte* source = src)
                {
                    if (ChangeProtection)
                    {
                        uint oldProtect = 0;
                        if (ProtectMemory(dst, (UIntPtr)src.Length, 0x40, out oldProtect))
                        {
                            Buffer.MemoryCopy(source, (void*)dst, src.Length, src.Length);
                            ProtectMemory(dst, (UIntPtr)src.Length, oldProtect, out oldProtect);
                        }
                    }
                    else
                    {
                        Buffer.MemoryCopy(source, (void*)dst, src.Length, src.Length);
                    }
                }
            }
        }

        /// <summary>
        /// copies memory from an IntPtr to a byte array.
        /// </summary>
        /// <param name="dst">The byte array destination in which the data will be copied to.</param>
        /// <param name="src">The IntPtr source in which the data will be copied from.</param>
        public static void CopyMem(byte[] dst, IntPtr src, bool ChangeProtection)
        {
            unsafe
            {
                fixed (byte* destination = dst)
                {
                    if (ChangeProtection)
                    {
                        uint oldProtect = 0;
                        if (ProtectMemory(src, (UIntPtr)dst.Length, 0x40, out oldProtect))
                        {
                            Buffer.MemoryCopy((void*)src, destination, dst.Length, dst.Length);
                            ProtectMemory(src, (UIntPtr)dst.Length, oldProtect, out oldProtect);
                        }
                    }
                    else
                    {
                        Buffer.MemoryCopy((void*)src, destination, dst.Length, dst.Length);
                    }
                }
            }
        }

        /// <summary>
        /// copies memory from an IntPtr to another.
        /// </summary>
        /// <param name="dst">The byte array destination in which the data will be copied to.</param>
        /// <param name="src">The IntPtr source in which the data will be copied from.</param>
        public static void CopyMem(IntPtr dst, IntPtr src, bool ChangeProtection)
        {
            unsafe
            {
                int SizeDst = Marshal.SizeOf(dst);
                if (ChangeProtection)
                {
                    uint oldProtect = 0;
                    if (ProtectMemory(dst, (UIntPtr)SizeDst, 0x40, out oldProtect))
                    {
                        Buffer.MemoryCopy((void*)src, (void*)dst, SizeDst, SizeDst);
                        ProtectMemory(dst, (UIntPtr)SizeDst, oldProtect, out oldProtect);
                    }
                }
                else
                {
                    Buffer.MemoryCopy((void*)src, (void*)dst, SizeDst, SizeDst);
                }
            }
        }

        /// <summary>
        /// Sees if the first string contains the second string.
        /// </summary>
        /// <param name="First">First string to see if it contains the second string.</param>
        /// <param name="Second">The second string that will be searched for.</param>
        /// <returns>if the second string contains a string from the first one then the result is true, otherwise false.</returns>
        public static bool Contains(string First, string Second)
        {
            if (CultureInfo.InvariantCulture.CompareInfo.IndexOf(First, Second, 0, First.Length, CompareOptions.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }
            return false;
        }

        /// <summary>
        /// The method which is invoked to test reflection for IsReflectionEnabled.
        /// </summary>
        /// <returns>a random number from 1-99</returns>
        private static int TestInvoke()
        {
            return new Random().Next(1, 99);
        }

        /// <summary>
        /// Checks if reflection is supported before doing reflection operations.
        /// </summary>
        /// <param name="FPSupport">Check if we can get a function pointer.</param>
        /// <param name="InvokeSupport">Check if we can invoke another function.</param>
        /// <returns>return true if reflection is enabled and supports the options you provided, otherwise false.</returns>
        public static bool IsReflectionEnabled(bool FPSupport, bool InvokeSupport)
        {
            try
            {
                MethodBase BaseMethodTest = MethodBase.GetCurrentMethod().DeclaringType.GetMethod("TestInvoke", BindingFlags.NonPublic | BindingFlags.Static);
                if (BaseMethodTest == null)
                    return false;
                if (InvokeSupport)
                {
                    if (BaseMethodTest.Invoke(null, null) == null || (int)BaseMethodTest.Invoke(null, null) == 0)
                        return false;
                }

                if (FPSupport)
                {
                    if (GetPointer(BaseMethodTest as MethodInfo) == IntPtr.Zero)
                        return false;
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Converts a cast to a stack pointer.
        /// </summary>
        /// <returns>The stack pointer of the cast you provided.</returns>
        private static IntPtr UnsafeCastToStackPointer<T>(ref T o) where T : class
        {
            unsafe
            {
                fixed (T* ptr = &o)
                {
                    return (IntPtr)ptr;
                }
            }
        }

        /// <summary>
        /// Gets the entry assembly directly using internal .NET functions using reflection.
        /// </summary>
        /// <returns>if successful then it returns the entry assembly, otherwise null.</returns>
        public static Assembly LowLevelGetEntryAssembly()
        {
            if (!IsReflectionEnabled(false, true))
                return null;
            Assembly EntryAsm = null;
            try
            {
                IntPtr AsmPtr = UnsafeCastToStackPointer(ref EntryAsm);
                if (AsmPtr != IntPtr.Zero)
                {
                    Type ObjectHandleOnStackType = Type.GetType("System.Runtime.CompilerServices.ObjectHandleOnStack");
                    if (ObjectHandleOnStackType != null)
                    {
                        object InstanceObjectHandle = Activator.CreateInstance(ObjectHandleOnStackType);
                        FieldInfo mPtrFieldObjectHandle = ObjectHandleOnStackType.GetField("m_ptr", BindingFlags.NonPublic | BindingFlags.Instance);
                        mPtrFieldObjectHandle.SetValue(InstanceObjectHandle, AsmPtr);
                        Utils.CallInternalCLRFunction("GetEntryAssembly", typeof(AppDomainManager), BindingFlags.NonPublic | BindingFlags.Static, null, new object[] { InstanceObjectHandle }, null);
                    }
                }
            }
            catch
            {
                return null;
            }
            return EntryAsm;
        }

        /// <summary>
        /// Gets the currently executing assembly directly using internal .NET functions using reflection.
        /// </summary>
        /// <returns>if successful then it returns the executing assembly, otherwise null.</returns>
        public static Assembly LowLevelGetExecutingAssembly()
        {
            if (!IsReflectionEnabled(false, true))
                return null;
            Assembly ExecutingAssembly = null;
            try
            {
                IntPtr AsmPtr = UnsafeCastToStackPointer(ref ExecutingAssembly);
                if (AsmPtr != IntPtr.Zero)
                {
                    Type ObjectHandleOnStackType = Type.GetType("System.Runtime.CompilerServices.ObjectHandleOnStack");
                    Type StackCrawlMarksType = Type.GetType("System.Runtime.CompilerServices.StackCrawlMarkHandle");
                    if (ObjectHandleOnStackType != null && StackCrawlMarksType != null)
                    {
                        object InstanceObjectHandle = Activator.CreateInstance(ObjectHandleOnStackType);
                        FieldInfo mPtrFieldObjectHandle = ObjectHandleOnStackType.GetField("m_ptr", BindingFlags.NonPublic | BindingFlags.Instance);
                        mPtrFieldObjectHandle.SetValue(InstanceObjectHandle, AsmPtr);
                        Type StackCrawlMarkEnumType = Type.GetType("System.Threading.StackCrawlMark");
                        object LookForMyCaller = Enum.Parse(StackCrawlMarkEnumType, "LookForMyCaller");
                        IntPtr StackCrawlMarkPtr = UnsafeCastToStackPointer(ref LookForMyCaller);
                        if (StackCrawlMarkPtr != IntPtr.Zero)
                        {
                            object InstanceStackCrawl = Activator.CreateInstance(StackCrawlMarksType);
                            FieldInfo mPtrFieldStackCrawl = StackCrawlMarksType.GetField("m_ptr", BindingFlags.NonPublic | BindingFlags.Instance);
                            mPtrFieldStackCrawl.SetValue(InstanceStackCrawl, StackCrawlMarkPtr);
                            Utils.CallInternalCLRFunction("GetExecutingAssembly", Type.GetType("System.Reflection.RuntimeAssembly"), typeof(void), new object[] { InstanceStackCrawl, InstanceObjectHandle }, null);
                        }
                    }
                }
            }
            catch
            {
                return null;
            }
            return ExecutingAssembly;
        }

        /// <summary>
        /// Calls methods in the CLR which isn't normally/directly accessible.
        /// </summary>
        /// <param name="InternalMethod">The name of the internal function.</param>
        /// <param name="InternalMethodType">The class or type that the method is in.</param>
        /// <param name="Flags">The method flags which will be used to find the exact method.</param>
        /// <param name="Parameters">The parameters which is used to search for the function using it, will be used instead of Flags if not left null.</param>
        /// <param name="InvokeParameters">The parameters passed to the method. can be null.</param>
        /// <param name="GenericParameter">The type arguments if the method is a generic method.</param>
        /// <returns>the return value of the method (if any).</returns>
        public static object CallInternalCLRFunction(string InternalMethod, Type InternalMethodType, BindingFlags Flags, Type[] Parameters, object[] InvokeParameters, Type GenericParameter = null)
        {
            try
            {
                if (!IsReflectionEnabled(false, true))
                    return null;
                if (string.IsNullOrEmpty(InternalMethod) || InternalMethodType == null)
                    return null;

                MethodInfo MI = null;
                if (Parameters != null)
                {
                    MI = InternalMethodType.GetMethod(InternalMethod, Parameters);
                }
                else
                {
                    MI = InternalMethodType.GetMethod(InternalMethod, Flags);
                }

                if(MI.IsGenericMethod && GenericParameter != null)
                {
                    MI = MI.MakeGenericMethod(GenericParameter);
                }
                
                if (MI != null)
                {
                    object instance = MI.IsStatic ? null : Activator.CreateInstance(InternalMethodType);
                    return MI.Invoke(instance, InvokeParameters);
                }
                return null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Calls methods in the CLR which isn't normally/directly accessible.
        /// </summary>
        /// <param name="InternalMethod">The name of the internal function.</param>
        /// <param name="InternalMethodType">The class or type that the method is in.</param>
        /// <param name="ReturnType">The return type of the method to be searched for.</param>
        /// <param name="InvokeParameters">The parameters passed to the method. can be null.</param>
        /// <param name="GenericParameter">The type arguments if the method is a generic method.</param>
        /// <returns>the return value of the method (if any).</returns>
        public static object CallInternalCLRFunction(string InternalMethod, Type InternalMethodType, Type ReturnType, object[] InvokeParameters, Type GenericParameter = null)
        {
            try
            {
                if (!IsReflectionEnabled(false, true))
                    return null;
                if (string.IsNullOrEmpty(InternalMethod) || InternalMethodType == null)
                    return null;
                MethodInfo MI = null;
                foreach (MethodInfo methods in InternalMethodType.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static))
                {
                    if (methods.Name.ToLower() == InternalMethod.ToLower())
                    {
                        if (methods.ReturnType == ReturnType)
                        {
                            MI = methods;
                            break;
                        }
                    }
                }

                if (MI.IsGenericMethod && GenericParameter != null)
                {
                    MI = MI.MakeGenericMethod(GenericParameter);
                }

                if (MI != null)
                {
                    object instance = MI.IsStatic ? null : Activator.CreateInstance(InternalMethodType);
                    return MI.Invoke(instance, InvokeParameters);
                }
                return null;
            }
            catch
            {
                return null;
            }
        }

        private static uint PAGE_EXECUTE_READWRITE = 0x40;
        private static uint MEM_RELEASE = 0x00008000;

        /// <summary>
        /// Gets the Process Environment Block with it's struct.
        /// </summary>
        /// <returns>returns the PEB.</returns>
        public static PEB GetPEB()
        {
            byte[] PEBCode = new byte[20];
            if (IntPtr.Size == 8)
                PEBCode = new byte[] { 0x48, 0x31, 0xC0, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0xC3 };
            else
                PEBCode = new byte[] { 0x31, 0xC0, 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0xC3 };
            IntPtr AllocatedCode = AllocateCode(PEBCode);
            if (AllocatedCode != IntPtr.Zero)
            {
                try
                {
                    GenericPtr PebDel = (GenericPtr)Marshal.GetDelegateForFunctionPointer(AllocatedCode, typeof(GenericPtr));
                    IntPtr PebPtr = PebDel();
                    FreeCode(AllocatedCode);
                    if (PebPtr != IntPtr.Zero)
                    {
                        return Marshal.PtrToStructure<PEB>(PebPtr);
                    }
                }
                catch
                {
                    FreeCode(AllocatedCode);
                }
            }
            return new PEB();
        }

        /// <summary>
        /// Allocates assembly code from byte array.
        /// </summary>
        /// <param name="Code">The assembly code in byte array.</param>
        /// <returns>Allocated memory to the assembly code.</returns>
        public static IntPtr AllocateCode(byte[] Code)
        {
            IntPtr Allocated = IntPtr.Zero;
            uint Length = (uint)Code.Length;
            uint Status = NtAllocateVirtualMemory(new IntPtr(-1), ref Allocated, 0, ref Length, 0x1000, PAGE_EXECUTE_READWRITE);
            if (Status == 0)
            {
                CopyMem(Allocated, Code, false);
                return Allocated;
            }
            return IntPtr.Zero;
        }

        /// <summary>
        /// Frees the allocated memory.
        /// </summary>
        /// <param name="AllocatedCode">The allocated assembly code to be freed.</param>
        /// <returns>An indicator if the memory was freed or not.</returns>
        public static bool FreeCode(IntPtr AllocatedCode)
        {
            return VirtualFree(AllocatedCode, 0, MEM_RELEASE);
        }

        /// <summary>
        /// Closes a handle.
        /// </summary>
        /// <param name="Handle">The handle to be closed.</param>
        /// <returns>true if the handle has been closed, otherwise false.</returns>
        public static bool CloseHandle(IntPtr Handle)
        {
            if (NtClose(Handle) == 0)
                return true;
            return false;
        }

        public static bool GetVirtualMemoryQuery(bool Syscall, IntPtr BaseAddress, ref MEMORY_BASIC_INFORMATION MemoryInformation, out uint ReturnLength)
        {
            uint Length = (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            uint Result = Syscall ? Syscalls.SyscallNtQueryVirtualMemory(new IntPtr(-1), BaseAddress, 0, ref MemoryInformation, Length, out ReturnLength) : NtQueryVirtualMemory(new IntPtr(-1), BaseAddress, 0, ref MemoryInformation, Length, out ReturnLength);
            if (Result == 0)
                return true;
            return false;
        }

        /// <summary>
        /// Installs a function hook.
        /// </summary>
        /// <param name="Source">The source function pointer to be hooked.</param>
        /// <param name="Destination">The destination function pointer to be the hooking function.</param>
        /// <param name="Hooked">The hooked code which will be written to if you wanna hook the function later (6 bytes in length).</param>
        private static bool HookFunction(IntPtr Source, IntPtr Destination, out byte[] Hooked)
        {
            byte[] HookCode = new byte[6];
            HookCode[0] = 0x90;
            HookCode[1] = 0xE9;
            if (IntPtr.Size == 8)
            {
                long offset = Destination.ToInt64() - Source.ToInt64() - HookCode.Length;
                byte[] offsetBytes = BitConverter.GetBytes(offset);
                Array.Copy(offsetBytes, 0, HookCode, 2, HookCode.Length - 2);
            }
            else
            {
                long offset = Destination.ToInt32() - Source.ToInt32() - HookCode.Length;
                byte[] offsetBytes = BitConverter.GetBytes((int)offset);
                Array.Copy(offsetBytes, 0, HookCode, 2, HookCode.Length - 2);
            }
            CopyMem(Source, HookCode, true);
            Hooked = HookCode;
            return true;
        }

        /// <summary>
        /// Installs/Uninstalls a hook to/from the function.
        /// </summary>
        /// <param name="code">The code which is hooked/unhooked to apply.</param>
        /// <param name="pFunction">pointer to the function.</param>
        public static void InstallOrUninstallHook(byte[] code, IntPtr pFunction)
        {
            CopyMem(pFunction, code, true);
        }

        /// <summary>
        /// The whitelisted function by the hook which should get the original function pointer.
        /// </summary>
        /// <param name="MI">The method to get the pointer for.</param>
        /// <returns>Returns the pointer if successful, otherwise IntPtr.Zero</returns>
        public static IntPtr GetPointer(MethodInfo MI)
        {
            return MI.MethodHandle.GetFunctionPointer();
        }

        /// <summary>
        /// The whitelisted function by the hook which should get the original function pointer from the delegate.
        /// </summary>
        /// <param name="MI">The method to get the pointer for.</param>
        /// <returns>Returns the pointer if successful, otherwise IntPtr.Zero</returns>
        public static IntPtr GetPointerDelegate(Delegate DelegateMethod)
        {
            if (IsReflectionEnabled(false, true))
            {
                return (IntPtr)CallInternalCLRFunction("GetFunctionPointerForDelegateInternal", typeof(Marshal), BindingFlags.NonPublic | BindingFlags.Static, null, new object[] { DelegateMethod });
            }
            return Marshal.GetFunctionPointerForDelegate(DelegateMethod);
        }

        //to be used later in future releases.
        /// <summary>
        /// Installs a WinAPI hook.
        /// </summary>
        /// <param name="Dll">The name of the module or dll to get the function from.</param>
        /// <param name="Function">The name of the function to be hooked.</param>
        /// <param name="HookingMethod">The method which will be the hook.</param>
        /// <param name="OriginalCode">The original code which will be written to if you wanna unhook the function later (6 bytes in length).</param>
        /// <param name="HookedCode">The hook code which can be used to hook the function after unhooking it. (6 bytes in length)</param>
        /// <param name="pFunction">A pointer to the function in which you can install/uninstall hooks from using InstallOrUninstallHook function.</param>
        /// <returns>Returns true if successfully hooked, otherwise false.</returns>
        public static bool InstallHookWinApi(string Dll, string Function, MethodInfo HookingMethod, byte[] OriginalCode, out byte[] HookedCode, out IntPtr pFunction)
        {
            try
            {
                if (!IsReflectionEnabled(true, true))
                {
                    HookedCode = null;
                    pFunction = IntPtr.Zero;
                    return false;
                }
                RuntimeHelpers.PrepareMethod(HookingMethod.MethodHandle);
                IntPtr pSource = GetFunctionExportAddress(Dll, Function);
                if (OriginalCode != null)
                    CopyMem(OriginalCode, pSource, false);
                IntPtr pHookingMethod = GetPointer(HookingMethod);
                if (pHookingMethod != IntPtr.Zero)
                {
                    if (HookFunction(pSource, pHookingMethod, out HookedCode))
                    {
                        pFunction = pSource;
                        return true;
                    }
                }
                HookedCode = null;
                pFunction = IntPtr.Zero;
                return false;
            }
            catch
            {
                HookedCode = null;
                pFunction = IntPtr.Zero;
                return false;
            }
        }

        //to be used later in future releases.
        /// <summary>
        /// Installs a WinAPI hook.
        /// </summary>
        /// <param name="Dll">The name of the module or dll to get the function from.</param>
        /// <param name="Function">The name of the function to be hooked.</param>
        /// <param name="HookingMethodDelegate">A delegate for the hooking function which is recommended if the hooking method receives incorrect parameters because of call conventions or reflection support.</param>
        /// <param name="OriginalCode">The original code which will be written to if you wanna unhook the function later (6 bytes in length).</param>
        /// <param name="HookedCode">The hook code which can be used to hook the function after unhooking it. (6 bytes in length)</param>
        /// <param name="pFunction">A pointer to the function in which you can install/uninstall hooks from using InstallOrUninstallHook function.</param>
        /// <returns>Returns true if successfully hooked, otherwise false.</returns>
        public static bool InstallHookWinApi(string Dll, string Function, Delegate HookingMethodDelegate, byte[] OriginalCode, out byte[] HookedCode, out IntPtr pFunction)
        {
            try
            {
                if (!IsReflectionEnabled(false, true))
                {
                    HookedCode = null;
                    pFunction = IntPtr.Zero;
                    return false;
                }
                IntPtr pSource = GetFunctionExportAddress(Dll, Function);
                if (OriginalCode != null)
                    CopyMem(OriginalCode, pSource, false);
                if (HookingMethodDelegate != null)
                {
                    IntPtr DelegatePtr = GetPointerDelegate(HookingMethodDelegate);
                    if (DelegatePtr != IntPtr.Zero)
                    {
                        if (HookFunction(pSource, DelegatePtr, out HookedCode))
                        {
                            pFunction = pSource;
                            return true;
                        }
                    }
                }
                HookedCode = null;
                pFunction = IntPtr.Zero;
                return false;
            }
            catch
            {
                HookedCode = null;
                pFunction = IntPtr.Zero;
                return false;
            }
        }

        /// <summary>
        /// Installs a CLR hook.
        /// </summary>
        /// <param name="SourceFunction">The method to be hooked.</param>
        /// <param name="DestinationFunction">The hook method.</param>
        /// <param name="OriginalCode">The original code which will be written to if you wanna unhook the function later (6 bytes in length).</param>
        /// <param name="HookedCode">The hook code which can be used to hook the function after unhooking it (6 bytes in length).</param>
        /// <param name="pFunction">A pointer to the function in which you can install/uninstall hooks from using InstallOrUninstallHook function.</param>
        /// <returns>Returns true if successfully hooked, otherwise false.</returns>
        public static bool InstallHookCLR(MethodInfo SourceFunction, MethodInfo DestinationFunction, byte[] OriginalCode, out byte[] HookedCode, out IntPtr pFunction)
        {
            try
            {
                if (!IsReflectionEnabled(true, true))
                {
                    HookedCode = null;
                    pFunction = IntPtr.Zero;
                    return false;
                }
                RuntimeHelpers.PrepareMethod(SourceFunction.MethodHandle);
                RuntimeHelpers.PrepareMethod(DestinationFunction.MethodHandle);
                IntPtr pSource = GetPointer(SourceFunction);
                IntPtr pDestination = GetPointer(DestinationFunction);
                if (pSource != IntPtr.Zero && pDestination != IntPtr.Zero)
                {
                    if (OriginalCode != null)
                        CopyMem(OriginalCode, pSource, false);
                    if (HookFunction(pSource, pDestination, out HookedCode))
                    {
                        pFunction = pSource;
                        return true;
                    }
                }
                HookedCode = null;
                pFunction = IntPtr.Zero;
                return false;
            }
            catch
            {
                HookedCode = null;
                pFunction = IntPtr.Zero;
                return false;
            }
        }

        /// <summary>
        /// Installs a CLR hook using delegates, for some software that have AOT.
        /// </summary>
        /// <param name="SourceFunction">The method to be hooked.</param>
        /// <param name="DestinationFunction">The hook method.</param>
        /// <param name="OriginalCode">The original code which will be written to if you wanna unhook the function later (6 bytes in length).</param>
        /// <param name="HookedCode">The hook code which can be used to hook the function after unhooking it (6 bytes in length).</param>
        /// <param name="pFunction">A pointer to the function in which you can install/uninstall hooks from using InstallOrUninstallHook function.</param>
        /// <returns>Returns true if successfully hooked, otherwise false.</returns>
        public static bool InstallHookCLR(Delegate SourceFunction, Delegate DestinationFunction, byte[] OriginalCode, out byte[] HookedCode, out IntPtr pFunction)
        {
            try
            {
                IntPtr pSource = GetPointerDelegate(SourceFunction);
                IntPtr pDestination = GetPointerDelegate(DestinationFunction);
                if (pSource != IntPtr.Zero && pDestination != IntPtr.Zero)
                {
                    if (OriginalCode != null)
                        CopyMem(OriginalCode, pSource, false);
                    if (HookFunction(pSource, pDestination, out HookedCode))
                    {
                        pFunction = pSource;
                        return true;
                    }
                }
                HookedCode = null;
                pFunction = IntPtr.Zero;
                return false;
            }
            catch
            {
                HookedCode = null;
                pFunction = IntPtr.Zero;
                return false;
            }
        }
    }
}