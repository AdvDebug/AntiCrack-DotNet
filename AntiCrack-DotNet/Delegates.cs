using System;
using System.Runtime.InteropServices;

namespace AntiCrack_DotNet
{
    public sealed class Delegates
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint SysNtQueryInformationProcess(IntPtr hProcess, uint ProcessInfoClass, out uint ProcessInfo, uint nSize, out uint ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint SysNtQueryInformationProcess2(IntPtr hProcess, uint ProcessInfoClass, out IntPtr ProcessInfo, uint nSize, uint ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint SysNtQueryInformationProcess3(IntPtr hProcess, uint ProcessInfoClass, ref Structs.PROCESS_BASIC_INFORMATION ProcessInfo, uint nSize, uint ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool SysNtClose(IntPtr Handle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint SysNtQuerySystemInformation(uint SystemInformationClass, ref Structs.SYSTEM_CODEINTEGRITY_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint SysNtQuerySystemInformation2(uint SystemInformationClass, ref Structs.SYSTEM_KERNEL_DEBUGGER_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint SysNtQuerySystemInformation3(uint SystemInformationClass, ref Structs.SYSTEM_SECUREBOOT_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint SysNtQueryVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, uint MemoryInformationClass, ref Structs.MEMORY_BASIC_INFORMATION MemoryInformation, uint MemoryInformationLength, out uint ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int SysNtQueryInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, ref IntPtr ThreadInformation, uint ThreadInformationLength, IntPtr ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr GenericPtr();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int GenericInt();
    }
}
