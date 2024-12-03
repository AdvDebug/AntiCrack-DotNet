using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;
using System.Threading;
using static AntiCrack_DotNet.Structs;
using System.Collections;
using System.Text.RegularExpressions;

namespace AntiCrack_DotNet
{
    public sealed class Utils
    {
        #region WinApi

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
        /// copies memory from a byte array to an IntPtr.
        /// </summary>
        /// <param name="dst">The IntPtr destination in which the data will be copied to.</param>
        /// <param name="src">The byte array source in which the data will be copied from.</param>
        public static void CopyMem(IntPtr dst, byte[] src)
        {
            unsafe
            {
                fixed (byte* source = src)
                {
                    Buffer.MemoryCopy(source, (void*)dst, src.Length, src.Length);
                }
            }
        }

        /// <summary>
        /// copies memory from an IntPtr to a byte array.
        /// </summary>
        /// <param name="dst">The byte array destination in which the data will be copied to.</param>
        /// <param name="src">The IntPtr source in which the data will be copied from.</param>
        public static void CopyMem(byte[] dst, IntPtr src)
        {
            unsafe
            {
                fixed (byte* destination = dst)
                {
                    Buffer.MemoryCopy((void*)src, destination, dst.Length, dst.Length);
                }
            }
        }

        /// <summary>
        /// Sees if the main string contains the second string.
        /// </summary>
        /// <param name="Main">Main string to see if it contains the second string.</param>
        /// <param name="Second">The second string that will be searched for.</param>
        /// <returns>An indicator if the Main string have the Second string in it.</returns>
        public static bool Contains(string Main, string Second)
        {
            if (Main.IndexOf(Second, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }
            return false;
        }
    }
}
