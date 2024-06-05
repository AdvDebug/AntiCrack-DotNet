using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;
using static AntiCrack_DotNet.Structs;

namespace AntiCrack_DotNet
{
    class AntiDllInjection
    {
        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lib);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr ModuleHandle, string Function);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(SafeHandle hProcess, IntPtr BaseAddress, byte[] Buffer, uint size, int NumOfBytes);

        [DllImport("kernelbase.dll", SetLastError = true)]
        public static extern bool SetProcessMitigationPolicy(int policy, ref Structs.PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY lpBuffer, int size);

        public static string PatchLoadLibraryA()
        {
            IntPtr KernelModule = GetModuleHandle("kernelbase.dll");
            IntPtr LoadLibraryA = GetProcAddress(KernelModule, "LoadLibraryA");
            byte[] HookedCode = { 0xC2, 0x04, 0x00 };
            bool Status = WriteProcessMemory(Process.GetCurrentProcess().SafeHandle, LoadLibraryA, HookedCode, 3, 0);
            if (Status)
                return "Success";
            return "Failed";
        }

        public static string PatchLoadLibraryW()
        {
            IntPtr KernelModule = GetModuleHandle("kernelbase.dll");
            IntPtr LoadLibraryW = GetProcAddress(KernelModule, "LoadLibraryW");
            byte[] HookedCode = { 0xC2, 0x04, 0x00 };
            bool Status = WriteProcessMemory(Process.GetCurrentProcess().SafeHandle, LoadLibraryW, HookedCode, 3, 0);
            if (Status)
                return "Success";
            return "Failed";
        }

        public static string BinaryImageSignatureMitigationAntiDllInjection()
        {
            Structs.PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY OnlyMicrosoftBinaries = new Structs.PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY();
            OnlyMicrosoftBinaries.MicrosoftSignedOnly = 1;
            if (SetProcessMitigationPolicy(8, ref OnlyMicrosoftBinaries, Marshal.SizeOf(typeof(Structs.PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY))))
                return "Success";
            return "Failed";
        }

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
        public static string SetDllLoadPolicy()
        {
            Structs.PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy = new Structs.PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
            {
                MicrosoftSignedOnly = 1
            };
            if (SetProcessMitigationPolicy(0x10, ref policy, Marshal.SizeOf(policy)))
                return "Success";
            return "Failed";
        }
    }
}
