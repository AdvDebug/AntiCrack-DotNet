using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace AntiCrack_DotNet
{
    internal sealed class AntiDllInjection
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

        #endregion


        /// <summary>
        /// Patches the LoadLibraryA function to prevent DLL injection.
        /// </summary>
        /// <returns>Returns "Success" if the patching was successful, otherwise "Failed".</returns>
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

        /// <summary>
        /// Patches the LoadLibraryW function to prevent DLL injection.
        /// </summary>
        /// <returns>Returns "Success" if the patching was successful, otherwise "Failed".</returns>
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

        /// <summary>
        /// Enables the binary image signature mitigation policy to only allow Microsoft-signed binaries.
        /// </summary>
        /// <returns>Returns "Success" if the policy was set successfully, otherwise "Failed".</returns>
        public static string BinaryImageSignatureMitigationAntiDllInjection()
        {
            Structs.PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY OnlyMicrosoftBinaries = new Structs.PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY();
            OnlyMicrosoftBinaries.MicrosoftSignedOnly = 1;
            if (SetProcessMitigationPolicy(8, ref OnlyMicrosoftBinaries, Marshal.SizeOf(typeof(Structs.PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY))))
                return "Success";
            return "Failed";
        }

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
            if (SetProcessMitigationPolicy(0x10, ref policy, Marshal.SizeOf(policy)))
                return "Success";
            return "Failed";
        }
    }
}