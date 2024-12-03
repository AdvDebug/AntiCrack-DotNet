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
    }
}