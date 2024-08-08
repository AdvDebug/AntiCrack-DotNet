using System;
using System.Security;
using System.Reflection;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace AntiCrack_DotNet
{
    public sealed class OtherChecks
    {
        #region WinApi 

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQuerySystemInformation(uint SystemInformationClass, ref Structs.SYSTEM_CODEINTEGRITY_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQuerySystemInformation(uint SystemInformationClass, ref Structs.SYSTEM_KERNEL_DEBUGGER_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQuerySystemInformation(uint SystemInformationClass, ref Structs.SYSTEM_SECUREBOOT_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        [DllImport("QCall", CharSet = CharSet.Unicode)]
        [SecurityCritical]
        [SuppressUnmanagedCodeSecurity]
        private static extern void GetExecutingAssembly(uint stackMark, IntPtr retAssembly);

        #endregion

        /// <summary>
        /// Checks if unsigned drivers are allowed on the system.
        /// </summary>
        /// <returns>Returns true if unsigned drivers are allowed, otherwise false.</returns>
        public static bool IsUnsignedDriversAllowed()
        {
            uint SystemCodeIntegrityInformation = 0x67;
            Structs.SYSTEM_CODEINTEGRITY_INFORMATION CodeIntegrityInfo = new Structs.SYSTEM_CODEINTEGRITY_INFORMATION();
            CodeIntegrityInfo.Length = (uint)Marshal.SizeOf(typeof(Structs.SYSTEM_CODEINTEGRITY_INFORMATION));
            uint ReturnLength = 0;
            if (NtQuerySystemInformation(SystemCodeIntegrityInformation, ref CodeIntegrityInfo, (uint)Marshal.SizeOf(CodeIntegrityInfo), out ReturnLength) >= 0 && ReturnLength == (uint)Marshal.SizeOf(CodeIntegrityInfo))
            {
                uint CODEINTEGRITY_OPTION_ENABLED = 0x01;
                if ((CodeIntegrityInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED) == CODEINTEGRITY_OPTION_ENABLED)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Checks if test-signed drivers are allowed on the system.
        /// </summary>
        /// <returns>Returns true if test-signed drivers are allowed, otherwise false.</returns>
        public static bool IsTestSignedDriversAllowed()
        {
            uint SystemCodeIntegrityInformation = 0x67;
            Structs.SYSTEM_CODEINTEGRITY_INFORMATION CodeIntegrityInfo = new Structs.SYSTEM_CODEINTEGRITY_INFORMATION();
            CodeIntegrityInfo.Length = (uint)Marshal.SizeOf(typeof(Structs.SYSTEM_CODEINTEGRITY_INFORMATION));
            uint ReturnLength = 0;
            if (NtQuerySystemInformation(SystemCodeIntegrityInformation, ref CodeIntegrityInfo, (uint)Marshal.SizeOf(CodeIntegrityInfo), out ReturnLength) >= 0 && ReturnLength == (uint)Marshal.SizeOf(CodeIntegrityInfo))
            {
                uint CODEINTEGRITY_OPTION_TESTSIGN = 0x02;
                if ((CodeIntegrityInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN) == CODEINTEGRITY_OPTION_TESTSIGN)
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Checks if kernel debugging is enabled on the system.
        /// </summary>
        /// <returns>Returns true if kernel debugging is enabled, otherwise false.</returns>
        public static bool IsKernelDebuggingEnabled()
        {
            uint SystemKernelDebuggerInformation = 0x23;
            Structs.SYSTEM_KERNEL_DEBUGGER_INFORMATION KernelDebugInfo = new Structs.SYSTEM_KERNEL_DEBUGGER_INFORMATION();
            KernelDebugInfo.KernelDebuggerEnabled = false;
            KernelDebugInfo.KernelDebuggerNotPresent = true;
            uint ReturnLength = 0;
            if (NtQuerySystemInformation(SystemKernelDebuggerInformation, ref KernelDebugInfo, (uint)Marshal.SizeOf(KernelDebugInfo), out ReturnLength) >= 0 && ReturnLength == (uint)Marshal.SizeOf(KernelDebugInfo))
            {
                if (KernelDebugInfo.KernelDebuggerEnabled || !KernelDebugInfo.KernelDebuggerNotPresent)
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Checks if Secure Boot is enabled on the system.
        /// </summary>
        /// <returns>Returns true if Secure Boot is enabled, otherwise false.</returns>
        public static bool IsSecureBootEnabled()
        {
            uint SystemSecureBootInformation = 0x91;
            Structs.SYSTEM_SECUREBOOT_INFORMATION SecureBoot = new Structs.SYSTEM_SECUREBOOT_INFORMATION();
            SecureBoot.SecureBootCapable = false;
            SecureBoot.SecureBootEnabled = false;
            uint ReturnLength = 0;
            if (NtQuerySystemInformation(SystemSecureBootInformation, ref SecureBoot, (uint)Marshal.SizeOf(SecureBoot), out ReturnLength) >= 0)
            {
                if (!SecureBoot.SecureBootCapable)
                    return false;
                if (SecureBoot.SecureBootEnabled)
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Checks if virtualization-based security is enabled on the system.
        /// </summary>
        /// <returns>Returns true if virtualization-based security is enabled, otherwise false.</returns>
        public static bool IsVirtualizationBasedSecurityEnabled()
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher(@"root\cimv2\Security\MicrosoftVolumeEncryption", "SELECT * FROM Win32_EncryptableVolume WHERE DriveLetter = C:"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        var protectionStatus = (uint)obj["ProtectionStatus"];
                        if (protectionStatus == 1)
                        {
                            return true;
                        }
                    }
                }
            }
            catch
            {
                return false;
            }
            return false;
        }

        /// <summary>
        /// Checks if memory integrity (Hypervisor-enforced Code Integrity) is enabled on the system.
        /// </summary>
        /// <returns>Returns true if memory integrity is enabled, otherwise false.</returns>
        public static bool IsMemoryIntegrityEnabled()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"))
                {
                    if (key != null)
                    {
                        object value = key.GetValue("Enabled");
                        if (value != null && (int)value == 1)
                        {
                            return true;
                        }
                    }
                }
            }
            catch
            {
                return false;
            }
            return false;
        }

        /// <summary>
        /// Checks if the current assembly is invoked by another assembly.
        /// </summary>
        /// <returns>Returns true if the current assembly is invoked by another assembly, otherwise false.</returns>
        public static bool IsInovkedAssembly()
        {
            MethodInfo Method = typeof(Assembly).GetMethod("GetExecutingAssembly");
            Assembly GetCallingAssem = (Assembly)Method.Invoke(null, null);
            if (GetCallingAssem.Location != Application.ExecutablePath)
                return true;
            return false;
        }
    }

}
