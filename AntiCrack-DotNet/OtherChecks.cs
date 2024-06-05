using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace AntiCrack_DotNet
{
    public class OtherChecks
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQuerySystemInformation(uint SystemInformationClass, ref Structs.SYSTEM_CODEINTEGRITY_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQuerySystemInformation(uint SystemInformationClass, ref Structs.SYSTEM_KERNEL_DEBUGGER_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQuerySystemInformation(uint SystemInformationClass, ref Structs.SYSTEM_SECUREBOOT_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        private static uint SystemCodeIntegrityInformation = 0x67;

        public static bool IsUnsignedDriversAllowed()
        {
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

        public static bool IsTestSignedDriversAllowed()
        {
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
                if (!SecureBoot.SecureBootEnabled)
                    return true;
            }
            return false;
        }
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
    }
}
