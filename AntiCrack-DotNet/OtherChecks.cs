using System;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.Diagnostics;
using static AntiCrack_DotNet.Structs;

namespace AntiCrack_DotNet
{
    public sealed class OtherChecks
    {
        #region WinApi 

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQuerySystemInformation(uint SystemInformationClass, ref SYSTEM_CODEINTEGRITY_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQuerySystemInformation(uint SystemInformationClass, ref SYSTEM_KERNEL_DEBUGGER_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQuerySystemInformation(uint SystemInformationClass, ref SYSTEM_SECUREBOOT_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        #endregion

        /// <summary>
        /// Checks if unsigned drivers are allowed on the system.
        /// <param name="Syscall">specifies if we should use syscall to call the WinAPI functions.</param>
        /// </summary>
        /// <returns>Returns true if unsigned drivers are allowed, otherwise false.</returns>
        public static bool IsUnsignedDriversAllowed(bool Syscall)
        {
            uint SystemCodeIntegrityInformation = 0x67;
            SYSTEM_CODEINTEGRITY_INFORMATION CodeIntegrityInfo = new SYSTEM_CODEINTEGRITY_INFORMATION();
            CodeIntegrityInfo.Length = (uint)Marshal.SizeOf(typeof(SYSTEM_CODEINTEGRITY_INFORMATION));
            uint ReturnLength = 0;
            uint result = Syscall ? Syscalls.SyscallNtQuerySystemInformation(SystemCodeIntegrityInformation, ref CodeIntegrityInfo, (uint)Marshal.SizeOf(CodeIntegrityInfo), out ReturnLength) : NtQuerySystemInformation(SystemCodeIntegrityInformation, ref CodeIntegrityInfo, (uint)Marshal.SizeOf(CodeIntegrityInfo), out ReturnLength);
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
        /// <param name="Syscall">specifies if we should use syscall to call the WinAPI functions.</param>
        /// </summary>
        /// <returns>Returns true if test-signed drivers are allowed, otherwise false.</returns>
        public static bool IsTestSignedDriversAllowed(bool Syscall)
        {
            uint SystemCodeIntegrityInformation = 0x67;
            SYSTEM_CODEINTEGRITY_INFORMATION CodeIntegrityInfo = new SYSTEM_CODEINTEGRITY_INFORMATION();
            CodeIntegrityInfo.Length = (uint)Marshal.SizeOf(typeof(SYSTEM_CODEINTEGRITY_INFORMATION));
            uint ReturnLength = 0;
            uint result = Syscall ? Syscalls.SyscallNtQuerySystemInformation(SystemCodeIntegrityInformation, ref CodeIntegrityInfo, (uint)Marshal.SizeOf(CodeIntegrityInfo), out ReturnLength) : NtQuerySystemInformation(SystemCodeIntegrityInformation, ref CodeIntegrityInfo, (uint)Marshal.SizeOf(CodeIntegrityInfo), out ReturnLength);
            if (result >= 0 && ReturnLength == (uint)Marshal.SizeOf(CodeIntegrityInfo))
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
        /// <param name="Syscall">specifies if we should use syscall to call the WinAPI functions.</param>
        /// </summary>
        /// <returns>Returns true if kernel debugging is enabled, otherwise false.</returns>
        public static bool IsKernelDebuggingEnabled(bool Syscall)
        {
            uint SystemKernelDebuggerInformation = 0x23;
            SYSTEM_KERNEL_DEBUGGER_INFORMATION KernelDebugInfo = new SYSTEM_KERNEL_DEBUGGER_INFORMATION();
            KernelDebugInfo.KernelDebuggerEnabled = false;
            KernelDebugInfo.KernelDebuggerNotPresent = true;
            uint ReturnLength = 0;
            uint result = Syscall ? Syscalls.SyscallNtQuerySystemInformation(SystemKernelDebuggerInformation, ref KernelDebugInfo, (uint)Marshal.SizeOf(KernelDebugInfo), out ReturnLength) : NtQuerySystemInformation(SystemKernelDebuggerInformation, ref KernelDebugInfo, (uint)Marshal.SizeOf(KernelDebugInfo), out ReturnLength);
            if (result >= 0 && ReturnLength == (uint)Marshal.SizeOf(KernelDebugInfo))
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
        /// <param name="Syscall">specifies if we should use syscall to call the WinAPI functions.</param>
        /// </summary>
        /// <returns>Returns true if Secure Boot is enabled, otherwise false.</returns>
        public static bool IsSecureBootEnabled(bool Syscall)
        {
            uint SystemSecureBootInformation = 0x91;
            SYSTEM_SECUREBOOT_INFORMATION SecureBoot = new SYSTEM_SECUREBOOT_INFORMATION();
            SecureBoot.SecureBootCapable = false;
            SecureBoot.SecureBootEnabled = false;
            uint ReturnLength = 0;
            uint result = Syscall ? Syscalls.SyscallNtQuerySystemInformation(SystemSecureBootInformation, ref SecureBoot, (uint)Marshal.SizeOf(SecureBoot), out ReturnLength) : NtQuerySystemInformation(SystemSecureBootInformation, ref SecureBoot, (uint)Marshal.SizeOf(SecureBoot), out ReturnLength);
            if (result >= 0)
            {
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
        /// <param name="DetectHooks">True if we are gonna check for hooks that may return incorrect assembly results, if we found a hook (or we are invoked) the method will return true.</param>
        /// <returns>Returns true if the current assembly is invoked by another assembly, otherwise false.</returns>
        public static bool IsInvokedAssembly(bool DetectHooks)
        {
            Assembly EntryAsm = Utils.LowLevelGetEntryAssembly();
            Assembly EntryAssemblyDM = new AppDomainManager().EntryAssembly;
            Assembly AsmEP = Assembly.GetEntryAssembly();
            Assembly ExecAsm = Utils.LowLevelGetExecutingAssembly();
            Assembly ExecutingAssembly = Assembly.GetExecutingAssembly();
            bool IsExecAsmNotNull = ExecAsm != null;
            bool IsEntryAsmNotNull = EntryAsm != null;
            bool IsEntryAssemblyDMNotNull = EntryAssemblyDM != null;
            string ExecutablePath = Process.GetCurrentProcess().MainModule.FileName;
            if (DetectHooks)
            {
                if (IsEntryAsmNotNull)
                {
                    if (AsmEP == null)
                        return true;
                    if (EntryAssemblyDM == null)
                        return true;
                    if (EntryAsm.Location != AsmEP.Location || EntryAsm.Location != EntryAssemblyDM.Location || EntryAsm.Location != ExecutablePath)
                        return true;
                }

                if (IsEntryAssemblyDMNotNull)
                {
                    if (AsmEP == null)
                        return true;
                    if (EntryAssemblyDM.Location != AsmEP.Location || EntryAssemblyDM.Location != ExecutablePath || AsmEP.Location != ExecutablePath)
                        return true;
                }

                if (AsmEP == null && IsEntryAsmNotNull || AsmEP == null && IsEntryAssemblyDMNotNull)
                    return true;

                if (IsExecAsmNotNull)
                {
                    if (ExecutingAssembly == null)
                        return true;
                    if (ExecAsm.Location != ExecutingAssembly.Location)
                        return true;
                }
            }

            if (IsEntryAsmNotNull || IsExecAsmNotNull)
            {
                if (IsExecAsmNotNull && IsEntryAsmNotNull && EntryAsm.Location != ExecAsm.Location)
                    return true;
                if (IsExecAsmNotNull && ExecAsm.Location != ExecutablePath)
                    return true;
                if (IsEntryAsmNotNull && IsExecAsmNotNull && EntryAsm.GetName().Name != ExecAsm.GetName().Name)
                    return true;
            }

            if (EntryAssemblyDM != null || AsmEP != null)
            {
                if (ExecutingAssembly.Location != EntryAssemblyDM.Location)
                    return true;
                if (ExecutingAssembly.GetName().Name != EntryAssemblyDM.GetName().Name)
                    return true;
                if (ExecutingAssembly.Location != ExecutablePath)
                    return true;
                if (ExecutingAssembly.Location != AsmEP.Location)
                    return true;
            }
            return false;
        }
    }
}