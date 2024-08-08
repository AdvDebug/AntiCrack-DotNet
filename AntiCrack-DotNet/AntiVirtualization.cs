using System;
using System.IO;
using System.Threading;
using System.Management;
using System.Diagnostics;
using System.ServiceProcess;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace AntiCrack_DotNet
{
    internal sealed class AntiVirtualization
    {

        #region WinApi

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lib);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr ModuleHandle, string Function);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(SafeHandle hProcess, IntPtr BaseAddress, byte[] Buffer, uint size, int NumOfBytes);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern bool IsProcessCritical(SafeHandle hProcess, ref bool BoolToCheck);

        [DllImport("ucrtbase.dll", SetLastError = true)]
        private static extern IntPtr fopen(string filename, string mode);

        [DllImport("ucrtbase.dll", SetLastError = true)]
        private static extern int fclose(IntPtr filestream);

        #endregion

        /// <summary>
        /// Checks if Sandboxie is present on the system.
        /// </summary>
        /// <returns>True if Sandboxie is detected, otherwise false.</returns>
        public static bool IsSandboxiePresent()
        {
            if (GetModuleHandle("SbieDll.dll").ToInt32() != 0)
                return true;
            return false;
        }

        /// <summary>
        /// Checks if Comodo Sandbox is present on the system.
        /// </summary>
        /// <returns>True if Comodo Sandbox is detected, otherwise false.</returns>
        public static bool IsComodoSandboxPresent()
        {
            if (GetModuleHandle("cmdvrt32.dll").ToInt32() != 0 || GetModuleHandle("cmdvrt64.dll").ToInt32() != 0)
                return true;
            return false;
        }

        /// <summary>
        /// Checks if Qihoo 360 Sandbox is present on the system.
        /// </summary>
        /// <returns>True if Qihoo 360 Sandbox is detected, otherwise false.</returns>
        public static bool IsQihoo360SandboxPresent()
        {
            if (GetModuleHandle("SxIn.dll").ToInt32() != 0)
                return true;
            return false;
        }

        /// <summary>
        /// Checks if Cuckoo Sandbox is present on the system.
        /// </summary>
        /// <returns>True if Cuckoo Sandbox is detected, otherwise false.</returns>
        public static bool IsCuckooSandboxPresent()
        {
            if (GetModuleHandle("cuckoomon.dll").ToInt32() != 0)
                return true;
            return false;
        }

        /// <summary>
        /// Checks if the environment is running in an emulation by measuring the sleep interval.
        /// </summary>
        /// <returns>True if emulation is detected, otherwise false.</returns>
        public static bool IsEmulationPresent()
        {
            long Tick = Environment.TickCount;
            Thread.Sleep(500);
            long Tick2 = Environment.TickCount;
            if (((Tick2 - Tick) < 500L))
            {
                return true;
            }
            return false;
        }

        /// <summary>
        /// Checks if the environment is running in Wine.
        /// </summary>
        /// <returns>True if Wine is detected, otherwise false.</returns>
        public static bool IsWinePresent()
        {
            IntPtr ModuleHandle = GetModuleHandle("kernel32.dll");
            if (GetProcAddress(ModuleHandle, "wine_get_unix_file_name").ToInt32() != 0)
                return true;
            return false;
        }

        /// <summary>
        /// Checks if the environment is running in VMware or VirtualBox.
        /// </summary>
        /// <returns>True if VMware or VirtualBox is detected, otherwise false.</returns>
        public static bool CheckForVMwareAndVirtualBox()
        {
            using (ManagementObjectSearcher ObjectSearcher = new ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
            {
                using (ManagementObjectCollection ObjectItems = ObjectSearcher.Get())
                {
                    foreach (ManagementBaseObject Item in ObjectItems)
                    {
                        string ManufacturerString = Item["Manufacturer"].ToString().ToLower();
                        string ModelName = Item["Model"].ToString();
                        if ((ManufacturerString == "microsoft corporation" && ModelName.ToUpperInvariant().Contains("VIRTUAL") || ManufacturerString.Contains("vmware")))
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        /// <summary>
        /// Checks if the environment is running in KVM.
        /// </summary>
        /// <returns>True if KVM is detected, otherwise false.</returns>
        public static bool CheckForKVM()
        {
            string[] BadDriversList = { "balloon.sys", "netkvm.sys", "vioinput", "viofs.sys", "vioser.sys" };
            foreach (string Drivers in Directory.GetFiles(Environment.GetFolderPath(Environment.SpecialFolder.System), "*"))
            {
                foreach (string BadDrivers in BadDriversList)
                {
                    if (Drivers.Contains(BadDrivers))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Checks if the environment is running in Hyper-V.
        /// </summary>
        /// <returns>True if Hyper-V is detected, otherwise false.</returns>
        public static bool CheckForHyperV()
        {
            ServiceController[] GetServicesOnSystem = ServiceController.GetServices();
            foreach (ServiceController CompareServicesNames in GetServicesOnSystem)
            {
                string[] Services = { "vmbus", "VMBusHID", "hyperkbd" };
                foreach (string ServicesToCheck in Services)
                {
                    if (CompareServicesNames.ServiceName.Contains(ServicesToCheck))
                        return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Checks if the current user name matches any blacklisted names.
        /// </summary>
        /// <returns>True if a blacklisted name is detected, otherwise false.</returns>
        public static bool CheckForBlacklistedNames()
        {
            string[] BadNames = { "Johnson", "Miller", "malware", "maltest", "CurrentUser", "Sandbox", "virus", "John Doe", "test user", "sand box", "WDAGUtilityAccount" };
            string Username = Environment.UserName.ToLower();
            foreach (string BadUsernames in BadNames)
            {
                if (Username == BadUsernames.ToLower())
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Detects bad VM-related files and directories on the system.
        /// </summary>
        /// <returns>True if bad VM-related files or directories are detected, otherwise false.</returns>
        public static bool BadVMFilesDetection()
        {
            try
            {
                string[] BadFileNames = { "VBoxMouse.sys", "VBoxGuest.sys", "VBoxSF.sys", "VBoxVideo.sys", "vmmouse.sys", "vboxogl.dll" };
                string[] BadDirs = { @"C:\Program Files\VMware", @"C:\Program Files\oracle\virtualbox guest additions" };
                foreach (string System32File in Directory.GetFiles(Environment.GetFolderPath(Environment.SpecialFolder.System)))
                {
                    try
                    {
                        foreach (string BadFileName in BadFileNames)
                        {
                            if (File.Exists(System32File) && Path.GetFileName(System32File).ToLower() == BadFileName.ToLower())
                            {
                                return true;
                            }
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }

                foreach (string BadDir in BadDirs)
                {
                    if (Directory.Exists(BadDir.ToLower()))
                    {
                        return true;
                    }
                }
            }
            catch
            {

            }
            return false;
        }

        /// <summary>
        /// Checks for the presence of bad VM-related process names.
        /// </summary>
        /// <returns>True if bad VM-related process names are detected, otherwise false.</returns>
        public static bool BadVMProcessNames()
        {
            try
            {
                string[] BadProcessNames = { "vboxservice", "VGAuthService", "vmusrvc", "qemu-ga" };
                foreach (Process Processes in Process.GetProcesses())
                {
                    foreach (string BadProcessName in BadProcessNames)
                    {
                        if (Processes.ProcessName == BadProcessName)
                        {
                            return true;
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        /// <summary>
        /// Checks for VM-related ports on the system.
        /// </summary>
        /// <returns>True if no port connectors are found, indicating a possible VM environment, otherwise false.</returns>
        public static bool PortConnectionAntiVM()
        {
            if (new ManagementObjectSearcher("SELECT * FROM Win32_PortConnector").Get().Count == 0)
                return true;
            return false;
        }

        /// <summary>
        /// Attempts to crash Sandboxie if detected.
        /// </summary>
        public static void CrashingSandboxie()
        {
            if (!Environment.Is64BitProcess)
            {
                byte[] UnHookedCode = { 0xB8, 0x26, 0x00, 0x00, 0x00 };
                IntPtr NtdllModule = GetModuleHandle("ntdll.dll");
                IntPtr NtOpenProcess = GetProcAddress(NtdllModule, "NtOpenProcess");
                WriteProcessMemory(Process.GetCurrentProcess().SafeHandle, NtOpenProcess, UnHookedCode, 5, 0);
                try
                {
                    Process[] GetProcesses = Process.GetProcesses();
                    foreach (Process ProcessesHandle in GetProcesses)
                    {
                        bool DoingSomethingWithHandle = false;
                        try
                        {
                            IsProcessCritical(ProcessesHandle.SafeHandle, ref DoingSomethingWithHandle);
                        }
                        catch
                        {
                            continue;
                        }
                    }
                }
                catch
                {

                }
            }
        }

        /// <summary>
        /// Checks for VM-related device names.
        /// </summary>
        /// <returns>True if VM-related device names are detected, otherwise false.</returns>
        public static bool CheckDevices()
        {
            string[] Devices = { "\\\\.\\pipe\\cuckoo", "\\\\.\\HGFS", "\\\\.\\vmci", "\\\\.\\VBoxMiniRdrDN", "\\\\.\\VBoxGuest", "\\\\.\\pipe\\VBoxMiniRdDN", "\\\\.\\VBoxTrayIPC", "\\\\.\\pipe\\VBoxTrayIPC" };
            foreach (string Device in Devices)
            {
                try
                {
                    IntPtr File = fopen(Device, "r");
                    if (File != IntPtr.Zero)
                    {
                        fclose(File);
                        return true;
                    }
                }
                catch
                {
                    continue;
                }
            }
            return false;
        }

        /// <summary>
        /// Checks if the environment is running in Parallels.
        /// </summary>
        /// <returns>True if Parallels is detected, otherwise false.</returns>
        public static bool CheckForParallels()
        {
            string[] BadDriversList = { "prl_sf", "prl_tg", "prl_eth" };
            foreach (string Drivers in Directory.GetFiles(Environment.GetFolderPath(Environment.SpecialFolder.System), "*"))
            {
                foreach (string BadDrivers in BadDriversList)
                {
                    if (Drivers.Contains(BadDrivers))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Checks for specific disk drive models that indicate a virtual environment.
        /// </summary>
        /// <returns>True if specific disk drive models are detected, otherwise false.</returns>
        public static bool TriageCheck()
        {
            using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive"))
            {
                foreach (var item in searcher.Get())
                {
                    string model = item["Model"].ToString();
                    if (model.Contains("DADY HARDDISK") || model.Contains("QEMU HARDDISK"))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        /// <summary>
        /// Checks for specific Machine GUIDs that indicate a virtual environment in Any.Run.
        /// </summary>
        /// <returns>True if specific Machine GUIDs are detected, otherwise false.</returns>
        public static bool AnyRunCheck()
        {
            string[] uuids = {
                "bb926e54-e3ca-40fd-ae90-2764341e7792", // win10 free
                "90059c37-1320-41a4-b58d-2b75a9850d2f", // win7 free
            };
            // https://app.any.run/tasks/a143d613-4e75-4cde-991a-6e096348bfec
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography"))
            {
                if (key != null)
                {
                    object value = key.GetValue("MachineGuid");

                    if (value != null)
                    {
                        foreach (string uuid in uuids)
                        {
                            if (uuid == value.ToString())
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        }

        /// <summary>
        /// Checks if the environment is running in QEMU.
        /// </summary>
        /// <returns>True if QEMU is detected, otherwise false.</returns>
        public static bool CheckForQemu()
        {
            string[] BadDriversList = { "qemu-ga", "qemuwmi" };
            foreach (string Drivers in Directory.GetFiles(Environment.GetFolderPath(Environment.SpecialFolder.System), "*"))
            {
                foreach (string BadDrivers in BadDriversList)
                {
                    if (Drivers.Contains(BadDrivers))
                    {
                        return true;
                    }
                }
            }

            return false;
        }
    }
}
