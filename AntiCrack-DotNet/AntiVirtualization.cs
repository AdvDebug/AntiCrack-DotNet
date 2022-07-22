using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading;

namespace AntiCrack_DotNet
{
    class AntiVirtualization
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lib);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr ModuleHandle, string Function);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr ProcHandle, IntPtr BaseAddress, byte[] Buffer, uint size, int NumOfBytes);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsProcessCritical(IntPtr Handle, ref bool BoolToCheck);

        public static bool IsSandboxiePresent()
        {
            if (GetModuleHandle("SbieDll.dll").ToInt32() != 0)
                return true;
            return false;
        }

        public static bool IsComodoSandboxPresent()
        {
            if (GetModuleHandle("cmdvrt32.dll").ToInt32() != 0 || GetModuleHandle("cmdvrt64.dll").ToInt32() != 0)
                return true;
            return false;
        }

        public static bool IsQihoo360SandboxPresent()
        {
            if (GetModuleHandle("SxIn.dll").ToInt32() != 0)
                return true;
            return false;
        }

        public static bool IsCuckooSandboxPresent()
        {
            if (GetModuleHandle("cuckoomon.dll").ToInt32() != 0)
                return true;
            return false;
        }

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

        public static bool IsWinePresent()
        {
            IntPtr ModuleHandle = GetModuleHandle("kernel32.dll");
            if (GetProcAddress(ModuleHandle, "wine_get_unix_file_name").ToInt32() != 0)
                return true;
            return false;
        }

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
            catch{}
            return false;
        }

        public static bool PortConnectionAntiVM()
        {
            if (new ManagementObjectSearcher("SELECT * FROM Win32_PortConnector").Get().Count == 0)
                return true;
            return false;
        }

        public static void CrashingSandboxie() //Only use if running as x86
        {
            if (!Environment.Is64BitProcess)
            {
                byte[] UnHookedCode = { 0xB8, 0x26, 0x00, 0x00, 0x00 };
                IntPtr NtdllModule = GetModuleHandle("ntdll.dll");
                IntPtr NtOpenProcess = GetProcAddress(NtdllModule, "NtOpenProcess");
                WriteProcessMemory(Process.GetCurrentProcess().Handle, NtOpenProcess, UnHookedCode, 5, 0);
                try
                {
                    Process[] GetProcesses = Process.GetProcesses();
                    foreach (Process ProcessesHandle in GetProcesses)
                    {
                        bool DoingSomethingWithHandle = false;
                        try
                        {
                            IsProcessCritical(ProcessesHandle.Handle, ref DoingSomethingWithHandle);
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
    }
}