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
using System.Threading.Tasks;

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

        public static string IsSandboxiePresent()
        {
            if (GetModuleHandle("SbieDll.dll").ToInt32() != 0)
                return "[Bad]";
            return "[Good]";
        }

        public static string IsComodoSandboxPresent()
        {
            if (GetModuleHandle("cmdvrt32.dll").ToInt32() != 0 || GetModuleHandle("cmdvrt64.dll").ToInt32() != 0)
                return "[Bad]";
            return "[Good]";
        }

        public static string IsQihoo360SandboxPresent()
        {
            if (GetModuleHandle("SxIn.dll").ToInt32() != 0)
                return "[Bad]";
            return "[Good]";
        }

        public static string IsCuckooSandboxPresent()
        {
            if (GetModuleHandle("cuckoomon.dll").ToInt32() != 0)
                return "[Bad]";
            return "[Good]";
        }

        public static string IsEmulationPresent()
        {
            long Tick = Environment.TickCount;
            Thread.Sleep(500);
            long Tick2 = Environment.TickCount;
            if (((Tick2 - Tick) < 500L))
            {
                return "[Bad]";
            }
            return "[Good]";
        }

        public static string IsWinePresent()
        {
            IntPtr ModuleHandle = GetModuleHandle("kernel32.dll");
            if (GetProcAddress(ModuleHandle, "wine_get_unix_file_name").ToInt32() != 0)
                return "[Bad]";
            return "[Good]";
        }

        public static string CheckForVMwareAndVirtualBox()
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
                            return "[Bad]";
                        }
                    }
                }
            }
            return "[Good]";
        }

        public static string CheckForKVM()
        {
            string[] BadDriversList = { "balloon.sys", "netkvm.sys", "vioinput", "viofs.sys", "vioser.sys" };
            string[] DriversFiles = Directory.GetFiles(Environment.GetFolderPath(Environment.SpecialFolder.Windows) + @"\System32", "*");
            foreach (string Drivers in DriversFiles)
            {
                foreach(string BadDrivers in BadDriversList)
                {
                    if (Drivers.Contains(BadDrivers))
                    {
                        return "[Bad]";
                    }
                }
            }
            return "[Good]";
        }

        public static string CheckForHyperV()
        {
            ServiceController[] GetServicesOnSystem = ServiceController.GetServices();
            foreach (ServiceController CompareServicesNames in GetServicesOnSystem)
            {
                string[] Services = { "vmbus", "VMBusHID", "hyperkbd" };
                foreach (string ServicesToCheck in Services)
                {
                    if (CompareServicesNames.ServiceName.Contains(ServicesToCheck))
                        return "[Bad]";
                }
            }
            return "[Good]";
        }
        
        public static string CheckForBlacklistedNames()
        {
            string[] BadNames = { "Johnson", "Miller", "malware", "maltest", "CurrentUser", "Sandbox", "virus", "John Doe", "test user", "sand box" };
            foreach (string BadUsernames in BadNames)
            {
                if (Environment.UserName == BadUsernames)
                {
                    return "[Bad]";
                }
            }
            return "[Good]";
        }

        public static void CrashingSandboxie()
        {
            byte[] UnHookedCode = { 0xB8, 0x26, 0x00, 0x00, 0x00 };
            IntPtr NtdllModule = GetModuleHandle("ntdll.dll");
            IntPtr NtOpenProcess = GetProcAddress(NtdllModule, "NtOpenProcess");
            WriteProcessMemory(Process.GetCurrentProcess().Handle, NtOpenProcess, UnHookedCode, 5, 0);
            Process[] GetProcesses = Process.GetProcesses();
            foreach(Process ProcessesHandle in GetProcesses)
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
    }
}
