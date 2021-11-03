using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace AntiCrack_DotNet
{
    class AntiDebug
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr Handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr Handle, ref bool CheckBool);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lib);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr ModuleHandle, string Function);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr ProcHandle, IntPtr BaseAddress, byte[] Buffer, uint size, int NumOfBytes);

        [DllImport("ntdll.dll")]
        private static extern uint NtSetInformationThread(IntPtr ThreadHandle, uint ThreadInformationClass, IntPtr ThreadInformation, int ThreadInformationLength);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenThread(uint DesiredAccess, bool InheritHandle, int ThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint GetTickCount();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern void OutputDebugStringA(string Text);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetLastError();

        public static bool CloseHandleAntiDebug()
        {
            try
            {
                CloseHandle((IntPtr)0x1231222L);
                return false;
            }
            catch (Exception ex)
            {
                if (ex.Message == "External component has thrown an exception.")
                {
                    return true;
                }
            }
            return false;
        }

        public static bool DebuggerIsAttached()
        {
            if (Debugger.IsAttached)
                return true;
            return false;
        }

        public static bool IsDebuggerPresentCheck()
        {
            if (IsDebuggerPresent())
                return true;
            return false;
        }

        public static bool CheckRemoteDebuggerPresentCheck()
        {
            bool IsThereADebuggerPresent = false;
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref IsThereADebuggerPresent);
            if (IsThereADebuggerPresent)
                return true;
            return false;
        }

        public static string PatchingDbgUiRemoteBreakin()
        {
            IntPtr NtdllModule = GetModuleHandle("ntdll.dll");
            IntPtr DbgUiRemoteBreakinAddress = GetProcAddress(NtdllModule, "DbgUiRemoteBreakin");
            byte[] Int3InvaildCode = { 0xCC };
            bool Status = WriteProcessMemory(Process.GetCurrentProcess().Handle, DbgUiRemoteBreakinAddress, Int3InvaildCode, 1, 0);
            if (Status)
                return "Success"; 
            return "Failed";
        }

        public static bool FindWindowAntiDebug()
        {
            Process[] GetProcesses = Process.GetProcesses();
            foreach(Process GetWindow in GetProcesses)
            {
                string[] BadWindowNames = { "x32dbg", "x64dbg", "ollydbg" };
                foreach (string BadWindows in BadWindowNames)
                {
                    if (GetWindow.MainWindowTitle.ToLower().Contains(BadWindows))
                        return true;
                }
            }
            return false;
        }

        public static string HideThreadsAntiDebug()
        {
            ProcessThreadCollection GetCurrentProcessThreads = Process.GetCurrentProcess().Threads;
            foreach (ProcessThread Threads in GetCurrentProcessThreads)
            {
                IntPtr ThreadsHandle = OpenThread(0x0020, false, Threads.Id);
                if (ThreadsHandle != IntPtr.Zero)
                {
                    uint Status = NtSetInformationThread(ThreadsHandle, 0x11, IntPtr.Zero, 0);
                    if (Status == 0x00000000)
                        return "Success";
                }
            }
            return "Failed";
        }

        public static bool GetTickCountAntiDebug()
        {
            uint Start = GetTickCount();
            string AnyJob = Process.GetCurrentProcess().MainModule.FileName;
            string AnyJob2 = Process.GetCurrentProcess().PrivateMemorySize64.ToString();
            return (GetTickCount() - Start) > 2;
        }

        public static bool OutputDebugStringAntiDebug()
        {
            OutputDebugStringA("just testing some stuff...");
            if (GetLastError() == 0)
                return true;
            return false;
        }

        public static void OllyDbgFormatStringExploit()
        {
            OutputDebugStringA("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s");
        }

        public static bool DebugBreakAntiDebug()
        {
            try
            {
                Debugger.Break();
                return false;
            }
            catch
            {
                return true;
            }
        }
    }
}