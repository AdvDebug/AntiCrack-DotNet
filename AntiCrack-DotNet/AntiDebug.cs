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

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtSetInformationThread(IntPtr ThreadHandle, uint ThreadInformationClass, IntPtr ThreadInformation, int ThreadInformationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint DesiredAccess, bool InheritHandle, int ThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetTickCount();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern void OutputDebugStringA(string Text);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetLastError();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr hThread, ref Structs.CONTEXT Context);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQueryInformationProcess(IntPtr hProcess, uint ProcessInfoClass, out uint ProcessInfo, uint nSize, uint ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQueryInformationProcess(IntPtr hProcess, uint ProcessInfoClass, out IntPtr ProcessInfo, uint nSize, uint ReturnLength);

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
            return Debugger.IsAttached;
        }

        public static bool IsDebuggerPresentCheck()
        {
            if (IsDebuggerPresent())
                return true;
            return false;
        }

        public static bool NtQueryInformationProcessCheck_ProcessDebugFlags()
        {
            uint ProcessDebugFlags = 0;
            NtQueryInformationProcess(Process.GetCurrentProcess().Handle, 0x1F, out ProcessDebugFlags, sizeof(uint), 0);
            if (ProcessDebugFlags == 0)
                return true;
            return false;
        }

        public static bool NtQueryInformationProcessCheck_ProcessDebugPort()
        {
            uint DebuggerPresent = 0;
            NtQueryInformationProcess(Process.GetCurrentProcess().Handle, 7, out DebuggerPresent, sizeof(uint), 0);
            if (DebuggerPresent != 0)
                return true;
            return false;
        }

        public static bool NtQueryInformationProcessCheck_ProcessDebugObjectHandle()
        {
            IntPtr hDebugObject = IntPtr.Zero;
            NtQueryInformationProcess(Process.GetCurrentProcess().Handle, 0x1E, out hDebugObject, sizeof(uint), 0);
            if (hDebugObject != IntPtr.Zero)
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
            foreach (Process GetWindow in GetProcesses)
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
                IntPtr ThreadHandle = OpenThread(0x0020, false, Threads.Id);
                if (ThreadHandle != IntPtr.Zero)
                {
                    uint Status = NtSetInformationThread(ThreadHandle, 0x11, IntPtr.Zero, 0);
                    CloseHandle(ThreadHandle);
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
            if (Marshal.GetLastWin32Error() == 0)
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

        private static long CONTEXT_DEBUG_REGISTERS = 0x00010000L | 0x00000010L;

        public static bool HardwareRegistersBreakpointsDetection()
        {
            Structs.CONTEXT Context = new Structs.CONTEXT();
            Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if(GetThreadContext(GetCurrentThread(), ref Context))
            {
                if ((Context.Dr1 != 0x00 || Context.Dr2 != 0x00 || Context.Dr3 != 0x00 || Context.Dr4 != 0x00 || Context.Dr5 != 0x00 || Context.Dr6 != 0x00 || Context.Dr7 != 0x00))
                {
                    return true;
                }
            }
            return false;
        }
    }
}