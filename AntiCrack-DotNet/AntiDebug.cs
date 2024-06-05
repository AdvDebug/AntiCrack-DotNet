using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Windows.Forms;
using System.ServiceProcess;
using System.Runtime.CompilerServices;

namespace AntiCrack_DotNet
{
    class AntiDebug
    {
        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern bool NtClose(IntPtr Handle);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr CreateMutexA(IntPtr lpMutexAttributes, bool bInitialOwner, string lpName);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lib);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr ModuleHandle, string Function);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(SafeHandle hProcess, IntPtr BaseAddress, byte[] Buffer, uint size, int NumOfBytes);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(SafeHandle hProcess, IntPtr BaseAddress, out byte[] Buffer, uint size, out int NumOfBytes);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtSetInformationThread(IntPtr ThreadHandle, uint ThreadInformationClass, IntPtr ThreadInformation, int ThreadInformationLength);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint DesiredAccess, bool InheritHandle, int ThreadId);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern uint GetTickCount();

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentThread();

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr hThread, ref Structs.CONTEXT Context);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQueryInformationProcess(SafeHandle hProcess, uint ProcessInfoClass, out uint ProcessInfo, uint nSize, uint ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQueryInformationProcess(SafeHandle hProcess, uint ProcessInfoClass, out IntPtr ProcessInfo, uint nSize, uint ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQueryInformationProcess(SafeHandle hProcess, uint ProcessInfoClass, ref Structs.PROCESS_BASIC_INFORMATION ProcessInfo, uint nSize, uint ReturnLength);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern int QueryFullProcessImageNameA(SafeHandle hProcess, uint Flags, byte[] lpExeName, Int32[] lpdwSize);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern int GetWindowTextLengthA(IntPtr HWND);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern int GetWindowTextA(IntPtr HWND, StringBuilder WindowText, int nMaxCount);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtSetDebugFilterState(ulong ComponentId, uint Level, bool State);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern void GetSystemInfo(out Structs.SYSTEM_INFO lpSystemInfo);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern IntPtr memset(IntPtr Dst, int val, uint size);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

        public static bool NtCloseAntiDebug_InvalidHandle()
        {
            try
            {
                NtClose((IntPtr)0x1231222L);
                return false;
            }
            catch
            {
                return true;
            }
        }

        public static bool NtCloseAntiDebug_ProtectedHandle()
        {
            IntPtr hMutex = CreateMutexA(IntPtr.Zero, false, new Random().Next(0, 9999999).ToString());
            uint HANDLE_FLAG_PROTECT_FROM_CLOSE = 0x00000002;
            SetHandleInformation(hMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
            bool Result = false;
            try
            {
                NtClose(hMutex);
                Result = false;
            }
            catch
            {
                Result = true;
            }
            SetHandleInformation(hMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0);
            NtClose(hMutex);
            return Result;
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
            NtQueryInformationProcess(Process.GetCurrentProcess().SafeHandle, 0x1F, out ProcessDebugFlags, sizeof(uint), 0);
            if (ProcessDebugFlags == 0)
                return true;
            return false;
        }

        public static bool NtQueryInformationProcessCheck_ProcessDebugPort()
        {
            uint DebuggerPresent = 0;
            uint Size = sizeof(uint);
            if (Environment.Is64BitProcess)
                Size = sizeof(uint) * 2;
            NtQueryInformationProcess(Process.GetCurrentProcess().SafeHandle, 7, out DebuggerPresent, Size, 0);
            if (DebuggerPresent != 0)
                return true;
            return false;
        }

        public static bool NtQueryInformationProcessCheck_ProcessDebugObjectHandle()
        {
            IntPtr hDebugObject = IntPtr.Zero;
            uint Size = sizeof(uint);
            if (Environment.Is64BitProcess)
                Size = sizeof(uint) * 2;
            NtQueryInformationProcess(Process.GetCurrentProcess().SafeHandle, 0x1E, out hDebugObject, Size, 0);
            if (hDebugObject != IntPtr.Zero)
                return true;
            return false;
        }

        public static string AntiDebugAttach()
        {
            IntPtr NtdllModule = GetModuleHandle("ntdll.dll");
            IntPtr DbgUiRemoteBreakinAddress = GetProcAddress(NtdllModule, "DbgUiRemoteBreakin");
            IntPtr DbgBreakPointAddress = GetProcAddress(NtdllModule, "DbgBreakPoint");
            byte[] Int3InvaildCode = { 0xCC };
            byte[] RetCode = { 0xC3 };
            bool Status = WriteProcessMemory(Process.GetCurrentProcess().SafeHandle, DbgUiRemoteBreakinAddress, Int3InvaildCode, 1, 0);
            bool Status2 = WriteProcessMemory(Process.GetCurrentProcess().SafeHandle, DbgBreakPointAddress, RetCode, 1, 0);
            if (Status && Status2)
                return "Success";
            return "Failed";
        }

        public static bool FindWindowAntiDebug()
        {
            Process[] GetProcesses = Process.GetProcesses();
            foreach (Process GetWindow in GetProcesses)
            {
                string[] BadWindowNames = { "x32dbg", "x64dbg", "windbg", "ollydbg", "dnspy", "immunity debugger", "hyperdbg", "cheat engine", "cheatengine", "ida" };
                foreach (string BadWindows in BadWindowNames)
                {
                    if (GetWindow.MainWindowTitle.ToLower().Contains(BadWindows))
                    {
                        GetWindow.Close();
                        return true;
                    }
                }
            }
            return false;
        }

        public static bool GetForegroundWindowAntiDebug()
        {
            string[] BadWindowNames = { "x32dbg", "x64dbg", "windbg", "ollydbg", "dnspy", "immunity debugger", "hyperdbg", "debug", "debugger", "cheat engine", "cheatengine", "ida" };
            IntPtr HWND = GetForegroundWindow();
            if (HWND != IntPtr.Zero)
            {
                int WindowLength = GetWindowTextLengthA(HWND);
                if (WindowLength != 0)
                {
                    StringBuilder WindowName = new StringBuilder(WindowLength + 1);
                    GetWindowTextA(HWND, WindowName, WindowLength + 1);
                    foreach (string BadWindows in BadWindowNames)
                    {
                        if (WindowName.ToString().ToLower().Contains(BadWindows))
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        public static string HideThreadsAntiDebug()
        {
            try
            {
                bool AnyThreadFailed = false;
                ProcessThreadCollection GetCurrentProcessThreads = Process.GetCurrentProcess().Threads;
                foreach (ProcessThread Threads in GetCurrentProcessThreads)
                {
                    IntPtr ThreadHandle = OpenThread(0x0020, false, Threads.Id);
                    if (ThreadHandle != IntPtr.Zero)
                    {
                        uint Status = NtSetInformationThread(ThreadHandle, 0x11, IntPtr.Zero, 0);
                        NtClose(ThreadHandle);
                        if (Status != 0x00000000)
                            AnyThreadFailed = true;
                    }
                }
                if (!AnyThreadFailed)
                    return "Success";
                return "Failed";
            }
            catch
            {
                return "Failed";
            }
        }

        public static bool GetTickCountAntiDebug()
        {
            uint Start = GetTickCount();
            Thread.Sleep(0x10);
            return (GetTickCount() - Start) > 0x10;
        }
        public static bool OutputDebugStringAntiDebug()
        {
            Debugger.Log(0, null, "just testing some stuff...");
            if (Marshal.GetLastWin32Error() == 0)
                return true;
            return false;
        }

        public static void OllyDbgFormatStringExploit()
        {
            Debugger.Log(0, null, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s");
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
            IntPtr CurrentThread = GetCurrentThread();
            if (GetThreadContext(CurrentThread, ref Context))
            {
                if ((Context.Dr1 != 0x00 || Context.Dr2 != 0x00 || Context.Dr3 != 0x00 || Context.Dr4 != 0x00 || Context.Dr5 != 0x00 || Context.Dr6 != 0x00 || Context.Dr7 != 0x00))
                {
                    NtClose(CurrentThread);
                    return true;
                }
            }
            NtClose(CurrentThread);
            return false;
        }
        private static string CleanPath(string Path)
        {
            string CleanedPath = null;
            foreach (char Null in Path)
            {
                if (Null != '\0')
                {
                    CleanedPath += Null;
                }
            }
            return CleanedPath;
        }

        public static bool ParentProcessAntiDebug()
        {
            try
            {
                Structs.PROCESS_BASIC_INFORMATION PBI = new Structs.PROCESS_BASIC_INFORMATION();
                uint ProcessBasicInformation = 0;
                if (NtQueryInformationProcess(Process.GetCurrentProcess().SafeHandle, ProcessBasicInformation, ref PBI, (uint)Marshal.SizeOf(typeof(Structs.PROCESS_BASIC_INFORMATION)), 0) == 0)
                {
                    int ParentPID = PBI.InheritedFromUniqueProcessId.ToInt32();
                    if (ParentPID != 0)
                    {
                        byte[] FileNameBuffer = new byte[256];
                        Int32[] Size = new Int32[256];
                        Size[0] = 256;
                        QueryFullProcessImageNameA(Process.GetProcessById(ParentPID).SafeHandle, 0, FileNameBuffer, Size);
                        string ParentFilePath = CleanPath(Encoding.UTF8.GetString(FileNameBuffer));
                        string ParentFileName = Path.GetFileName(ParentFilePath);
                        string[] Whitelisted = { "explorer.exe", "cmd.exe" };
                        foreach (string WhitelistedFileName in Whitelisted)
                        {
                            if (ParentFileName.Equals(WhitelistedFileName))
                            {
                                return false;
                            }
                        }
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }

        public static bool NtSetDebugFilterStateAntiDebug()
        {
            if (NtSetDebugFilterState(0, 0, true) != 0)
                return false;
            return true;
        }

        delegate int ExecutionDelegate();
        public static bool PageGuardAntiDebug()
        {
            Structs.SYSTEM_INFO SysInfo = new Structs.SYSTEM_INFO();
            GetSystemInfo(out SysInfo);
            uint MEM_COMMIT = 0x00001000;
            uint MEM_RESERVE = 0x00002000;
            uint PAGE_EXECUTE_READWRITE = 0x40;
            uint PAGE_GUARD = 0x100;
            uint MEM_RELEASE = 0x00008000;
            IntPtr AllocatedSpace = VirtualAlloc(IntPtr.Zero, SysInfo.PageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (AllocatedSpace != IntPtr.Zero)
            {
                memset(AllocatedSpace, 1, 0xC3);
                uint OldProtect = 0;
                if (VirtualProtect(AllocatedSpace, SysInfo.PageSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, out OldProtect))
                {
                    try
                    {
                        ExecutionDelegate IsDebugged = Marshal.GetDelegateForFunctionPointer<ExecutionDelegate>(AllocatedSpace);
                        int Result = IsDebugged();
                    }
                    catch
                    {
                        VirtualFree(AllocatedSpace, SysInfo.PageSize, MEM_RELEASE);
                        return false;
                    }
                    VirtualFree(AllocatedSpace, SysInfo.PageSize, MEM_RELEASE);
                    return true;
                }
            }
            return false;
        }
    }
}
