using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using static AntiCrack_DotNet.Structs;

namespace AntiCrack_DotNet
{
    public sealed class Structs
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT
        {
            public uint P1Home;
            public uint P2Home;
            public uint P3Home;
            public uint P4Home;
            public uint P5Home;
            public uint P6Home;
            public long ContextFlags;
            public IntPtr MxCsr;
            public IntPtr SegCs;
            public IntPtr SegDs;
            public IntPtr SegEs;
            public IntPtr SegFs;
            public IntPtr SegGs;
            public IntPtr SegSs;
            public IntPtr EFlags;
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;
        }

        public struct PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
        {
            public uint MicrosoftSignedOnly;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct SYSTEM_CODEINTEGRITY_INFORMATION
        {
            [FieldOffset(0)]
            public ulong Length;

            [FieldOffset(4)]
            public uint CodeIntegrityOptions;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            internal IntPtr Reserved1;
            internal IntPtr PebBaseAddress;
            internal IntPtr Reserved2_0;
            internal IntPtr Reserved2_1;
            internal IntPtr UniqueProcessId;
            internal IntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_KERNEL_DEBUGGER_INFORMATION
        {
            [MarshalAs(UnmanagedType.U1)]
            public bool KernelDebuggerEnabled;

            [MarshalAs(UnmanagedType.U1)]
            public bool KernelDebuggerNotPresent;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        public struct ANSI_STRING
        {
            public short Length;
            public short MaximumLength;
            public string Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_SECUREBOOT_INFORMATION
        {
            public bool SecureBootEnabled;
            public bool SecureBootCapable;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public ushort ProcessorArchitecture;
            ushort Reserved;
            public uint PageSize;
            public IntPtr MinimumApplicationAddress;
            public IntPtr MaximumApplicationAddress;
            public IntPtr ActiveProcessorMask;
            public uint NumberOfProcessors;
            public uint ProcessorType;
            public uint AllocationGranularity;
            public ushort ProcessorLevel;
            public ushort ProcessorRevision;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OSVERSIONINFOEX
        {
            public int dwOSVersionInfoSize;
            public int dwMajorVersion;
            public int dwMinorVersion;
            public int dwBuildNumber;
            public int dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
            public ushort wServicePackMajor;
            public ushort wServicePackMinor;
            public ushort wSuiteMask;
            public byte wProductType;
            public byte wReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;
            public ushort e_cblp;
            public ushort e_cp;
            public ushort e_crlc;
            public ushort e_cparhdr;
            public ushort e_minalloc;
            public ushort e_maxalloc;
            public ushort e_ss;
            public ushort e_sp;
            public ushort e_csum;
            public ushort e_ip;
            public ushort e_cs;
            public ushort e_lfarlc;
            public ushort e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res1;
            public ushort e_oemid;
            public ushort e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;
            public int e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct IMAGE_NT_HEADERS32
        {
            public UInt32 Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct IMAGE_NT_HEADERS64
        {
            public UInt32 Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBaseLong;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public ulong SizeOfStackReserve;
            public ulong SizeOfStackCommit;
            public ulong SizeOfHeapReserve;
            public ulong SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            public IMAGE_DATA_DIRECTORY DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;
            public IMAGE_DATA_DIRECTORY DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint Name;
            public uint Base;
            public uint NumberOfFunctions;
            public uint NumberOfNames;
            public uint AddressOfFunctions;
            public uint AddressOfNames;
            public uint AddressOfNameOrdinals;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Name;

            public uint VirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public uint Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr Blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _PEB_LDR_DATA
        {
            public UInt32 Length;
            public Byte Initialized;
            public IntPtr SsHandle;
            public _LIST_ENTRY InLoadOrderModuleList;
            public _LIST_ENTRY InMemoryOrderModuleList;
            public _LIST_ENTRY InInitializationOrderModuleList;
            public IntPtr EntryInProgress;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _LDR_DATA_TABLE_ENTRY
        {
            public _LIST_ENTRY InLoadOrderLinks;
            public _LIST_ENTRY InMemoryOrderLinks;
            public _LIST_ENTRY InInitializationOrderLinks;
            public IntPtr DllBase;
            public IntPtr EntryPoint;
            public UInt32 SizeOfImage;
            public UNICODE_STRING FullDllName;
            public UNICODE_STRING BaseDllName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RTL_USER_PROCESS_PARAMETERS
        {
            public long MaximumLength;
            public long Length;
            public long Flags;
            public long DebugFlags;
            public IntPtr ConsoleHandle;
            public long ConsoleFlags;
            public IntPtr StdInputHandle;
            public IntPtr StdOutputHandle;
            public IntPtr StdErrorHandle;
            public IntPtr CurrentDirectory;
            public UNICODE_STRING DllPath;
            public UNICODE_STRING ImagePathName;
            public UNICODE_STRING CommandLine;
            public IntPtr Environment;
            public long StartingPositionLeft;
            public long StartingPositionTop;
            public long Width;
            public long Height;
            public long CharWidth;
            public long CharHeight;
            public long ConsoleTextAttributes;
            public long WindowFlags;
            public long ShowWindowFlags;
            public UNICODE_STRING WindowTitle;
            public UNICODE_STRING DesktopName;
            public UNICODE_STRING ShellInfo;
            public UNICODE_STRING RuntimeData;
            public IntPtr DLCurrentDirectory;
            public long EnvironmentSize;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct PEB
        {
            public byte InheritedAddressSpace;
            public byte ReadImageFileExecOptions;
            public byte BeingDebugged;
            public byte SpareBool;
            public IntPtr Mutant;
            public IntPtr ImageBaseAddress;
            public IntPtr Ldr;
            public IntPtr ProcessParameters;
            public IntPtr SubSystemData;
            public IntPtr ProcessHeap;
            public IntPtr FastPebLock;
            public IntPtr AtlThunkSListPtr;
            public IntPtr IFEOKey;
            public uint CrossProcessFlags;
            public IntPtr KernelCallbackTable;
            public uint SystemReserved;
            public uint AtlThunkSListPtr32;
            public IntPtr ApiSetMap;
            public uint TlsExpansionCounter;
            public IntPtr TlsBitmap;
            public fixed uint TlsBitmapBits[2];
            public IntPtr ReadOnlySharedMemoryBase;
            public IntPtr SharedData;
            public IntPtr ReadOnlyStaticServerData;
            public IntPtr AnsiCodePageData;
            public IntPtr OemCodePageData;
            public IntPtr UnicodeCaseTableData;
            public uint NumberOfProcessors;
            public uint NtGlobalFlag;
        }
    }
}