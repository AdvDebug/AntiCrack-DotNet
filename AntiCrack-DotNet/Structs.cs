using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace AntiCrack_DotNet
{
    class Structs
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT
        {
            public long ContextFlags;
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr4;
            public uint Dr5;
            public uint Dr6;
            public uint Dr7;
        }

        public struct PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
        {
            public uint MicrosoftSignedOnly;
        }
    }
}