using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace AntiCrack_DotNet
{
    public class OtherChecks
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQuerySystemInformation(uint SystemInformationClass, ref Structs.SYSTEM_CODEINTEGRITY_INFORMATION SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        public static bool IsUnsignedDriversAllowed()
        {
            Structs.SYSTEM_CODEINTEGRITY_INFORMATION CodeIntegrity = new Structs.SYSTEM_CODEINTEGRITY_INFORMATION();
            CodeIntegrity.Length = (uint)Marshal.SizeOf(typeof(Structs.SYSTEM_CODEINTEGRITY_INFORMATION));
            uint ReturnLength = 0;
            if (NtQuerySystemInformation(0x67, ref CodeIntegrity, (uint)Marshal.SizeOf(CodeIntegrity), out ReturnLength) >= 0 && ReturnLength == (uint)Marshal.SizeOf(CodeIntegrity))
            {
                uint CODEINTEGRITY_OPTION_ENABLED = 0x01;
                if ((CodeIntegrity.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED) == CODEINTEGRITY_OPTION_ENABLED)
                {
                    return false;
                }
            }
            return true;
        }

        public static bool IsTestSignedDriversAllowed()
        {
            Structs.SYSTEM_CODEINTEGRITY_INFORMATION CodeIntegrity = new Structs.SYSTEM_CODEINTEGRITY_INFORMATION();
            CodeIntegrity.Length = (uint)Marshal.SizeOf(typeof(Structs.SYSTEM_CODEINTEGRITY_INFORMATION));
            uint ReturnLength = 0;
            if(NtQuerySystemInformation(0x67, ref CodeIntegrity, (uint)Marshal.SizeOf(CodeIntegrity), out ReturnLength) >= 0 && ReturnLength == (uint)Marshal.SizeOf(CodeIntegrity))
            {
                uint CODEINTEGRITY_OPTION_TESTSIGN = 0x02;
                if ((CodeIntegrity.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN) == CODEINTEGRITY_OPTION_TESTSIGN)
                {
                    return true;
                }
            }
            return false;
        }
    }
}