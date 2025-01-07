using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Windows.Forms;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.TrackBar;
using static AntiCrack_DotNet.Structs;

namespace AntiCrack_DotNet
{
    public sealed class Hooks
    {
        private static byte[] EnsureNonNullMethodInfoOriginal = new byte[6];
        private static byte[] EnsureNonNullMethodInfoHooked = new byte[6];
        private static IntPtr pEnsureNonNullMethodInfo = IntPtr.Zero;
        private static readonly object ENNM_lock = new object();
        private static bool PrintGFP = false;
        private static List<IntPtr> Whitelisted_FP = new List<IntPtr>();
        private static List<IntPtr> Blacklisted_FP = new List<IntPtr>();
        private static bool Whitelisting_FP = false;
        private static bool Blacklisting_FP = false;

        /// <summary>
        /// The hook to prevent unauthorized function retrieval by abusing EnsureNonNullMethodInfo without modifying GetFunctionPointer directly.
        /// </summary>
        /// <returns>Returns the method if all the conditions are right.</returns>
        private static MethodInfo EnsureNonNullHook(MethodInfo MI)
        {
            lock (ENNM_lock)
            {
                bool IsWhitelisted = false;
                bool IsBlacklisted = false;
                if (MI == null)
                    return null;
                try
                {
                    StackTrace trace = new StackTrace();
                    MethodBase IsGetFunctionPointer = trace.GetFrame(1)?.GetMethod();
                    if (IsGetFunctionPointer.Name == "GetFunctionPointer")
                    {
                        MethodBase MB = trace.GetFrame(2)?.GetMethod();
                        if (Whitelisting_FP)
                        {
                            if (MB != null)
                            {
                                Utils.InstallOrUninstallHook(EnsureNonNullMethodInfoOriginal, pEnsureNonNullMethodInfo);
                                IntPtr pSourceFunction = MB.MethodHandle.GetFunctionPointer();
                                Utils.InstallOrUninstallHook(EnsureNonNullMethodInfoHooked, pEnsureNonNullMethodInfo);
                                if (Whitelisted_FP != null)
                                {
                                    foreach (IntPtr WhiteListedMethod in Whitelisted_FP)
                                    {
                                        if (WhiteListedMethod != IntPtr.Zero)
                                        {
                                            if (WhiteListedMethod != IntPtr.Zero && WhiteListedMethod == pSourceFunction)
                                            {
                                                IsWhitelisted = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        else if (Blacklisting_FP)
                        {
                            if (Blacklisted_FP != null)
                            {
                                Utils.InstallOrUninstallHook(EnsureNonNullMethodInfoOriginal, pEnsureNonNullMethodInfo);
                                IntPtr pSourceFunction = MI.MethodHandle.GetFunctionPointer();
                                Utils.InstallOrUninstallHook(EnsureNonNullMethodInfoHooked, pEnsureNonNullMethodInfo);
                                foreach (IntPtr BlacklistedMethod in Blacklisted_FP)
                                {
                                    if (BlacklistedMethod != IntPtr.Zero)
                                    {
                                        if (BlacklistedMethod != IntPtr.Zero && BlacklistedMethod == pSourceFunction)
                                        {
                                            IsBlacklisted = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        bool RefuseAccess = (Blacklisting_FP && IsBlacklisted || Whitelisting_FP && !IsWhitelisted);
                        if (PrintGFP)
                        {
                            if (RefuseAccess)
                            {
                                string message = string.Empty;
                                if (MB != null)
                                {
                                    message = $"---------------------------------------------------------\n";
                                    message += $"The function \"{MB}\" at the class \"{MB.DeclaringType?.Name}\" tried to get a function pointer directly and got prevented.\n";
                                    message += $"---------------------------------------------------------\n";
                                }
                                else
                                {
                                    message = $"---------------------------------------------------------\nA function tried to get a function pointer directly and got prevented.\n---------------------------------------------------------\n";
                                }
                                Console.ForegroundColor = ConsoleColor.DarkRed;
                                Console.WriteLine(message);
                                Console.ForegroundColor = ConsoleColor.White;
                            }
                        }

                        if (RefuseAccess)
                            return null;
                        return MI;
                    }
                    else
                    {
                        return MI;
                    }
                }
                catch
                {
                    return null;
                }
            }
        }



        /// <summary>
        /// Prevents the usage of GetFunctionPointer() from unauthorized assemblies.
        /// </summary>
        /// <param name="PrintAccessAttempts">An indication to know if the hook should print illegal access attempts to function pointers.</param>
        /// <param name="WhitelistedMethods">The methods which is always allowed to have a pointer of any function but no other method can, can be null if BlacklistedMethods parameter is not null (only one of them is accepted).</param>
        /// <param name="BlacklistedMethods">The methods that it's function pointer can't be retrieved, can be null if WhitelistedMethods is not null (only of them is accepted).</param>
        /// <returns>Returns true if successfully hooked, otherwise false.</returns>
        public static bool PreventUnauthorizedFunctionPointerRetrieval(bool PrintAccessAttempts, MethodInfo[] WhitelistedMethods, MethodInfo[] BlacklistedMethods, Type[] WhitelistedDeclaringTypes = null)
        {
            try
            {
                if (!Utils.IsReflectionEnabled(true, true))
                    return false;

                if (WhitelistedMethods == null && BlacklistedMethods == null)
                    return false;

                if (WhitelistedMethods != null && BlacklistedMethods != null)
                    return false;

                if (WhitelistedMethods != null)
                {
                    foreach(MethodInfo MIs in WhitelistedMethods)
                    {
                        try
                        {
                            if(MIs != null)
                            {
                                RuntimeHelpers.PrepareMethod(MIs.MethodHandle);
                                IntPtr FP = Utils.GetPointer(MIs);
                                if(FP != IntPtr.Zero)
                                {
                                    Whitelisted_FP.Add(FP);
                                }
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }
                    Whitelisting_FP = true;
                }
                else if (BlacklistedMethods != null)
                {
                    foreach (MethodInfo MIs in BlacklistedMethods)
                    {
                        try
                        {
                            if (MIs != null)
                            {
                                RuntimeHelpers.PrepareMethod(MIs.MethodHandle);
                                IntPtr FP = Utils.GetPointer(MIs);
                                if (FP != IntPtr.Zero)
                                {
                                    Blacklisted_FP.Add(FP);
                                }
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }
                    Blacklisting_FP = true;
                }
                
                PrintGFP = PrintAccessAttempts;
                MethodInfo MI = typeof(RuntimeMethodHandle).GetMethod("EnsureNonNullMethodInfo", BindingFlags.NonPublic | BindingFlags.Static);
                if (MI != null)
                {
                    foreach (MethodInfo Methods in MethodBase.GetCurrentMethod().DeclaringType.GetMethods(BindingFlags.Static | BindingFlags.NonPublic))
                    {
                        if (Methods != null)
                        {
                            if (Methods.ReturnType == typeof(MethodInfo)) //corresponds to EnsureNonNullHook method but we are getting it like this to support renaming obfuscation
                            {
                                if (Utils.InstallHookCLR(MI, Methods, EnsureNonNullMethodInfoOriginal, out EnsureNonNullMethodInfoHooked, out pEnsureNonNullMethodInfo))
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
    }
}