using System;
using System.Runtime.InteropServices;
using System.Security;

namespace SyscallsExtractor
{
    internal static class Internals
    {
        [DllImport("kernel32")]
        internal static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string procName);


        [SuppressUnmanagedCodeSecurity]
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int RtlGetVersion(ref OSVersionInfoExW versionInfo);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct OSVersionInfoExW
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
    }
}