using System;
using System.Runtime.InteropServices;

namespace SyscallsExtractor
{
    internal static class Program
    {
        private enum SysCalls
        {
            NtOpenProcess,
            NtCreateThreadEx,
            NtWriteVirtualMemory,
            ZwAllocateVirtualMemory,
            NtCreateSection,
            ZwMapViewOfSection,
            NtCreateProcess,
            ZwProtectVirtualMemory,
            ZwReadVirtualMemory,
            NtCreateThread,
            NtUnmapViewOfSection,
            NtCreateUserProcess,
            ZwFreeVirtualMemory,
            NtQueueApcThread
        }

        public static void Main(string[] args)
        {
            var osVersionInfo = new Internals.OSVersionInfoExW { dwOSVersionInfoSize = Marshal.SizeOf(typeof(Internals.OSVersionInfoExW)) };
            var ntStatus = Internals.RtlGetVersion(ref osVersionInfo);
            
            if(ntStatus != 0)
            {
                Console.WriteLine($"Error getting version info, NTStatus: {ntStatus}");
                return;
            }
            
            Console.WriteLine($"[*] Platform ID: {osVersionInfo.dwPlatformId}");
            Console.WriteLine($"[*] Build Number: {osVersionInfo.dwBuildNumber}");
            Console.WriteLine($"[*] Major Version: {osVersionInfo.dwMajorVersion}");
            Console.WriteLine($"[*] Minor Version: {osVersionInfo.dwMinorVersion}");
            Console.WriteLine($"[*] Service Pack Major: {osVersionInfo.wServicePackMajor}");
            Console.WriteLine($"[*] Service Pack Minor: {osVersionInfo.wServicePackMinor}");
            Console.WriteLine("\n[*] Syscalls\n");
            
            var hNtdll = Internals.LoadLibrary("ntdll.dll");

            if (hNtdll == IntPtr.Zero)
            {
                Console.WriteLine($"Unable to load ntdll.dll, last error: 0x{Internals.GetLastError():X}");
                return;
            }

            var pNtOpenProcess = Internals.GetProcAddress(hNtdll, Enum.GetName(typeof(SysCalls), SysCalls.NtOpenProcess));
            Console.WriteLine($"NtOpenProcess:\t\t 0x{Marshal.ReadInt32(pNtOpenProcess + 4):X}");

            var pNtCreateThreadEx = Internals.GetProcAddress(hNtdll, Enum.GetName(typeof(SysCalls), SysCalls.NtCreateThreadEx));
            Console.WriteLine($"NtCreateThreadEx:\t 0x{Marshal.ReadInt32(pNtCreateThreadEx + 4):X}");
            
            var pNtWriteVirtualMemory = Internals.GetProcAddress(hNtdll, Enum.GetName(typeof(SysCalls), SysCalls.NtWriteVirtualMemory));
            Console.WriteLine($"NtWriteVirtualMemory:\t 0x{Marshal.ReadInt32(pNtWriteVirtualMemory + 4):X}");

            var pZwAllocateVirtualMemory = Internals.GetProcAddress(hNtdll, Enum.GetName(typeof(SysCalls), SysCalls.ZwAllocateVirtualMemory));
            Console.WriteLine($"ZwAllocateVirtualMemory: 0x{Marshal.ReadInt32(pZwAllocateVirtualMemory + 4):X}");

            var pNtCreateSection = Internals.GetProcAddress(hNtdll, Enum.GetName(typeof(SysCalls), SysCalls.NtCreateSection));
            Console.WriteLine($"NtCreateSection:\t 0x{Marshal.ReadInt32(pNtCreateSection + 4):X}");

            var pZwMapViewOfSection = Internals.GetProcAddress(hNtdll, Enum.GetName(typeof(SysCalls), SysCalls.ZwMapViewOfSection));
            Console.WriteLine($"ZwMapViewOfSection:\t 0x{Marshal.ReadInt32(pZwMapViewOfSection + 4):X}");

            var pNtCreateProcess = Internals.GetProcAddress(hNtdll, Enum.GetName(typeof(SysCalls), SysCalls.NtCreateProcess));
            Console.WriteLine($"NtCreateProcess:\t 0x{Marshal.ReadInt32(pNtCreateProcess + 4):X}");

            var pZwProtectVirtualMemory = Internals.GetProcAddress(hNtdll, Enum.GetName(typeof(SysCalls), SysCalls.ZwProtectVirtualMemory));
            Console.WriteLine($"ZwProtectVirtualMemory:\t 0x{Marshal.ReadInt32(pZwProtectVirtualMemory + 4):X}");

            var pZwReadVirtualMemory = Internals.GetProcAddress(hNtdll, Enum.GetName(typeof(SysCalls), SysCalls.ZwReadVirtualMemory));
            Console.WriteLine($"ZwReadVirtualMemory:\t 0x{Marshal.ReadInt32(pZwReadVirtualMemory + 4):X}");

            var pNtCreateThread = Internals.GetProcAddress(hNtdll, Enum.GetName(typeof(SysCalls), SysCalls.NtCreateThread));
            Console.WriteLine($"NtCreateThread:\t\t 0x{Marshal.ReadInt32(pNtCreateThread + 4):X}");

            var pNtUnmapViewOfSection = Internals.GetProcAddress(hNtdll, Enum.GetName(typeof(SysCalls), SysCalls.NtUnmapViewOfSection));
            Console.WriteLine($"NtUnmapViewOfSection:\t 0x{Marshal.ReadInt32(pNtUnmapViewOfSection + 4):X}");

            var pNtCreateUserProcess = Internals.GetProcAddress(hNtdll, Enum.GetName(typeof(SysCalls), SysCalls.NtCreateUserProcess));
            Console.WriteLine($"NtCreateUserProcess:\t 0x{Marshal.ReadInt32(pNtCreateUserProcess + 4):X}");

            var pZwFreeVirtualMemory = Internals.GetProcAddress(hNtdll, Enum.GetName(typeof(SysCalls), SysCalls.ZwFreeVirtualMemory));
            Console.WriteLine($"ZwFreeVirtualMemory:\t 0x{Marshal.ReadInt32(pZwFreeVirtualMemory + 4):X}");

            var pNtQueueApcThread = Internals.GetProcAddress(hNtdll, Enum.GetName(typeof(SysCalls), SysCalls.NtQueueApcThread));
            Console.WriteLine($"NtQueueApcThread:\t 0x{Marshal.ReadInt32(pNtQueueApcThread + 4):X}");
            
            Console.WriteLine("\n[*] Done");
        }
    }
}