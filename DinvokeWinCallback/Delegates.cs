using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
namespace Dinvoke
{
    public class Delegates
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr EnumDisplayMonitors(
        IntPtr hdc,
        IntPtr lprcClip,
        IntPtr lpfnEnum,
        IntPtr dwData);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr VirtualAlloc(
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect
        );
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect
         );
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateThread(
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Boolean CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            ref Structs.SECURITY_ATTRIBUTES lpProcessAttributes,
            ref Structs.SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            Structs.ProcessCreationFlags
            dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref Structs.STARTUPINFO lpStartupInfo,
            out Structs.PROCESS_INFORMATION lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Boolean CreateProcess2(
            string lpApplicationName,
            string lpCommandLine,
            ref Structs.SECURITY_ATTRIBUTES lpProcessAttributes,
            ref Structs.SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            Structs.ProcessCreationFlags
            dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref Structs.STARTUPINFOEX lpStartupInfo,
            out Structs.PROCESS_INFORMATION lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 ZwQueryInformationProcess(
            IntPtr hProcess,
            Int32 procInformationClass,
            ref Structs.PROCESS_BASIC_INFORMATION procInformation,
            UInt32 ProcInfoLen,
            ref UInt32 retlen);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            Int32 nSize,
            out IntPtr lpNumberOfBytesRead);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            Int32 nSize,
            out IntPtr lpNumberOfBytesWritten);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr OpenThread(
            Structs.ThreadAccess dwDesiredAccess,
            bool bInheritHandle,
            int dwThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Boolean VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            int dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr QueueUserAPC(
            IntPtr pfnAPC,
            IntPtr hThread,
            IntPtr dwData);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint ResumeThread(
            IntPtr hThhread);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 LdrLoadDll(
            IntPtr PathToFile,
            UInt32 dwFlags,
            ref Structs.UNICODE_STRING ModuleFileName,
            ref IntPtr ModuleHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void RtlInitUnicodeString(
            ref Structs.UNICODE_STRING DestinationString,
            [MarshalAs(UnmanagedType.LPWStr)] string SourceString);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            out IntPtr lpThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Structs.NTSTATUS NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            //UInt32 ZeroBits, 
            IntPtr ZeroBits,
            //ref UInt32 RegionSize, 
            ref IntPtr RegionSize,
            UInt32 AllocationType,
            UInt32 Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Structs.NTSTATUS NtWriteVirtualMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            IntPtr buffer,
            uint bufferLength,
            ref UInt32 NumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Structs.NTSTATUS NtCreateThreadEx(
            ref IntPtr threadHandle,
            UInt32 desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool inCreateSuspended,
            Int32 stackZeroBits,
            Int32 sizeOfStack,
            Int32 maximumStackSize,
            IntPtr attributeList
            );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList, 
            int dwAttributeCount, 
            int dwFlags, 
            ref IntPtr lpSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate  bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList, 
            uint dwFlags, 
            IntPtr Attribute, 
            IntPtr lpValue, 
            IntPtr cbSize, 
            IntPtr lpPreviousValue, 
            IntPtr lpReturnSize);
    }
}
