# Dinvoke_Stuff
Implementing common injection techniques with Dinvoke instead of Pinvoke. Because why not.

The loader.b64 file is a base64 encoded output of donut shellcode. You should probably change that because it won't work unless you happen to have a Mythic C2 server listening on 10.10.16.19 for HackTheBox. Make sure it is an embedded resource in VS or the compilation might cry about it. Also this project is called DinvokeWinCallback because I don't know how to rename it.

Alternatively, just specify a file to use on disc or remote file. I thought it would be sneakier to use a slightly encoded, embedded file. ¯\\_(ツ)_/¯. The file has to be base64 encoded shellcode.  

Currently Available:  
1. Local Process Injection (via CreateRemoteThread and [EnumDisplayMonitors](https://marcoramilli.com/2022/06/15/running-shellcode-through-windows-callbacks/)  
2. Remote Process Injection (via creating a internet explorer instance)
3. Remote Process Injection (via section + mapping views on microsoft edge)
4. 
Credit to [rasta-mouse](https://github.com/rasta-mouse/DInvoke) for the minimalist implementation of Dinvoke Libraries.
```
[-] Usage: DinvokeDeez.exe
    Mandatory Keys
    /m => Specifies the injection type. 1 = Local Process Injection, 2 = Remote Process Injection, 3 = Injection via NtCreateSection + NtMapViewOfSection (default)
          Mapping will use edge, remote process injection uses internet explorer ¯\_(ツ)_/¯

    Optional Keys
    /f => Specifies a path to alternative base64 encoded shellcode to inject with. Can be a url too.
    
    example: DinvokeDeez.exe /m:1 /f:D:\Downloads\donut_v0.9.3\test.bin
```
