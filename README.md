# Dinvoke_Stuff
Implementing common injection techniques with Dinvoke instead of Pinvoke. 
 
The loader.b64 file is a base64 encoded output of donut shellcode. You should probably change that because it won't work unless you happen to have a Mythic C2 server listening on 10.10.16.19 for HackTheBox. Make sure it is an embedded resource in VS or the program might cry about it.  

Alternatively, just specify a file to use on disc. I thought it would be sneakier to use a slightly encoded, embedded file. ¯\_(ツ)_/¯  

Currently Available:  
1. Local Process Injection (via CreateRemoteThread and [EnumDisplayMonitors](https://marcoramilli.com/2022/06/15/running-shellcode-through-windows-callbacks/)  
2. Remote Process Injection (via creating a internet explorer instance)

Credit to [rasta-mouse](https://github.com/rasta-mouse/DInvoke) for the mimalist implementation of Dinvoke Libraries.
