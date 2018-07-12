# NoAnkama

## How to use ?

First of all, you have to initialize the class by passing informations about the process.
You have 3 differents ways to create the class.

```CS
WinsockHook winsockHook = new WinsockHook("Dofus"); // Here the process name is Dofus, so the class will get its handle.
```

```CS
WinsockHook winsockHook = new WinsockHook(1234); // Here the process id is 1234, so the class will find the process which it correspond and get its handle.
```

```CS
WinsockHook winsockHook = new WinsockHook(process); // Here the process is directly passed to the constructor, so it will get its handle.
```


You have to specify the IP address you want to blacklist, and the IP address on which you want to redirect the connection.
```CS
winsockHook.SourceIPs = new List<System.Net.IPAddress>
{
  System.Net.IPAddress.Parse("213.248.126.40"),
  System.Net.IPAddress.Parse("213.248.126.41"),
};
winsockHook.RemoteIP = new System.Net.IPEndPoint(System.Net.IPAddress.Parse("127.0.0.1"), 5555);
```



Then to hook the function you have just to do this:
```CS
winsock.Hook();
```



You can also Unhook the function by doing this:
```CS
winsock.Unhook();
```



The class will detect automatically if the function is already hooked. If the property 
```CS
public bool AllowReplace { get; set; }
```
is not set to ``True`` then, the function won't be hooked because it will cause crash.



I add some events to get some informations about the hook.
```CS
public class WinsockHookEventArgs : EventArgs
{

  public WinsockHookEventArgs(Process process, IntPtr apiAdd, IntPtr hookAdd, IntPtr continueAdd)
  {
    Process = process;
    ApiAdd = apiAdd;
    HookAdd = hookAdd;
    ContinueAdd = continueAdd;
  }

  public Process Process { get; private set; }
  public IntPtr ApiAdd { get; private set; }
  public IntPtr HookAdd { get; private set; }
  public IntPtr ContinueAdd { get; private set; }
  
}

public delegate void WinsockHookEventHandler(object sender, Events.WinsockHookEventArgs e);
public event WinsockHookEventHandler OnHook;
public event WinsockHookEventHandler OnUnhook;
public event WinsockHookEventHandler OnHookDetected;
```

## Example

```CS
using System;
using System.Collections.Generic;
using System.Threading;

namespace NoAnkama
{
    class Program
    {
        static void Main(string[] args)
        {
            ConsoleColor consoleColor = Console.ForegroundColor;
            WinsockHook winsockHook = new WinsockHook("Dofus");
            winsockHook.SourceIPs = new List<System.Net.IPAddress>
            {
                System.Net.IPAddress.Parse("213.248.126.40"),
                System.Net.IPAddress.Parse("213.248.126.41"),
            };
            winsockHook.RemoteIP = new System.Net.IPEndPoint(System.Net.IPAddress.Parse("127.0.0.1"), 5555);
            winsockHook.AllowReplace = true;

            winsockHook.OnHook += (sender, e) =>
             {
                 Console.ForegroundColor = ConsoleColor.Green;
                 Console.WriteLine("----------------");
                 Console.WriteLine("API function hooked !");
                 PrintEventArgs(e);
                 Console.WriteLine("----------------");
                 Console.ForegroundColor = consoleColor;
                 Console.WriteLine();
             };
            winsockHook.OnUnhook += (sender, e) =>
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("----------------");
                Console.WriteLine("API function unhooked !");
                PrintEventArgs(e);
                Console.WriteLine("----------------");
                Console.ForegroundColor = consoleColor;
                Console.WriteLine();
            };
            winsockHook.OnHookDetected += (sender, e) =>
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("----------------");
                Console.WriteLine("API function is already hooked !");
                PrintEventArgs(e);
                Console.WriteLine("----------------");
                Console.ForegroundColor = consoleColor;
                Console.WriteLine();
            };

            winsockHook.Hook();
            Thread.Sleep(10000);
            winsockHook.Unhook();

            Console.Read();
        }

        static void PrintEventArgs(Events.WinsockHookEventArgs e)
        {
            Console.WriteLine("Process: {0} (PID={1})", e.Process.ProcessName, e.Process.Id);
            Console.WriteLine("\"connect\" add: 0x{0}", e.ApiAdd.ToInt32().ToString("X8"));
            Console.WriteLine("Continue add: 0x{0}", e.ContinueAdd.ToInt32().ToString("X8"));
            Console.WriteLine("Hook add: 0x{0}", e.HookAdd.ToInt32().ToString("X8"));
        }
    }
}
```
You can find it in ``Program.cs``.


## Demo

[demo](https://i.imgur.com/AZFPhCU.gifv)

# TODO
- [ ] Dispose
- [ ] Support 64-bit
- [x] Support 32-bit
- [ ] Avoid crashes
- [ ] Pretty Code

# Informations

I'm sorry if my code isn't pretty, I wrote it quick and the errors swelled me.
But otherwise, I think my code works on every platforms. If you have any problems, please create an issue.

The code is based on the idea of Luax: [MiniHook a detours alternative](https://yann.voidmx.net/blog/post/minihook-a-detours-alternative)
