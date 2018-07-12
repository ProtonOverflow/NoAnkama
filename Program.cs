using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

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
