using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NoAnkama.Events
{
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
}
