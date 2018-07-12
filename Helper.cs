using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NoAnkama
{
    public static class Helper
    {
        public static int CalculateJmp(int source, int dest)
        {
            if (source > dest)
                return dest - source - 5;
            return source - dest - 5;
        }

        public static ushort FormatPort(int port)
        {
            /* 5555 = 0x15B3, but it has to be 0xB315
             * 0x15B3 = 00010101 10110011 and 0xB315 = 10110011 00010101
             * We have to rotate right (or left since it's short and it's only 2 bytes).
             * (00010101 10110011) << 8 = 10110011 00000000
             * (00010101 10110011) >> 8 = 00000000 00010101
             * In this case, "add" and "or" does the same, so we have just the or the 2 nums to rotate bytes.
             */

            return (ushort)((port << 8) | (port >> 8));
        }

        public static bool DetectHook(IntPtr hProcess, IntPtr lpAddress, bool replace)
        {
            byte[] bytes = new byte[5];
            if (!NativeMethods.ReadProcessMemory(hProcess, lpAddress, bytes, 5, out IntPtr lpNumberOfBytesRead))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (bytes[0] != 0xE9)
            {
                return false;
            }

            if (!replace)
            {
                return true;
            }

            byte[] originalBytes = new byte[5]
            {
                0x8b,0xff, // mov edi, edi
                0x55,      // push ebp
                0x8b,0xec  // mov ebp, esp
            };

            if (!NativeMethods.VirtualProtectEx(hProcess, lpAddress, new UIntPtr((uint)originalBytes.Length), (uint)NativeMethods.MemoryProtection.ExecuteReadWrite, out uint oldProtection))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (!NativeMethods.WriteProcessMemory(hProcess, lpAddress, originalBytes, originalBytes.Length, out lpNumberOfBytesRead))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (!NativeMethods.VirtualProtectEx(hProcess, lpAddress, new UIntPtr((uint)originalBytes.Length), oldProtection, out oldProtection))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return true;
        }

    }
}
