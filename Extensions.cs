using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NoAnkama
{

    public static class Extensions
    {

        /// <summary>
        /// Indicate if there is any Process Module which respects the condition(s).
        /// </summary>
        /// <param name="processModuleCollection">The ProcessModuleCollection you want to search in.</param>
        /// <param name="predicate">The condition(s).</param>
        /// <returns>It returns true if there is a module which respects the condition(s), else it returns false.</returns>
        public static bool Any(this ProcessModuleCollection processModuleCollection, Func<ProcessModule, bool> predicate)
        {
            foreach (ProcessModule processModule in processModuleCollection)
            {
                if (predicate(processModule))
                {
                    return true;
                }
            }
            return false;
        }
    }
}
