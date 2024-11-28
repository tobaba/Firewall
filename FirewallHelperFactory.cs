using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Firewall
{
    public static class FirewallHelperFactory
    {
        public static IFirewallHelper Create()
        {
            if (!SystemRequirements.CheckSystemRequirements(out string message))
            {
                throw new InvalidOperationException(message);
            }

            return IsWindows10OrLater() ?
                (IFirewallHelper)FirewallPSHelper.Instance :
                (IFirewallHelper)FirewallHelper.Instance;
        }

        private static bool IsWindows10OrLater()
        {
            var windows10Version = new Version(10, 0);
            return Environment.OSVersion.Version >= windows10Version;
        }
    }
}
