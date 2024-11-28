using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;

namespace Firewall
{
    public static class SystemRequirements
    {
        public static bool CheckSystemRequirements(out string message)
        {
            if (!IsWindowsOS())
            {
                message = "仅支持Windows操作系统";
                return false;
            }

            if (!IsFirewallServiceRunning())
            {
                message = "Windows防火墙服务未运行";
                return false;
            }

            if (!IsAdministrator())
            {
                message = "需要管理员权限";
                return false;
            }

            message = "系统检查通过";
            return true;
        }

        private static bool IsFirewallServiceRunning()
        {
            using var service = new ServiceController("MpsSvc");
            return service.Status == ServiceControllerStatus.Running;
        }

        private static bool IsWindowsOS()
        {
            return Environment.OSVersion.Platform == PlatformID.Win32NT;
        }

        private static bool IsAdministrator()
        {
            return new WindowsPrincipal(WindowsIdentity.GetCurrent())
                .IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}
