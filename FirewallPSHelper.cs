using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Net;
using System.Security.Principal;
using System.Text;

namespace Firewall
{
    public sealed class FirewallPSHelper : IFirewallHelper
    {
        #region Fields
        private static readonly Lazy<FirewallPSHelper> _instance = new(() => new FirewallPSHelper());
        private readonly bool _isAdministrator;
        #endregion

        #region Properties
        public static FirewallPSHelper Instance => _instance.Value;
        public bool IsAdministrator => _isAdministrator;
        #endregion

        private FirewallPSHelper()
        {
            _isAdministrator = new WindowsPrincipal(WindowsIdentity.GetCurrent())
                .IsInRole(WindowsBuiltInRole.Administrator);
            // 确保已注册编码提供程序
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        }

        #region Program Rules (已测试)

        public async Task<(bool success, string message)> AddInboundProgramRuleAsync(string ruleName, string programPath)
        {
            return await AddProgramRuleAsync(ruleName, programPath, true);
        }

        public async Task<(bool success, string message)> AddOutboundProgramRuleAsync(string ruleName, string programPath)
        {
            return await AddProgramRuleAsync(ruleName, programPath, false);
        }

        private async Task<(bool success, string message)> AddProgramRuleAsync(string ruleName, string programPath, bool isInbound)
        {
            try
            {
                if (!_isAdministrator)
                    return (false, "需要管理员权限");

                if (string.IsNullOrWhiteSpace(ruleName))
                    return (false, "规则名称不能为空");

                if (!File.Exists(programPath))
                    return (false, "程序不存在");

                var command = $@"
                New-NetFirewallRule -DisplayName '{ruleName}' 
                -Direction {(isInbound ? "Inbound" : "Outbound")}
                -Action Allow 
                -Program '{programPath}'
                -Profile Any
                -Protocol Any
                -Enabled True";

                var (success, output) = await ExecutePowerShellCommandAsync(command);
                return success ? (true, "规则添加成功") : (false, $"添加失败: {output}");
            }
            catch (Exception ex)
            {
                return (false, $"错误: {ex.Message}");
            }
        }

        #endregion

        #region Port Rules (已测试)

        public async Task<(bool success, string message)> AddPortRuleAsync(string ruleName, int port, bool isInbound = true, string protocol = "TCP")
        {
            try
            {
                if (!_isAdministrator)
                    return (false, "需要管理员权限");

                if (string.IsNullOrWhiteSpace(ruleName))
                    return (false, "规则名称不能为空");

                if (port < 1 || port > 65535)
                    return (false, "端口号无效");

                var command = $@"
                New-NetFirewallRule -DisplayName '{ruleName}'
                -Direction {(isInbound ? "Inbound" : "Outbound")}
                -Action Allow
                -Protocol {protocol}
                -LocalPort {port}
                -Profile Any
                -Enabled True";

                var (success, output) = await ExecutePowerShellCommandAsync(command);
                return success ? (true, "规则添加成功") : (false, $"添加失败: {output}");
            }
            catch (Exception ex)
            {
                return (false, $"错误: {ex.Message}");
            }
        }

        #endregion

        #region IP Rules (已测试)

        public async Task<(bool success, string message)> AddRemoteIPRuleAsync(string ruleName, string remoteIP, bool isInbound = true, bool allow = true)
        {
            try
            {
                if (!_isAdministrator)
                    return (false, "需要管理员权限");

                if (string.IsNullOrWhiteSpace(ruleName))
                    return (false, "规则名称不能为空");

                if (!IsValidIPAddress(remoteIP))
                    return (false, "IP地址无效");

                var command = $@"
                New-NetFirewallRule -DisplayName '{ruleName}'
                -Direction {(isInbound ? "Inbound" : "Outbound")}
                -Action {(allow ? "Allow" : "Block")}
                -RemoteAddress {remoteIP}
                -Profile Any
                -Enabled True";

                var (success, output) = await ExecutePowerShellCommandAsync(command);
                return success ? (true, "规则添加成功") : (false, $"添加失败: {output}");
            }
            catch (Exception ex)
            {
                return (false, $"错误: {ex.Message}");
            }
        }

        public async Task<(bool success, string message)> AddLocalIPRuleAsync(string ruleName, string localIP, bool isInbound = true, bool allow = true)
        {
            try
            {
                if (!_isAdministrator)
                    return (false, "需要管理员权限");

                if (string.IsNullOrWhiteSpace(ruleName))
                    return (false, "规则名称不能为空");

                if (!IsValidIPAddress(localIP))
                    return (false, "IP地址无效");

                var command = $@"
                New-NetFirewallRule -DisplayName '{ruleName}'
                -Direction {(isInbound ? "Inbound" : "Outbound")}
                -Action {(allow ? "Allow" : "Block")}
                -LocalAddress {localIP}
                -Profile Any
                -Enabled True";

                var (success, output) = await ExecutePowerShellCommandAsync(command);
                return success ? (true, "规则添加成功") : (false, $"添加失败: {output}");
            }
            catch (Exception ex)
            {
                return (false, $"错误: {ex.Message}");
            }
        }

        #endregion

        #region Rule Management (已测试)

        public async Task<(bool success, string message)> DeleteRuleAsync(string ruleName)
        {
            try
            {
                if (!_isAdministrator)
                    return (false, "需要管理员权限");

                var command = $"Remove-NetFirewallRule -DisplayName '{ruleName}' -ErrorAction SilentlyContinue";
                var (success, output) = await ExecutePowerShellCommandAsync(command);

                return success ? (true, "规则删除成功") : (false, $"删除失败: {output}");
            }
            catch (Exception ex)
            {
                return (false, $"错误: {ex.Message}");
            }
        }

        public async Task<(bool success, List<string> rules, string message)> GetRulesAsync()
        {
            var rules = new List<string>();
            try
            {
                if (!_isAdministrator)
                    return (false, rules, "需要管理员权限");

                var command = @"
                Get-NetFirewallRule | 
                Where-Object { $_.Enabled -eq 'True' } |
                Select-Object DisplayName";

                var (success, output) = await ExecutePowerShellCommandAsync(command);
                if (!success)
                    return (false, rules, $"获取规则失败: {output}");

                rules.AddRange(output.Split(new[] { Environment.NewLine },
                    StringSplitOptions.RemoveEmptyEntries));

                return (true, rules, $"成功获取 {rules.Count} 条规则");
            }
            catch (Exception ex)
            {
                return (false, rules, $"错误: {ex.Message}");
            }
        }

        public async Task<(bool exists, string message)> CheckRuleExistsAsync(string ruleName)
        {
            try
            {
                if (!_isAdministrator)
                    return (false, "需要管理员权限");

                var command = $"Get-NetFirewallRule -DisplayName '{ruleName}' -ErrorAction SilentlyContinue";
                var (success, output) = await ExecutePowerShellCommandAsync(command);

                return (!string.IsNullOrWhiteSpace(output),
                    string.IsNullOrWhiteSpace(output) ? "规则不存在" : "规则已存在");
            }
            catch (Exception ex)
            {
                return (false, $"检查失败: {ex.Message}");
            }
        }

        public async Task<(bool success, string message)> SetRuleEnabledAsync(string ruleName, bool enabled)
        {
            try
            {
                if (!_isAdministrator)
                    return (false, "需要管理员权限");

                var command = $@"
                Set-NetFirewallRule -DisplayName '{ruleName}' 
                -Enabled {(enabled ? "$true" : "$false")}";

                var (success, output) = await ExecutePowerShellCommandAsync(command);
                return success ?
                    (true, $"规则已{(enabled ? "启用" : "禁用")}") :
                    (false, $"操作失败: {output}");
            }
            catch (Exception ex)
            {
                return (false, $"错误: {ex.Message}");
            }
        }

        #endregion

        #region Firewall Policy (已测试)

        public async Task<(bool success, string message)> ExportPolicyAsync(string filePath)
        {
            try
            {
                if (!_isAdministrator)
                    return (false, "需要管理员权限");

                var command = $@"
                $policy = Get-NetFirewallRule | 
                Select-Object DisplayName,Enabled,Direction,Action,Program,Protocol,LocalPort,RemoteAddress,LocalAddress
                $policy | Export-Clixml -Path '{filePath}'";

                var (success, output) = await ExecutePowerShellCommandAsync(command);
                return success ?
                    (true, $"策略已导出到: {filePath}") :
                    (false, $"导出失败: {output}");
            }
            catch (Exception ex)
            {
                return (false, $"错误: {ex.Message}");
            }
        }

        public async Task<(bool success, string message)> ImportPolicyAsync(string filePath)
        {
            try
            {
                if (!_isAdministrator)
                    return (false, "需要管理员权限");

                if (!File.Exists(filePath))
                    return (false, "文件不存在");

                var command = $@"
                $rules = Import-Clixml -Path '{filePath}'
                foreach ($rule in $rules) {{
                    New-NetFirewallRule -DisplayName $rule.DisplayName `
                        -Enabled $rule.Enabled `
                        -Direction $rule.Direction `
                        -Action $rule.Action `
                        -Program $rule.Program `
                        -Protocol $rule.Protocol `
                        -LocalPort $rule.LocalPort `
                        -RemoteAddress $rule.RemoteAddress `
                        -LocalAddress $rule.LocalAddress `
                        -ErrorAction SilentlyContinue
                }}";

                var (success, output) = await ExecutePowerShellCommandAsync(command);
                return success ? (true, "策略导入成功") : (false, $"导入失败: {output}");
            }
            catch (Exception ex)
            {
                return (false, $"错误: {ex.Message}");
            }
        }

        public async Task<(bool success, string message)> ResetPolicyAsync()
        {
            try
            {
                if (!_isAdministrator)
                    return (false, "需要管理员权限");

                var command = @"
                Remove-NetFirewallRule -All -ErrorAction SilentlyContinue
                Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
                Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow";

                var (success, output) = await ExecutePowerShellCommandAsync(command);
                return success ? (true, "防火墙已重置") : (false, $"重置失败: {output}");
            }
            catch (Exception ex)
            {
                return (false, $"错误: {ex.Message}");
            }
        }

        #endregion

        #region Helper Methods

        private async Task<(bool success, string output)> ExecutePowerShellCommandAsync(string command)
        {
            try
            {
                using var runspace = RunspaceFactory.CreateRunspace();
                runspace.Open();

                using var ps = PowerShell.Create(runspace);
                ps.AddScript(command);

                var results = await ps.InvokeAsync();

                if (ps.HadErrors)
                {
                    var errors = string.Join(Environment.NewLine,
                        ps.Streams.Error.Select(e => e.ToString()));
                    return (false, errors);
                }

                return (true, string.Join(Environment.NewLine,
                    results.Select(r => r?.ToString() ?? string.Empty)));
            }
            catch (Exception ex)
            {
                return (false, ex.Message);
            }
        }

        private bool IsValidIPAddress(string ip)
        {
            string[] validKeywords = { "any", "localsubnet", "dns", "dhcp", "wins", "defaultgateway" };

            if (validKeywords.Contains(ip.ToLower()))
                return true;

            if (ip.Contains("-"))
            {
                var ips = ip.Split('-');
                return ips.Length == 2 &&
                       IPAddress.TryParse(ips[0].Trim(), out _) &&
                       IPAddress.TryParse(ips[1].Trim(), out _);
            }

            if (ip.Contains("/"))
            {
                var parts = ip.Split('/');
                if (parts.Length != 2) return false;

                return IPAddress.TryParse(parts[0].Trim(), out _) &&
                       int.TryParse(parts[1], out int subnet) &&
                       subnet >= 0 && subnet <= 32;
            }

            return IPAddress.TryParse(ip, out _);
        }

        #endregion
    }
}
