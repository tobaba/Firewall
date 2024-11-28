using System.Diagnostics;
using System.Net;
using System.Security.Principal;
using System.Text;

namespace Firewall;



public sealed class FirewallHelper: IFirewallHelper
{
    #region Fields
    private const string NETSH_PATH = "netsh";
    private static readonly Lazy<FirewallHelper> _instance = new(() => new FirewallHelper());
    private readonly bool _isAdministrator;
    #endregion

    #region Properties
    public static FirewallHelper Instance => _instance.Value;
    public bool IsAdministrator => _isAdministrator;
    #endregion

    private FirewallHelper()
    {
        _isAdministrator = new WindowsPrincipal(WindowsIdentity.GetCurrent())
            .IsInRole(WindowsBuiltInRole.Administrator);
    }

    #region Program Rules (已测试)

    /// <summary>
    /// 添加程序的入站规则
    /// </summary>
    public async Task<(bool success, string message)> AddInboundProgramRuleAsync(string ruleName, string programPath)
    {
        return await AddProgramRuleAsync(ruleName, programPath, true);
    }

    /// <summary>
    /// 添加程序的出站规则
    /// </summary>
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

            var arguments = $"advfirewall firewall add rule" +
                            $" name=\"{ruleName}\"" +
                            $" dir={(isInbound ? "in" : "out")}" +
                            $" action=allow" +
                            $" program=\"{programPath}\"" +
                            $" enable=yes";

            var (success, output) = await ExecuteNetshCommandAsync(arguments);
            return success ? (true, "规则添加成功") : (false, $"添加失败: {output}");
        }
        catch (Exception ex)
        {
            return (false, $"错误: {ex.Message}");
        }
    }

    #endregion

    #region Port Rules (已测试)

    /// <summary>
    /// 添加端口规则
    /// </summary>
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

            var arguments = $"advfirewall firewall add rule" +
                            $" name=\"{ruleName}\"" +
                            $" dir={(isInbound ? "in" : "out")}" +
                            $" action=allow" +
                            $" protocol={protocol.ToLower()}" +
                            $" localport={port}" +
                            $" enable=yes";

            var (success, output) = await ExecuteNetshCommandAsync(arguments);
            return success ? (true, "规则添加成功") : (false, $"添加失败: {output}");
        }
        catch (Exception ex)
        {
            return (false, $"错误: {ex.Message}");
        }
    }

    #endregion

    #region IP Rules (已测试)

    /// <summary>
    /// 添加远程IP规则
    /// </summary>
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

            var arguments = $"advfirewall firewall add rule" +
                            $" name=\"{ruleName}\"" +
                            $" dir={(isInbound ? "in" : "out")}" +
                            $" action={(allow ? "allow" : "block")}" +
                            $" remoteip={remoteIP}" +
                            $" enable=yes";

            var (success, output) = await ExecuteNetshCommandAsync(arguments);
            return success ? (true, "规则添加成功") : (false, $"添加失败: {output}");
        }
        catch (Exception ex)
        {
            return (false, $"错误: {ex.Message}");
        }
    }

    /// <summary>
    /// 添加本地IP规则
    /// </summary>
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

            var arguments = $"advfirewall firewall add rule" +
                            $" name=\"{ruleName}\"" +
                            $" dir={(isInbound ? "in" : "out")}" +
                            $" action={(allow ? "allow" : "block")}" +
                            $" localip={localIP}" +
                            $" enable=yes";

            var (success, output) = await ExecuteNetshCommandAsync(arguments);
            return success ? (true, "规则添加成功") : (false, $"添加失败: {output}");
        }
        catch (Exception ex)
        {
            return (false, $"错误: {ex.Message}");
        }
    }

    #endregion

    #region Rule Management (已测试)

    /// <summary>
    /// 删除规则
    /// </summary>
    public async Task<(bool success, string message)> DeleteRuleAsync(string ruleName)
    {
        try
        {
            if (!_isAdministrator)
                return (false, "需要管理员权限");

            if (string.IsNullOrWhiteSpace(ruleName))
                return (false, "规则名称不能为空");

            var arguments = $"advfirewall firewall delete rule name=\"{ruleName}\"";
            var (success, output) = await ExecuteNetshCommandAsync(arguments);

            if (output.Contains("没有与指定条件匹配的规则") ||
                output.Contains("No rules match the specified criteria"))
                return (false, "规则不存在");

            return success ? (true, "规则删除成功") : (false, $"删除失败: {output}");
        }
        catch (Exception ex)
        {
            return (false, $"错误: {ex.Message}");
        }
    }

    /// <summary>
    /// 获取所有规则
    /// </summary>
    public async Task<(bool success, List<string> rules, string message)> GetRulesAsync()
    {
        var rules = new List<string>();
        try
        {
            if (!_isAdministrator)
                return (false, rules, "需要管理员权限");

            var arguments = "advfirewall firewall show rule name=all";
            var (success, output) = await ExecuteNetshCommandAsync(arguments);

            if (!success)
                return (false, rules, $"获取规则失败: {output}");

            var lines = output.Split('\n');
            foreach (var line in lines)
            {
                if (line.StartsWith("规则名称:") || line.StartsWith("Rule Name:"))
                {
                    var name = line.Split(':')[1].Trim();
                    rules.Add(name);
                }
            }

            return (true, rules, "获取成功");
        }
        catch (Exception ex)
        {
            return (false, rules, $"错误: {ex.Message}");
        }
    }

    /// <summary>
    /// 检查规则是否存在
    /// </summary>
    public async Task<(bool exists, string message)> RuleExistsAsync(string ruleName)
    {
        try
        {
            if (!_isAdministrator)
                return (false, "需要管理员权限");

            var arguments = $"advfirewall firewall show rule name=\"{ruleName}\"";
            var (success, output) = await ExecuteNetshCommandAsync(arguments);

            if (output.Contains("没有与指定条件匹配的规则") ||
                output.Contains("No rules match the specified criteria"))
                return (false, "规则不存在");

            return (true, "规则存在");
        }
        catch (Exception ex)
        {
            return (false, $"错误: {ex.Message}");
        }
    }

    /// <summary>
    /// 启用/禁用规则
    /// </summary>
    public async Task<(bool success, string message)> SetRuleEnabledAsync(string ruleName, bool enabled)
    {
        try
        {
            if (!_isAdministrator)
                return (false, "需要管理员权限");

            var arguments = $"advfirewall firewall set rule name=\"{ruleName}\" new enable={(enabled ? "yes" : "no")}";
            var (success, output) = await ExecuteNetshCommandAsync(arguments);

            return success ? (true, $"规则已{(enabled ? "启用" : "禁用")}") : (false, $"操作失败: {output}");
        }
        catch (Exception ex)
        {
            return (false, $"错误: {ex.Message}");
        }
    }

    #endregion

    #region Firewall Policy (已测试)

    /// <summary>
    /// 导出防火墙策略
    /// </summary>
    public async Task<(bool success, string message)> ExportPolicyAsync(string filePath)
    {
        try
        {
            if (!_isAdministrator)
                return (false, "需要管理员权限");

            var arguments = $"advfirewall export \"{filePath}\"";
            var (success, output) = await ExecuteNetshCommandAsync(arguments);

            return success ? (true, $"策略已导出到: {filePath}") : (false, $"导出失败: {output}");
        }
        catch (Exception ex)
        {
            return (false, $"错误: {ex.Message}");
        }
    }

    /// <summary>
    /// 导入防火墙策略
    /// </summary>
    public async Task<(bool success, string message)> ImportPolicyAsync(string filePath)
    {
        try
        {
            if (!_isAdministrator)
                return (false, "需要管理员权限");

            if (!File.Exists(filePath))
                return (false, "文件不存在");

            var arguments = $"advfirewall import \"{filePath}\"";
            var (success, output) = await ExecuteNetshCommandAsync(arguments);

            return success ? (true, "策略导入成功") : (false, $"导入失败: {output}");
        }
        catch (Exception ex)
        {
            return (false, $"错误: {ex.Message}");
        }
    }

    /// <summary>
    /// 重置防火墙策略
    /// </summary>
    public async Task<(bool success, string message)> ResetPolicyAsync()
    {
        try
        {
            if (!_isAdministrator)
                return (false, "需要管理员权限");

            var arguments = "advfirewall reset";
            var (success, output) = await ExecuteNetshCommandAsync(arguments);

            return success ? (true, "防火墙已重置") : (false, $"重置失败: {output}");
        }
        catch (Exception ex)
        {
            return (false, $"错误: {ex.Message}");
        }
    }

    #endregion

    #region Helper Methods

    private async Task<(bool success, string output)> ExecuteNetshCommandAsync(string arguments)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = NETSH_PATH,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                // 设置正确的编码
                StandardOutputEncoding = Encoding.GetEncoding("GB2312"),  // 或 "GBK"
                StandardErrorEncoding = Encoding.GetEncoding("GB2312")
            }
        };

        var output = new StringBuilder();
        var error = new StringBuilder();

        try
        {
            process.OutputDataReceived += (s, e) => { if (e.Data != null) output.AppendLine(e.Data); };
            process.ErrorDataReceived += (s, e) => { if (e.Data != null) error.AppendLine(e.Data); };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            await process.WaitForExitAsync();

            if (error.Length > 0)
                return (false, error.ToString());

            return (process.ExitCode == 0, output.ToString());
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    private bool IsValidIPAddress(string ip)
    {
        // 支持以下格式:
        // 1. 单个IP: 192.168.1.1
        // 2. IP范围: 192.168.1.1-192.168.1.255
        // 3. 子网: 192.168.1.0/24
        // 4. 关键字: Any, LocalSubnet, DNS, DHCP, WINS, DefaultGateway

        string[] validKeywords = { "any", "localsubnet", "dns", "dhcp", "wins", "defaultgateway" };

        if (validKeywords.Contains(ip.ToLower()))
            return true;

        // 检查是否是IP范围
        if (ip.Contains("-"))
        {
            var ips = ip.Split('-');
            return ips.Length == 2 &&
                   IPAddress.TryParse(ips[0].Trim(), out _) &&
                   IPAddress.TryParse(ips[1].Trim(), out _);
        }

        // 检查是否是子网
        if (ip.Contains("/"))
        {
            var parts = ip.Split('/');
            if (parts.Length != 2) return false;

            return IPAddress.TryParse(parts[0].Trim(), out _) &&
                   int.TryParse(parts[1], out int subnet) &&
                   subnet >= 0 && subnet <= 32;
        }

        // 检查单个IP
        return IPAddress.TryParse(ip, out _);
    }
    // 新增方法：检查特定规则是否存在
    public async Task<(bool exists, string message)> CheckRuleExistsAsync(string ruleName)
    {
        try
        {
            var arguments = $"advfirewall firewall show rule name=\"{ruleName}\"";
            var (success, output) = await ExecuteNetshCommandAsync(arguments);

            // 如果包含"没有规则匹配"或"No rules match"，则规则不存在
            if (output.Contains("没有规则匹配") || output.Contains("No rules match"))
            {
                return (false, "规则不存在");
            }

            // 如果输出包含规则信息，则规则存在
            return (true, "规则已存在");
        }
        catch (Exception ex)
        {
            return (false, $"检查失败: {ex.Message}");
        }
    }
    #endregion
}