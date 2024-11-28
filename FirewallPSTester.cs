using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Firewall
{
    public class FirewallPSTester
    {
        public readonly IFirewallHelper _fw;
        private const string TEST_PREFIX = "TEST_PS_";

        public FirewallPSTester()
        {
            _fw = FirewallPSHelper.Instance;
            Console.OutputEncoding = Encoding.UTF8;
            // 确保已注册编码提供程序
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        }

        public async Task RunAllTests()
        {
            if (!_fw.IsAdministrator)
            {
                Console.WriteLine("请以管理员权限运行此程序!");
                return;
            }

            try
            {
                Console.WriteLine("开始 PowerShell 防火墙规则测试...\n");

                // 1. 测试程序规则
                await TestProgramRules();

                // 2. 测试端口规则
                await TestPortRules();

                // 3. 测试IP规则
                await TestIPRules();

                // 4. 测试规则管理
                await TestRuleManagement();

                // 5. 测试策略管理
                await TestPolicyManagement();

                Console.WriteLine("\n所有测试完成!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n测试过程中发生错误: {ex.Message}");
            }
            finally
            {
                // 清理测试规则
                await CleanupTestRules();
            }
        }

        private async Task TestProgramRules()
        {
            Console.WriteLine("=== 测试程序规则 ===");

            // 测试程序路径
            string testApp = Process.GetCurrentProcess().MainModule?.FileName
                ?? throw new Exception("无法获取当前程序路径");

            // 1. 检查规则是否已存在
            var (existsIn, _) = await _fw.CheckRuleExistsAsync($"{TEST_PREFIX}Program_In");
            var (existsOut, _) = await _fw.CheckRuleExistsAsync($"{TEST_PREFIX}Program_Out");

            if (!existsIn)
            {
                // 2. 添加入站规则
                var (inSuccess, inMessage) = await _fw.AddInboundProgramRuleAsync(
                    $"{TEST_PREFIX}Program_In",
                    testApp
                );
                Console.WriteLine($"添加入站程序规则: {inMessage}");
            }

            if (!existsOut)
            {
                // 3. 添加出站规则
                var (outSuccess, outMessage) = await _fw.AddOutboundProgramRuleAsync(
                    $"{TEST_PREFIX}Program_Out",
                    testApp
                );
                Console.WriteLine($"添加出站程序规则: {outMessage}");
            }

            // 4. 验证规则添加成功
            (existsIn, _) = await _fw.CheckRuleExistsAsync($"{TEST_PREFIX}Program_In");
            (existsOut, _) = await _fw.CheckRuleExistsAsync($"{TEST_PREFIX}Program_Out");
            Console.WriteLine($"规则验证: 入站={existsIn}, 出站={existsOut}");
        }

        private async Task TestPortRules()
        {
            Console.WriteLine("\n=== 测试端口规则 ===");

            // 1. 检查规则是否存在
            var (existsTcp, _) = await _fw.CheckRuleExistsAsync($"{TEST_PREFIX}Port_TCP");
            var (existsUdp, _) = await _fw.CheckRuleExistsAsync($"{TEST_PREFIX}Port_UDP");

            if (!existsTcp)
            {
                // 2. 添加TCP端口规则
                var (tcpSuccess, tcpMessage) = await _fw.AddPortRuleAsync(
                    $"{TEST_PREFIX}Port_TCP",
                    8080,
                    isInbound: true,
                    protocol: "TCP"
                );
                Console.WriteLine($"添加TCP端口规则: {tcpMessage}");
            }

            if (!existsUdp)
            {
                // 3. 添加UDP端口规则
                var (udpSuccess, udpMessage) = await _fw.AddPortRuleAsync(
                    $"{TEST_PREFIX}Port_UDP",
                    8081,
                    isInbound: true,
                    protocol: "UDP"
                );
                Console.WriteLine($"添加UDP端口规则: {udpMessage}");
            }

            // 4. 验证规则添加成功
            (existsTcp, _) = await _fw.CheckRuleExistsAsync($"{TEST_PREFIX}Port_TCP");
            (existsUdp, _) = await _fw.CheckRuleExistsAsync($"{TEST_PREFIX}Port_UDP");
            Console.WriteLine($"规则验证: TCP={existsTcp}, UDP={existsUdp}");
        }

        private async Task TestIPRules()
        {
            Console.WriteLine("\n=== 测试IP规则 ===");

            // 1. 检查规则是否存在
            var (existsRemote, _) = await _fw.CheckRuleExistsAsync($"{TEST_PREFIX}IP_Remote");
            var (existsLocal, _) = await _fw.CheckRuleExistsAsync($"{TEST_PREFIX}IP_Local");

            if (!existsRemote)
            {
                // 2. 添加远程IP规则
                var (remoteSuccess, remoteMessage) = await _fw.AddRemoteIPRuleAsync(
                    $"{TEST_PREFIX}IP_Remote",
                    "192.168.1.0/24",
                    isInbound: true,
                    allow: true
                );
                Console.WriteLine($"添加远程IP规则: {remoteMessage}");
            }

            if (!existsLocal)
            {
                // 3. 添加本地IP规则
                var (localSuccess, localMessage) = await _fw.AddLocalIPRuleAsync(
                    $"{TEST_PREFIX}IP_Local",
                    "10.0.0.1-10.0.0.255",
                    isInbound: true,
                    allow: true
                );
                Console.WriteLine($"添加本地IP规则: {localMessage}");
            }

            // 4. 验证规则添加成功
            (existsRemote, _) = await _fw.CheckRuleExistsAsync($"{TEST_PREFIX}IP_Remote");
            (existsLocal, _) = await _fw.CheckRuleExistsAsync($"{TEST_PREFIX}IP_Local");
            Console.WriteLine($"规则验证: 远程IP={existsRemote}, 本地IP={existsLocal}");
        }

        private async Task TestRuleManagement()
        {
            Console.WriteLine("\n=== 测试规则管理 ===");

            // 1. 获取所有规则
            var (listSuccess, rules, listMessage) = await _fw.GetRulesAsync();
            if (listSuccess)
            {
                var testRules = rules.Where(r => r.StartsWith(TEST_PREFIX)).ToList();
                Console.WriteLine($"找到 {testRules.Count} 条测试规则:");
                foreach (var rule in testRules)
                {
                    Console.WriteLine($"- {rule}");
                }
            }

            // 2. 测试启用/禁用规则
            var testRule = $"{TEST_PREFIX}Program_In";
            var (exists, _) = await _fw.CheckRuleExistsAsync(testRule);
            if (exists)
            {
                // 禁用规则
                var (disableSuccess, disableMessage) = await _fw.SetRuleEnabledAsync(testRule, false);
                Console.WriteLine($"禁用规则 {testRule}: {disableMessage}");

                // 启用规则
                var (enableSuccess, enableMessage) = await _fw.SetRuleEnabledAsync(testRule, true);
                Console.WriteLine($"启用规则 {testRule}: {enableMessage}");
            }
            else
            {
                Console.WriteLine($"规则 {testRule} 不存在，跳过启用/禁用测试");
            }
        }

        private async Task TestPolicyManagement()
        {
            Console.WriteLine("\n=== 测试策略管理 ===");

            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            string backupFile = Path.Combine(desktop, "firewall_backup_ps.xml");

            try
            {
                // 1. 导出策略
                var (exportSuccess, exportMessage) = await _fw.ExportPolicyAsync(backupFile);
                Console.WriteLine($"导出策略: {exportMessage}");

                if (exportSuccess && File.Exists(backupFile))
                {
                    // 2. 导入策略
                    var (importSuccess, importMessage) = await _fw.ImportPolicyAsync(backupFile);
                    Console.WriteLine($"导入策略: {importMessage}");

                    // 3. 清理备份文件
                    File.Delete(backupFile);
                    Console.WriteLine("已删除策略备份文件");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"策略管理测试失败: {ex.Message}");
            }
        }

        private async Task CleanupTestRules()
        {
            Console.WriteLine("\n=== 清理测试规则 ===");

            try
            {
                // 1. 获取所有测试规则
                var (success, rules, _) = await _fw.GetRulesAsync();
                if (!success) return;

                var testRules = rules.Where(r => r.StartsWith(TEST_PREFIX)).ToList();
                Console.WriteLine($"找到 {testRules.Count} 条测试规则需要清理");

                // 2. 删除所有测试规则
                foreach (var rule in testRules)
                {
                    var (deleteSuccess, deleteMessage) = await _fw.DeleteRuleAsync(rule);
                    Console.WriteLine($"删除规则 {rule}: {deleteMessage}");
                }

                // 3. 验证清理结果
                (success, rules, _) = await _fw.GetRulesAsync();
                var remainingRules = rules.Where(r => r.StartsWith(TEST_PREFIX)).ToList();
                if (remainingRules.Any())
                {
                    Console.WriteLine($"警告: 仍有 {remainingRules.Count} 条测试规则未清理");
                }
                else
                {
                    Console.WriteLine("所有测试规则已清理完成");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"清理测试规则时发生错误: {ex.Message}");
            }
        }
    }
}
