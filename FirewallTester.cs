using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Firewall
{
    using System.Text;

    class FirewallTester
    {
        public readonly FirewallHelper _fw;
        private const string TEST_PREFIX = "TEST_";

        public FirewallTester()
        {
            _fw = FirewallHelper.Instance;
            Console.OutputEncoding = Encoding.UTF8;
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
                Console.WriteLine("开始防火墙规则测试...\n");

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
            string testApp = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName
                ?? throw new Exception("无法获取当前程序路径");

            // 1. 添加入站规则
            var (inSuccess, inMessage) = await _fw.AddInboundProgramRuleAsync(
                $"{TEST_PREFIX}Program_In",
                testApp
            );
            Console.WriteLine($"添加入站程序规则: {inMessage}");

            // 2. 添加出站规则
            var (outSuccess, outMessage) = await _fw.AddOutboundProgramRuleAsync(
                $"{TEST_PREFIX}Program_Out",
                testApp
            );
            Console.WriteLine($"添加出站程序规则: {outMessage}");
        }

        private async Task TestPortRules()
        {
            Console.WriteLine("\n=== 测试端口规则 ===");

            // 1. 添加TCP端口规则
            var (tcpSuccess, tcpMessage) = await _fw.AddPortRuleAsync(
                $"{TEST_PREFIX}Port_TCP",
                8080,
                isInbound: true,
                protocol: "TCP"
            );
            Console.WriteLine($"添加TCP端口规则: {tcpMessage}");

            // 2. 添加UDP端口规则
            var (udpSuccess, udpMessage) = await _fw.AddPortRuleAsync(
                $"{TEST_PREFIX}Port_UDP",
                8081,
                isInbound: true,
                protocol: "UDP"
            );
            Console.WriteLine($"添加UDP端口规则: {udpMessage}");
        }

        private async Task TestIPRules()
        {
            Console.WriteLine("\n=== 测试IP规则 ===");

            // 1. 添加远程IP规则
            var (remoteSuccess, remoteMessage) = await _fw.AddRemoteIPRuleAsync(
                $"{TEST_PREFIX}IP_Remote",
                "192.168.1.0/24",
                isInbound: true,
                allow: true
            );
            Console.WriteLine($"添加远程IP规则: {remoteMessage}");

            // 2. 添加本地IP规则
            var (localSuccess, localMessage) = await _fw.AddLocalIPRuleAsync(
                $"{TEST_PREFIX}IP_Local",
                "10.0.0.1-10.0.0.255",
                isInbound: true,
                allow: true
            );
            Console.WriteLine($"添加本地IP规则: {localMessage}");
        }

        private async Task TestRuleManagement()
        {
            Console.WriteLine("\n=== 测试规则管理 ===");

            // 1. 获取所有规则
            var (listSuccess, rules, listMessage) = await _fw.GetRulesAsync();
            if (listSuccess)
            {
                Console.WriteLine("当前测试规则:");
                foreach (var rule in rules.Where(r => r.StartsWith(TEST_PREFIX)))
                {
                    Console.WriteLine($"- {rule}");
                }
            }

            // 2. 测试启用/禁用规则
            var testRule = $"{TEST_PREFIX}Program_In";
            var (disableSuccess, disableMessage) = await _fw.SetRuleEnabledAsync(testRule, false);
            Console.WriteLine($"禁用规则 {testRule}: {disableMessage}");

            var (enableSuccess, enableMessage) = await _fw.SetRuleEnabledAsync(testRule, true);
            Console.WriteLine($"启用规则 {testRule}: {enableMessage}");
        }

        private async Task TestPolicyManagement()
        {
            Console.WriteLine("\n=== 测试策略管理 ===");

            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            string backupFile = Path.Combine(desktop, "firewall_backup.wfw");

            // 1. 导出策略
            var (exportSuccess, exportMessage) = await _fw.ExportPolicyAsync(backupFile);
            Console.WriteLine($"导出策略: {exportMessage}");

            if (exportSuccess)
            {
                // 2. 导入策略
                var (importSuccess, importMessage) = await _fw.ImportPolicyAsync(backupFile);
                Console.WriteLine($"导入策略: {importMessage}");

                // 清理备份文件
                if (File.Exists(backupFile))
                {
                    File.Delete(backupFile);
                    Console.WriteLine("已删除策略备份文件");
                }
            }
        }

        private async Task CleanupTestRules()
        {
            Console.WriteLine("\n=== 清理测试规则 ===");

            // 获取所有测试规则
            var (success, rules, _) = await _fw.GetRulesAsync();
            if (!success) return;

            // 删除所有测试规则
            foreach (var rule in rules.Where(r => r.StartsWith(TEST_PREFIX)))
            {
                var (deleteSuccess, deleteMessage) = await _fw.DeleteRuleAsync(rule);
                Console.WriteLine($"删除规则 {rule}: {deleteMessage}");
            }
        }
    }
}
