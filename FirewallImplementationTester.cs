using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace Firewall
{
    public class FirewallImplementationTester
    {
        private readonly FirewallTester _netshTester;
        private readonly FirewallPSTester _psTester;
        private readonly StringBuilder _log;
        private readonly string _currentExe;

        public FirewallImplementationTester()
        {
            _netshTester = new FirewallTester();
            _psTester = new FirewallPSTester();
            _log = new StringBuilder();
            // 获取当前控制台程序路径
            _currentExe = Process.GetCurrentProcess().MainModule?.FileName
                ?? throw new Exception("无法获取当前程序路径");
        }

        public async Task RunComparisonTests()
        {
            LogMessage($"开始防火墙实现对比测试...\n");
            LogMessage($"测试程序路径: {_currentExe}\n");

            try
            {
                // 1. 测试 Netsh 实现
                LogMessage("=== Netsh 实现测试 ===");
                await RunNetshTests();

                // 2. 测试 PowerShell 实现
                LogMessage("\n=== PowerShell 实现测试 ===");
                await RunPowerShellTests();

                // 3. 性能对比测试
                LogMessage("\n=== 性能对比测试 ===");
                await RunPerformanceTests();

                LogMessage("\n所有对比测试完成!");
            }
            catch (Exception ex)
            {
                LogMessage($"\n测试过程中发生错误: {ex.Message}");
            }
        }

        private async Task RunNetshTests()
        {
            var sw = Stopwatch.StartNew();
            await _netshTester.RunAllTests();
            sw.Stop();
            LogMessage($"\nNetsh 测试总耗时: {sw.ElapsedMilliseconds}ms");
        }

        private async Task RunPowerShellTests()
        {
            var sw = Stopwatch.StartNew();
            await _psTester.RunAllTests();
            sw.Stop();
            LogMessage($"\nPowerShell 测试总耗时: {sw.ElapsedMilliseconds}ms");
        }

        private async Task RunPerformanceTests()
        {
            // 1. 规则添加性能
            await TestRuleAdditionPerformance();

            // 2. 规则查询性能
            await TestRuleQueryPerformance();

            // 3. 规则删除性能
            await TestRuleDeletionPerformance();
        }

        private async Task TestRuleAdditionPerformance()
        {
            LogMessage("\n规则添加性能测试:");

            // Netsh
            var swNetsh = Stopwatch.StartNew();
            var (successNetsh, messageNetsh) = await _netshTester._fw.AddInboundProgramRuleAsync(
                "PERF_TEST_NETSH",
                _currentExe
            );
            swNetsh.Stop();
            LogMessage($"Netsh 添加规则: {swNetsh.ElapsedMilliseconds}ms ({messageNetsh})");

            // PowerShell
            var swPs = Stopwatch.StartNew();
            var (successPs, messagePs) = await _psTester._fw.AddInboundProgramRuleAsync(
                "PERF_TEST_PS",
                _currentExe
            );
            swPs.Stop();
            LogMessage($"PowerShell 添加规则: {swPs.ElapsedMilliseconds}ms ({messagePs})");

            // 清理测试规则
            await _netshTester._fw.DeleteRuleAsync("PERF_TEST_NETSH");
            await _psTester._fw.DeleteRuleAsync("PERF_TEST_PS");
        }

        private async Task TestRuleQueryPerformance()
        {
            LogMessage("\n规则查询性能测试:");

            // Netsh
            var swNetsh = Stopwatch.StartNew();
            var (successNetsh, rulesNetsh, messageNetsh) = await _netshTester._fw.GetRulesAsync();
            swNetsh.Stop();
            LogMessage($"Netsh 查询规则: {swNetsh.ElapsedMilliseconds}ms (找到 {rulesNetsh.Count} 条规则)");

            // PowerShell
            var swPs = Stopwatch.StartNew();
            var (successPs, rulesPs, messagePs) = await _psTester._fw.GetRulesAsync();
            swPs.Stop();
            LogMessage($"PowerShell 查询规则: {swPs.ElapsedMilliseconds}ms (找到 {rulesPs.Count} 条规则)");
        }

        private async Task TestRuleDeletionPerformance()
        {
            LogMessage("\n规则删除性能测试:");

            // 先添加测试规则
            await _netshTester._fw.AddInboundProgramRuleAsync("PERF_DEL_NETSH", _currentExe);
            await _psTester._fw.AddInboundProgramRuleAsync("PERF_DEL_PS", _currentExe);

            // Netsh
            var swNetsh = Stopwatch.StartNew();
            var (successNetsh, messageNetsh) = await _netshTester._fw.DeleteRuleAsync("PERF_DEL_NETSH");
            swNetsh.Stop();
            LogMessage($"Netsh 删除规则: {swNetsh.ElapsedMilliseconds}ms ({messageNetsh})");

            // PowerShell
            var swPs = Stopwatch.StartNew();
            var (successPs, messagePs) = await _psTester._fw.DeleteRuleAsync("PERF_DEL_PS");
            swPs.Stop();
            LogMessage($"PowerShell 删除规则: {swPs.ElapsedMilliseconds}ms ({messagePs})");
        }

        private void LogMessage(string message)
        {
            _log.AppendLine(message);
            Console.WriteLine(message);
        }

        public string GetTestReport()
        {
            return _log.ToString();
        }
    }
}
