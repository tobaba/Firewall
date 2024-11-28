// See https://aka.ms/new-console-template for more information
using Firewall;
using System.Text;
// 在使用 GB2312 之前注册编码提供程序
Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
//var tester = new FirewallTester();
//await tester.RunAllTests();

//Console.WriteLine("\n按任意键退出...");
//Console.ReadKey();

//var testerPs = new FirewallPSTester();
//await testerPs.RunAllTests();
//Console.WriteLine("\n按任意键退出...");
//Console.ReadKey();

Console.OutputEncoding = Encoding.UTF8;

try
{
    var tester = new FirewallImplementationTester();
    await tester.RunComparisonTests();

    // 保存测试报告
    var reportPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        $"FirewallTest_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
    );
    File.WriteAllText(reportPath, tester.GetTestReport());
    Console.WriteLine($"\n测试报告已保存到: {reportPath}");
}
catch (Exception ex)
{
    Console.WriteLine($"\n测试失败: {ex.Message}");
}

Console.WriteLine("\n按任意键退出...");
Console.ReadKey();