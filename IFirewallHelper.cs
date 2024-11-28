using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Firewall
{
    public interface IFirewallHelper
    {
        bool IsAdministrator { get; }

        #region Program Rules
        Task<(bool success, string message)> AddInboundProgramRuleAsync(string ruleName, string programPath);
        Task<(bool success, string message)> AddOutboundProgramRuleAsync(string ruleName, string programPath);
        #endregion

        #region Port Rules
        Task<(bool success, string message)> AddPortRuleAsync(string ruleName, int port, bool isInbound = true, string protocol = "TCP");
        #endregion

        #region IP Rules
        Task<(bool success, string message)> AddRemoteIPRuleAsync(string ruleName, string remoteIP, bool isInbound = true, bool allow = true);
        Task<(bool success, string message)> AddLocalIPRuleAsync(string ruleName, string localIP, bool isInbound = true, bool allow = true);
        #endregion

        #region Rule Management
        Task<(bool success, string message)> DeleteRuleAsync(string ruleName);
        Task<(bool success, List<string> rules, string message)> GetRulesAsync();
        Task<(bool exists, string message)> CheckRuleExistsAsync(string ruleName);
        Task<(bool success, string message)> SetRuleEnabledAsync(string ruleName, bool enabled);
        #endregion

        #region Firewall Policy
        Task<(bool success, string message)> ExportPolicyAsync(string filePath);
        Task<(bool success, string message)> ImportPolicyAsync(string filePath);
        Task<(bool success, string message)> ResetPolicyAsync();
        #endregion
    }
}
