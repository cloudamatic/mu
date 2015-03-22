
require 'chef/mixin/shell_out'

module WinFW
  class Helper
    extend Chef::Mixin::ShellOut

    def self.firewall_rule_enabled?(rule_name=nil)
      cmd = shell_out("netsh advfirewall firewall show rule \"#{rule_name}\"")
      cmd.stderr.empty? && (cmd.stdout =~ /Enabled:\s*Yes/i)
    end

  end
end