require 'chef/mixin/shell_out'
include Chef::Mixin::PowershellOut
include Chef::Mixin::ShellOut

module Mutools
	module Helper
		def ssh_user_set?(ssh_user_guard)
			cmd = powershell_out("$sshd_service = Get-WmiObject Win32_service | Where-Object {$_.Name -eq 'sshd'}; $sshd_service.startname -eq '#{ssh_user_guard}'")
			return cmd.stdout.match(/True/)
		end
	end
end

Chef::Recipe.send(:include, Mutools::Helper)
Chef::Resource.send(:include, Mutools::Helper)
Chef::Provider.send(:include, Mutools::Helper)
