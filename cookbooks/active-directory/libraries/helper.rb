
require 'chef/mixin/shell_out'
include Chef::Mixin::PowershellOut
include Chef::Mixin::ShellOut

module Activedirecotry
	module Helper
    # extend Chef::Mixin::ShellOut

		def in_domain?
			cmd = powershell_out("((Get-WmiObject win32_computersystem).partofdomain -eq $true)").run_command
			return cmd.stdout.match(/True/)
		end

		def is_domain_controller?
			cmd = powershell_out("(Get-ADDomainController).name -eq '#{new_resource.computer_name}'").run_command
			return cmd.stdout.match(/True/)
		end

		def dhcp_enabled?
			cmd = powershell_out("(Get-NetIPInterface -InterfaceAlias Ethernet* -AddressFamily IPv4).Dhcp -eq 'Enabled'").run_command
			return cmd.stdout.match(/True/)
		end

		def domain_exists?
			cmd = powershell_out("(Get-ADDomain).DNSRoot -eq '#{new_resource.dns_name}'").run_command
			return cmd.stdout.match(/True/)
		end

		def replication_rpc_port_set?
			cmd = powershell_out("(Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTFRS\\Parameters 'RPC TCP/IP Port Assignment').'RPC TCP/IP Port Assignment' -eq \"#{new_resource.ntfrs_static_port}\"").run_command
			return cmd.stdout.match(/True/)
		end

		def replication_tcp_port_set?
			cmd = powershell_out("(Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters 'TCP/IP Port').'TCP/IP Port' -eq \"#{new_resource.ntds_static_port}\"").run_command
			return cmd.stdout.match(/True/)
		end

		def dfsr_rpc_port_set?
			cmd = powershell_out("(Get-DfsrServiceConfiguration).RPCPort -eq #{new_resource.dfsr_static_port}").run_command
			return cmd.stdout.match(/True/)
		end

		def netlogon_port_set?
			cmd = powershell_out("(Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters 'DCTcpipPort').'DCTcpipPort' -eq \"#{new_resource.netlogon_static_port}\"").run_command
			return cmd.stdout.match(/True/)
		end

		def domain_admin_user_exist?
			cmd = powershell_out("(Get-ADUser -Filter {Name -eq '#{new_resource.domain_admin_user}'}).Name -eq '#{new_resource.domain_admin_user}'").run_command
			return cmd.stdout.match(/True/)
		end

		def uac_remote_restrictions_enabled?
			cmd = powershell_out("(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System 'LocalAccountTokenFilterPolicy').'LocalAccountTokenFilterPolicy' -eq 1").run_command
			return cmd.stdout.match(/True/)
		end
	end
end
