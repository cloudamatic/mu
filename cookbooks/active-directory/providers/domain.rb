include Chef::Mixin::PowershellOut

def whyrun_supported?
	true
end

action :create do
	install_ad_features
	elevate_remote_access
	set_computer_name
	configure_network_interface
	create_domain
	configure_domain
end

action :delete do
	delete_domain
end

def load_current_resource
	@current_resource = @new_resource.dup
	@current_resource.exists = domain_exists?(@new_resource.name)
end

case node.platform
when "windows"
	def admin_creds
		"(New-Object System.Management.Automation.PSCredential('#{new_resource.netbios_name}\\#{new_resource.domain_admin_user}', (ConvertTo-SecureString '#{new_resource.domain_admin_password}' -AsPlainText -Force)))"
	end

	def configure_network_interface
		if dhcp_enabled?
			code =<<-EOH
				$netipconfig = Get-NetIPConfiguration
				$netadapter = Get-NetAdapter
				$netipaddress = $netadapter | Get-NetIPAddress -AddressFamily IPv4
				$netadapter | Set-NetIPInterface -Dhcp Disabled
				$netadapter | New-NetIPAddress -IPAddress #{node.ec2.private_ip_address} -PrefixLength $netipaddress.PrefixLength -DefaultGateway $netipconfig.IPv4DefaultGateway.NextHop
			EOH
			cmd = powershell_out(code).run_command
		end

		cmd = powershell_out("Get-NetAdapter | Set-DnsClientServerAddress -PassThru -ServerAddresses #{new_resource.existing_dc_ips.join(",")}").run_command if !new_resource.existing_dc_ips.empty?
	end

	def install_ad_features
		cmd = powershell_out("Install-WindowsFeature AD-Domain-Services, rsat-adds, FS-DFS-Replication, RSAT-DFS-Mgmt-Con -IncludeAllSubFeature").run_command
	end

	def create_domain_admin_user
		unless domain_admin_user_exist?
			code =<<-EOH
				New-ADUser -Name #{new_resource.domain_admin_user} -UserPrincipalName #{new_resource.domain_admin_user}@#{new_resource.dns_name} -AccountPassword (convertto-securestring '#{new_resource.domain_admin_password}' -asplaintext -force) -Enabled $true -PasswordNeverExpires $true
				Add-ADGroupMember 'Domain Admins' -Members #{new_resource.domain_admin_user}
			EOH
			cmd = powershell_out(code).run_command
		end
	end

	#This will restart the OS. The OS needs to be restated after creating the domain
	def create_domain
		unless domain_exists?
			require 'chef/win32/version'
			version = Chef::ReservedNames::Win32::Version.new
			
			if version.windows_server_2012?
				code =<<-EOH
					$DCPromoFile = @"
					[DCINSTALL]
					InstallDNS=yes
					NewDomain=forest
					NewDomainDNSName=#{new_resource.dns_name}
					DomainNetBiosName=#{new_resource.netbios_name}
					SiteName=#{new_resource.site_name}
					ReplicaorNewDomain=domain
					ForestLevel=5
					DomainLevel=5
					ConfirmGC=Yes
					SafeModeAdminPassword="#{new_resource.restore_mode_password}"
					RebootonCompletion=Yes
					"@
					$DCPromoFile | out-file c:/dcpromoanswerfile.txt -Force
					dcpromo.exe /unattend:c:/dcpromoanswerfile.txt
				EOH
				cmd = powershell_out(code).run_command
			elsif version.windows_server_2012_r2?
				cmd = powershell_out("Install-ADDSForest -DomainName #{new_resource.dns_name} -SafeModeAdministratorPassword (convertto-securestring '#{new_resource.restore_mode_password}' -asplaintext -force) -DomainMode Win2012R2 -DomainNetbiosName #{new_resource.netbios_name} -ForestMode Win2012R2 -Confirm:$false -Force").run_command
		
				Chef::Application.fatal!("Failed to create Active Directory Domain #{new_resource.dns_name}") if cmd.exitstatus != 0
				Chef::Application.fatal!("Active Directory Domain #{new_resource.dns_name} was created, rebooting. Will have to run chef again")
			end
		end
	end

	def rename_default_site
		powershell_script "Rename AD site to #{new_resource.site_name}" do
			guard_interpreter :powershell_script
			code "Get-ADObject -Credential #{admin_creds} -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -filter {Name -eq 'Default-First-Site-Name'} | Rename-ADObject -Credential #{admin_creds} -NewName #{new_resource.site_name}"
			not_if "(Get-ADReplicationSite).name -eq '#{new_resource.site_name}'"
			sensitive true
		end
	end

	def configure_replication
		new_resource.sites.each { |site|
			if site[:name] != new_resource.site_name
				powershell_script "Creating AD ReplicationSite #{site[:name]}" do
					guard_interpreter :powershell_script
					code "New-ADReplicationSite #{site[:name]} -Credential #{admin_creds}"
					not_if "(Get-ADObject -Credential #{admin_creds} -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -filter {Name -eq '#{site[:name]}'}).name -eq '#{site[:name]}'"
					sensitive true
				end

				powershell_script "Configure AD Replication between AD sites and" do
					guard_interpreter :powershell_script
					code "Get-ADReplicationSiteLink -Credential #{admin_creds} -Filter * | Set-ADReplicationSiteLink -Credential #{admin_creds} -SitesIncluded @{add='#{site[:name]}'} -ReplicationFrequencyInMinutes 15"
					sensitive true
				end
			end

			powershell_script "Create AD Replication subnet #{site[:ip_block]} for site #{site[:name]}" do
				guard_interpreter :powershell_script
				code "New-ADReplicationSubnet -Credential #{admin_creds} -Name #{site[:ip_block]} -Site #{site[:name]}"
				not_if "(Get-ADReplicationSubnet -Credential #{admin_creds} -Identity #{site[:ip_block]}).name -eq '#{site[:ip_block]}'"
				sensitive true
			end
		}
	end

	def set_replication_static_ports
		cmd = powershell_out("New-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters -Name 'TCP/IP Port' -PropertyType DWord -Force -Value #{new_resource.ntds_static_port}").run_command unless replication_tcp_port_set?	
		cmd = powershell_out("New-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTFRS\\Parameters -Name 'RPC TCP/IP Port Assignment' -PropertyType DWord -Force -Value #{new_resource.ntfrs_static_port}").run_command unless replication_rpc_port_set?
		cmd = powershell_out("New-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters -Name 'DCTcpipPort' -PropertyType DWord -Force -Value #{new_resource.netlogon_static_port}").run_command unless netlogon_port_set?
		cmd = powershell_out("Set-DfsrServiceConfiguration -RPCPort #{new_resource.dfsr_static_port}").run_command unless dfsr_rpc_port_set?
	end
	
	def set_computer_name
		# Theoretically this should have been done for us already, but let's cover the oddball cases.
		if node.hostname != new_resource.computer_name
			cmd = powershell_out("Rename-Computer -NewName '#{new_resource.computer_name}' -Force -PassThru -Restart -DomainCredential #{admin_creds}").run_command
			execute "shutdown -r -f -t 0"
		end
	end
	
	def elevate_remote_access
		cmd = powershell_out("New-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name 'LocalAccountTokenFilterPolicy' -PropertyType DWord -Force -Value 1").run_command unless uac_remote_restrictions_enabled?
	end

	def configure_domain
		# Move these to somewhere that makes sense
		powershell_out("Set-Service NTDS -StartupType Automatic").run_command
		powershell_out("Set-Service ADWS -StartupType Automatic").run_command

		set_computer_name
		create_domain_admin_user
		rename_default_site
		configure_replication
		set_replication_static_ports
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
when "centos", "redhat"
	# To do: Do Active Directory on Linux
else
	Chef::Log.info("Unsupported platform #{node.platform}")
end
