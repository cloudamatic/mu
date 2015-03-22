#
# Author:: John Stange (<john.stange@eglobaltech.com>)
# Cookbook Name:: mu-tools
# Provider:: active_directory_domain
#
# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#     http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

include Chef::Mixin::PowershellOut


# Support whyrun
def whyrun_supported?
	true
end

# Helper to notify our Chef node structure that we've initialized this node as
# a controller. While we're in there, return the name of the node class we
# belong to.
def update_chef_node_struct
	node.deployment.servers.each_pair { |node_class, nodes|
		nodes.each_pair { |node_name, data|
			if node_name == Chef::Config[:node_name]
				node.normal.deployment.servers[node_class][node_name]['activedirectory_dc_initialized'] = true
				node.save
				return node_class
			end
		}
	}
	return nil
end


action :create do
	install_ad_features
	create_ad_domain if !node_is_dc?
	gpo_disable_uac
	configure_ad_domain
#	configure_ad_replication
	Chef::Log.info "Finalizing creation of Active Directory Domain #{new_resource.name}"
	node_class = update_chef_node_struct
	node.normal.deployment.activedirectory_domain_created = node_class
	node.save
#	if @current_resource.exists == true
#		Chef::Log.info "Domain #{ @new_resource } already exists - looking to see if we need to do anything else"
#		#We need to create the user after the domain exists
#		configure_ad_domain
#		configure_ad_replication
#	else
#		converge_by("Create #{ @new_resource }") do
#		end
#	end
end

action :add_controller do
	install_ad_features
	set_ad_dns_servers_address
	add_computer_to_domain
	promote_to_controller if !node_is_dc?
	set_ad_replication_static_ports
#	configure_ad_replication
	update_chef_node_struct
end

action :join do
	install_ad_features
	set_ad_dns_servers_address
	add_computer_to_domain
end

def admin_creds
	"(New-Object System.Management.Automation.PSCredential('#{new_resource.netbios_name}\\#{new_resource.domain_admin_user}', (ConvertTo-SecureString '#{new_resource.domain_admin_password}' -AsPlainText -Force)))"
end

def promote_to_controller
	# XXX this wants a guard
	powershell_script "Promoting to domain controller in #{new_resource.dns_name} with domain admin #{new_resource.netbios_name}\\#{new_resource.domain_admin_user}" do
		guard_interpreter :powershell_script
		code <<-EOH
			Import-Module ADDSDeployment ; Install-ADDSDomainController -InstallDns -DomainName #{new_resource.dns_name} -Credential #{admin_creds} -SafeModeAdministratorPassword (convertto-securestring '#{new_resource.safe_mode_pw}' -asplaintext -force) -Force -Confirm:$false
		EOH
		not_if "(Get-ADDomainController).name -eq '#{new_resource.computer_name}'"
		sensitive true
	end
	# XXX it'll reboot, too...
end

def node_in_a_domain?
	cmd = powershell_out("((Get-WmiObject win32_computersystem).partofdomain -eq $true)")
	cmd.run_command
	if cmd.exitstatus == 0 and !cmd.stdout.empty? and cmd.stdout.match(/True/i)
		return true
	else
		return false
	end
	return false
end

def add_computer_to_domain
	# XXX or maybe this should use ad_domain_is(new_resource.name)
	if !node_in_a_domain?
		powershell_script "Add computer #{new_resource.computer_name} to domain #{new_resource.dns_name}" do
			code <<-EOH
				Add-Computer -DomainName #{new_resource.dns_name} -Credential #{admin_creds} -Restart -PassThru
			EOH
			sensitive true
		end
#		sleep 10
#		Chef::Application.fatal!("Just added #{new_resource.computer_name} to AD domain, now rebooting. Will need to invoke Chef again.")
	end
end

def load_current_resource
  @current_resource = @new_resource.dup

	# XXX strictly speaking we should look for differences in attributes vs.
	# reality and offer to reconfigure. In practice this is a rabbit hole, where
	# AD is concerned, and we maybe don't care that much.
	@current_resource.exists = ad_domain_is(@new_resource.name)
	# @current_resource.dhcp_disabled = dhcp_disabled?
	# @current_resource.domain_admin_user_exist = domain_admin_user_exist?
end

def ad_domain_is(domain)	
	cmd = powershell_out("Import-Module ADDSDeployment ; Get-ADDomain")
#	cmd = powershell_out("(Get-ADDomain).DNSRoot")
	cmd.run_command
	if cmd.exitstatus == 0 and !cmd.stdout.empty? and cmd.stdout.match(/#{domain}/)
		return true
	else
		return false
	end
	return false
end

def node_is_dc?
	cmd = powershell_out("(Get-ADDomainController).name -eq '#{new_resource.computer_name}'")
	cmd.run_command
	log "(Get-ADDomainController).name -eq '#{new_resource.computer_name}':\n#{cmd.stdout}\n#{cmd.stderr}"
	if cmd.stdout.match(/True/)
		return true
	else
		return false
	end
	return false
end

def dhcp_disabled?
	cmd = powershell_out("(Get-NetIPAddress | ?{$_.IpAddress -eq (Get-NetIPConfiguration).IPv4Address.IpAddress}).PrefixOrigin")
	cmd.run_command
	if cmd.stdout.chop == 'Manual'
		return true
	end
	return false
end

def repl_rpc_port_set?
	cmd = powershell_out("(Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTFRS\\Parameters 'RPC TCP/IP Port Assignment').'RPC TCP/IP Port Assignment' -eq \"#{new_resource.ntfrs_static_port}\"")
	cmd.run_command
	if cmd.stdout.match(/True/)
		return true
	else
		return false
	end
	return false
end

def repl_tcp_port_set?
	cmd = powershell_out("(Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters 'TCP/IP Port').'TCP/IP Port' -eq \"#{new_resource.ntds_static_port}\"")
	cmd.run_command
	if cmd.stdout.match(/True/)
		return true
	else
		return false
	end
	return false
end

def dfsr_rpc_port_set?
	cmd = powershell_out("(Get-DfsrServiceConfiguration).RPCPort -eq #{new_resource.dfsr_static_port}")
	cmd.run_command
	if cmd.stdout.match(/True/)
		return true
	else
		return false
	end 
	return false
end

def domain_admin_user_exist?
	cmd = powershell_out("(Get-ADUser -Filter {Name -eq '#{new_resource.domain_admin_user}'}).Name")
	cmd.run_command
	if !cmd.stdout.empty?
		return true
	else
		return false
	end
	return false
end


def uac_disabled_gpo_exist?
	cmd = powershell_out("Get-GPO -name no_uac")
	cmd.run_command
	if !cmd.stdout.empty?
		return true
	else
		return false
	end
	return false
end


#Because this sets a static IP it will have to be run on new instance creation.   
def configure_network_interface
	# if !@current_resource.dhcp_disabled
		powershell_script "Disable DHCP" do
			code <<-EOH
				Import-Module NetAdapter
				$ipconfig = Get-NetIPAddress | ?{$_.IpAddress -eq $netip.IPv4Address.IpAddress}
				if ( $ipconfig.PrefixOrigin -eq "Dhcp" )
				{
					Get-NetAdapter | Set-NetIPInterface -DHCP Disabled
				}
			EOH
		end
		if new_resource.existing_dc_ips.size > 0
			powershell_script "Set DNS to #{new_resource.existing_dc_ips.join(",")}" do
				code <<-EOH
					Import-Module NetTCPIP
					$netip = Get-NetIPConfiguration
					if ( $netip.DNSServer.ServerAddresses -ne "" )
					{	
						Get-NetAdapter | Set-DnsClientServerAddress -PassThru -ServerAddresses #{new_resource.existing_dc_ips.join(",")}
					}
				EOH
			end
		end
	# end
	# @current_resource.dhcp_disabled = true
end

#need to restart OS after renaming and before creating the domain
def rename_computer(name)
	powershell_script "Rename Computer to #{name}" do
		guard_interpreter :powershell_script
		not_if "$env:computername -eq '#{name}'"
#		code "if ($env:computername -ne '#{name}') {Rename-Computer -NewName '#{name}' -Force -PassThru -Restart}"
		code "Rename-Computer -NewName '#{name}' -Force -PassThru -Restart"
	end
end

#need to restart OS after installing the features and before creating the domain  
def install_ad_features
	configure_network_interface
	if !new_resource.computer_name.nil?
		if new_resource.computer_name.length > 15 or new_resource.computer_name.empty?
			Chef::Log.warn "Requested invalid computer name #{new_resource.computer_name}"
		else
			rename_computer(new_resource.computer_name)
		end
	end
	cmd = powershell_out("Import-Module ServerManager ; Install-WindowsFeature AD-Domain-Services, rsat-adds, FS-DFS-Replication, RSAT-DFS-Mgmt-Con -IncludeAllSubFeature")
	cmd.run_command
# XXX This spews errors, but somehow succeeds. Windows.
#	if cmd.exitstatus != 0
#		Chef::Application.fatal!("FAILED: Install-WindowsFeature AD-Domain-Services, rsat-adds, FS-DFS-Replication, RSAT-DFS-Mgmt-Con, ADFS-Federation, ADLDS -IncludeAllSubFeature\n#{cmd.stderr}\n#{cmd.stdout}")
#	end
end

def create_domain_admin_user
	if domain_admin_user_exist? == false
		powershell_script "Create Domain Admin User #{new_resource.domain_admin_user}" do
			code <<-EOH
				New-ADUser -Name #{new_resource.domain_admin_user} -UserPrincipalName #{new_resource.domain_admin_user}@#{new_resource.dns_name} -AccountPassword (convertto-securestring '#{new_resource.domain_admin_password}' -asplaintext -force) -Enabled $true -PasswordNeverExpires $true
				Add-ADGroupMember 'Domain Admins' -Members #{new_resource.domain_admin_user}
			EOH
			sensitive true
		end
	end
end

#This will restart the OS. There is probably a flag to disable this. The OS needs to be restated after creating the domain
def create_ad_domain

	if node_is_dc? == false
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
				SafeModeAdminPassword="#{new_resource.safe_mode_pw}"
				RebootonCompletion=Yes
				"@
				$DCPromoFile | out-file c:\dcpromoanswerfile.txt -Force
				dcpromo.exe /unattend:c:\dcpromoanswerfile.txt
			EOH
			cmd = powershell_out(code)
			return true
		elsif version.windows_server_2012_r2?
			cmd = powershell_out("echo $env:PSModulePath ; Import-Module ADDSDeployment ; Install-ADDSForest -DomainName #{new_resource.dns_name} -SafeModeAdministratorPassword (convertto-securestring '#{new_resource.safe_mode_pw}' -asplaintext -force) -DomainMode Win2012R2 -DomainNetbiosName #{new_resource.netbios_name} -ForestMode Win2012R2 -Confirm:$false -Force")
			cmd.run_command
			if cmd.exitstatus != 0
				log "Install-ADDSForest stdout: "+cmd.stdout
				log "Install-ADDSForest stderr: "+cmd.stderr
				Chef::Application.fatal!("FAILED: Import-Module ADDSDeployment ; Install-ADDSForest -DomainName #{new_resource.dns_name} -SafeModeAdministratorPassword (convertto-securestring '#{new_resource.safe_mode_pw}' -asplaintext -force) -DomainMode Win2012R2 -DomainNetbiosName #{new_resource.netbios_name} -ForestMode Win2012R2 -Confirm:$false -Force\n#{cmd.stderr}\n#{cmd.stdout}")
			end
			powershell_script "Set-Service NTDS -StartupType Automatic"
			powershell_script "Set-Service ADWS -StartupType Automatic"
#			node.normal.deployment.servers['ad'][Chef::Config[:node_name]]['activedirectory_domain_created'] = true
#			node.save
			
			Chef::Application.fatal!("Just created AD domain, now rebooting. Will need to invoke Chef again.")
		end
		return true
	end
end

#not running the following
def rename_site
	powershell_script "Rename AD site to #{new_resource.site_name}" do
		guard_interpreter :powershell_script
		code "Get-ADObject -Credential #{admin_creds} -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -filter {Name -eq 'Default-First-Site-Name'} | Rename-ADObject -Credential #{admin_creds} -NewName #{new_resource.site_name}"
		not_if "(Get-ADReplicationSite).name -eq '#{new_resource.site_name}'"
		sensitive true
	end
end

def configure_ad_replication
	new_resource.sites.each do |site|
		#next if site == new_resource.site_name
		if !site['name'].nil? and site['name'] != new_resource.site_name and !site['name'].empty?
			powershell_script "Creating AD ReplicationSite #{site['name']}" do
				guard_interpreter :powershell_script
				code "New-ADReplicationSite #{site['name']} -Credential #{admin_creds}"
				#not_if "(Get-ADReplicationSite).name -eq #{site['name']}"
				not_if "(Get-ADObject -Credential #{admin_creds} -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -filter {Name -eq '#{site['name']}'}).name -eq '#{site['name']}'"
				sensitive true
			end
			powershell_script "Configure AD Replication between AD sites and" do
				guard_interpreter :powershell_script
				code <<-EOH
					Get-ADReplicationSiteLink -Credential #{admin_creds} -Filter * | Set-ADReplicationSiteLink -Credential #{admin_creds} -SitesIncluded @{add='#{site['name']}'} -ReplicationFrequencyInMinutes 15
				EOH
				sensitive true
			end
		end
		powershell_script "Create AD Replication subnet #{site['ip_block']} for site #{site['name']}" do
			guard_interpreter :powershell_script
			code <<-EOH
				New-ADReplicationSubnet -Credential #{admin_creds} -Name #{site['ip_block']} -Site #{site['name']}
			EOH
			not_if "(Get-ADReplicationSubnet -Credential #{admin_creds} -Identity #{site['ip_block']}).name -eq '#{site['ip_block']}'"
			sensitive true
		end
	end

end

def set_ad_dns_servers_address
	powershell_script "Configure instance to use AD DNS servers: #{new_resource.existing_dc_ips.join(", ")}" do
		code <<-EOH
			Get-NetAdapter | Set-DnsClientServerAddress -PassThru -ServerAddresses #{new_resource.existing_dc_ips.join(", ")}
		EOH
	end
end

def set_ad_replication_static_ports
	if !repl_tcp_port_set?
		powershell_script "Set AD replication TCP/IP port to #{new_resource.ntds_static_port}" do
			code <<-EOH
				New-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters -Name 'TCP/IP Port' -PropertyType DWord -Force -Value #{new_resource.ntds_static_port}
			EOH
		end
	end
	if !repl_rpc_port_set?
		powershell_script "Set AD replication RPC port to #{new_resource.ntfrs_static_port}" do
			code <<-EOH
				New-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTFRS\\Parameters -Name 'RPC TCP/IP Port Assignment' -PropertyType DWord -Force -Value #{new_resource.ntfrs_static_port}
			EOH
		end
	end

	if !dfsr_rpc_port_set?
		powershell_script "Set AD dfsr RPC port to #{new_resource.dfsr_static_port}" do
			code <<-EOH
				Set-DfsrServiceConfiguration -RPCPort #{new_resource.dfsr_static_port}
			EOH
		end
	end
			
end

def gpo_disable_uac
	cookbook_file "#{Chef::Config[:file_cache_path]}/gpo_no_uac.zip" do
		source 'gpo_no_uac.zip'
	end

	windows_zipfile "#{Chef::Config[:file_cache_path]}/gpo_no_uac" do
		source "#{Chef::Config[:file_cache_path]}/gpo_no_uac.zip"
		action :unzip
		not_if {::File.exists?("#{Chef::Config[:file_cache_path]}/gpo_no_uac")}
	end
	
	powershell_script "Import GPO to disable UAC" do
		code <<-EOH
			Import-Module GroupPolicy; Import-GPO -BackupId 7C91285C-9713-434E-85FC-E9AF23492E6C -TargetName no_uac -path #{Chef::Config[:file_cache_path]}/gpo_no_uac -CreateIfNeeded
		EOH
	end

	# cmd = powershell_out("Import-Module GroupPolicy; new-gplink -name no_uac -target 'ou=#{node.ad.dn_dc_ou},#{node.ad.dn_domain_cmpnt}'")
	# cmd.run_command
	
	# if !uac_disabled_gpo_exist?
		# powershell_script "Restart computer after adding domain controller" do
			# code <<-EOH
				# Restart-Computer -Force
			# EOH
		# end
	# end
end

def configure_ad_domain
	if domain_admin_user_exist? == false
		Chef::Log.info "Domain admin user #{new_resource.domain_admin_user} doesn't exist, creating"
		create_domain_admin_user
	else
		Chef::Log.info "Domain admin user #{new_resource.domain_admin_user} exists, nothing to do"
	end
	rename_site
	configure_ad_replication
	set_ad_dns_servers_address
	set_ad_replication_static_ports
end
