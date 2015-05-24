# Cookbook Name:: mu-tools
# Recipe:: ad-client
#
# Copyright:: Copyright (c) 2015 eGlobalTech, Inc., all rights reserved
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

include_recipe "chef-vault"

auth_info = chef_vault_item(node.ad.auth_vault, node.ad.auth_item)
usr = auth_info[node.ad.auth_username_field]
pwd = auth_info[node.ad.auth_password_field]

case node[:platform]
    when "centos"

		# Disable SELinux when running authconfig, winbind, sftp. Need to find policies that allow these to run without disabling SELinux
		execute "setenforce 0"

		directory "/home/#{node.ad.domain_name}" do
			mode 0755
		end

		# XXX This is a lousy place to get these packages, find somewhere better.
		yum_repository "glusterfs-samba" do
			description 'Glusterfs Samba repo'
			url "http://download.gluster.org/pub/gluster/glusterfs/samba/EPEL.repo/epel-$releasever/$basearch/"
			enabled true
			gpgkey "http://download.gluster.org/pub/gluster/glusterfs/samba/EPEL.repo/pub.key"
		end

		%w{samba-winbind-modules authconfig krb5-workstation pam_krb5 samba-common oddjob-mkhomedir samba-winbind-clients}.each do |pkg|
			package pkg
		end
		
		template "/etc/ntp.conf" do
			source "ntp.conf.erb"
			owner "root"
			group "root"
			mode 0644
		end

		service "sshd"
		template "/etc/ssh/sshd_config" do
			source "sshd_config.erb"
			owner "root"
			group "root"
			mode 0600
			notifies :restart, "service[sshd]", :immediately
		end

		node.ad.dc_ips.each do |ip|
			execute "sed -i '2i nameserver #{ip}' /etc/resolv.conf" do
				not_if "grep #{ip} /etc/resolv.conf"
			end
		end

		%w[/run /run/samba /run/samba/winbindd].each do |path|
			directory path do
				owner 'root'
				group 'root'
				mode '0755'
				# notifies :restart, "service[winbind]", :immediately
			end
		end
		
		link "/lib64/security/pam_winbind.so" do
			to "/usr/lib64/security/pam_winbind.so"
		end

		service "messagebus" do 
			action [ :enable, :start ]
		end

		execute "setsebool -P ssh_chroot_rw_homedirs 1" do
			not_if "grep ssh_chroot_rw_homedirs=1 /etc/selinux/targeted/modules/active/booleans.local"
		end

		execute "enable Kerberos PAM authentication" do
			command "authconfig --disablecache --enablewinbind --enablewinbindauth --smbsecurity=ads --smbworkgroup=#{node.ad.netbios_name.upcase} --smbrealm=#{node.ad.domain_name.upcase} --enablewinbindusedefaultdomain --winbindtemplatehomedir=/home/#{node.ad.domain_name.downcase}/%U --winbindtemplateshell=/bin/bash --enablekrb5 --krb5realm=#{node.ad.domain_name.upcase} --smbservers='#{node.ad.dcs.join(" ")}' --enablekrb5kdcdns --enablekrb5realmdns --enablelocauthorize --enablemkhomedir --enablepamaccess --updateall"
			not_if "grep pam_krb5.so /etc/pam.d/system-auth"
		end

		execute "echo 'session optional pam_umask.so umask=0077' >> /etc/pam.d/sshd" do
			not_if "grep pam_umask.so /etc/pam.d/sshd"
		end

		directory "/etc/skel" do
			mode 0700
		end
		[".bashrc", ".bash_profile", ".bash_logout"].each { |file|
			file "/etc/skel/#{file}" do
				mode 0600
			end
		}

		template "/etc/krb5.conf" do
			source "krb5.conf.erb"
			owner "root"
			group "root"
			mode 0644
		end

		bash "Join node to domain net ads join #{node.ad.domain_name.downcase}" do
			code "net ads join #{node.ad.domain_name.downcase} -U #{usr}%#{pwd}"
			sensitive true
			not_if "net ads testjoin | grep 'Join is OK'"
		end

		# Add Policies to SELinux to allow winbind and ssh to auth correctly

		 cookbook_file "mypol.te" do
			 path "/tmp/mypol.te"
			 :create_if_missing
		 end

		 cookbook_file "mypol.pp" do
			 path "/tmp/mypol.pp"
			 :create_if_missing
		 end

		 cookbook_file "sshd_pol.te" do
			 path "/tmp/sshd_pol.te"
			 :create_if_missing
		 end

		 cookbook_file "sshd_pol.pp" do
			 path "/tmp/sshd_pol.pp"
			 :create_if_missing
		 end

		 bash "Add sshd to SELinux" do
			 code "cd /tmp && /usr/sbin/semodule -i sshd_pol.pp"
			 not_if "/usr/sbin/semodule -l | grep sshd_pol"
		 end
		
		 bash "Add winbind to SELinux" do
			 code "cd /tmp &&  /usr/sbin/semodule -i mypol.pp"
			 not_if "/usr/sbin/semodule -l | grep mypol"
		 end
			

		# Enable SElinux. See reason from above
		# execute "setenforce 1"

		service "winbind"
		template "/etc/samba/smb.conf" do
			source "smb.conf.erb"
			owner "root"
			group "root"
			mode 0644
			notifies :restart, "service[winbind]", :immediately
		end
		
		# Becuase authconfig dosen't always update those
		%w[password-auth system-auth].each do |file|
			cookbook_file "/etc/pam.d/#{file}" do
				source file
				manage_symlink_source true
			end
		end

	when "windows"
		::Chef::Recipe.send(:include, Chef::Mixin::PowershellOut)
		include_recipe 'windows::reboot_handler'

		auth_info = chef_vault_item(node.ad.auth.data_bag, node.ad.auth.data_bag_item)
		usr = auth_info['username']
		pwd = auth_info['password']

		cmd = powershell_out('(Get-WmiObject win32_computersystem).partofdomain')
		cmd.run_command
		if cmd.stdout.match(/True/)
			in_domain = true
		else
			in_domain = false
		end

		windows_reboot 1 do
			reason 'Adding computer to domain'
			action :nothing
		end

		if !in_domain
			powershell_script "Set DNS Server Addresses" do
				code "Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses #{node.ad.dc_ips.join(", ")}"
			end

			# This will allow us to add a new computer account to the correct OU so the right group policy is applied
			begin
				if node.ad.computer_ou
					cmd = "Add-Computer -DomainName #{node.ad.domain_name} -Credential(New-Object System.Management.Automation.PSCredential('femadata\\#{usr}', (ConvertTo-SecureString '#{pwd}' -AsPlainText -Force))) -OUPath '#{node.ad.computer_ou}' -PassThru -Restart -Verbose -Force"
				end
			rescue NoMethodError
				cmd = "Add-Computer -DomainName #{node.ad.domain_name} -Credential(New-Object System.Management.Automation.PSCredential('femadata\\#{usr}', (ConvertTo-SecureString '#{pwd}' -AsPlainText -Force))) -PassThru -Restart -Verbose -Force"
			end

			powershell_script "Add Computer to Domain" do
				code cmd
				notifies :request, 'windows_reboot[1]', :immediately
				sensitive true
			end
		end

		# Theoretically this should have been done for us already, but let's cover
		# the oddball cases.
		if !node.ad.computer_name.nil?
			powershell_script "Rename Computer to #{node.ad.computer_name}" do
				guard_interpreter :powershell_script
				not_if "$env:computername -eq '#{node.ad.computer_name}'"
				code "Rename-Computer -NewName '#{node.ad.computer_name}' -Force -PassThru -Restart -DomainCredential(New-Object System.Management.Automation.PSCredential('femadata\\#{usr}', (ConvertTo-SecureString '#{pwd}' -AsPlainText -Force)))"
				notifies :request, 'windows_reboot[1]', :immediately
			end
		end rescue NoMethodError

#node.windows_admin_username

		# sshd service user change over to domain user
#		service "sshd" do
#			action :nothing
#		end
#
#		execute "sc start sshd" do
#			action :nothing
#		end
#		execute "sc stop sshd" do
#			action :nothing
#			notifies :run, "execute[sc start sshd]", :immediately
#		end
#
#		batch "Change local ssh service user account to domain account" do
#			code "sc config sshd obj= \"femadata\\#{$ssh_svc_ad_usr}\" password= \"#{$ssh_svc_ad_pwd}\""
#			not_if "sc qc sshd | grep SERVICE_START_NAME | grep femadata\\\\#{$ssh_svc_ad_usr}"
#			notifies :run, "execute[sc stop sshd]", :delayed
#			sensitive true
#			end
#		end

# Run userdata as a domain admin user, too
#		cookbook_file "#{Chef::Config[:file_cache_path]}/run-userdata_scheduledtask.xml" do
#			source 'run-userdata_scheduledtask.xml'
#		end

#		powershell_script "Import run-userdata scheduled task" do
#			guard_interpreter :powershell_script
#			code "Register-ScheduledTask -Xml (get-content '#{Chef::Config[:file_cache_path]}/run-userdata_scheduledtask.xml' | out-string) -TaskName 'run-userdata' -User #{$ad_admin_usr} -Password '#{$ad_admin_pwd}' -Force"
#			not_if "Get-ScheduledTask -TaskName 'run-userdata'"
#			#(Get-ScheduledTask -TaskName 'run-userdata').TaskName -eq 'run-userdata'
#		end

		# Will allow remote users to get around UAC. Used for remote configuration
		registry_key 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
			values [{
				:name => 'LocalAccountTokenFilterPolicy',
				:type => :dword,
				:data => '1'
			}]
			action :create
			recursive true
		end

	else
		log "#{node[:platform]} not supported"
end
