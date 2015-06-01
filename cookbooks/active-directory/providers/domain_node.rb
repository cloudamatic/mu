require 'chef/mixin/shell_out'
include Chef::Mixin::ShellOut
include Chef::Mixin::PowershellOut

def whyrun_supported?
	true
end

action :add do
	join_domain
end

action :remove do
	disjoin_domain
end

def load_current_resource
	@current_resource = @new_resource.dup
end

case node.platform
when "windows"
	def admin_creds
		"(New-Object System.Management.Automation.PSCredential('#{new_resource.netbios_name}\\#{new_resource.join_user}', (ConvertTo-SecureString '#{new_resource.join_password}' -AsPlainText -Force)))"
	end

	def join_domain(computer_name)
		set_client_dns
		elevate_remote_access
		set_computer_name

		unless in_domain?
			# This will allow us to add a new computer account to the correct OU so the right group policy is applied
			begin
				if new_resource.computer_ou
					code = "Add-Computer -DomainName #{new_resource.dns_name} -Credential(New-Object System.Management.Automation.PSCredential('#{new_resource.netbios_name}\\#{new_resource.join_user}', (ConvertTo-SecureString '#{new_resource.join_password}' -AsPlainText -Force))) -NewName #{new_resource.computer_name} -OUPath '#{new_resource.computer_ou}' -PassThru -Restart -Verbose -Force"
				end
			rescue NoMethodError
				code = "Add-Computer -DomainName #{new_resource.dns_name} -Credential(New-Object System.Management.Automation.PSCredential('#{new_resource.netbios_name}\\#{new_resource.join_user}', (ConvertTo-SecureString '#{new_resource.join_password}' -AsPlainText -Force))) -NewName #{new_resource.computer_name} -PassThru -Restart -Verbose -Force"
			end

			cmd = powershell_out(code).run_command
			#Let's make sure the run breaks here
			execute "shutdown -r -f -t 0"
		end
	end

	def set_client_dns
		cmd = powershell_out("Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses #{new_resource.dc_ips.join(", ")}").run_command unless client_dns_set?
	end

	def set_computer_name
		# Theoretically this should have been done for us already, but let's cover the oddball cases.
		if node.hostname != new_resource.computer_name
			cmd = powershell_out("Rename-Computer -NewName '#{new_resource.computer_name}' -Force -PassThru -Restart -DomainCredential(New-Object System.Management.Automation.PSCredential('#{new_resource.netbios_name}\\#{new_resource.join_user}', (ConvertTo-SecureString '#{new_resource.join_password}' -AsPlainText -Force)))").run_command
			execute "shutdown -r -f -t 0"
		end
	end

	def elevate_remote_access
		cmd = powershell_out("New-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name 'LocalAccountTokenFilterPolicy' -PropertyType DWord -Force -Value 1").run_command unless uac_remote_restrictions_enabled?
	end
	
	def in_domain?
		cmd = powershell_out("((Get-WmiObject win32_computersystem).partofdomain -eq $true)").run_command
		return cmd.stdout.match(/True/)
	end

	def uac_remote_restrictions_enabled?
		cmd = powershell_out("(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System 'LocalAccountTokenFilterPolicy').'LocalAccountTokenFilterPolicy' -eq 1").run_command
		return cmd.stdout.match(/True/)
	end
when "centos", "redhat"
	def join_domain
		install_ad_client_packages

		%w{sshd winbind}.each { |svc|
			service svc do
				action :nothing
			end
		}
		
		service "messagebus" do 
			action [ :enable, :start ]
		end

		set_selinux_policies
		config_ssh_ntp_dns
		create_pam_winbind_directories
		pam_winbind_lib
		configure_winbind_kerberos_authentication
		
		execute "net ads join #{new_resource.dns_name.downcase} -U #{new_resource.join_user}%#{new_resource.join_password}" do
			sensitive true
			not_if "net ads testjoin | grep 'Join is OK'"
		end

		template "/etc/samba/smb.conf" do
			source "smb.conf.erb"
			owner "root"
			group "root"
			mode 0644
			notifies :restart, "service[winbind]"
			variables(
				:domain_name => new_resource.dns_name,
				:dcs => new_resource.dc_names,
				:netbios_name => new_resource.netbios_name
			)
		end
	end

	def install_ad_client_packages
	# XXX This is a lousy place to get these packages, Copy those packages to S3
		yum_repository "mu-platform" do
			description 'Mu-Platform Repo'
			url "https://s3.amazonaws.com/cap-public/repo/el/$releasever/$basearch/"
			enabled true
			gpgcheck false
		end

		%w{samba-winbind-modules authconfig krb5-workstation pam_krb5 samba-common oddjob-mkhomedir samba-winbind-clients}.each { |pkg|
			package pkg
		}
	end

	def set_selinux_policies
		# Disable SELinux. Need to test if existing policies below work without having to disabling SELinux.
		execute "setenforce 0"
		# Add Policies to SELinux to allow winbind and ssh to work correctly. TO DO - TEST THIS
		%w{mypol sshd_pol}.each { |policy_file|
			%w{te pp}.each { |ext|
				 cookbook_file "#{Chef::Config[:file_cache_path]}/#{policy_file}.#{ext}" do
					 source "#{policy_file}.#{ext}"
				 end
			}

			execute "semodule -i #{policy_file}.pp" do
				cwd Chef::Config[:file_cache_path]
				not_if "semodule -l | grep #{policy_file}"
				notifies :restart, "service[winbind]", :immediately
				notifies :restart, "service[sshd]", :immediately
			end
		}
		
		execute "setsebool -P ssh_chroot_rw_homedirs 1" do
			not_if "grep ssh_chroot_rw_homedirs=1 /etc/selinux/targeted/modules/active/booleans.local"
		end
	end

	def config_ssh_ntp_dns
		template "/etc/ntp.conf" do
			source "ntp.conf.erb"
			owner "root"
			group "root"
			mode 0644
			variables(
				:dcs => new_resource.dc_names
			)
		end

		template "/etc/ssh/sshd_config" do
			source "sshd_config.erb"
			owner "root"
			group "root"
			mode 0600
			notifies :restart, "service[sshd]", :immediately
			# variables(
				# :allow_password_auth => new_resource.allow_password_auth,
				# :allow_groups => new_resource.allow_groups,
				# :sftp_only_group => new_resource.sftp_only_group,
				# :sftp_chroot => new_resource.sftp_chroot
			# )
		end

		new_resource.dc_ips.each { |ip|
			execute "sed -i '2i nameserver #{ip}' /etc/resolv.conf" do
				not_if "grep #{ip} /etc/resolv.conf"
			end
		}
	end

	def create_pam_winbind_directories
		directory "/home/#{new_resource.dns_name}" do
			owner "root"
			group "root"
			mode 0755
		end

		%w[/run /run/samba /run/samba/winbindd].each { |path|
			directory path do
				owner "root"
				group "root"
				mode 0755
			end
		}

		directory "/etc/skel" do
			owner "root"
			group "root"
			mode 0700
		end

		%w{.bashrc .bash_profile .bash_logout}.each { |file|
			file "/etc/skel/#{file}" do
				owner "root"
				group "root"
				mode 0600
			end
		}
	end

	def pam_winbind_lib
		link "/lib64/security/pam_winbind.so" do
			to "/usr/lib64/security/pam_winbind.so"
		end

		execute "echo 'session optional pam_umask.so umask=0077' >> /etc/pam.d/sshd" do
			not_if "grep pam_umask.so /etc/pam.d/sshd"
		end
	end

	def configure_winbind_kerberos_authentication
		execute "authconfig --disablecache --enablewinbind --enablewinbindauth --smbsecurity=ads --smbworkgroup=#{new_resource.netbios_name.upcase} --smbrealm=#{new_resource.dns_name.upcase} --enablewinbindusedefaultdomain --winbindtemplatehomedir=/home/#{new_resource.dns_name.downcase}/%U --winbindtemplateshell=/bin/bash --enablekrb5 --krb5realm=#{new_resource.dns_name.upcase} --smbservers='#{new_resource.dc_names.join(" ")}' --enablekrb5kdcdns --enablekrb5realmdns --enablelocauthorize --enablemkhomedir --enablepamaccess --updateall" do
			not_if "grep pam_krb5.so /etc/pam.d/system-auth"
		end

		template "/etc/krb5.conf" do
			source "krb5.conf.erb"
			owner "root"
			group "root"
			mode 0644
			variables(
				:domain_name => new_resource.dns_name,
				:dcs => new_resource.dc_names
			)
		end

		# Because authconfig doesn't always update those
		%w{password-auth system-auth}.each { |file|
			cookbook_file "/etc/pam.d/#{file}" do
				source file
				manage_symlink_source true
			end
		}
	end

else
	Chef::Log.info("Unsupported platform #{node.platform}")
end
