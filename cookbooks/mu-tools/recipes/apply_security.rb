# Cookbook Name:: mu-tools
# Recipe:: apply_security
#
# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#		 http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Apply security patterns for hardening

if !node['application_attributes']['skip_recipes'].include?('apply_security')
  case node['platform_family']
    when "rhel", "amazon"
      include_recipe "mu-tools::aws_api"
      include_recipe "mu-tools::google_api"
  
      if node['platform_version'].to_i < 6
        package "policycoreutils"
      elsif node['platform_version'].to_i < 8
        package "policycoreutils-python"
      else
        package "xfsprogs"
        package "xfsprogs-devel"
        package "policycoreutils-python-utils"
      end
  
      %w{ authconfig aide }.each do |pkg|
        package "apply_security package #{pkg}" do
          package_name pkg
        end
      end

      if node['platform_version'].to_i < 8
        package "ntp"
        bash "NTP" do
          user "root"
          code <<-EOH
    				chkconfig ntpd on
  	  			ntpdate pool.ntp.org
  		  		service ntpd start
          EOH
        end
      else
        package "chrony"
        service "chronyd"
      end

      execute "enable manual auditd restarts" do
        command "sed -i s/RefuseManualStop=yes/#RefuseManualStop=yes/ /usr/lib/systemd/system/auditd.service ; pkill auditd"
        ignore_failure true
        action :nothing
        only_if "grep ^RefuseManualStop=yes /usr/lib/systemd/system/auditd.service"
      end
  
      service "auditd" do
        action :nothing
        notifies :run, "execute[enable manual auditd restarts]", :before
      end
  
      if node['platform_version'].to_i < 7
        cookbook_file "/etc/audit/audit.rules" do
          source "etc/audit/stig.rules"
          notifies :restart, "service[auditd]", :delayed
        end
      end
  
      file "/etc/profile.d/tmout.sh" do
        content "TMOUT=900
  readonly TMOUT
  export TMOUT
  "
      end
  
      file "/etc/profile.d/autologout.csh" do
        content "set -r autologout 15\n"
      end
  
  
      #File integrity checking. Default configuration
      bash "AIDE" do
        code <<-EOH
  				aide --init
  				mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
        EOH
        not_if { File.exist?("/var/lib/aide/aide.db.gz") }
      end
      cron "AIDE daily scan" do
        action :create
        minute "0"
        hour "5"
        user "root"
        command "/usr/sbin/aide --check"
        only_if { File.exist?("/usr/sbin/aide") }
      end
  
      cookbook_file "/etc/security/limits.conf" do
        source "etc/security/limits.conf"
        mode 0644
        owner "root"
        group "root"
      end
      cookbook_file "/etc/sysctl.conf" do
        source "etc/sysctl.conf"
        mode 0644
        owner "root"
        group "root"
      end
  
      cookbook_file "/etc/sysconfig/init" do
        source "etc/sysconfig/init"
        mode 0644
        owner "root"
        group "root"
      end
  
  
      bash "Logging and Auditing" do
        code <<-EOH
  				#4.1.4 Create and Set Permissions on rsyslog Log Files
  				#find `awk '/^ *[^#$]/ { print $2 }' /etc/rsyslog.conf | egrep -o "/.*"` -perm /o+rwx
  				chmod og-rwx /var/log/boot.log
        EOH
      end
  
      bash "Network Configuration and Firewalls" do
        code <<-EOH
  				#5.1.2 Disable Send Packet Redirects
  				sysctl -w net.ipv4.conf.default.send_redirects=0
  				sysctl -w net.ipv4.conf.all.send_redirects=0
  				sysctl -w net.ipv4.route.flush=1
  
  				#5.2.2 Disable ICMP Redirect Acceptance
  				sysctl -w net.ipv4.conf.all.accept_redirects=0
  				sysctl -w net.ipv4.conf.default.accept_redirects=0
  				sysctl -w net.ipv4.route.flush=1
  
  				#5.2.4 Log Suspicious Packets
  				sysctl -w net.ipv4.conf.all.log_martians=1
  				sysctl -w net.ipv4.conf.default.log_martians=1
  				sysctl -w net.ipv4.route.flush=1
  
  				#5.4.1.1 Disable IPv6 Router Advertisements
  				sysctl -w net.ipv6.conf.all.accept_ra=0
  				sysctl -w net.ipv6.conf.default.accept_ra=0
  				sysctl -w net.ipv6.route.flush=1
  
  				#5.4.1.2 Disable IPv6 Redirect Acceptance
  				sysctl -w net.ipv6.conf.all.accept_redirects=0
  				sysctl -w net.ipv6.conf.default.accept_redirects=0
  				sysctl -w net.ipv6.route.flush=1
        EOH
      end
  
  
      if node['root_login_disabled']
        #some code
      end
  
  
      bash "System Access, Authentication and Authorization" do
        user "root"
        code <<-EOH
  				#6.1 Configure cron and anacron
  				
  				#6.1.11 Restrict at/cron to Authorized Users
  				rm -f /etc/cron.deny
  
  				#6.1.3 Set User/Group Owner and Permission on /etc/anacrontab
  				chmod og-rwx /etc/anacrontab
  
  				#6.1.4 Set User/Group Owner and Permission on /etc/crontab
  				chmod og-rwx /etc/crontab
  
  				#6.1.5 Set User/Group Owner and Permission on /etc/cron.hourly
  				chmod og-rwx /etc/cron.hourly
  
  				#6.1.6 Set User/Group Owner and Permission on /etc/cron.daily
  				chmod og-rwx /etc/cron.daily
  
  				#6.1.7 Set User/Group Owner and Permission on /etc/cron.weekly
  				chmod og-rwx /etc/cron.weekly
  
  				#6.1.8 Set User/Group Owner and Permission on /etc/cron.monthly
  				chmod og-rwx /etc/cron.monthly
  
  				#6.1.9 Set User/Group Owner and Permission on /etc/cron.d
  				chmod og-rwx /etc/cron.d
  
  				#6.1.10 Restrict at Daemon
  				touch /etc/at.allow
  				chown root:root /etc/at.allow
  				chmod og-rwx /etc/at.allow
  
  				#6.1.11 Restrict at/cron to Authorized Users
  				touch /etc/cron.allow
  				chown root:root /etc/cron.allow
  				chmod og-rwx /etc/cron.allow
  
        EOH
      end
  
      # 6.2 Configure SSH
      begin
        resources('service[sshd]')
      rescue Chef::Exceptions::ResourceNotFound
        service "sshd" do
          action [:enable, :start]
        end
      end
  
      # Make sure we don't lock ourselves out of nodes when setting AllowGroups
      # in sshd.
      if !node['application_attributes']['sshd_allow_groups'].empty?
        group "mu_sshd_system_login"
        ['root', 'centos', 'ec2-user'].each { |sys_login|
          group "add #{sys_login} to mu_sshd_system_login" do
            group_name "mu_sshd_system_login"
            members sys_login
            append true
            ignore_failure true
          end
        }
        node.override['application_attributes']['sshd_allow_groups'] = "mu_sshd_system_login "+node['application_attributes']['sshd_allow_groups']
      end rescue NoMethodError
  
      template "/etc/ssh/sshd_config" do
        source "sshd_config.erb"
        owner "root"
        group "root"
        mode 0600
        cookbook "mu-tools"
        notifies :restart, "service[sshd]", :immediately
      end
  
      cookbook_file "/etc/issue.net" do
        source node['banner']['path']
        mode 0644
        owner "root"
        group "root"
      end
  
      cookbook_file "/etc/issue" do
        source node['banner']['path']
        mode 0644
        owner "root"
        group "root"
      end
      #		cookbook_file "/etc/motd" do
      #			source node['banner']['path']
      #			mode 0644
      #			owner "root"
      #			group "root"
      #		end
      #		cookbook_file "/etc/pam.d/su" do
      #			source "etc/pam.d/su"
      #			mode 0644
      #			owner "root"
      #			group "root"
      #		end
      # 6.3 Configure PAM
      # 6.3.2 Set Password Creation Requirement Parameters Using pam_cracklib
#      template "/etc/pam.d/password-auth-local" do
#        source "etc_pamd_password-auth.erb"
#        mode 0644
#      end
#      link "/etc/pam.d/password-auth" do
#        to "/etc/pam.d/password-auth-local"
#      end
      #6.3.3 Set Lockout for Failed Password Attempts
#      template "/etc/pam.d/system-auth-local" do
#        source "etc_pamd_system-auth.erb"
#        mode 0644
#      end
#      link "/etc/pam.d/system-auth" do
#        to "/etc/pam.d/system-auth-local"
#      end
  
      #SV-50303r1_rule/SV-50304r1_rule
      execute "chown root:root /etc/shadow"
      #SV-50305r1_rule
      execute "chmod 0000 /etc/shadow"
      #SV-50243r1_rule/SV-50248r1_rule
      execute "chown root:root /etc/gshadow"
      #SV-50249r1_rule
      execute "chmod 0000 /etc/gshadow"
      #SV-50250r1_rule/SV-50251r1_rule
      execute "chown root:root /etc/passwd"
      #SV-50257r1_rule
      execute "chmod 0644 /etc/passwd"
      #SV-50258r1_rule/SV-50259r1_rule
      execute "chown root:root /etc/group"
      #SV-50261r1_rule
      execute "chmod 0644 /etc/group"
  
      %w{ /lib /lib64 /usr/lib /usr/lib64 }.each do |dir|
        execute "chown -R root #{dir}"
      end
  
  
      # 7.1 Set Shadow Password Suite Parameters (/etc/login.defs)
      cookbook_file "/etc/login.defs" do
        source "etc/login.defs"
        mode 0644
        owner "root"
        group "root"
      end
  
      # 7.4 Set default umask for users
      cookbook_file "/etc/bashrc" do
        source "etc/bashrc"
        mode 0644
        owner "root"
        group "root"
      end
  
      cookbook_file "/etc/profile" do
        source "etc/profile"
        mode 0644
        owner "root"
        group "root"
      end
  
      # 7.5 Lock Inactive User Accounts
      bash "Lock Inactive Accounts" do
        user "root"
        code <<-EOH
  				useradd -D -f 35
        EOH
      end
  
      # disable some filesystems
      ["cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf"].each { |fs|
        execute "disable #{fs}" do
          command "echo 'install #{fs} /bin/true' >> /etc/modprobe.d/dist.conf"
          not_if "grep '^install #{fs} ' /etc/modprobe.d/dist.conf"
        end
      }

      mu_tools_disk "swap" do
        device node['application_attributes']['swap']['mount_device']
        size node['application_attributes']['swap']['volume_size_gb']
        swap true
      end

      mu_tools_disk "/home" do
        device node['application_attributes']['home']['mount_device']
        size node['application_attributes']['home']['volume_size_gb']
        preserve_data true
      end

      Chef::Log.info("Value of login_disabled is #{node['root_login_disabled']}")
  
      ruby_block "do a bunch of weird stuff" do # ~FC014
        block do
          cmd = Mixlib::ShellOut.new('chcon -Rv --type=user_home_t /home')
          cmd.run_command
          cmd = Mixlib::ShellOut.new('rm -rf /tmp/moveusers.tgz')
          cmd.run_command
          # `chcon -Rv --type=user_home_t /home`
          # `rm -rf /tmp/moveusers.tgz`
          valid_users="AllowUsers root"
          node['etc']['passwd'].each do |user, data|
            if data['uid'] >= 500 && data['shell'] !~ /nologin/ then
              valid_users += " " + user
            end
          end
          Chef::Log.info("Enabling ssh users #{valid_users}")
          fe = Chef::Util::FileEdit.new("/etc/ssh/sshd_config")
          fe.search_file_replace_line(/^AllowUsers.*$/, valid_users)
          fe.write_file
        end
        only_if { ::File.exist?("/tmp/moveusers.tgz") }
      end
  
      execute "mount -oremount /dev/shm" do
        action :nothing
      end
      mount "/dev/shm" do
        device "tmpfs"
        options "nodev,nosuid,noexec"
        action [:enable, :mount]
        notifies :run, "execute[mount -oremount /dev/shm]", :immediately
      end
  
      # XXX This is where ephemeral storage seems to land, usually. Usually. We'd
      # probably like a more robust way of identifying it.
      if !node['tmp_dev'].nil?
        if node['platform_version'].to_i == 6
          execute "mkfs.ext4 #{node['tmp_dev']}" do
            not_if "tune2fs -l #{node['tmp_dev']}"
          end
        elsif node['platform_version'].to_i == 7
          execute "mkfs.xfs -i size=512 #{node['tmp_dev']}" do
            not_if "xfs_info #{node['tmp_dev']}"
          end
        end
  
        mount "/tmp" do
          device node['tmp_dev']
          options "nodev,nosuid,noexec"
          action [:mount, :enable]
          notifies :run, "execute[fix /tmp permissions]", :immediately
        end
        mount "/var/tmp" do
          device "/tmp"
          options "bind"
          action [:mount, :enable]
        end
        execute "fix /tmp permissions" do
          command "chmod 1777 /tmp ; /sbin/restorecon -R /tmp"
        end
      end rescue NoMethodError
  
    when "ubuntu"
      # Make sure we don't lock ourselves out of nodes when setting AllowGroups
      # in sshd.
      if !node['application_attributes']['sshd_allow_groups'].empty?
        group "mu_sshd_system_login"
        ['root', 'ubuntu'].each { |sys_login|
          group "mu_sshd_system_login" do
            members sys_login
            append true
            ignore_failure true
          end
        }
        node.override['application_attributes']['sshd_allow_groups'] = "mu_sshd_system_login "+node['application_attributes']['sshd_allow_groups']
      end rescue NoMethodError
  
      template "/etc/ssh/sshd_config" do
        source "sshd_config.erb"
        owner "root"
        group "root"
        mode 0600
        cookbook "mu-tools"
        notifies :restart, "service[sshd]", :immediately
      end
      cookbook_file "/etc/issue.net" do
        source node['banner']['path']
        mode 0644
        owner "root"
        group "root"
      end
      cookbook_file "/etc/motd.tail" do
        source node['banner']['path']
        mode 0644
        owner "root"
        group "root"
      end
    else
      Chef::Log.info("Unsupported platform #{node['platform']}")
  end
end
