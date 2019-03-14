# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
# Cookbook Name:: mu-tools
# Recipe:: windows-client
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#	  http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

if !node['application_attributes']['skip_recipes'].include?('windows-client')
  case node['platform']
    when "windows"
      include_recipe 'chef-vault'
      ::Chef::Recipe.send(:include, Chef::Mixin::PowershellOut)

#      remote_file "cygwin-x86_64.exe" do
#        path "#{Chef::Config[:file_cache_path]}/cygwin-x86_64.exe"
#        source "http://cygwin.com/setup-x86_64.exe"
# XXX guard with a version check
#      end

# XXX keep a local cache of packages... really our own damn mirror
      cygwindir = "c:/bin/cygwin"
#      pkgs = ["bash", "mintty", "vim", "curl", "openssl", "wget", "lynx", "openssh"]

#      powershell_script "install Cygwin" do
#        code <<-EOH
#          Start-Process -wait -FilePath "#{Chef::Config[:file_cache_path]}/cygwin-x86_64.exe" -ArgumentList "-q -n -l #{Chef::Config[:file_cache_path]} -L -R c:/bin/cygwin -s http://mirror.cs.vt.edu/pub/cygwin/cygwin/ -P #{pkgs.join(",")}"
#        EOH
#        not_if { ::File.exist?("#{cygwindir}/Cygwin.bat") }
#      end

      # Be prepared to reinit installs that are missing key utilities
#      file "#{cygwindir}/etc/setup/installed.db" do
#        action :delete
#        not_if { ::File.exist?("#{cygwindir}/bin/cygcheck.exe") }
#      end

#      pkgs.each { |pkg|
#        execute "install Cygwin package: #{pkg}" do
#          cwd Chef::Config[:file_cache_path]
#          command "#{Chef::Config[:file_cache_path]}/cygwin-x86_64.exe -f -A -q -R #{cygwindir} -s http://mirror.cs.vt.edu/pub/cygwin/cygwin/ -P #{pkg}"
#          not_if "#{cygwindir}/bin/cygcheck -c #{pkg}".include? "OK"
#        end
#      }

      reboot "Cygwin LSA" do
        action :nothing
        reason "Enabling Cygwin LSA support"
      end

      powershell_script "Configuring Cygwin LSA support" do
        code <<-EOH
          Invoke-Expression '& #{cygwindir}/bin/bash.exe --login -c "echo yes | /bin/cyglsa-config"'
        EOH
        not_if {
          lsa_found = false
          if registry_key_exists?("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa")
            registry_get_values("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa").each { |val|
              if val[:name] == "Authentication Packages"
                lsa_found = true if val[:data].grep(/cyglsa64\.dll/)
                break
              end
            }
          end
          lsa_found
        }
        notifies :reboot_now, "reboot[Cygwin LSA]", :immediately
      end

      windows_vault = chef_vault_item(node['windows_auth_vault'], node['windows_auth_item'])
      sshd_user = windows_vault[node['windows_sshd_username_field']]
      sshd_password = windows_vault[node['windows_sshd_password_field']]
      powershell_script "enable Cygwin sshd" do
        code <<-EOH
          Invoke-Expression -Debug '& #{cygwindir}/bin/bash.exe --login -c "ssh-host-config -y -c ntsec -w ''#{sshd_password}'' -u #{sshd_user}"'
          Invoke-Expression -Debug '& #{cygwindir}/bin/bash.exe --login -c "sed -i.bak ''s/#.*StrictModes.*yes/StrictModes no/'' /etc/sshd_config"'
          Invoke-Expression -Debug '& #{cygwindir}/bin/bash.exe --login -c "sed -i.bak ''s/#.*PasswordAuthentication.*yes/PasswordAuthentication no/'' /etc/sshd_config"'
          Invoke-Expression -Debug '& #{cygwindir}/bin/bash --login -c "chown #{sshd_user} /var/empty /var/log/sshd.log /etc/ssh*; chmod 755 /var/empty"'
        EOH
        sensitive true
        not_if %Q{Get-Service "sshd"}
      end
      powershell_script "set unix-style Cygwin sshd permissions" do
        code <<-EOH
          if((Get-WmiObject win32_computersystem).partofdomain){
            Invoke-Expression -Debug '& #{cygwindir}/bin/bash --login -c "mkpasswd -d > /etc/passwd"'
            Invoke-Expression -Debug '& #{cygwindir}/bin/bash --login -c "mkgroup -l -d > /etc/group"'
          } else {
            Invoke-Expression -Debug '& #{cygwindir}/bin/bash --login -c "mkpasswd -l > /etc/passwd"'
            Invoke-Expression -Debug '& #{cygwindir}/bin/bash --login -c "mkgroup -l > /etc/group"'
          }
          Invoke-Expression -Debug '& #{cygwindir}/bin/bash --login -c "chown #{sshd_user} /var/empty /var/log/sshd.log /etc/ssh*; chmod 755 /var/empty"'
        EOH
      end

      include_recipe 'mu-activedirectory'

      ::Chef::Recipe.send(:include, Chef::Mixin::PowershellOut)

      template "c:/bin/cygwin/etc/sshd_config" do
        source "sshd_config.erb"
        mode 0644
        cookbook "mu-tools"
        ignore_failure true
      end

      ec2config_user= windows_vault[node['windows_ec2config_username_field']]
      ec2config_password = windows_vault[node['windows_ec2config_password_field']]
      login_dom = "."

      if in_domain?

        ad_vault = chef_vault_item(node['ad']['domain_admin_vault'], node['ad']['domain_admin_item'])
        login_dom = node['ad']['netbios_name']

        windows_users node['ad']['computer_name'] do
          username ad_vault[node['ad']['domain_admin_username_field']]
          password ad_vault[node['ad']['domain_admin_password_field']]
          domain_name node['ad']['domain_name']
          netbios_name node['ad']['netbios_name']
          dc_ips node['ad']['dc_ips']
          ssh_user sshd_user
          ssh_password sshd_password
          ec2config_user ec2config_user
          ec2config_password ec2config_password
        end

        aws_windows "ec2" do
          username ec2config_user
          service_username "#{node['ad']['netbios_name']}\\#{ec2config_user}"
          password ec2config_password
        end

        scheduled_tasks "tasks" do
          username ad_vault[node['ad']['domain_admin_username_field']]
          password ad_vault[node['ad']['domain_admin_password_field']]
        end

        sshd_service "sshd" do
          service_username "#{node['ad']['netbios_name']}\\#{sshd_user}"
          username sshd_user
          password sshd_password
        end

        begin
          resources('service[sshd]')
        rescue Chef::Exceptions::ResourceNotFound
          service "sshd" do
            action [:enable, :start]
            sensitive true
          end
        end
      else
        windows_users node['hostname'] do
          username node['windows_admin_username']
          password windows_vault[node['windows_auth_password_field']]
          ssh_user sshd_user
          ssh_password sshd_password
          ec2config_user ec2config_user
          ec2config_password ec2config_password
        end

        aws_windows "ec2" do
          username ec2config_user
          service_username ".\\#{ec2config_user}"
          password ec2config_password
        end

        scheduled_tasks "tasks" do
          username node['windows_admin_username']
          password windows_vault[node['windows_auth_password_field']]
        end

        sshd_service "sshd" do
          username sshd_user
          service_username ".\\#{sshd_user}"
          password sshd_password
        end
        begin
          resources('service[sshd]')
        rescue Chef::Exceptions::ResourceNotFound
          service "Cygwin sshd as '#{sshd_user}'" do
						service_name "sshd"
            action [:enable, :start]
            sensitive true
          end
        end
      end

    else
      Chef::Log.info("mu-tools::windows-client: Unsupported platform #{node['platform']}")
  end
end
