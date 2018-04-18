# Cookbook Name:: mu-tools
# Recipe:: updates
#
# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
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

if !node[:application_attributes][:skip_recipes].include?('updates')
  case node[:platform]
  # Note- most of this Windows logic is now dealt with in userdata (setup)
  # and initial Mu bootstrap (running updates), but this recipe is still
  # useful for updating existing hosts.
    when "windows"
      ::Chef::Recipe.send(:include, Chef::Mixin::PowershellOut)
  
      ["C:\\Users\\#{node[:windows_admin_username]}", "C:\\Users\\#{node[:windows_admin_username]}\\Documents", "C:\\Users\\#{node[:windows_admin_username]}\\Documents\\WindowsPowerShell", "C:\\Users\\#{node[:windows_admin_username]}\\Documents\\WindowsPowerShell\\Modules"].each { |dir|
        directory dir
      }
  
      remote_file "#{Chef::Config[:file_cache_path]}/PSWindowsUpdate.zip" do
        source "https://s3.amazonaws.com/cloudamatic/PSWindowsUpdate.zip"
      end
  
      ["C:/Users/#{node[:windows_admin_username]}/Documents/WindowsPowerShell/Modules", "c:\\windows\\System32\\WindowsPowerShell\\v1.0\\Modules"].each { |dir|
        windows_zipfile dir do
          source "#{Chef::Config[:file_cache_path]}/PSWindowsUpdate.zip"
          action :unzip
          not_if { File.exists?("#{dir}/PSWindowsUpdate") }
        end
      }
  
      registry_key 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update' do
        values [{
                    :name => 'AUOptions',
                    :type => :dword,
                    :data => '3'
                }]
        action :create
        recursive true
      end
  
      if node[:os_updates_using_chef] or node[:application_attributes][:os_updates_using_chef]
        powershell_script "Install Windows Updates" do
          # XXX Something in here throws a security error now. Whee.
          #				 Set-ExecutionPolicy RemoteSigned -Force
          #				 if (!(Test-Path -path c:\\windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\PSWindowsUpdate))
          #				 {
          #					 cmd /c mklink /D c:\\windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\PSWindowsUpdate C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\Modules\\PSWindowsUpdate
          #				 }
          code <<-EOH
  				Import-Module PSWindowsUpdate
  				Get-WUInstall -AcceptAll -ignorereboot
          EOH
        end
  
        reboot "Windows updates" do
          action :reboot_now
          reason "Windows Update has requested a reboot"
          only_if {
            registry_key_exists?("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired")
          }
        end

      end
    when "centos"
      execute "yum -y update" if node[:os_updates_using_chef]
    when "ubuntu"
      include_recipe "mu-utility::apt"
  
      if node[:os_updates_using_chef]
        bash "Install system updates" do
          user "root"
          code <<-EOH
  				apt-get -y upgrade
  				cat >> /etc/ssh/sshd_config << EOF
  					PermitRootLogin without-password
  				EOF
  				cat /root/.ssh/authorized_keys | sed 's/^.*ssh-rsa//g' > /tmp/temp && mv /tmp/temp /root/.ssh/authorized_keys
  				cat /root/.ssh/authorized_keys | sed '1s/^/ssh-rsa/' > /tmp/temp && mv /tmp/temp /root/.ssh/authorized_keys
  				/etc/init.d/ssh restart
          EOH
        end
      end
    else
      Chef::Log.info("Unsupported platform #{node[:platform]}")
  end
end
