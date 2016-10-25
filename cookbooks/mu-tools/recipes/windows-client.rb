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

      windows_vault = chef_vault_item(node['windows_auth_vault'], node['windows_auth_item'])
      ec2config_user= windows_vault[node['windows_ec2config_username_field']]
      ec2config_password = windows_vault[node['windows_ec2config_password_field']]
      sshd_user = windows_vault[node['windows_sshd_username_field']]
      sshd_password = windows_vault[node['windows_sshd_password_field']]

      if in_domain?
        ad_vault = chef_vault_item(node['ad']['domain_admin_vault'], node['ad']['domain_admin_item'])

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
      end rescue NoMethodError
    else
      Chef::Log.info("Unsupported platform #{node['platform']}")
  end
end
