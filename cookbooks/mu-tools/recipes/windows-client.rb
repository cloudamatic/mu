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

case node.platform
  when "windows"
    include_recipe 'chef-vault'

    %w{run-userdata_scheduledtask.xml run_chefclient_scheduledtask.xml}.each { |file|
      remote_file "#{Chef::Config[:file_cache_path]}/#{file}" do
        source "https://s3.amazonaws.com/cap-public/#{file}"
      end
    }

    windows_vault = chef_vault_item(node.windows_auth_vault, node.windows_auth_item)
    ec2config_user= windows_vault[node.windows_ec2config_username_field]
    ec2config_password = windows_vault[node.windows_ec2config_password_field]
    sshd_user = windows_vault[node.windows_sshd_username_field]
    sshd_password = windows_vault[node.windows_sshd_password_field]

    if in_domain?
      ad_vault = chef_vault_item(node.ad.domain_admin_vault, node.ad.domain_admin_item)

      mu_tools_windows_client node.ad.computer_name do
        user_name "#{node.ad.netbios_name}\\#{ad_vault[node.ad.domain_admin_username_field]}"
        password ad_vault[node.ad.domain_admin_password_field]
        domain_admin_user ad_vault[node.ad.domain_admin_username_field]
        domain_name node.ad.domain_name
        netbios_name node.ad.netbios_name
        ssh_user sshd_user
        ssh_password sshd_password
        ssh_service_user "#{node.ad.netbios_name}\\#{sshd_user}"
        ec2config_user ec2config_user
        ec2config_password ec2config_password
        ec2config_service_user "#{node.ad.netbios_name}\\#{ec2config_user}"
      end
    else
      mu_tools_windows_client node.hostname do
        user_name node.windows_admin_username
        password windows_vault[node.windows_auth_password_field]
        ssh_user sshd_user
        ssh_password sshd_password
        ssh_service_user ".\\#{sshd_user}"
        ec2config_user ec2config_user
        ec2config_password ec2config_password
        ec2config_service_user ".\\#{ec2config_user}"
      end
    end rescue NoMethodError
  else
    Chef::Log.info("Unsupported platform #{node.platform}")
end
