#
# Cookbook Name:: mu-tools
# Recipe:: set_mu_hostname
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

if !node['application_attributes']['skip_recipes'].include?('set_mu_hostname')
  $hostname = node.name
  if !node['ad']['computer_name'].nil? and !node['ad']['computer_name'].empty?
    $hostname = node['ad']['computer_name']
  end rescue NoMethodError
  $ipaddress = node['ipaddress']

  if !platform_family?("windows")
    sibs=get_sibling_nodes(node)

    template "/etc/hosts" do
      source "etc_hosts.erb"
      variables(
        hostname: $hostname,
        ipaddress: $ipaddress,
        nodes: sibs
      )
    end
  end

  case node['platform']
    when "centos", "redhat", "amazon"
      template "/etc/sysconfig/network" do
        source "etc_sysconfig_network.erb"
        notifies :run, "execute[set hostname]", :immediately if elversion != 7
        variables(
          hostname: $hostname,
          platform: node['platform']
        )
      end

      if elversion == 7
        execute "sed -i '/ssh_pwauth/a preserve_hostname: true' /etc/cloud/cloud.cfg" do
          not_if "grep 'preserve_hostname: true' /etc/cloud/cloud.cfg"
        end

        execute "hostnamectl set-hostname #{$hostname} --static && systemctl restart systemd-hostnamed" do
          # not_if "hostnamectl | grep Static | grep #{$hostname.downcase}"
          not_if "grep #{$hostname} /etc/hostname"
        end

        file "/etc/hostname" do
          content $hostname
        end
      else
        execute "set hostname" do
          command "hostname #{$hostname}"
          not_if "test \"`hostname`\" = \"#{$hostname}\" "
        end
      end
    when "ubuntu"
      execute "set hostname" do
        command "hostname #{$hostname}"
        not_if "test \"`hostname`\" = \"#{$hostname}\" "
      end

      file "/etc/hostname" do
        content $hostname
      end
    else
      Chef::Log.info("Unsupported platform #{node['platform']}")
  end
end