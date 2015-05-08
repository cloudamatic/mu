#
# Cookbook Name:: mu-tools
# Recipe:: set_cap_hostname
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

$hostname = node.name
$ipaddress = node.ipaddress

if !platform_family?("windows")
	template "/etc/hosts" do
		source "etc_hosts.erb"
	end

	execute "set hostname" do
		command "hostname #{$hostname}"
		not_if "test \"`hostname`\" = \"#{$hostname}\" "
	end
end

case node[:platform]
when "centos", "redhat"
	template "/etc/sysconfig/network" do
	  source "etc_sysconfig_network.erb"
	  notifies :run, "execute[set hostname]", :immediately
	end

	if node.platform_version.to_i == 7
		# nah, stil not saved across reboots. cloud-init needs to be configured to keep the hostname
		include_recipe "mu-utility::cloudinit"

		execute "hostnamectl set-hostname #{$hostname} && systemctl restart systemd-hostnamed" do
			not_if "hostnamectl | grep Static | grep #{$hostname.downcase}"
		end
		
		file "/etc/hostname" do
			content $hostname
		end
	end
when "ubuntu"
	file "/etc/hostname" do
	  content $hostname
	end
else
	Chef::Log.info("Unsupported platform #{node[:platform]}")
end
