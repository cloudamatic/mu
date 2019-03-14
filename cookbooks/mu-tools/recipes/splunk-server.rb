#
# Cookbook Name:: mu-tools
# Recipe:: splunk-server
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

[443, 8089, 9997].each { |port|
  bash "Allow #{port} through iptables for Splunk" do
    user "root"
    not_if "/sbin/iptables -nL | egrep '^ACCEPT.*dpt:#{port}($| )'"
    code <<-EOH
			iptables -I INPUT -p tcp --dport #{port} -j ACCEPT
			service iptables save
    EOH
  end
}

if !node['splunk']['splunkdb']['dev'].nil?
  directory node['splunk']['splunkdb']['path'] do
    recursive true
  end
  execute "mkfs.ext4 #{node['splunk']['splunkdb']['dev']}" do
    not_if "tune2fs -l #{node['splunk']['splunkdb']['dev']}"
  end
  mount node['splunk']['splunkdb']['path'] do
    device node['splunk']['splunkdb']['dev']
    action [:mount, :enable]
  end
end

include_recipe "mu-splunk::server"

if node['splunk']['splunkdb']['path'] != "/opt/splunk/var/lib/splunk"
  execute "set SPLUNK_DB path in splunk-launch.conf to #{node['splunk']['splunkdb']['path']}" do
    command "sed -i 's/^ *SPLUNK_DB//' /opt/splunk/etc/splunk-launch.conf ; echo 'SPLUNK_DB=#{node['splunk']['splunkdb']['path']}' >> /opt/splunk/etc/splunk-launch.conf; chown splunk:splunk #{node['splunk']['splunkdb']['path']}"
    not_if "grep '^SPLUNK_DB=#{node['splunk']['splunkdb']['path']}'"
    notifies :restart, "service[splunk]", :immediately
  end
end

if node['splunk']['minfreespace'] != 5000
  server_conf = "/opt/splunk/etc/system/local/server.conf"
  execute "set minFreeSpace in #{server_conf}" do
    command "echo '[diskUsage]' >> #{server_conf}; echo 'minFreeSpace = #{node['splunk']['minfreespace']}' >> #{server_conf}"
    not_if "grep '^minFreeSpace = #{node['splunk']['minfreespace']}$' #{server_conf}"
    notifies :restart, "service[splunk]", :immediately
  end
end

file "/opt/splunk/etc/.ui_login"

remote_directory "/opt/splunk/etc/deployment-apps/" do
  files_mode "0644"
  files_owner "splunk"
  mode "0744"
  owner "splunk"
  source "splunk-apps"
end

cookbook_file "/opt/splunk/etc/system/local/serverclass.conf" do
  source "serverclass.conf"
  mode "0644"
end

if node['splunk']['license'] != nil
  directory "/opt/splunk/etc/licenses/enterprise" do
    owner "splunk"
    group "splunk"
    mode 00644
    action :create
  end

  if !node['splunk']['license_cookbook'].nil? and !node['splunk']['license_cookbook'].empty?
    cookbook_file "/opt/splunk/etc/licenses/enterprise/Splunk.license" do
      source "splunk.license"
      cookbook node['splunk']['license_cookbook']
      notifies :restart, "service[splunk]", :immediately
    end
  end rescue NoMethodError
end

#splunk_auth_info = chef_vault_item(node['splunk'][:auth][:data_bag], node['splunk'][:auth][:data_bag_item])['auth']
#admin_user, admin_pw = splunk_auth_info.split(':')
#
#node[:deployment][:admins].each_pair { |name, data|
#	execute "add #{data['email']} as Splunk power user" do
#		user "splunk"
#		command "/opt/splunk/bin/splunk add user #{data['email']} -password changeme -role admin -email #{data['email']} -full-name '#{name}' -auth #{admin_user}:#{admin_pw}"
#		not_if "grep ^:#{data['email']}: /opt/splunk/etc/passwd"
#	end
#}

