#
# Cookbook Name:: mu-tools
# Recipe:: set_local_fw
#
# Copyright:: Copyright (c) 2016 eGlobalTech, Inc., all rights reserved
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

case node[:platform_family]
  when "rhel"
    master_ips = []
    master_ips << "127.0.0.1" if Chef::Config[:node_name] == "MU-MASTER"
    master = search(:node, "name:MU-MASTER")
    master.each { |server|
      next if server.ec2.nil?
      master_ips << server.ec2.public_ipv4 if !server.ec2.public_ipv4.nil? and !server.ec2.public_ipv4.empty?
      master_ips << server.ec2.local_ipv4 if !server.ec2.local_ipv4.nil? and !server.ec2.local_ipv4.empty?
    }
    if node['platform_version'].to_i >= 7
      execute "/bin/firewall-cmd --reload" do
        action :nothing
      end
      execute "/bin/firewall-cmd --permanent --new-zone=mu" do
        not_if "/bin/firewall-cmd --permanent --get-zones | /bin/egrep '(^| )mu( |$)'"
        notifies :run, "execute[/bin/firewall-cmd --reload]", :immediately
      end
      master_ips.each { |ip|
        execute "/bin/firewall-cmd --permanent --zone=mu --add-source=#{ip}" do
          not_if "/bin/firewall-cmd --permanent --list-sources --zone=mu | /bin/egrep '(^| )#{ip}( |$)'"
          notifies :run, "execute[/bin/firewall-cmd --reload]", :immediately
        end
      }
      execute "/bin/firewall-cmd --permanent --zone=mu --add-port=1-65535/tcp" do
        notifies :run, "execute[/bin/firewall-cmd --reload]", :immediately
      end
      execute "/bin/firewall-cmd --permanent --zone=mu --add-port=1-65535/udp" do
        notifies :run, "execute[/bin/firewall-cmd --reload]", :immediately
      end
#    bash "open ICMP for Mu Master" do
#      user "root"
#      code <<-EOH
#        for t in `/bin/firewall-cmd --get-icmptypes`;do
#
#        done
#      EOH
#    end
    end
end
