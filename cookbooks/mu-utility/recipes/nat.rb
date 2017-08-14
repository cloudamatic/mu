#
# Cookbook Name:: mu-utility
# Recipe:: nat
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

if platform_family?("windows")
  Chef::Log.info "I don't know how to make Windows be a NAT host"
else
  $ip_block = "10.0.0.0/16"
  if !node[:application_attributes][:nat][:private_net].empty?
    $ip_block = node[:application_attributes][:nat][:private_net]
  end rescue NoMethodError

  if platform_family?("rhel")
    $ssh_service_name = "sshd"

    if node[:platform_version].to_i == 7
      # Iptables or FirewallD are not installed by default on CentOS7. Using iptables for backwards compatibility.
      # Looks like only the AWS marketplace image doesn't have FirewallD installed by default. Clean installation of CentOS7 minimal does, so removing.
      package "firewalld" do
        action :remove
      end

      package "iptables-services"
    end

    node.default['firewall']['iptables']['defaults'][:ruleset] = {
      '*filter' => 1,
      ':INPUT DROP' => 2,
      ':FORWARD ACCEPT' => 3, # we'll add a DROP after the other stuff
      ':OUTPUT ACCEPT_FILTER' => 4,
      'COMMIT_FILTER' => 100,
      '*nat' => 101,
      ':OUTPUT ACCEPT_NAT' => 104,
      'COMMIT_NAT' => 200
    }

    firewall_rule "NAT postrouting" do
      raw "-A POSTROUTING -o eth0 -s #{$ip_block} -j MASQUERADE"
      position 150
    end
    firewall_rule "NAT stateful connections" do
      raw "-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT"
      position 97
    end
    firewall_rule "NAT forwarding" do
      raw "-A FORWARD -s #{$ip_block} -j ACCEPT"
      position 98
    end
    firewall_rule "NAT forwarding drop other traffic" do
      raw "-A FORWARD -j DROP"
      position 99
    end
    bash "make sure ip forwarding is enabled for NAT traffic" do
      code <<-EOH
        sysctl -w net.ipv4.ip_forward=1
        sysctl -w net.ipv4.conf.eth0.send_redirects=0
      EOH
    end
  elsif platform_family?("debian")
    $ssh_service_name = "ssh"
# XXX port this to firewall_rule
    bash "enable NAT with ufw" do
      not_if "grep '^*nat' /etc/ufw/before.rules"
      code <<-EOH
				sed -i 's/DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
				echo "net.ipv4.ip_forward=1" >> /etc/ufw/sysctl.conf
				echo '*nat' >> /etc/ufw/before.rules
				echo ':POSTROUTING ACCEPT [0:0]' >> /etc/ufw/before.rules
				echo ':POSTROUTING ACCEPT [0:0]' >> /etc/ufw/before.rules
				echo '-A POSTROUTING -s #{$ip_block} -o eth0 -j MASQUERADE' >> /etc/ufw/before.rules
				echo 'COMMIT' >> /etc/ufw/before.rules
      EOH
    end
  end

  execute "restart sshd" do
    command "/sbin/service #{$ssh_service_name} restart"
    action :nothing
  end
  bash "enable SSH tunneling" do
    not_if "grep '^PermitTunnel yes' /etc/ssh/sshd_config"
    code <<-EOH
			echo "" >> /etc/ssh/sshd_config
			echo "PermitTunnel yes" >> /etc/ssh/sshd_config
			echo "" >> /etc/ssh/sshd_config
			echo "AllowTcpForwarding yes" >> /etc/ssh/sshd_config
    EOH
    notifies :run, "execute[restart sshd]", :immediately
  end
end
