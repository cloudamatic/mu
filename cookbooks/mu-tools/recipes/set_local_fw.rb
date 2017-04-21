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


master_ips = get_mu_master_ips
case node[:platform]
when "centos", "redhat"
  include_recipe 'mu-firewall'

  if elversion < 7
    service "iptables" do
      action :nothing
    end
  else
    package "firewall-config"
    execute "firewall-cmd --reload" do
      action :nothing
    end
  end

  if elversion <= 6
    firewall_rule "Allow loopback in" do
      raw "-A INPUT -i lo -j ACCEPT"
      notifies :reload, "service[iptables]"
    end

    firewall_rule "Allow loopback out" do
      raw "-A OUTPUT -o lo -j ACCEPT"
      notifies :reload, "service[iptables]"
    end
  end

  opento = master_ips.map { |x| "#{x}/32"}

  opento.uniq.each { |src|
    [:tcp, :udp, :icmp].each { |proto|
      firewall_rule "allow all #{src} #{proto.to_s} traffic" do
        source src
        protocol proto
        notifies :reload, "service[iptables]" if elversion < 7
        notifies :run, 'execute[firewall-cmd --reload]' if elversion >= 7
      end
    }
  }
end
