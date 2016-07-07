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

case node.platform_family
when "rhel"
  case elversion
  when 7
    master_ips = get_mu_master_ips

    package "firewalld"
    service "firewalld" do
      action [ :enable, :start ]
    end

    execute "/bin/firewall-cmd --reload" do
      action :nothing
    end

    execute "/bin/firewall-cmd --permanent --new-zone=mu" do
      not_if "/bin/firewall-cmd --get-zones | /bin/egrep '(^| )mu( |$)'"
      notifies :run, "execute[/bin/firewall-cmd --reload]", :immediately
    end

    master_ips.each { |ip|
      execute "/bin/firewall-cmd --permanent --zone=mu --add-source=#{ip}" do
        not_if "/bin/firewall-cmd --list-sources --zone=mu | /bin/egrep '(^| )#{ip}( |$)'"
        notifies :run, "execute[/bin/firewall-cmd --reload]", :immediately
      end
    }

    %w{1-65535/tcp 1-65535/udp}.each { |rule|
      execute "/bin/firewall-cmd --permanent --zone=mu --add-port=#{rule}" do
        notifies :run, "execute[/bin/firewall-cmd --reload]", :immediately
        not_if "/bin/firewall-cmd --list-ports --zone=mu | /bin/egrep '(^| )#{rule}( |$)'"
      end
    }
  end
end
