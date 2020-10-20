#
# Cookbook Name:: mu-tools
# Recipe:: rsyslog
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

if !node['application_attributes']['skip_recipes'].include?('rsyslog')
  case node['platform_family']
  when "rhel", "debian", "amazon"
    package "rsyslog"
    package "rsyslog-gnutls"
    execute "chcon -R -h -t var_log_t /Mu_Logs" do
      action :nothing
      only_if { ::Dir.exist?("/Mu_Logs") }
      not_if "/sbin/getenforce | grep -cim1  disabled"
    end
    service "rsyslog" do
      action [:enable, :start]
      notifies :run, "execute[chcon -R -h -t var_log_t /Mu_Logs]", :immediately
    end
    if platform_family?("rhel") or platform_family?("amazon")
      $rsyslog_ssl_ca_path = "/etc/pki/Mu_CA.pem"
      if !platform?("amazon")
        semanage_pkg = if node['platform_version'].to_i < 6
          "policycoreutils"
        elsif node['platform_version'].to_i < 8
          "policycoreutils-python"
        else
          "policycoreutils-python-utils"
        end
        package semanage_pkg
        execute "allow rsyslog to meddle with port 10514" do
          command "/usr/sbin/semanage port -a -t syslogd_port_t -p tcp 10514"
          not_if "/usr/sbin/semanage port -l | grep '^syslog.*10514'"
        end
      end
  
    elsif platform_family?("debian")
      include_recipe "mu-utility::apt"
      $rsyslog_ssl_ca_path = "/etc/ssl/Mu_CA.pem"
      package "policycoreutils"
    end

    if node.name != "MU-MASTER" # XXX I'm sure we can come up with a smarter condition than this
      master_ips = get_mu_master_ips
# XXX This should prefer a master IP that's in our private subnet, and also
# be able to tell which ones are private and which are public.
      template "/etc/rsyslog.d/0-mu-log-client.conf" do
        source "0-mu-log-client.conf.erb"
        variables(
          :syslog_server => master_ips.last,
          :ssl_ca_path => $rsyslog_ssl_ca_path
        )
        notifies :restart, "service[rsyslog]", :delayed
      end
      cookbook_file "Mu_CA.pem" do
        path $rsyslog_ssl_ca_path
      end
    end
  end
end
