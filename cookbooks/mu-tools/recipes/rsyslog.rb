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

if !platform_family?("windows")
  package "rsyslog"
  package "rsyslog-gnutls"
  service "rsyslog" do
    action [:enable, :start]
  end
  if platform_family?("rhel")
    $rsyslog_ssl_ca_path = "/etc/pki/Mu_CA.pem"
    package "policycoreutils-python"
  elsif platform_family?("debian")
    include_recipe "mu-utility::apt"
    $rsyslog_ssl_ca_path = "/etc/ssl/Mu_CA.pem"
    package "policycoreutils"
  end
  template "/etc/rsyslog.d/0-mu-log-client.conf" do
    source "0-mu-log-client.conf.erb"
    notifies :restart, "service[rsyslog]", :delayed
  end
  cookbook_file "Mu_CA.pem" do
    path $rsyslog_ssl_ca_path
  end
  execute "allow rsyslog to meddle with port 10514" do
    command "/usr/sbin/semanage port -a -t syslogd_port_t -p tcp 10514"
    not_if "/usr/sbin/semanage port -l | grep '^syslogd_port_t.*10514'"
  end
end
