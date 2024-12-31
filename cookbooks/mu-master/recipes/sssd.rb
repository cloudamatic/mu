#
# Cookbook Name:: mu-master
# Recipe:: sssd
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

include_recipe 'mu-master::firewall-holes'
include_recipe "mu-master::389ds"

package "sssd"
package "sssd-ldap"
package "sssd-client"

package "nss-pam-ldapd" do
  action :remove
end
package "pam_ldap" do
  action :remove
end
package "dbus"
if !(node['platform_family'] == 'amazon' && node['platform_version'].to_i == 2023)
  service "messagebus" do
    action [:enable, :start]
  end
end
package "nscd"
service "nscd" do
  action [:disable, :stop]
end
package "oddjob-mkhomedir"
execute "restorecon -r /usr/sbin"
service "sshd" do
  action :nothing
end

# SELinux Policy for oddjobd and its interaction with syslogd
cookbook_file "syslogd_oddjobd.pp" do
  path "#{Chef::Config[:file_cache_path]}/syslogd_oddjobd.pp"
end

execute "Add oddjobd and syslogd interaction to SELinux allow list" do
  command "/usr/sbin/semodule -i syslogd_oddjobd.pp"
  cwd Chef::Config[:file_cache_path]
  not_if "/usr/sbin/semodule -l | grep syslogd_oddjobd"
  notifies :restart, "service[oddjobd]", :delayed
end

service "oddjobd" do
  start_command "sh -x /etc/init.d/oddjobd start" if %w{redhat centos}.include?(node['platform']) && node['platform_version'].to_i == 6  # seems to actually work
  action [:enable, :start]
end
package "authconfig"

# XXX SSSD seems to not work on Amazon 2023 at all right now. It fails silently
# on startup over some kind of systemd/permission issue (it can't write its
# PID file, no it's not SELinux's fault either).
#
# If you run it interactively (sssd -i), it can't seem to enumerate users from
# the LDAP server, though they are definitely present. 
#
# Working around this problem elsewhere.
if !(node['platform_family'] == 'amazon' && node['platform_version'].to_i == 2023)
  execute "LC_ALL=C /usr/sbin/authconfig --disablenis --disablecache --disablewinbind --disablewinbindauth --enablemkhomedir --disablekrb5 --enablesssd --enablesssdauth --enablelocauthorize --disableforcelegacy --disableldap --disableldapauth --updateall" do
    notifies :restart, "service[oddjobd]", :immediately
    notifies :reload, "service[sshd]", :delayed
    not_if "grep pam_sss.so /etc/pam.d/password-auth"
  end
  directory "/var/log/sssd" do
    mode 0750
    recursive true
  end
  service "sssd" do
    action :nothing
    notifies :restart, "service[sshd]", :immediately
  end
  template "/etc/sssd/sssd.conf" do
    source "sssd.conf.erb"
    mode 0600
    owner "root"
    group "root"
    notifies :restart, "service[sssd]", :immediately
    variables(
      :base_dn => $MU_CFG['ldap']['base_dn'],
      :user_ou => $MU_CFG['ldap']['user_ou'],
      :dcs => $MU_CFG['ldap']['dcs']
    )
  end
  service "sssd" do
    action [:enable, :start]
    notifies :restart, "service[sshd]", :immediately
  end
end
