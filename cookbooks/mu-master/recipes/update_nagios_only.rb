#
# Cookbook Name:: mu-master
# Recipe:: update_nagios_only
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

if $MU_CFG.has_key?('ldap')
  include_recipe 'chef-vault'
  bind_creds = chef_vault_item($MU_CFG['ldap']['bind_creds']['vault'], $MU_CFG['ldap']['bind_creds']['item'])
  node.normal.nagios.server_auth_method = "ldap"
  node.normal.nagios.ldap_bind_dn = bind_creds[$MU_CFG['ldap']['bind_creds']['username_field']]
  node.normal.nagios.ldap_bind_password = bind_creds[$MU_CFG['ldap']['bind_creds']['password_field']]
  if $MU_CFG['ldap']['type'] == "Active Directory"
    node.normal.nagios.ldap_url = "ldap://#{$MU_CFG['ldap']['dcs'].first}/#{$MU_CFG['ldap']['base_dn']}?sAMAccountName?sub?(objectClass=*)"
  else
    node.normal.nagios.ldap_url = "ldap://#{$MU_CFG['ldap']['dcs'].first}/#{$MU_CFG['ldap']['base_dn']}?uid?sub?(objectClass=*)"
  end
  node.normal.nagios.server_auth_require = "ldap-group #{$MU_CFG['ldap']['user_group_dn']}"
  node.normal.nagios.ldap_authoritative = "On"
  node.save
end

# XXX The Nagios init script from source is buggy; config test always fails
# when invoked via "service nagios start," which is what the cookbook does.
# This at least keeps it from trashing our Chef runs.
file "/etc/sysconfig/nagios" do
  content "checkconfig=\"false\"\n"
  mode 0600
end
include_recipe "nagios"

cookbook_file "nagios_fifo.pp" do
  path "#{Chef::Config[:file_cache_path]}/nagios_fifo.pp"
end

execute "Add Nagios cmd FIFO to SELinux allow list" do
  command "/usr/sbin/semodule -i nagios_fifo.pp"
  cwd Chef::Config[:file_cache_path]
  not_if "/usr/sbin/semodule -l | grep nagios_fifo"
  notifies :reload, "service[apache2]", :delayed
end


# Workaround for minor Nagios (cookbook?) bug. It looks for this at the wrong
# URL at the moment, so copy it where it's actually looking.
if File.exists?("/usr/lib/cgi-bin/nagios/statusjson.cgi")
  remote_file "/usr/lib/cgi-bin/statusjson.cgi" do
    source "file:///usr/lib/cgi-bin/nagios/statusjson.cgi"
    mode 0755
    owner "root"
    group "nagios"
  end
end

# ... the nagios cookbook is bafflingly inconsistent
directory "/usr/lib/cgi-bin/nagios" do
  mode 0755
  owner "root"
  group "nagios"
end
Dir.glob("/usr/lib/cgi-bin/*.cgi").each { |script|
  shortname = script.gsub(/.*?\/([^\/]+)$/, '\1')
  remote_file "/usr/lib/cgi-bin/nagios/#{shortname}" do
    source "file:///#{script}"
    mode 0755
    owner "root"
    group "nagios"
  end
}

["/usr/lib/nagios", "/etc/nagios", "/etc/nagios3", "/var/log/nagios", "/var/www/html/docs"].each { |dir|
  if Dir.exist?(dir)
    execute "chcon -R -h -t httpd_sys_content_t #{dir}" do
      not_if "ls -aZ #{dir} | grep ':httpd_sys_content_t:'"
      returns [0, 1]
      notifies :reload, "service[apache2]", :delayed
    end
  end
}

["/usr/lib/cgi-bin"].each { |cgidir|
  if Dir.exist?(cgidir)
    execute "chcon -R -h -t httpd_sys_script_exec_t #{cgidir}" do
      not_if "ls -aZ #{cgidir} | grep ':httpd_sys_script_exec_t:'"
      notifies :reload, "service[apache2]", :delayed
    end
  end
}
if File.exist?("/usr/lib64/nagios/plugins/check_nagios")
  execute "chcon -R -h -t nagios_unconfined_plugin_exec_t /usr/lib64/nagios/plugins/check_nagios" do
    not_if "ls -aZ /usr/lib64/nagios/plugins/check_nagios | grep ':nagios_unconfined_plugin_exec_t:'"
  end
end

execute "chgrp apache /var/log/nagios"

# The Nagios cookbook currently screws up this setting, so work around it.
execute "sed -i s/^interval_length=.*/interval_length=1/ || echo 'interval_length=1' >> /etc/nagios/nagios.cfg" do
  not_if "grep '^interval_length=1$' /etc/nagios/nagios.cfg"
  notifies :reload, "service[nagios]", :delayed
end

package "nagios-plugins-nrpe"
