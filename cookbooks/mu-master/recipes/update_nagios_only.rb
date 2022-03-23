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

include_recipe "mu-nagios::server_source"
include_recipe "mu-nagios"
include_recipe 'mu-master::firewall-holes'

log "#{node['recipes']}"

# Define this so it's present for solo runs of this recipe
if !node['recipes'].include?("mu-master::default") or node['update_nagios_only']
  service 'apache2' do
    extend Apache2::Cookbook::Helpers
    service_name lazy { apache_platform_service_name }
    supports restart: true, status: true, reload: true
    action :enable
  end
end

if $MU_CFG['disable_nagios']
  log "Ignoring Nagios setup per Mu config"
else
  if $MU_CFG.has_key?('ldap')
    include_recipe 'chef-vault'
    bind_creds = chef_vault_item($MU_CFG['ldap']['bind_creds']['vault'], $MU_CFG['ldap']['bind_creds']['item'])
    node.normal['nagios']['server_auth_method'] = "ldap"
    node.normal['nagios']['ldap_bind_dn'] = bind_creds[$MU_CFG['ldap']['bind_creds']['username_field']]
    node.normal['nagios']['ldap_bind_password'] = bind_creds[$MU_CFG['ldap']['bind_creds']['password_field']]
    if $MU_CFG['ldap']['type'] == "Active Directory"
      node.normal['nagios']['ldap_url'] = "ldap://#{$MU_CFG['ldap']['dcs'].first}/#{$MU_CFG['ldap']['base_dn']}?sAMAccountName?sub?(objectClass=*)"
    else
      node.normal['nagios']['ldap_url'] = "ldap://#{$MU_CFG['ldap']['dcs'].first}/#{$MU_CFG['ldap']['base_dn']}?uid?sub?(objectClass=*)"
      node.normal['nagios']['ldap_group_attribute'] = "memberUid"
      node.normal['nagios']['ldap_group_attribute_is_dn'] = "Off"
  # Trying to use SSL seems to cause mod_ldap to die without logging any errors,
  # currently. Probably an Apache bug? XXX
  #    node.normal['nagios'][:ldap_trusted_global_cert] = "CA_BASE64 #{$MU_CFG['ssl']['chain']}"
  #    node.normal['nagios'][:ldap_trusted_mode] = "SSL"
    end
    node.normal['nagios']['server_auth_require'] = "ldap-group #{$MU_CFG['ldap']['user_group_dn']}"
    node.normal['nagios']['ldap_authoritative'] = "On"
    node.save
  end

  # XXX The Nagios init script from source is buggy; config test always fails
  # when invoked via "service nagios start," which is what the cookbook does.
  # This at least keeps it from trashing our Chef runs.
  file "/etc/sysconfig/nagios" do
    content "checkconfig=\"false\"\n"
    mode 0600
  end
  include_recipe "mu-nagios"

  # scrub our old stuff if it's around
  ["nagios_fifo", "nagios_more_selinux"].each { |policy|
    execute "/usr/sbin/semodule -r #{policy}" do
      only_if "/usr/sbin/semodule -l | egrep '^#{policy}(\t|$)'"
    end
  }

  nagios_policies = ["nagios_selinux"]

  if platform_family?("rhel") and node['platform_version'].to_i == 7
    nagios_policies << "nagios_selinux_7"
  end

  # Restart Nagios inelegantly, because the standard service resource doesn't
  # seem to work reliably on CentOS 7 or RHEL 7. May be an issue with the nagios
  # community cookbook? Maybe it doesn't do systemctl correctly?
  bash "RHEL7-family Nagios restart" do
    code <<-EOH
      /bin/systemctl stop nagios.service
      /bin/pkill -u nagios
      /bin/rm -f /var/run/nagios/nagios.pid
      /bin/systemctl start nagios.service
    EOH
    action :nothing
  end

  nagios_policies.each { |policy|
    execute "/usr/sbin/semodule -r #{policy}" do
      action :nothing
      only_if "/usr/sbin/semodule -l | egrep '^#{policy}(\t|$)'"
    end
    cookbook_file "#{policy}.pp" do
      path "#{Chef::Config[:file_cache_path]}/#{policy}.pp"
      notifies :run, "execute[/usr/sbin/semodule -r #{policy}]", :immediately
    end
    execute "Add Nagios-related SELinux policies: #{policy}" do
      command "/usr/sbin/semodule -i #{policy}.pp"
      cwd Chef::Config[:file_cache_path]
      not_if "/usr/sbin/semodule -l | egrep '^#{policy}(\t|$)'"
      notifies :reload, "service[apache2]", :delayed
      notifies :restart, "service[nrpe]", :delayed
      if platform_family?("rhel") and node['platform_version'].to_i >= 7
        notifies :run, "bash[RHEL7-family Nagios restart]", :delayed
      else
        notifies :reload, "service[nagios]", :delayed
      end
    end
  }

  # Workaround for minor Nagios (cookbook?) bug. It looks for this at the wrong
  # URL at the moment, so copy it where it's actually looking.
  if File.exist?("/usr/lib/cgi-bin/nagios/statusjson.cgi")
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

  # Fish up any non-Chef hosts, which otherwise won't appear in Chef's
  # inventory, and tell Nagios about them.
  non_chef = {}
  baskets.each_pair { |deploy_id, basket|
    if basket["servers"]
      basket["servers"].each { |server|
        next if server["groomer"] == "Chef"
        non_chef[deploy_id] ||= []
        non_chef[deploy_id] << server
      }
    end
    if basket["server_pools"]
      basket["server_pools"].each { |pool|
        next if pool["groomer"] == "Chef"
        non_chef[deploy_id] ||= []
        non_chef[deploy_id] << pool
      }
    end
  }
  deploy_metadata = deployments()
  non_chef.each_pair { |deploy_id, servers|
    servers.each { |server_blob|
      servername = server_blob["name"]
      platform = server_blob["platform"] =~ /^win/ ? "windows" : "linux"
      deploy_metadata[deploy_id]['servers'][servername].each_pair { |mu_name, server|
        nagios_host mu_name do
          options(
            "hostgroups" => ([platform] + server["run_list"] + ["mu-node"] + [deploy_metadata[deploy_id]["environment"]]).join(","),
            "address" => server["private_ip_address"]
          )
        end
      }
    }
  }

  ["/usr/lib/nagios", "/etc/nagios", "/etc/nagios3", "/var/www/html/docs"].each { |dir|
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
      execute "chcon -R -t httpd_sys_script_exec_t #{cgidir}" do
        not_if "ls -aZ #{cgidir} | grep ':httpd_sys_script_exec_t:'"
        notifies :reload, "service[apache2]", :delayed
      end
    end
  }
  if File.exist?("/usr/lib64/nagios/plugins/check_nagios")
    execute "chcon -R -h system_u:object_r:nagios_unconfined_plugin_exec_t /usr/lib64/nagios/plugins/check_nagios" do
      not_if "ls -aZ /usr/lib64/nagios/plugins/check_nagios | grep 'object_r:nagios_'"
    end
  end

  # execute "chgrp apache /var/log/nagios"
  ["/etc/nagios/conf.d/", "/etc/nagios/*.cfg", "/var/run/nagios.pid"].each { |dir|
    execute "/sbin/restorecon -R #{dir}" do
      not_if "ls -aZ #{dir} | grep ':nagios_etc_t:'"
      only_if { ::File.exist?(dir) }
    end
  }

  execute "/sbin/restorecon -R /var/log/nagios"

  # The Nagios cookbook currently screws up this setting, so work around it.
  execute "sed -i s/^interval_length=.*/interval_length=1/ || echo 'interval_length=1' >> /etc/nagios/nagios.cfg" do
    not_if "grep '^interval_length=1$' /etc/nagios/nagios.cfg"
    if platform_family?("rhel") and node['platform_version'].to_i >= 7
      notifies :run, "bash[RHEL7-family Nagios restart]", :delayed
    else
      notifies :reload, "service[nagios]", :delayed
    end
  end

  package "nagios-plugins-nrpe"
  package "nagios-plugins-disk"
  include_recipe "mu-tools::nrpe"

  cookbook_file "/usr/lib64/nagios/plugins/check_mem" do
    source "check_mem.pl"
    mode 0755
    owner "root"
    notifies :restart, "service[nrpe]", :delayed
  end

  cookbook_file "/usr/lib64/nagios/plugins/check_elastic" do
    source "check_elastic.sh"
    mode 0755
    owner "root"
  end

  cookbook_file "/usr/lib64/nagios/plugins/check_kibana" do
    source "check_kibana.rb"
    mode 0755
    owner "root"
  end

  nagios_command "check_elastic" do
    options 'command_line' => %Q{$USER1$/check_elastic -H $HOSTADDRESS$ -t status -S -u $ARG1$ -p $ARG2$}
  end

  nagios_command "check_kibana" do
    options 'command_line' => %Q{$USER1$/check_kibana -h $HOSTADDRESS$ -u $ARG1$ -p $ARG2$}
  end


  file "/etc/sysconfig/nrpe" do
    content "NRPE_SSL_OPT=\"\"\n"
  end

  # Sometimes doesn't exist on the first run
  directory "/opt/mu/var/nagios_user_home" do
    owner "nagios"
  	group "nagios"
  	mode 0700
  end

  directory "/opt/mu/var/nagios_user_home/.ssh" do
    owner "nagios"
  	group "nagios"
  	mode 0711
  end
  file "/opt/mu/var/nagios_user_home/.ssh/known_hosts" do
    owner "nagios"
  	group "nagios"
  	mode 0600
  end
  file "/opt/mu/var/nagios_user_home/.ssh/known_hosts2" do
    owner "nagios"
  	group "nagios"
  	mode 0600
  end


  nrpe_check "check_mem" do
    command "#{node['nrpe']['plugin_dir']}/check_mem"
    warning_condition '80'
    critical_condition '95'
    action :add
  end

  nagios_command 'host_notify_by_email' do
    options 'command_line' => '/usr/bin/printf "%b" "$LONGDATETIME$\n\n$HOSTALIAS$ $NOTIFICATIONTYPE$ $HOSTSTATE$ ('+$MU_CFG['hostname']+')\n\n$HOSTOUTPUT$\n\nLogin: ssh://$HOSTNAME$" | ' + node['nagios']['server']['mail_command'] + ' -s "$NOTIFICATIONTYPE$ - $HOSTALIAS$ $HOSTSTATE$! ('+$MU_CFG['hostname']+')" $CONTACTEMAIL$'
  end

  nagios_command 'service_notify_by_email' do
    options 'command_line' => '/usr/bin/printf "%b" "$LONGDATETIME$ - $SERVICEDESC$ $SERVICESTATE$ ('+$MU_CFG['hostname']+')\n\n$HOSTALIAS$  $NOTIFICATIONTYPE$\n\n$SERVICEOUTPUT$\n\nLogin: ssh://$HOSTNAME$" | ' + node['nagios']['server']['mail_command'] + ' -s "** $NOTIFICATIONTYPE$ - $HOSTALIAS$ - $SERVICEDESC$ - $SERVICESTATE$ ('+$MU_CFG['hostname']+')" $CONTACTEMAIL$'
  end

  nagios_command 'host_notify_by_sms_email' do
    options 'command_line' => '/usr/bin/printf "%b" "$HOSTALIAS$ $NOTIFICATIONTYPE$ $HOSTSTATE$ ('+$MU_CFG['hostname']+')\n\n$HOSTOUTPUT$" | ' + node['nagios']['server']['mail_command'] + ' -s "$HOSTALIAS$ $HOSTSTATE$! ('+$MU_CFG['hostname']+')" $CONTACTPAGER$'
  end

  nagios_command 'service_notify_by_sms_email' do
    options 'command_line' => '/usr/bin/printf "%b" "$SERVICEDESC$ $NOTIFICATIONTYPE$ $SERVICESTATE$ ('+$MU_CFG['hostname']+')\n\n$SERVICEOUTPUT$" | ' + node['nagios']['server']['mail_command'] + ' -s "$HOSTALIAS$ $SERVICEDESC$ $SERVICESTATE$! ('+$MU_CFG['hostname']+')" $CONTACTPAGER$'
  end

  execute "chgrp nrpe /etc/nagios/nrpe.d/*"
  execute "/sbin/restorecon /etc/nagios/nrpe.cfg" do
    if platform_family?("rhel") and node['platform_version'].to_i >= 7
      notifies :run, "bash[RHEL7-family Nagios restart]", :delayed
    end
  end
  include_recipe "mu-master::init" # gem permission fixes, mainly
end
