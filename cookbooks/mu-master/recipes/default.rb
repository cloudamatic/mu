#
# Cookbook Name:: mu-master
# Recipe:: default
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

response = Net::HTTP.get_response(URI("http://169.254.169.254/latest/meta-data/instance-id"))
instance_id = response.body
search_domains = ["ec2.internal", "server.#{instance_id}.platform-mu", "platform-mu"]

if $MU_CFG.has_key?('ldap')
  include_recipe 'chef-vault'
  if $MU_CFG['ldap']['type'] == "389 Directory Services" and Dir.exists?("/etc/dirsrv/slapd-#{$MU_CFG['hostname']}")
    package "pam_ldap"
    package "nss-pam-ldapd"
    service "nslcd" do
      action [:enable, :start]
    end
    package "oddjob-mkhomedir"
    execute "restorecon -r /usr/sbin"
    service "oddjobd" do
      start_command "sh -x /etc/init.d/oddjobd start" # seems to actually work
      action [:enable, :start]
    end
    execute "/usr/sbin/authconfig --enableldap --enableldapauth --disablenis --enablecache --ldapserver=#{$MU_CFG['ldap']['dcs'].first} --ldapbasedn=\"#{$MU_CFG['ldap']['base_dn']}\" --disablewinbind --disablewinbindauth --enablemkhomedir --disablekrb5 --enableldaptls --updateall"
    template "/etc/pam_ldap.conf" do
      source "pam_ldap.conf.erb"
      mode 0644
      variables(
        :base_dn => $MU_CFG['ldap']['base_dn'],
        :dc => $MU_CFG['ldap']['dcs'].first
      )
    end
    template "/etc/nslcd.conf" do
      source "nslcd.conf.erb"
      mode 0600
      notifies :restart, "service[nslcd]", :immediately
      variables(
        :base_dn => $MU_CFG['ldap']['base_dn'],
        :dc => $MU_CFG['ldap']['dcs'].first
      )
    end
  elsif $MU_CFG['ldap']['type'] == "Active Directory"
    node.normal.ad = {}
    node.normal.ad.computer_name = "MU-MASTER"
    node.normal.ad.node_class = "mumaster"
    node.normal.ad.node_type = "domain_node"
    node.normal.ad.domain_operation = "join"
    node.normal.ad.domain_name = $MU_CFG['ldap']['domain_name']
    search_domains << node.normal.ad.domain_name
    node.normal.ad.netbios_name = $MU_CFG['ldap']['domain_netbios_name']
    node.normal.ad.dcs = $MU_CFG['ldap']['dcs']
    node.normal.ad.domain_join_vault = $MU_CFG['ldap']['join_creds']['vault']
    node.normal.ad.domain_join_item = $MU_CFG['ldap']['join_creds']['item']
    node.normal.ad.domain_join_username_field = $MU_CFG['ldap']['join_creds']['username_field']
    node.normal.ad.domain_join_password_field = $MU_CFG['ldap']['join_creds']['password_field']
    if !node.application_attributes.sshd_allow_groups.match(/(^|\s)#{$MU_CFG['ldap']['user_group_name']}(\s|$)/i)
      node.normal.application_attributes.sshd_allow_groups = node.application_attributes.sshd_allow_groups+" "+$MU_CFG['ldap']['user_group_name'].downcase
    end
    node.save
    log "'#{node.ad.domain_join_vault}' '#{node.ad.domain_join_item}' '#{node.ad.domain_join_username_field}' '#{node.ad.domain_join_password_field}'"
    include_recipe "mu-activedirectory::domain-node"
  end
end

directory "#{MU.mainDataDir}/deployments"

sudoer_line = "%#{$MU_CFG['ldap']['admin_group_name']} ALL=(ALL) NOPASSWD: ALL"
execute "echo '#{sudoer_line}' >> /etc/sudoers" do
  not_if "grep '^#{sudoer_line}$' /etc/sudoers"
end

cookbook_file "/root/.vimrc" do
  source "vimrc"
  action :create_if_missing
end

package "nagios" do
  action :remove
end

# The Nagios cookbook will only rebuild if the main executable is missing, so
# remove it if we've got a version bump coming down the pike.
execute "remove old Nagios binary" do
  command "rm -f /usr/sbin/nagios"
  not_if "/usr/sbin/nagios -V | grep 'Nagios Core #{node.nagios.server.version}'"
end
include_recipe "nagios::server_source"
include_recipe "nagios"

package "nagios-plugins-all"

directory "/home/nagios" do
  owner "nagios"
  mode 0711
end

directory "/home/nagios/.ssh" do
  owner "nagios"
  mode 0711
end

file "/home/nagios/.ssh/config" do
  owner "nagios"
  mode 0600
end

execute "dhclient-script" do
  command "/sbin/dhclient-script"
  action :nothing
end

service "network" do
  action :nothing
end

if !$MU_CFG['public_address'].match(/^\d+\.\d+\.\d+\.\d+$/)
  my_name = $MU_CFG['public_address']
  begin
    search_domains << my_name.dup
    my_name.sub!(/^[^\.]+?\./, "")
  end while my_name.match(/\./)
end
template "/etc/dhcp/dhclient-eth0.conf" do
  source "dhclient-eth0.conf.erb"
  mode 0644
  notifies :restart, "service[network]", :immediately unless %w{redhat centos}.include?(node.platform) && node.platform_version.to_i == 7
  variables(
    :search_domains => search_domains
  )
end

# nagios keeps disabling the default vhost, so let's make another one
web_app "mu_docs" do
  server_name node.hostname
  server_aliases [node.fqdn, node.hostname, node['local_hostname'], node['local_ipv4'], node['public_hostname'], node['public_ipv4']]
  docroot "/var/www/html"
  cookbook "mu-master"
end
web_app "https_proxy" do
  server_name node.hostname
  server_port "443"
  server_aliases [node.fqdn, node.hostname, node['local_hostname'], node['local_ipv4'], node['public_hostname'], node['public_ipv4']]
  docroot "/var/www/html"
  cookbook "mu-master"
end

link "/etc/nagios3" do
  to "/etc/nagios"
  notifies :reload, "service[apache2]", :delayed
end

directory "/usr/lib64/nagios"

link "/usr/lib64/nagios/cgi-bin" do
  to "/usr/lib/cgi-bin"
  notifies :reload, "service[apache2]", :delayed
end

directory "/var/www/html/docs" do
  owner "apache"
  group "apache"
end

include_recipe "mu-master::update_nagios_only"

remote_file "/etc/httpd/ssl/nagios.crt" do
  source "file:///#{MU.mainDataDir}/ssl/nagios.crt"
  mode 0444
end

remote_file "/etc/httpd/ssl/nagios.key" do
  source "file:///#{MU.mainDataDir}/ssl/nagios.key"
  mode 0400
end

include_recipe "postfix"

# Use a real hostname for mail if we happen to have one assigned
if !MU.mu_public_addr.match(/^\d+\.\d+\.\d+\.\d+$/)
  node.normal.postfix.main.myhostname = MU.mu_public_addr
  node.normal.postfix.main.mydomain = MU.mu_public_addr.sub(/^.*?([^\.]+\.[^\.]+)$/, '\1')
  node.normal.postfix.main.myorigin = MU.mu_public_addr.sub(/^.*?([^\.]+\.[^\.]+)$/, '\1')
end
node.normal.postfix.main.inet_interfaces = "all"
node.save

file "/etc/motd" do
  content "
*******************************************************************************

 This is a Mu Master server. Mu is installed in #{MU.myRoot}.

 Nagios monitoring GUI: https://#{MU.mu_public_addr}/nagios/

 Jenkins interface GUI: https://#{MU.mu_public_addr}:9443/

 Mu API documentation: http://#{MU.mu_public_addr}/docs/frames.html

 Mu metadata are stored in #{MU.mainDataDir}

 Users: #{node.mu.user_list}

*******************************************************************************

"
end

file "/var/www/html/index.html" do
  owner "apache"
  group "apache"
  content "

 <h1>This is a Mu Master server</h2>

<p>
 <a href='https://#{MU.mu_public_addr}/nagios/'>Nagios monitoring GUI</a>
</p>
<p>
 <a href='https://#{MU.mu_public_addr}:443/'>Jenkins interface GUI</a>
</p>
<p>
 <a href='http://#{MU.mu_public_addr}/docs/frames.html'>Mu API documentation</a>
</p>
"
end

execute "echo 'devnull: /dev/null' >> /etc/aliases" do
  not_if "grep '^devnull: /dev/null$' /etc/aliases"
end

node.mu.user_map.each_pair { |mu_user, mu_email|
  execute "echo '#{mu_user}: #{mu_email}' >> /etc/aliases" do
    not_if "grep '^#{mu_user}: #{mu_email}$' /etc/aliases"
  end
}
execute "/usr/bin/newaliases"

include_recipe "mu-tools::aws_api"

ruby_block "create_logs_volume" do
  extend CAPVolume
  block do
    require 'aws-sdk-core'
    if !File.open("/etc/mtab").read.match(/ #{node.application_attributes.logs.mount_directory} /) and !volume_attached(node.application_attributes.logs.mount_device)
      create_node_volume("logs")
      result = attach_node_volume("logs")
    end
  end
  notifies :restart, "service[rsyslog]", :delayed
end

directory "/Mu_Logs"

ruby_block "mount_logs_volume" do
  extend CAPVolume
  block do
    if !File.open("/etc/mtab").read.match(/ #{node.application_attributes.logs.mount_directory} /)
      ebs_keyfile = node.application_attributes.logs.ebs_keyfile
      temp_dev = "/dev/ram7"
      temp_mount = "/tmp/ram7"

      if File.open("/proc/mounts").read.match(/ #{temp_mount} /)
        destroy_temp_disk(temp_dev)
      end

      make_temp_disk!(temp_dev, temp_mount)
      s3 = Aws::S3::Client.new

      begin
        resp = s3.get_object(bucket: node.application_attributes.logs.secure_location, key: "log_vol_ebs_key")
      rescue Exception => e
        Chef::Log.info(e.inspect)
        destroy_temp_disk(temp_dev)
        raise e
      end

      if resp.body.nil? or resp.body.size == 0
        destroy_temp_disk(temp_dev)
        raise "Couldn't fetch log volume key #{node.application_attributes.logs.secure_location}:/log_vol_ebs_key"
      end

      ebs_key_handle = File.new("#{temp_mount}/log_vol_ebs_key", File::CREAT|File::TRUNC|File::RDWR, 0400)
      ebs_key_handle.puts resp.body
      ebs_key_handle.close
      mount_node_volume("logs", "#{temp_mount}/log_vol_ebs_key")
      destroy_temp_disk(temp_dev)
    end
  end
  notifies :restart, "service[rsyslog]", :delayed
end

ruby_block "label #{node.application_attributes.logs.mount_device} as #{node.application_attributes.logs.label}" do
  extend CAPVolume
  block do
    tags = [{key: "Name", value: node.application_attributes.logs.label}]
    tag_volume(node.application_attributes.logs.mount_device, tags)
  end
end rescue NoMethodError

ruby_block "label /dev/sda1 as #{node.hostname} /" do
  extend CAPVolume
  block do
    tags = [{key: "Name", value: "#{node.hostname} /"}]
    tag_volume("/dev/sda1", tags)
  end
end rescue NoMethodError

include_recipe "mu-tools::rsyslog"

cookbook_file "0-mu-log-server.conf" do
  path "/etc/rsyslog.d/0-mu-log-server.conf"
  notifies :restart, "service[rsyslog]", :delayed
end

execute "echo '/opt/chef/bin/chef-client' >> /etc/rc.d/rc.local" do
  not_if "grep ^/opt/chef/bin/chef-client /etc/rc.d/rc.local"
end

directory "/etc/pki/rsyslog"
["Mu_CA.pem", "rsyslog.crt", "rsyslog.key"].each { |file|
  execute "install rsyslog SSL cert file #{file}" do
    command "cp -f #{MU.mainDataDir}/ssl/#{file} /etc/pki/rsyslog/#{file} && chmod 400 /etc/pki/rsyslog/#{file}"
    not_if "diff #{MU.mainDataDir}/ssl/#{file} /etc/pki/rsyslog/#{file}"
  end
}

execute "chcon -R -h -t var_log_t /Mu_Logs" do
  not_if "ls -aZ /Mu_Logs | grep ':var_log_t:'"
  notifies :restart, "service[rsyslog]", :delayed
end

package "logrotate"

file "/etc/logrotate.d/Mu_audit_logs" do
  content "/Mu_Logs/master.log
/Mu_Logs/nodes.log
{
  sharedscripts
  daily
  delaycompress
  postrotate
    #{MU.mainDataDir}/bin/mu-aws-setup -u
    /bin/kill -HUP `cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true
  endscript
}
"
end

service "sshd" do
  action :nothing
end

template "/etc/ssh/sshd_config" do
  source "sshd_config.erb"
  mode 0600
  owner "root"
  group "root"
  notifies :reload, "service[sshd]", :delayed
  cookbook "mu-tools"
end

cron "Sync client firewall allow rules" do
  action :create
  minute "10"
  user "root"
  command "#{MU.installDir}/bin/mu-firewall-allow-clients"
end

cron "Rotate vault keys and purge MIA clients" do
  action :create
  minute "10"
  hour "6"
  user "root"
  command "/opt/mu/bin/knife vault rotate all keys --clean-unknown-clients"
end

# This is stuff that can break for no damn reason at all
include_recipe "mu-utility::cloudinit"
