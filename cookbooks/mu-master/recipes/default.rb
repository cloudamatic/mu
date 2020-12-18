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

# XXX this is nonsense if we're not in AWS
instance_id = node.name
search_domains = ["platform-mu"]
if node['ec2']
  response = Net::HTTP.get_response(URI("http://169.254.169.254/latest/meta-data/instance-id"))
  instance_id = response.body
  search_domains = ["ec2.internal", "server.#{instance_id}.platform-mu", "platform-mu"]
elsif node['gce']
  instance_id = node['gce']['instance']['name']
  domains = node['gce']['instance']['hostname'].split(/\./)
  domains.shift
  search_domains = []
  begin
    search_domains << domains.join(".")+"."
    domains.shift
  end while domains.size > 1
  search_domains << "google.internal."
end

if ::File.exist?("/etc/sudoers.d/waagent")
  sshgroup = if node['platform'] == "centos"
    "centos"
  elsif node['platform'] == "ubuntu"
    "ubuntu"
  elsif node['platform'] == "windows"
    "windows"
  else
    "root"
  end
  
  File.readlines("/etc/sudoers.d/waagent").each { |l|
    l.chomp!
    user = l.sub(/ .*/, '')
    group sshgroup do
      members user
      append true
    end
  }
end

include_recipe 'mu-master::init'
include_recipe 'mu-master::basepackages'
include_recipe 'mu-master::firewall-holes'
include_recipe 'mu-master::ssl-certs'
include_recipe 'mu-master::vault'
include_recipe 'mu-tools::gcloud'
#include_recipe 'mu-master::kubectl'

master_ips = get_mu_master_ips
master_ips << "127.0.0.1"
master_ips.uniq!
master_ips.each { |host|
  firewall_rule "Mu Master ports for self (#{host})" do
    source "#{host}/32"
  end
  if host.match(/^(?:10\.|172\.(1[6789]|2[0-9]|3[01])\.|192\.168\.)/)
    hostsfile_entry host do
      hostname $MU_CFG['hostname']
      aliases [node.name, "MU-MASTER"]
      action :append
    end
  end
}

["#{$MU_CFG['installdir']}/etc/mu.yaml", "#{$MU_CFG['installdir']}/lib/Berksfile.lock"].each { |f|
  file f do
    mode 0644
  end
}

if !node['update_nagios_only']

  include_recipe 'chef-vault'
  if $MU_CFG.has_key?('ldap')
    if $MU_CFG['ldap']['type'] == "389 Directory Services" and Dir.exist?("/etc/dirsrv/slapd-#{$MU_CFG['hostname']}")
      include_recipe 'mu-master::sssd'
    elsif $MU_CFG['ldap']['type'] == "Active Directory"
      node.normal['ad'] = {}
      node.normal['ad']['computer_name'] = "MU-MASTER"
      node.normal['ad']['node_class'] = "mumaster"
      node.normal['ad']['node_type'] = "domain_node"
      node.normal['ad']['domain_operation'] = "join"
      node.normal['ad']['domain_name'] = $MU_CFG['ldap']['domain_name']
      search_domains << node.normal['ad']['domain_name']
      node.normal['ad']['netbios_name'] = $MU_CFG['ldap']['domain_netbios_name']
      node.normal['ad']['dcs'] = $MU_CFG['ldap']['dcs']
      node.normal['ad']['domain_join_vault'] = $MU_CFG['ldap']['join_creds']['vault']
      node.normal['ad']['domain_join_item'] = $MU_CFG['ldap']['join_creds']['item']
      node.normal['ad']['domain_join_username_field'] = $MU_CFG['ldap']['join_creds']['username_field']
      node.normal['ad']['domain_join_password_field'] = $MU_CFG['ldap']['join_creds']['password_field']
      if !node['application_attributes']['sshd_allow_groups'].match(/(^|\s)#{$MU_CFG['ldap']['user_group_name']}(\s|$)/i)
        node.normal['application_attributes']['sshd_allow_groups'] = node['application_attributes']['sshd_allow_groups']+" "+$MU_CFG['ldap']['user_group_name'].downcase
      end
      node.save
      include_recipe "mu-activedirectory::domain-node"
    end
  end

  execute "set Mu Master's hostname" do
    command "PATH=/bin:/usr/bin hostname #{$MU_CFG['hostname']}"
    not_if "PATH=/bin:/usr/bin hostname | grep '^#{$MU_CFG['hostname']}$'"
  end

  file "/etc/hostname" do
    content "#{$MU_CFG['hostname']}\n"
  end

  execute "updating hostname in /etc/sysconfig/network" do
    command "sed -i 's/^HOSTNAME=.*/HOSTNAME=#{$MU_CFG['hostname']}.platform-mu/' /etc/sysconfig/network"
    not_if "grep '^HOSTNAME=#{$MU_CFG['hostname']}.platform-mu'"
  end

  sudoer_line = "%#{$MU_CFG['ldap']['admin_group_name']} ALL=(ALL) NOPASSWD: ALL"
  execute "echo '#{sudoer_line}' >> /etc/sudoers" do
    not_if "grep '^#{sudoer_line}$' /etc/sudoers"
  end

  cookbook_file "/root/.vimrc" do
    source "vimrc"
    action :create_if_missing
  end

  file "/etc/profile.d/usr_local_bin.sh" do
    content "export PATH=\"${PATH}:/usr/local/bin\"\n"
    mode 0644
  end

  cookbook_file "/var/www/html/cloudamatic.png" do
    source "cloudamatic.png"
    mode 0644
  end

  package "nagios" do
    action :remove
  end

  # The Nagios cookbook will only rebuild if the main executable is missing, so
  # remove it if we've got a version bump coming down the pike.
  execute "remove old Nagios binary" do
    command "rm -f /usr/sbin/nagios"
    not_if "/usr/sbin/nagios -V | grep 'Nagios Core #{node['nagios']['server']['version']}'"
  end
end

include_recipe "mu-master::update_nagios_only"

if !node['update_nagios_only']

  package %w(nagios-plugins-breeze nagios-plugins-by_ssh nagios-plugins-cluster nagios-plugins-dhcp nagios-plugins-dig nagios-plugins-disk nagios-plugins-disk_smb nagios-plugins-dns nagios-plugins-dummy nagios-plugins-file_age nagios-plugins-flexlm nagios-plugins-fping nagios-plugins-game nagios-plugins-hpjd nagios-plugins-http nagios-plugins-icmp nagios-plugins-ide_smart nagios-plugins-ircd nagios-plugins-ldap nagios-plugins-load nagios-plugins-log nagios-plugins-mailq nagios-plugins-mrtg nagios-plugins-mrtgtraf nagios-plugins-nagios nagios-plugins-nt nagios-plugins-ntp nagios-plugins-ntp-perl nagios-plugins-nwstat nagios-plugins-oracle nagios-plugins-overcr nagios-plugins-pgsql nagios-plugins-ping nagios-plugins-procs nagios-plugins-real nagios-plugins-rpc nagios-plugins-sensors nagios-plugins-smtp nagios-plugins-snmp nagios-plugins-ssh nagios-plugins-swap nagios-plugins-tcp nagios-plugins-time nagios-plugins-ups nagios-plugins-users nagios-plugins-wave) do
    action :install
  end

  package %w(nagios-plugins-mysql) do
      action :install
      not_if { node['platform'] == 'amazon' }
  end

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
    my_name = $MU_CFG['public_address'].dup
    begin
      search_domains << my_name.dup
      my_name.sub!(/^[^\.]+?\./, "")
    end while my_name.match(/\./)
  end
  template "/etc/dhcp/dhclient-eth0.conf" do
    source "dhclient-eth0.conf.erb"
    mode 0644
    notifies :restart, "service[network]", :immediately unless %w{redhat centos}.include?(node['platform']) && node['platform_version'].to_i == 7
    variables(
      :search_domains => search_domains
    )
  end

  svrname = node['hostname']
  if !$MU_CFG['public_address'].match(/^\d+\.\d+\.\d+\.\d+$/)
    svrname = $MU_CFG['public_address']
  end

  apache2_mod_proxy ""
  apache2_mod_ldap ""
#  apache2_mod "proxy_http"
#  apache2_mod "rewrite"
#  apache2_mod "authnz_ldap"
  apache2_mod_cgid ""
  apache2_mod_ssl ""
  apache2_mod "php"

  # nagios keeps disabling the default vhost, so let's make another one
  apache2_default_site "" do
    action :disable
  end
  execute "Allow net connect to local for apache" do
    command "/usr/sbin/setsebool -P httpd_can_network_connect on"
    not_if "/usr/sbin/getsebool httpd_can_network_connect | grep -cim1 ^.*on$"
    not_if "/sbin/getenforce | grep -cim1  disabled"
    notifies :reload, "service[apache2]", :delayed
  end

  aliases = [node['fqdn'], node['hostname'], node['local_hostname'], node['local_ipv4'], node['public_hostname'], node['public_ipv4']]
  if node['ec2']
    aliases << node['ec2']['local_ipv4']
    aliases << node['ec2']['local_hostname']
    aliases << node['ec2']['public_ipv4']
    aliases << node['ec2']['public_hostname']
  end
  aliases.uniq!
  aliases.reject! { |a| a.nil? or a.empty? }

  service 'apache2' do
    extend Apache2::Cookbook::Helpers
    service_name lazy { apache_platform_service_name }
    supports restart: true, status: true, reload: true
    action :nothing
  end

  template '/etc/httpd/sites-available/mu_docs.conf' do
    variables(
      server_name: svrname,
      server_port: "80",
      server_aliases: aliases,
      docroot: "/var/www/html"
    )
    cookbook 'mu-master'
    source 'web_app.conf.erb'
    notifies :reload, "service[apache2]", :delayed
  end
  apache2_site "mu_docs"
  template '/etc/httpd/sites-available/https_proxy.conf' do
    variables(
      server_name: svrname,
      server_port: "443",
      server_aliases: aliases,
      docroot: "/var/www/html"
    )
    cookbook 'mu-master'
    source 'web_app.conf.erb'
    notifies :reload, "service[apache2]", :delayed
  end
  apache2_site "https_proxy"

#  apache2_conf "mu_docs" do
#    server_name svrname
#    server_aliases aliases
#    docroot "/var/www/html"
#    cookbook "mu-master"
#    notifies :reload, "service[apache2]", :delayed
#    action :enable
#  end
#  apache2_conf "https_proxy" do
#    server_name svrname
#    server_port "443"
#    server_aliases aliases
#    docroot "/var/www/html"
#    cookbook "mu-master"
#    notifies :reload, "service[apache2]", :delayed
#    action :enable
#  end

  # configure the appropriate authentication method for the web server
  case node['nagios']['server_auth_method']
  when 'openid'
    apache2_mod 'auth_openid'
  when 'cas'
    apache2_mod 'auth_cas'
  end

#  apache2_conf "nagios" do
#    server_name svrname
#    server_aliases aliases
#    template 'nagios.conf.erb'
#    cookbook "mu-master"
#    notifies :reload, "service[apache2]", :delayed
#    action :enable
#  end
  template '/etc/httpd/sites-available/nagios.conf' do
    variables(
      server_name: svrname,
      server_port: "443",
      server_aliases: aliases,
      docroot: "/var/www/html"
    )
    cookbook 'mu-master'
    source 'nagios.conf.erb'
    notifies :reload, "service[apache2]", :delayed
  end
  apache2_site "nagios"

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

  include_recipe "postfix"

  # Use a real hostname for mail if we happen to have one assigned
  if !MU.mu_public_addr.match(/^\d+\.\d+\.\d+\.\d+$/)
    node.normal['postfix']['main']['myhostname'] = MU.mu_public_addr
    node.normal['postfix']['main']['mydomain'] = MU.mu_public_addr.sub(/^.*?([^\.]+\.[^\.]+)$/, '\1')
    node.normal['postfix']['main']['myorigin'] = MU.mu_public_addr.sub(/^.*?([^\.]+\.[^\.]+)$/, '\1')
  else
    node.normal['postfix']['main']['myhostname'] = $MU_CFG['hostname']
    node.normal['postfix']['main']['mydomain'] = "platform-mu"
    node.normal['postfix']['main']['myorigin'] = "platform-mu"
  end
  node.normal['postfix']['main']['inet_interfaces'] = "all"
  node.save

  mubranch=`cd #{MU_BASE}/lib && git rev-parse --abbrev-ref HEAD` # ~FC048

  file "/var/www/html/index.html" do
    owner "apache"
    group "apache"
    content "

   <h1>This is a Mu Master server</h2>

  <p>
   <a href='https://#{MU.mu_public_addr}/nagios/'>Nagios monitoring GUI</a>
  </p>
  <p>
   <a href='#{(mubranch.nil? or mubranch == "master" or mubranch.match(/detached from/)) ? "https://cloudamatic.gitlab.io/mu/" : "http://"+MU.mu_public_addr+"/docs"}'>Mu API documentation</a>
  </p>
  "
  end

  execute "echo 'devnull: /dev/null' >> /etc/aliases" do
    not_if "grep '^devnull: /dev/null$' /etc/aliases"
  end

  directory "/Mu_Logs"

  include_recipe "mu-tools::rsyslog"

  cookbook_file "0-mu-log-server.conf" do
    path "/etc/rsyslog.d/0-mu-log-server.conf"
    notifies :restart, "service[rsyslog]", :delayed
  end
  file "0-mu-log-client.conf" do
    path "/etc/rsyslog.d/0-mu-log-client.conf"
    action :delete
    notifies :restart, "service[rsyslog]", :delayed
  end

  execute "echo '/sbin/restorecon -r /home' >> /etc/rc.d/rc.local" do
    not_if "grep '^/sbin/restorecon -r /home' /etc/rc.d/rc.local"
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

  package "logrotate"

  file "/etc/logrotate.d/Mu_audit_logs" do
    content "/Mu_Logs/master.log
  /Mu_Logs/nodes.log
  {
    sharedscripts
    daily
    delaycompress
    postrotate
      #{MU.myRoot}/bin/mu-aws-setup -u
      /bin/kill -HUP `cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true
    endscript
  }
  "
  end

# XXX this will catch the occasional 4am groom. Need a way to graceful-restart momma.
  file "/etc/logrotate.d/Mu_momma_cat" do
    content "/var/log/mu-momma-cat.log
  {
    sharedscripts
    size 100M
    delaycompress
    postrotate
      /etc/init.d/mu-momma-cat restart
    endscript
  }
  "
  end

  template "#{MU.etcDir}/mu.rc" do
    source "mu.rc.erb"
    mode 0644
    owner "root"
    variables(
      :installdir => MU.installDir,
      :repos => MU.muCfg['repos']
    )
    not_if { ::File.size?("#{MU.etcDir}/mu.rc") }
  end

  execute "source #{MU.etcDir}/mu.rc from root dotfiles" do
    command "echo 'source #{MU.etcDir}/mu.rc' >> #{Etc.getpwnam("root").dir}/.bashrc"
    not_if "test -f #{Etc.getpwnam("root").dir}/.bashrc && grep '^source #{MU.etcDir}/mu.rc$' #{Etc.getpwnam("root").dir}/.bashrc"
  end

  begin
    resources('service[sshd]')
  rescue Chef::Exceptions::ResourceNotFound
    service "sshd" do
      action [:enable, :start]
    end
  end

  template "Mu Master /etc/ssh/sshd_config" do
    path "/etc/ssh/sshd_config"
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

  # XXX bug in Chef vault is current purging basically all clients
  cron "Rotate vault keys and purge MIA clients" do
    action :delete
    minute "10"
    hour "6"
    user "root"
    command "/opt/mu/bin/knife vault rotate all keys --clean-unknown-clients"
  end

  # TODO fine if we're SysV-compatible, but cover the other guys
  template "/etc/init.d/mu-momma-cat" do
    source "mu-momma-cat.erb"
    variables(
      :installdir => MU.installDir,
      :ssl_key => $MU_CFG['ssl']['key'],
      :ssl_cert => $MU_CFG['ssl']['cert'],
    )
    mode 0755
  end
  link "/opt/mu/bin/mu-momma-cat" do
    to "/etc/init.d/mu-momma-cat"
  end
  service "mu-momma-cat" do
    action [:enable, :start]
  end

  # This is stuff that can break for no damn reason at all
  include_recipe "mu-tools::cloudinit"


  begin
    node.normal['mu']['user_map'] = MU::Master.listUsers
    node.normal['mu']['user_list'] = []
    node['mu']['user_map'].each_pair { |user, data|
      node.normal['mu']['user_list'] << "#{user} (#{data['email']})"
    }
    node.save
  
    file "/root/.gitconfig" do
      content "[user]
        name = #{node['mu']['user_map']['mu']['realname']}
        email = #{node['mu']['user_map']['mu']['email']}
[push]
        default = current
"
    end
  
    # XXX placeholder- we should have a "federal" flag which invokes
    # mu-tools::apply_security, which has its own gov-compliant /etc/issue.net
    # The one that ships on CentOS images seems incorrect, so nuking it for now
    file "/etc/issue.net" do
      action :delete  
    end

    node['mu']['user_map'].each_pair { |mu_user, data|
      execute "echo '#{mu_user}: #{data['email']}' >> /etc/aliases" do
        not_if "grep '^#{mu_user}: #{data['email']}$' /etc/aliases"
      end
    }

    file "/etc/motd" do
      content "
*******************************************************************************

 This is a Mu Master server. Mu is installed in #{MU.myRoot}.

 Nagios monitoring GUI: https://#{MU.mu_public_addr}/nagios/

 Mu API documentation: #{(mubranch.nil? or mubranch == "master" or mubranch.match(/detached from/)) ? "https://cloudamatic.gitlab.io/mu/" : "http://"+MU.mu_public_addr+"/docs"}

 Mu metadata are stored in #{MU.mainDataDir}

 Users: #{node['mu']['user_list'].join(", ")}

*******************************************************************************

"
    end
  rescue Exception
    log "Can't list users" do
      message "Doesn't seem like I can list available users. Hopefully this is initial setup."
      level :warn
    end
  end
end
