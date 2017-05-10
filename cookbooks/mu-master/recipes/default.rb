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

include_recipe 'mu-master::firewall-holes'
include_recipe 'mu-master::vault'

master_ips = get_mu_master_ips
master_ips << "127.0.0.1"
master_ips.uniq!
master_ips.each { |host|
  firewall_rule "Mu Master ports for self (#{host})" do
    source "#{host}/32"
  end
}

if !node.update_nagios_only

  service "sshd" do
    action :nothing
  end

  include_recipe 'chef-vault'
  if $MU_CFG.has_key?('ldap')
    if $MU_CFG['ldap']['type'] == "389 Directory Services" and Dir.exists?("/etc/dirsrv/slapd-#{$MU_CFG['host_name']}")
      include_recipe "389ds"

      package "sssd"
      package "sssd-ldap"
      package "nss-pam-ldapd" do
        action :remove
      end
      package "pam_ldap" do
        action :remove
      end
      service "messagebus" do
        action [:enable, :start]
      end
      package "nscd"
      service "nscd" do
        action [:disable, :stop]
      end
      package "oddjob-mkhomedir"
      execute "restorecon -r /usr/sbin"

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
      execute "/usr/sbin/authconfig --disablenis --disablecache --disablewinbind --disablewinbindauth --enablemkhomedir --disablekrb5 --enablesssd --enablesssdauth --enablelocauthorize --disableforcelegacy --disableldap --disableldapauth --updateall" do
        notifies :restart, "service[oddjobd]", :immediately
        notifies :reload, "service[sshd]", :delayed
        not_if "grep pam_sss.so /etc/pam.d/password-auth"
      end
      service "sssd" do
        action :nothing
        notifies :restart, "service[sshd]", :immediately
      end
      template "/etc/sssd/sssd.conf" do
        source "sssd.conf.erb"
        mode 0600
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

  #    cookbook_file "/etc/pam.d/sshd" do
  #      source "pam_sshd"
  #      mode 0644
  #      notifies :reload, "service[sshd]", :delayed
  #    end

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

  execute "set Mu Master's hostname" do
    command "/bin/hostname #{$MU_CFG['hostname']}"
    not_if "/bin/hostname | grep '^#{$MU_CFG['hostname']}$'"
  end
  execute "updating hostname in /etc/sysconfig/network" do
    command "sed -i 's/^HOSTNAME=.*/HOSTNAME=#{$MU_CFG['hostname']}.platform-mu/' /etc/sysconfig/network"
    not_if "grep '^HOSTNAME=#{$MU_CFG['hostname']}.platform-mu'"
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
    not_if "/usr/sbin/nagios -V | grep 'Nagios Core #{node.nagios.server.version}'"
  end
end

include_recipe "mu-master::update_nagios_only"

if !node.update_nagios_only
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
    my_name = $MU_CFG['public_address'].dup
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

  svrname = node.hostname
  if !$MU_CFG['public_address'].match(/^\d+\.\d+\.\d+\.\d+$/)
    svrname = $MU_CFG['public_address']
  end

  # nagios keeps disabling the default vhost, so let's make another one
  include_recipe "apache2::mod_proxy"
  include_recipe "apache2::mod_proxy_http"
  include_recipe "apache2::mod_rewrite"
  include_recipe "apache2::mod_ldap"
  include_recipe "apache2::mod_authnz_ldap"
  apache_site "default" do
    enable false
  end
  execute "Allow net connect to local for apache" do
    command "/usr/sbin/setsebool -P httpd_can_network_connect on"
    not_if "/usr/sbin/getsebool httpd_can_network_connect | grep -cim1 ^.*on$"
    notifies :reload, "service[apache2]", :delayed
  end

  web_app "mu_docs" do
    server_name svrname
    server_aliases [node.fqdn, node.hostname, node['local_hostname'], node['local_ipv4'], node['public_hostname'], node['public_ipv4']]
    docroot "/var/www/html"
    cookbook "mu-master"
    notifies :reload, "service[apache2]", :delayed
  end
  web_app "https_proxy" do
    server_name svrname
    server_port "443"
    server_aliases [node.fqdn, node.hostname, node['local_hostname'], node['local_ipv4'], node['public_hostname'], node['public_ipv4']]
    docroot "/var/www/html"
    cookbook "mu-master"
    notifies :reload, "service[apache2]", :delayed
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

  include_recipe "postfix"

  # Use a real hostname for mail if we happen to have one assigned
  if !MU.mu_public_addr.match(/^\d+\.\d+\.\d+\.\d+$/)
    node.normal[:postfix][:main][:myhostname] = MU.mu_public_addr
    node.normal[:postfix][:main][:mydomain] = MU.mu_public_addr.sub(/^.*?([^\.]+\.[^\.]+)$/, '\1')
    node.normal[:postfix][:main][:myorigin] = MU.mu_public_addr.sub(/^.*?([^\.]+\.[^\.]+)$/, '\1')
  else
    node.normal[:postfix][:main][:myhostname] = $MU_CFG['hostname']
    node.normal[:postfix][:main][:mydomain] = "platform-mu"
    node.normal[:postfix][:main][:myorigin] = "platform-mu"
  end
  node.normal[:postfix][:main][:inet_interfaces] = "all"
  node.save


  file "/var/www/html/index.html" do
    owner "apache"
    group "apache"
    content "

   <h1>This is a Mu Master server</h2>

  <p>
   <a href='https://#{MU.mu_public_addr}/nagios/'>Nagios monitoring GUI</a>
  </p>
  <p>
   <a href='https://#{MU.mu_public_addr}/jenkins/'>Jenkins interface GUI</a>
  </p>
  <p>
   <a href='http://#{MU.mu_public_addr}/docs/frames.html'>Mu API documentation</a>
  </p>
  "
  end

  execute "echo 'devnull: /dev/null' >> /etc/aliases" do
    not_if "grep '^devnull: /dev/null$' /etc/aliases"
  end

  # execute "/usr/bin/newaliases"

  include_recipe "mu-tools::aws_api"


  ruby_block "create_logs_volume" do
    extend CAPVolume
    block do
      require 'aws-sdk-core'
      if !File.open("/etc/mtab").read.match(/ #{node[:application_attributes][:logs][:mount_directory]} /) and !volume_attached(node[:application_attributes][:logs][:mount_device])
        create_node_volume("logs")
        result = attach_node_volume("logs")
      end
    end
    not_if "grep #{node[:application_attributes][:logs][:mount_directory]} /etc/mtab"
    notifies :restart, "service[rsyslog]", :delayed
  end

  directory "/Mu_Logs"

  log "Log bucket is at #{node[:application_attributes][:logs][:secure_location]}"

  ruby_block "mount_logs_volume" do
    extend CAPVolume
    block do
      if !File.open("/etc/mtab").read.match(/ #{node[:application_attributes][:logs][:mount_directory]} /)
        ebs_keyfile = node[:application_attributes][:logs][:ebs_keyfile]
        temp_dev = "/dev/ram7"
        temp_mount = "/tmp/ram7"

        if File.open("/proc/mounts").read.match(/ #{temp_mount} /)
          destroy_temp_disk(temp_dev)
        end

        make_temp_disk!(temp_dev, temp_mount)
        s3 = Aws::S3::Client.new

        begin
          resp = s3.get_object(bucket: node[:application_attributes][:logs][:secure_location], key: "log_vol_ebs_key")
        rescue Exception => e
          Chef::Log.info(e.inspect)
          destroy_temp_disk(temp_dev)
          raise e
        end

        if resp.body.nil? or resp.body.size == 0
          destroy_temp_disk(temp_dev)
          raise "Couldn't fetch log volume key #{node[:application_attributes][:logs][:secure_location]}:/log_vol_ebs_key"
        end

        ebs_key_handle = File.new("#{temp_mount}/log_vol_ebs_key", File::CREAT|File::TRUNC|File::RDWR, 0400)
        ebs_key_handle.puts resp.body
        ebs_key_handle.close
        mount_node_volume("logs", "#{temp_mount}/log_vol_ebs_key")
        destroy_temp_disk(temp_dev)
      end
    end
    notifies :restart, "service[rsyslog]", :delayed
    not_if "grep #{node[:application_attributes][:logs][:mount_directory]} /etc/mtab"
  end

  ruby_block "label #{node[:application_attributes][:logs][:mount_device]} as #{node.application_attributes.logs.label}" do
    extend CAPVolume
    block do
      tags = [{key: "Name", value: node[:application_attributes][:logs][:label]}]
      tag_volume(node[:application_attributes][:logs][:mount_device], tags)
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

  template "#{MU.etcDir}/mu.rc" do
    source "mu.rc.erb"
    mode 0644
    owner "root"
    variables(
      :installdir => MU.installDir
    )
    not_if { ::File.size?("#{MU.etcDir}/mu.rc") }
  end
  execute "source #{MU.etcDir}/mu.rc from root dotfiles" do
    command "echo 'source #{MU.etcDir}/mu.rc' >> #{Etc.getpwnam("root").dir}/.bashrc"
    not_if "test -f #{Etc.getpwnam("root").dir}/.bashrc && grep '^source #{MU.etcDir}/mu.rc$' #{Etc.getpwnam("root").dir}/.bashrc"
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
  include_recipe "mu-tools::cloudinit"

  begin
    node.normal[:mu][:user_map] = MU::Master.listUsers
    node.normal[:mu][:user_list] = []
    node[:mu][:user_map].each_pair { |user, data|
      node.normal[:mu][:user_list] << "#{user} (#{data['email']})"
    }
    node.save
  
    sudoer_line = "%#{$MU_CFG['ldap']['admin_group_name']} ALL=(ALL) NOPASSWD: ALL"
    execute "echo '#{sudoer_line}' >> /etc/sudoers" do
      not_if "grep '^#{sudoer_line}$' /etc/sudoers"
    end

    file "/root/.gitconfig" do
      content "[user]
        name = #{node[:mu][:user_map]['mu']['realname']}
        email = #{node[:mu][:user_map]['mu']['email']}
[push]
        default = current
"
    end
  
    node[:mu][:user_map].each_pair { |mu_user, data|
      execute "echo '#{mu_user}: #{data['email']}' >> /etc/aliases" do
        not_if "grep '^#{mu_user}: #{data['email']}$' /etc/aliases"
      end
      }
    file "/etc/motd" do
      content "
*******************************************************************************

 This is a Mu Master server. Mu is installed in #{MU.myRoot}.

 Nagios monitoring GUI: https://#{MU.mu_public_addr}/nagios/

 Jenkins interface GUI: https://#{MU.mu_public_addr}/jenkins/

 Mu API documentation: http://#{MU.mu_public_addr}/docs/frames.html

 Mu metadata are stored in #{MU.mainDataDir}

 Users: #{node[:mu][:user_list].join(", ")}

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
