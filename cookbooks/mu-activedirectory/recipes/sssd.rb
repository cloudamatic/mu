#
# Cookbook Name:: mu-activedirectory
# Recipe:: sssd
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

    service "sshd" do
      action :nothing
    end

    packages = %w(epel-release dbus sssd sssd-ldap sssd-ad authconfig nscd oddjob-mkhomedir git automake libtool openldap-devel libxslt-devel)

    package packages

    packages_uninstall = %w(nss-pam-ldapd pam_ldap)
    
    package packages_uninstall do
      action :remove
    end

    execute "git clone git://anongit.freedesktop.org/realmd/adcli" do
      cwd "/root"
      not_if { ::Dir.exists?("/root/adcli") }
    end

    execute "git fetch && git pull" do
      cwd "/root/adcli"
    end

    include_recipe "build-essential"

    # This is our workaround until the RPM makes it way back into a repo
    # somewhere. It was removed from EPEL after it became part of mainstream
    # RHEL 6.8, but CentOS doesn't have it yet.
    execute "compile adcli" do
      cwd "/root/adcli"
      command "./autogen.sh --disable-doc --prefix=/usr && make && make install"
      not_if { ::File.exists?("/usr/sbin/adcli") }
    end

    case elversion
    when 7
      # trying to make sure Chef doesn’t try to start the service if it's already started
      execute "sed -i 's/--nopidfile//' /usr/lib/systemd/system/messagebus.service && systemctl daemon-reload" do
        only_if "grep '\--nopidfile' /usr/lib/systemd/system/messagebus.service"
      end
    end

    service "messagebus" do
      action [:enable, :start]
    end

    service "nscd" do
      action [:disable, :stop]
    end

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

    case elversion
    when 6
      service "oddjobd" do
        start_command "sh -x /etc/init.d/oddjobd start" # seems to actually work
        action [:enable, :start]
      end
    when 7
      # Seems to work on CentOS7
      service "oddjobd" do
        action [:enable, :start]
      end
    end

    execute "/usr/sbin/authconfig --disablenis --disablecache --disablewinbind --disablewinbindauth --enablemkhomedir --disablekrb5 --enablesssd --enablesssdauth --enablelocauthorize --disableforcelegacy --disableldap --disableldapauth --updateall" do
      notifies :restart, "service[oddjobd]", :immediately
      notifies :reload, "service[sshd]", :delayed
      not_if "grep pam_sss.so /etc/pam.d/password-auth"
    end

    include_recipe 'chef-vault'
    domain_creds = chef_vault_item(node.ad.join_auth[:vault], node.ad.join_auth[:item])
    node.ad.dc_ips.each { |ip|
      # XXX there's a more correct way to touch resolv.conf
      execute "sed -i '2i nameserver #{ip}' /etc/resolv.conf" do
        not_if "grep #{ip} /etc/resolv.conf"
      end
    }
    service "sssd" do
      action :nothing
      notifies :restart, "service[sshd]", :immediately
      only_if { ::File.exists?("/etc/krb5.keytab") }
    end
    directory "/etc/sssd"
    template "/etc/sssd/sssd.conf" do
      source "sssd.conf.erb"
      mode 0600
      cookbook "mu-activedirectory"
      notifies :restart, "service[sssd]", :immediately
      variables(
        :domain => node.ad.domain_name,
        :short_domain => node.ad.netbios_name,
        :base_dn => node.ad.domain_name.split(/\./).map { |x| "dc=#{x}" }.join(","),
        :dcs => node.ad.dc_ips
      )
    end
    # If adcli fails mysteriously, look for bogus /etc/hosts entries pointing
    # to your DCs. It seems to dumbly trust any reverse mapping it sees,
    # whether or not the name matches the actual Kerberos tickets you et.
    execute "Run ADCLI" do
      not_if { ::File.exists?("/etc/krb5.keytab") }
      command "echo -n '#{domain_creds[node.ad.join_auth[:password_field]]}' | /usr/sbin/adcli join #{node.ad.domain_name} --domain-realm=#{node.ad.domain_name.upcase} -U #{domain_creds[node.ad.join_auth[:username_field]]} --stdin-password"
      notifies :restart, "service[sssd]", :immediately
      sensitive true
    end

  else
    Chef::Log.info("Unsupported platform #{node.platform}")
end
