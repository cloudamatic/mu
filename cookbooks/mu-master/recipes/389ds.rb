#
# Cookbook Name:: mu-master
# Recipe:: 389ds
#
# Copyright:: Copyright (c) 2017 eGlobalTech, Inc., all rights reserved
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

if node['platform_version'].to_i >= 8
  execute "/bin/dnf -y module install 389-directory-server:stable/default"
  package ["389-ds-base", "389-ds-base-libs", "389-ds-base-devel", "389-ds-base-legacy-tools"]
else
  package ["389-ds", "389-ds-console"]
end

include_recipe 'chef-vault'

# How to completely undo all of this: service dirsrv stop ; pkill ns-slapd ; yum erase -y 389-ds 389-ds-console 389-ds-base 389-admin 389-adminutil 389-console 389-ds-base-libs; rm -rf /etc/dirsrv /var/lib/dirsrv /var/log/dirsrv /var/lock/dirsrv /var/run/dirsrv /etc/sysconfig/dirsrv* /usr/lib64/dirsrv /usr/share/dirsrv; knife data bag delete -y mu_ldap

# Retrieve credentials we need to do LDAP things. Generate from scratch if they
# haven't been provided.
$CREDS = {
  "bind_creds" => {
    "user" => "CN=mu_bind_creds,#{$MU_CFG["ldap"]['user_ou']}"
  },
  "join_creds" => {
    "user" => "CN=mu_join_creds,#{$MU_CFG["ldap"]['user_ou']}"
  },
  "cfg_directory_adm" => {
    "user" => "admin"
  },
  "root_dn_user" => {
    "user" => "CN=root_dn_user"
  }
}

service_name = "dirsrv"
if node['platform_version'].to_i >= 7 || (node['platform_family'] == 'amazon' && node['platform_version'].to_i == 2)
  service_name = service_name + "@" + $MU_CFG["hostname"]
end

directory "/root/389ds.tmp" do
  recursive true
  mode 0700
end
$CREDS.each_pair { |creds, _cfg|
  user = pw = data = nil
  if $MU_CFG["ldap"].has_key?(creds)
    data = chef_vault_item($MU_CFG['ldap'][creds]['vault'], $MU_CFG['ldap'][creds]['item'])
    user = data[$MU_CFG["ldap"][creds]["username_field"]]
    pw = data[$MU_CFG["ldap"][creds]["password_field"]]
  else
    data = chef_vault_item("mu_ldap", creds)
    user = data["username"]
    pw = data["password"]
  end
  $CREDS[creds]['user'] = user if !$CREDS[creds]['user']
  $CREDS[creds]['pw'] = pw if !$CREDS[creds]['pw']
}
directory "/var/log/dirsrv/admin-serv" do
  user "nobody"
  group "nobody"
  mode 0770
  recursive true
end

#  %x{/usr/sbin/setenforce 0}
execute "initialize 389 Directory Services" do
  if node['platform_version'].to_i >= 8
    command "/sbin/dscreate from-file /root/389ds.tmp/389-directory-setup.inf"
  else
    command "/usr/sbin/setup-ds-admin.pl -s -f /root/389ds.tmp/389-directory-setup.inf --continue --debug #{Dir.exist?("/etc/dirsrv/slapd-#{$MU_CFG["hostname"]}") ? "--update" : ""}"
  end
  action :nothing
end

template "/root/389ds.tmp/389-directory-setup.inf"do
  if node['platform_version'].to_i >= 8
    source "389-dscreate.inf.erb"
  else
    source "389-directory-setup.inf.erb"
  end
  variables :hostname => $MU_CFG["hostname"],
            :address => $MU_CFG["public_address"].match(/^\d+\.\d+\.\d+\.\d+$/) ? "localhost" : $MU_CFG["public_address"],
            :domain => $MU_CFG["ldap"]["domain_name"],
            :domain_dn => $MU_CFG["ldap"]["domain_name"].split(/\./).map{ |x| "DC=#{x}" }.join(","),
            :creds => $CREDS
  not_if { ::Dir.exist?("/etc/dirsrv/slapd-#{$MU_CFG["hostname"]}") }
  notifies :run, "execute[initialize 389 Directory Services]", :immediately
end

service service_name do
  action [:enable, :start]
end

if platform_family?("rhel") and node['platform_version'].to_i >= 7
  cookbook_file "dirsrv_admin.pp" do
    path "#{Chef::Config[:file_cache_path]}/dirsrv_admin.pp"
  end

  execute "Add dirsrv-admin to SELinux allow list" do
    command "/usr/sbin/semodule -i dirsrv_admin.pp"
    cwd Chef::Config[:file_cache_path]
    not_if "/usr/sbin/semodule -l | grep dirsrv_admin"
  end
end

#service "dirsrv-admin" do
#  action [:enable, :start]
#end

chef_gem "expect" do
  compile_time true
end
file "/root/389ds.tmp/blank" do
  content ""
  action :nothing
end
execute "389ds cert util" do
  if $MU_CFG['ssl'] and $MU_CFG['ssl']['chain']
    command "/usr/bin/certutil -d /etc/dirsrv/slapd-#{$MU_CFG["hostname"]} -A -n \"Mu Master CA\" -t CT,, -a -i #{$MU_CFG['ssl']['chain']}"
  else
    command "/usr/bin/certutil -d /etc/dirsrv/slapd-#{$MU_CFG["hostname"]} -A -n \"Mu Master CA\" -t CT,, -a -i /opt/mu/var/ssl/Mu_CA.pem"
  end
  action :nothing
  notifies :restart, "service[#{service_name}]", :delayed
end

# Why is this utility interactive-only? So much hate.
ruby_block "import SSL certificates for 389ds" do
  block do
    certimportcmd = "/usr/bin/pk12util -i /opt/mu/var/ssl/ldap.p12 -d /etc/dirsrv/slapd-#{$MU_CFG["hostname"]} -w /root/389ds.tmp/blank -W \"\""
    require 'pty'
    require 'expect'
    PTY.spawn(certimportcmd) { |r, w, _pid|
      begin
        r.expect("Enter new password:") do
          w.puts
        end
        r.expect("Re-enter password:") do
          w.puts
        end
      rescue Errno::EIO
        break
      end
    }

  end
  notifies :create, "file[/root/389ds.tmp/blank]", :before
  notifies :run, "execute[389ds cert util]", :immediately
end


{"ssl_enable.ldif" => "nsslapd-security: on", "addRSA.ldif" => "nsSSLActivation: on"}.each_pair { |ldif, guardstr|
  cookbook_file "/root/389ds.tmp/#{ldif}" do
    source ldif
  end

  execute "/usr/bin/ldapmodify -x -D #{$CREDS["root_dn_user"]['user']} -w #{$CREDS["root_dn_user"]['pw']} -f /root/389ds.tmp/#{ldif}" do
    notifies :restart, "service[#{service_name}]", :delayed
    not_if "grep '#{guardstr}' /etc/dirsrv/slapd-#{$MU_CFG['hostname']}/dse.ldif"
  end
}

#  %x{/usr/sbin/setenforce 1}
