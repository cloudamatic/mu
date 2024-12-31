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

# We had to hand-roll 389DS packages for Amazon 2023. It was ludicrious.
if node['platform_family'] == 'amazon' && node['platform_version'].to_i == 2023
  base_url = "https://s3.amazonaws.com/icras-ruby/"

  # Mozilla's ancient LDAP library. We don't actually run code out of it, but
  # a bunch of the supporting tools for 389DS insist on linking to it.
  pkgs = ["mozldap-6.0.7-1.amzn2023.x86_64.rpm", "mozldap-devel-6.0.7-1.amzn2023.x86_64.rpm", "mozldap-tools-6.0.7-1.amzn2023.x86_64.rpm"]
  execute "install legacy Mozilla LDAP library" do
    command "rpm -ivh #{pkgs.map { |p| base_url+p }.join(' ')}"
    not_if "rpm -q mozldap mozldap-devel mozldap-tools"
  end
  link "/usr/local/mozldap/lib" do
    to "/usr/local/mozldap/lib64"
  end

  # Prereqs for 389-admin, including miscellaneous difficult-to-source Perl modules
  package ["cyrus-sasl-gssapi", "cyrus-sasl-md5", "nss-tools", "perl-Archive-Tar", "perl-DB_File", "perl-debugger", "perl-sigtrap", "openssl-perl", "python3-pytest", "perl-FileHandle", "perl-Log-Log4perl", "perl-LDAP"]

  version = "3.1.1"
  pkgs = ["389-ds-base-libs-#{version}-icrasmu.x86_64.rpm", "389-ds-base-3.1.1-icrasmu.x86_64.rpm", "python3-lib389-#{version}-icrasmu.noarch.rpm", "389-ds-base-devel-#{version}-icrasmu.x86_64.rpm"]
  # XXX These RPMs will conflict with themselves if they try to install twice. They are very stupid.
  execute "install 389DS packages" do
    command "rpm -ivh #{pkgs.map { |p| base_url+p }.join(' ')}"
    not_if "rpm -q 389-ds-base 389-ds-base-libs python3-lib389 389-ds-base-devel"
  end

  pkgs = ["389-adminutil-devel-1.1.23-1.amzn2023.x86_64.rpm", "389-adminutil-1.1.23-1.amzn2023.x86_64.rpm"]
  execute "install 389DS adminutil packages" do
    command "rpm -ivh #{pkgs.map { |p| base_url+p }.join(' ')}"
    not_if "rpm -q 389-adminutil 389-adminutil-devel"
  end
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
    "user" => "cn=Directory Manager"
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
  command "/usr/sbin/dscreate from-file /root/389ds.tmp/389-directory-setup.inf"
  action :nothing
end

confdir = "/etc/dirsrv/slapd-#{$MU_CFG["hostname"]}"

template "/root/389ds.tmp/389-directory-setup.inf"do
  source "389-directory-setup.inf.erb"
  variables :hostname => $MU_CFG["hostname"],
            :address => $MU_CFG["public_address"].match(/^\d+\.\d+\.\d+\.\d+$/) ? "localhost" : $MU_CFG["public_address"],
            :domain => $MU_CFG["ldap"]["domain_name"],
            :domain_dn => $MU_CFG["ldap"]["domain_name"].split(/\./).map{ |x| "DC=#{x}" }.join(","),
            :creds => $CREDS
  not_if { ::Dir.exist?(confdir) }
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

# This is the PIN for the certificate store, not the LDAP server's root password
execute "ensure plainpin.txt" do
  command "cat #{confdir}/pin.txt | cut -d: -f 2 > #{confdir}/plainpin.txt"
  not_if { File.exist?("#{confdir}/plainpin.txt") }
end

# ... the LDAP server's root password is a crypt in #{confdir}/dse.ldif, the
# line nsslapd-rootpw. You can generate a new one with the /usr/bin/pwdhash
# utility.

execute "389ds set Mu CA" do
  if $MU_CFG['ssl'] and $MU_CFG['ssl']['chain']
    command "/usr/bin/certutil -d #{confdir} -A -f #{confdir}/plainpin.txt -n \"Mu Master CA\" -t CTP,C,C -a -i #{$MU_CFG['ssl']['chain']}"
  else
    command "/usr/bin/certutil -d #{confdir} -A -f #{confdir}/plainpin.txt -n \"Mu Master CA\" -t CTP,C,C -a -i /opt/mu/var/ssl/Mu_CA.pem"
  end
  action :nothing
  notifies :restart, "service[#{service_name}]", :delayed
end

execute "remove existing Server-Cert" do
  command "/usr/bin/certutil -D -d #{confdir} -f #{confdir}/plainpin.txt -n Server-Cert"
  only_if "/usr/bin/certutil -L -d #{confdir} -f #{confdir}/plainpin.txt -n Server-Cert | grep CN=ssca.389ds.example.com" # XXX make this look for any mismatch with the correct one
end

# certutil is too stupid to import a key, so we have to do this little dance with pk12util instead
execute "389ds set Mu server key" do
  command "PW=\"`cat #{confdir}/plainpin.txt`\" /usr/bin/pk12util -d #{confdir} -i /opt/mu/var/ssl/ldap.p12 -W \"\" -K \"`cat #{confdir}/plainpin.txt`\""
  #  not_if # XXX be a lot cooler if we guarded this
  notifies :restart, "service[#{service_name}]", :delayed
end
execute "389ds set Mu server cert" do
  command "/usr/bin/certutil -d #{confdir} -A -f #{confdir}/plainpin.txt -n ldap -t TP,, -a -i /opt/mu/var/ssl/ldap.crt"
  notifies :run, "execute[389ds set Mu CA]", :before
end

#{"ssl_enable.ldif" => "nsSSL3: off", "addRSA.ldif" => "nsSSLActivation: on"}.each_pair { |ldif, guardstr|
{"setCertName.ldif" => "nsSSLPersonalitySSL: ldap"}.each_pair { |ldif, guardstr|
  cookbook_file "/root/389ds.tmp/#{ldif}" do
    source ldif
  end

  execute "/usr/bin/ldapmodify -x -D \"#{$CREDS["cfg_directory_adm"]['user']}\" -w \"#{$CREDS["cfg_directory_adm"]['pw']}\" -f /root/389ds.tmp/#{ldif}" do
    notifies :restart, "service[#{service_name}]", :delayed
    not_if "grep '#{guardstr}' #{confdir}/dse.ldif"
  end
}

#  %x{/usr/sbin/setenforce 1}
