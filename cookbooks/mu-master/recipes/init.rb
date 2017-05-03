# Cookbook Name:: mu-master
# Recipe:: init
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

require 'etc'

CHEF_SERVER_VERSION="12.11.1-1"
CHEF_CLIENT_VERSION="12.17.44-1"
MU_BRANCH="its_all_your_vault"
MU_BASE="/opt/mu"
SSH_USER="root"

execute "reconfigure Chef server" do
  command "/opt/opscode/bin/chef-server-ctl reconfigure"
  action :nothing
end

basepackages = []
removepackages = []
rpms = {}
dpkgs = {}

if platform_family?("rhel") 
  basepackages = ["git", "curl", "vim-enhanced", "zip", "unzip", "java-1.8.0-openjdk", "gcc", "gcc-c++", "make", "libxml2-devel", "libxslt-devel", "cryptsetup-luks", "python-pip", "lsof", "mlocate", "strace", "nmap", "openssl-devel", "readline-devel", "python-devel", "diffutils", "patch", "bind-utils", "httpd-tools", "mailx", "postgresql-devel", "openssl", "libyaml", "graphviz", "ImageMagick-devel", "graphviz-devel", "jq", "vim"]
  rpms = {
    "epel-release" => "http://mirror.metrocast.net/fedora/epel/epel-release-latest-#{node[:platform_version].to_i}.noarch.rpm",
    "chef-server-core" => "https://packages.chef.io/stable/el/#{node[:platform_version].to_i}/chef-server-core-#{CHEF_SERVER_VERSION}.el#{node[:platform_version].to_i}.x86_64.rpm"
  }

  if node[:platform_version].to_i < 6 or node[:platform_version].to_i >= 8
    raise "Mu Masters on RHEL-family hosts must be equivalent to RHEL6 or RHEL7"

  # RHEL6, CentOS6, Amazon Linux
  elsif node[:platform_version].to_i < 7
    basepackages.concat(["java-1.5.0-gcj", "mysql-server", "mysql-devel", "autoconf"])
    rpms["ruby23"] = "https://s3.amazonaws.com/mu-stuff/ruby23-2.3.1-1.el6.x86_64.rpm"
    removepackages = ["nagios"]
    basepackages << "gecode-devel" if node[:platform] == "amazon"

  # RHEL7, CentOS7
  elsif node[:platform_version].to_i < 8
    basepackages.concat(["gecode-devel", "mariadb", "mariadb-devel", "qt", "qt-x11", "iptables-services"])
    rpms["ruby23"] = "https://s3.amazonaws.com/mu-stuff/ruby23-2.3.1-1.el7.centos.x86_64.rpm"
    rpms["gecode"] = "https://s3.amazonaws.com/cap-public/gecode-3.7.3-2.el7.centos.x86_64.rpm"
    rpms["gecode-devel"] = "https://s3.amazonaws.com/cap-public/gecode-devel-3.7.3-2.el7.centos.x86_64.rpm"
    removepackages = ["nagios", "firewalld"]
  end

else
  raise "Mu Masters are currently only supported on RHEL-family hosts."
end

if File.read("/etc/ssh/sshd_config").match(/^AllowUser\s+([^\s]+)(?: |$)/)
  SSH_USER=Regexp.last_match[1].chomp
end


package basepackages
rpms.each_pair { |pkg, src|
  rpm_package pkg do
    source src
    notifies :run, "execute[reconfigure Chef server]", :immediately if pkg == "chef-server-core" and File.exists?("/opt/opscode/bin/chef-server-ctl")
  end
}
package removepackages do
  action :remove
end

["bin", "etc", "lib", "var/users/mu", "var/deployments", "var/orgs/mu"].each { |mudir|
  directory "#{MU_BASE}/#{mudir}" do
    mode mudir.match(/^var\//) ? 0700 : 0755
    owner "root"
    recursive true
  end
}

git "#{MU_BASE}/lib" do
  repository "git://github.com/cloudamatic/mu.git"
  # XXX if we can check that we're not in chef-apply mode, use an attribute to pick our branch; otherwise use the default
  revision MU_BRANCH
end

["mu-aws-setup", "mu-cleanup", "mu-deploy", "mu-firewall-allow-clients", "mu-gen-docs", "mu-load-config.rb", "mu-load-murc.rb", "mu-momma-cat", "mu-node-manage", "mu-tunnel-nagios", "mu-upload-chef-artifacts", "mu-user-manage"].each { |exe|
  link "#{MU_BASE}/bin/#{exe}" do
    to "#{MU_BASE}/lib/bin/#{exe}"
  end
}
remote_file "#{MU_BASE}/bin/mu-self-update" do
  source "file://#{MU_BASE}/lib/bin/mu-self-update"
  mode 0755
end
remote_file "#{MU_BASE}/bin/mu-configure" do
  source "file://#{MU_BASE}/lib/install/mu_setup"
  mode 0755
end

["/usr/local/ruby-current/bin/gem", "/opt/chef/embedded/bin/gem", "/opt/opscode/embedded/bin/gem"].each { |gembin|
  bundler_path = gembin.sub(/gem$/, "bundle")
  gem_package bundler_path do
    gem_binary gembin
    package_name "bundler"
  end
  execute "#{bundler_path} install" do
    cwd "#{MU_BASE}/lib/modules"
    umask 0022
    not_if "#{bundler_path} check"
  end
}

# Get a 'mu' Chef org in place and populate it with artifacts
directory "/root/.chef"
#remote_file "temporary root knife.rb for initial setup" do
#  source "file:///etc/opscode/pivotal.rb"
#  path "/root/.chef/knife.rb"
#end
execute "initial Chef artifact upload" do
  command "CHEF_PUBLIC_IP=127.0.0.1 MU_INSTALLDIR=#{MU_BASE} MU_LIBDIR=#{MU_BASE}/lib MU_DATADIR=#{MU_BASE}/var #{MU_BASE}/lib/bin/mu-upload-chef-artifacts"
  action :nothing
end
gem "simple-password-gen" do
  compile_time true
end
require "simple-password-gen"
# XXX this would make an awesome library
execute "create mu Chef user" do
  command "/opt/opscode/bin/chef-server-ctl user-create mu Mu Master root@example.com #{Password.pronounceable} -f #{MU_BASE}/var/users/mu/mu.user.key"
  umask 0277
  not_if "/opt/opscode/bin/chef-server-ctl user-list | grep '^mu$'"
end
execute "create mu Chef org" do
  command "/opt/opscode/bin/chef-server-ctl org-create mu mu -a mu -f #{MU_BASE}/var/orgs/mu/mu.org.key"
  umask 0277
  not_if "/opt/opscode/bin/chef-server-ctl org-list | grep '^mu$'"
end
file "initial root knife.rb" do
  path "/root/.chef/knife.rb"
  content "
  node_name 'mu'
  client_key '#{MU_BASE}/var/users/mu/mu.user.key'
  validation_client_name 'mu-validator'
  validation_key '#{MU_BASE}/var/orgs/mu/mu.org.key'
  chef_server_url 'https://127.0.0.1/organizations/mu'
  chef_server_root 'https://127.0.0.1/organizations/mu'
  syntax_check_cache_path  '/root/.chef/syntax_check_cache'
  cookbook_path [ '/root/.chef/cookbooks', '/root/.chef/site_cookbooks' ]
  ssl_verify_mode :verify_none
  knife[:vault_mode] = 'client'
  knife[:vault_admins] = ['mu']\n"
  only_if { !::File.exists?("/root/.chef/knife.rb") }
  notifies :run, "execute[initial Chef artifact upload]", :immediately
end


# Rig us up for a knife bootstrap
SSH_DIR="#{Etc.getpwnam(SSH_USER).dir}/.ssh"
directory SSH_DIR do
  mode 0700
end
bash "add localhost ssh to authorized_keys and config" do
  code <<-EOH
    cat #{SSH_DIR}/id_rsa.pub >> #{SSH_DIR}/authorized_keys
    echo "Host localhost" >> #{SSH_DIR}/config
    echo "  IdentityFile #{SSH_DIR}/id_rsa" >> #{SSH_DIR}/config
  EOH
  action :nothing
end
execute "ssh-keygen -N '' -f #{SSH_DIR}/id_rsa" do
  umask 0177
  not_if { ::File.exists?("#{SSH_DIR}/id_rsa") }
  notifies :run, "bash[add localhost ssh to authorized_keys and config]", :immediately
end
execute "create MU-MASTER Chef client" do
  command "/opt/chef/bin/knife bootstrap -N MU-MASTER --no-node-verify-api-cert --node-ssl-verify-mode=none 127.0.0.1"
  not_if "/opt/chef/bin/knife node list | grep '^MU-MASTER$'"
end

#remote_file "#{Chef::Config[:file_cache_path]}/vault-#{node[:mu][:vault][:version]}.zip" do
#  source "https://releases.hashicorp.com/vault/#{node[:mu][:vault][:version]}/vault_#{node[:mu][:vault][:version]}_linux_amd64.zip"
#end
#remote_file "#{Chef::Config[:file_cache_path]}/consul-#{node[:mu][:consul][:version]}.zip" do
#  source "https://releases.hashicorp.com/consul/#{node[:mu][:consul][:version]}/vault_#{node[:mu][:consul][:version]}_linux_amd64.zip"
#end
