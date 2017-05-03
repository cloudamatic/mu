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

CHEF_SERVER_VERSION="12.11.1-1"
CHEF_CLIENT_VERSION="12.17.44-1"
MU_BRANCH="its_all_your_vault"

execute "reconfigure Chef server" do
  command "/opt/opscode/bin/chef-server-ctl reconfigure"
  action :nothing
end

basepackages = []
removepackages = []
rpms = {}
dpkgs = {}

if platform_family?("rhel") 
  basepackages = ["git", "curl", "vim-enhanced", "zip", "unzip", "java-1.8.0-openjdk", "gcc", "gcc-c++", "make", "libxml2-devel", "libxslt-devel", "cryptsetup-luks", "python-pip", "lsof", "mlocate", "strace", "nmap", "openssl-devel", "readline-devel", "python-devel", "diffutils", "patch", "bind-utils", "httpd-tools", "mailx", "postgresql-devel", "openssl", "libyaml", "graphviz", "ImageMagick-devel", "graphviz-devel", "jq"]
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

package basepackages
rpms.each_pair { |pkg, src|
  rpm_package pkg do
    source src
    notifies :run, "execute[reconfigure Chef server]", :immediately if pkg == "chef-server-core"
  end
}
package removepackages do
  action :remove
end

["bin", "etc", "lib", "var"].each { |mudir|
  directory "/opt/mu/#{mudir}" do
    mode 0755
    owner "root"
    recursive true
  end
}

git "/opt/mu/lib" do
  repository "git://github.com/cloudamatic/mu.git"
  # XXX if we can check that we're not in chef-apply mode, use an attribute to pick our branch; otherwise use the default
  revision "its_all_your_vault"
end

["/usr/local/ruby-current/bin/gem", "/opt/chef/embedded/bin/gem", "/opt/opscode/embedded/bin/gem"].each { |gembin|
  bundler_path = gembin.sub(/gem$/, "bundle")
  gem_package bundler_path do
    gem_binary gembin
    package_name "bundler"
  end
  execute "#{bundler_path} install" do
    cwd "/opt/mu/lib/modules"
    umask 0022
    not_if "#{bundler_path} check"
  end
}

#remote_file "#{Chef::Config[:file_cache_path]}/vault-#{node[:mu][:vault][:version]}.zip" do
#  source "https://releases.hashicorp.com/vault/#{node[:mu][:vault][:version]}/vault_#{node[:mu][:vault][:version]}_linux_amd64.zip"
#end
#remote_file "#{Chef::Config[:file_cache_path]}/consul-#{node[:mu][:consul][:version]}.zip" do
#  source "https://releases.hashicorp.com/consul/#{node[:mu][:consul][:version]}/vault_#{node[:mu][:consul][:version]}_linux_amd64.zip"
#end
