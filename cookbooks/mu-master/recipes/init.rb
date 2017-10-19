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

# This recipe is meant to be invoked standalone, by chef-apply. It can safely
# be invoked during a regular chef-client run.
#
# When modifying this recipe, DO NOT ADD EXTERNAL DEPENDENCIES. That means no
# references to other cookbooks, no include_recipes, no cookbook_files, no
# templates.

require 'etc'
require 'open-uri'
require 'socket'

# XXX We want to be able to override these things when invoked from chef-apply,
# but, like, how?
CHEF_SERVER_VERSION="12.16.14-1"
CHEF_CLIENT_VERSION="12.21.14-1"
KNIFE_WINDOWS="1.9.0"
MU_BRANCH="master"
MU_BASE="/opt/mu"
if File.read("/etc/ssh/sshd_config").match(/^AllowUsers\s+([^\s]+)(?:\s|$)/)
  SSH_USER = Regexp.last_match[1].chomp
else
  SSH_USER="root"
end
RUNNING_STANDALONE=node[:application_attributes].nil?

execute "stop iptables" do
  command "/sbin/service iptables stop"
  ignore_failure true
  action :nothing
  only_if "( /bin/systemctl -l --no-pager | grep iptables.service ) || ( /sbin/chkconfig --list | grep ^iptables )"
end
execute "start iptables" do
  command "/sbin/service iptables start"
  ignore_failure true
  action :nothing
  only_if "( /bin/systemctl -l --no-pager | grep iptables.service ) || ( /sbin/chkconfig --list | grep ^iptables )"
end

# These guys are a workaround for Opscode bugs that seems to affect some Chef
# Server upgrades.
directory "/var/run/postgresql" do
  mode 0755
#  owner "opscode-pgsql"
#  group "opscode-pgsql"
  action :nothing
end
#link "/tmp/.s.PGSQL.5432" do
#  to "/var/run/postgresql/.s.PGSQL.5432"
#  owner "opscode-pgsql"
#  group "opscode-pgsql"
#  action :nothing
#  only_if { !::File.exists?("/tmp/.s.PGSQL.5432") }
#  only_if { ::File.exists?("/var/run/postgresql/.s.PGSQL.5432") }
#end
link "/var/run/postgresql/.s.PGSQL.5432" do
  to "/tmp/.s.PGSQL.5432"
#  owner "opscode-pgsql"
#  group "opscode-pgsql"
  notifies :create, "directory[/var/run/postgresql]", :before
  only_if { !::File.exists?("/var/run/postgresql/.s.PGSQL.5432") }
#  only_if { ::File.exists?("/tmp/.s.PGSQL.5432") }
end
execute "Chef Server rabbitmq workaround" do
  # This assumes we get clean stop, which *should* be the case if we execute
  # before any upgrade or reconfigure. If that assumption is wrong we'd prepend:
  # stop private-chef-runsvdir ; ps auxww | egrep '(opscode|runsv|postgres)' | grep -v grep | awk '{print $2}' | xargs kill
  command "rm -rf /var/log/opscode/rabbitmq/* /var/opt/opscode/rabbitmq/* /var/opt/opscode/rabbitmq/.??*"
  action :nothing
  notifies :stop, "service[chef-server]", :before
end

remote_file "back up /etc/hosts" do
  path "/etc/hosts.muinstaller"
  source "file:///etc/hosts"
  action :nothing
end
file "use a clean /etc/hosts during install" do
  path "/etc/hosts"
  content "
127.0.0.1       localhost
::1     localhost6.localdomain6 localhost6
"
  notifies :create, "remote_file[back up /etc/hosts]", :before
  only_if { RUNNING_STANDALONE }
  not_if { ::Dir.exists?("#{MU_BASE}/lib/.git") }
end

execute "reconfigure Chef server" do
  command "/opt/opscode/bin/chef-server-ctl reconfigure"
  action :nothing
  notifies :run, "execute[stop iptables]", :before
#  notifies :create, "link[/tmp/.s.PGSQL.5432]", :before
  notifies :create, "link[/var/run/postgresql/.s.PGSQL.5432]", :before
  notifies :restart, "service[chef-server]", :immediately
  notifies :run, "execute[start iptables]", :immediately
  only_if { RUNNING_STANDALONE }
end
execute "upgrade Chef server" do
  command "/opt/opscode/bin/chef-server-ctl upgrade"
  action :nothing
  timeout 1200 # this can take a while
  notifies :run, "execute[stop iptables]", :before
  notifies :run, "execute[Chef Server rabbitmq workaround]", :before
#  notifies :create, "link[/tmp/.s.PGSQL.5432]", :before
  notifies :create, "link[/var/run/postgresql/.s.PGSQL.5432]", :before
  notifies :run, "execute[start iptables]", :immediately
  only_if { RUNNING_STANDALONE }
end
service "chef-server" do
  restart_command "/opt/opscode/bin/chef-server-ctl restart"
  stop_command "/opt/opscode/bin/chef-server-ctl stop"
  start_command "/opt/opscode/bin/chef-server-ctl start"
  pattern "/opt/opscode/embedded/sbin/nginx"
  action :nothing
#  notifies :create, "link[/tmp/.s.PGSQL.5432]", :before
#  notifies :create, "link[/var/run/postgresql/.s.PGSQL.5432]", :before
  notifies :run, "execute[stop iptables]", :before
  notifies :run, "execute[start iptables]", :immediately
  only_if { RUNNING_STANDALONE }
end

basepackages = []
removepackages = []
rpms = {}
dpkgs = {}

if platform_family?("rhel") 
  basepackages = ["git", "curl", "diffutils", "patch", "gcc", "gcc-c++", "make", "postgresql-devel", "libyaml"]
  rpms = {
    "epel-release" => "http://dl.fedoraproject.org/pub/epel/epel-release-latest-#{node[:platform_version].to_i}.noarch.rpm",
    "chef-server-core" => "https://packages.chef.io/files/stable/chef-server/#{CHEF_SERVER_VERSION.sub(/\-\d+$/, "")}/el/#{node[:platform_version].to_i}/chef-server-core-#{CHEF_SERVER_VERSION}.el#{node[:platform_version].to_i}.x86_64.rpm"
  }

  if node[:platform_version].to_i < 6 or node[:platform_version].to_i >= 8
    raise "Mu Masters on RHEL-family hosts must be equivalent to RHEL6 or RHEL7"

  # RHEL6, CentOS6, Amazon Linux
  elsif node[:platform_version].to_i < 7
    basepackages.concat(["mysql-devel"])
    rpms["ruby23"] = "https://s3.amazonaws.com/mu-stuff/ruby23-2.3.1-1.el6.x86_64.rpm"
    removepackages = ["nagios"]

  # RHEL7, CentOS7
  elsif node[:platform_version].to_i < 8
    basepackages.concat(["libX11", "tcl", "tk", "mariadb-devel"])
    rpms["ruby23"] = "https://s3.amazonaws.com/mu-stuff/ruby23-2.3.1-1.el7.centos.x86_64.rpm"
    removepackages = ["nagios", "firewalld"]
  end

else
  raise "Mu Masters are currently only supported on RHEL-family hosts."
end

package basepackages

directory MU_BASE do
  recursive true
  mode 0755
end
bash "set git default branch" do
  cwd "#{MU_BASE}/lib"
  code <<-EOH
    git config branch.#{MU_BRANCH}.remote origin
    git config branch.#{MU_BRANCH}.merge refs/heads/#{MU_BRANCH}
  EOH
  action :nothing
end
git "#{MU_BASE}/lib" do
  repository "git://github.com/cloudamatic/mu.git"
  revision MU_BRANCH
  not_if { ::Dir.exists?("#{MU_BASE}/lib/.git") }
  notifies :run, "bash[set git default branch]", :immediately
end

directory MU_BASE+"/var" do
  recursive true
  mode 0755
end
directory MU_BASE+"/install" do
  recursive true
  mode 0755
end
directory MU_BASE+"/deprecated-bash-library.sh" do
  recursive true
  mode 0755
end

# Stub files so standalone Ruby programs like mu-configure can know what
# version to install/find without loading the full Mu library.
file "#{MU_BASE}/var/mu-chef-client-version" do
  content CHEF_CLIENT_VERSION
  mode 0644
end
file "#{MU_BASE}/var/mu-chef-server-version" do
  content CHEF_SERVER_VERSION
  mode 0644
end

# Account for Chef Server upgrades, which require some extra behavior
execute "move aside old Chef Server files" do
	command "mv /opt/opscode /opt/opscode.upgrading.backup"
  notifies :run, "execute[rm -rf /opt/opscode.upgrading.backup]", :delayed
  action :nothing
end
execute "rm -rf /opt/opscode.upgrading.backup" do
  action :nothing
end
rpm_package "Chef Server upgrade package" do
  source rpms["chef-server-core"]  
  action :upgrade
  only_if "rpm -q chef-server-core"
  notifies :run, "execute[move aside old Chef Server files]", :before
  notifies :run, "execute[upgrade Chef server]", :immediately
  notifies :run, "execute[reconfigure Chef server]", :immediately
  notifies :restart, "service[chef-server]", :immediately
  only_if { RUNNING_STANDALONE }
end
# Regular old rpm-based installs
rpms.each_pair { |pkg, src|
  rpm_package pkg do
    source src
    if pkg == "chef-server-core" and File.size?("/etc/opscode/chef-server.rb")
      # On a normal install this will execute when we set up chef-server.rb,
      # but on a reinstall or an install on an image where that file already
      # exists, we need to invoke this some other way.
      notifies :run, "execute[reconfigure Chef server]", :immediately
      only_if { RUNNING_STANDALONE }
    end
  end
}
package "jq"
package removepackages do
  action :remove
end
execute "clean up old Ruby 2.1.6" do
  command "rm -rf /opt/rubies/ruby-2.1.6"
  only_if { ::Dir.exists?("/opt/rubies/ruby-2.1.6") }
end

file "initial chef-server.rb" do
  path "/etc/opscode/chef-server.rb"
  content "server_name='127.0.0.1'
api_fqdn server_name
nginx['server_name'] = server_name
nginx['enable_non_ssl'] = false
nginx['non_ssl_port'] = 81
nginx['ssl_port'] = 7443
nginx['ssl_ciphers'] = 'HIGH:MEDIUM:!LOW:!kEDH:!aNULL:!ADH:!eNULL:!EXP:!SSLv2:!SEED:!CAMELLIA:!PSK'
nginx['ssl_protocols'] = 'TLSv1.2'
bookshelf['external_url'] = 'https://127.0.0.1:7443'
bookshelf['vip_port'] = 7443\n"
  not_if { ::File.size?("/etc/opscode/chef-server.rb") }
  notifies :run, "execute[reconfigure Chef server]", :immediately
end

["bin", "etc", "lib", "var/users/mu", "var/deployments", "var/orgs/mu"].each { |mudir|
  directory "#{MU_BASE}/#{mudir}" do
    mode mudir.match(/^var\//) ? 0700 : 0755
    owner "root"
    recursive true
  end
}
file "#{MU_BASE}/var/users/mu/email" do
  content "root@example.com\n"
  action :create_if_missing
end
file "#{MU_BASE}/var/users/mu/realname" do
  content "Mu Administrator\n"
  action :create_if_missing
end


["mu-aws-setup", "mu-cleanup", "mu-configure", "mu-deploy", "mu-firewall-allow-clients", "mu-gen-docs", "mu-load-config.rb", "mu-node-manage", "mu-tunnel-nagios", "mu-upload-chef-artifacts", "mu-user-manage", "mu-ssh"].each { |exe|
  link "#{MU_BASE}/bin/#{exe}" do
    to "#{MU_BASE}/lib/bin/#{exe}"
  end
  file "#{MU_BASE}/lib/bin/#{exe}" do
    mode 0755
  end
}
remote_file "#{MU_BASE}/bin/mu-self-update" do
  source "file://#{MU_BASE}/lib/bin/mu-self-update"
  mode 0755
end

["/usr/local/ruby-current", "/opt/chef/embedded", "/opt/opscode/embedded"].each { |rubydir|
  gembin = rubydir+"/bin/gem"
  gemdir = Dir.glob("#{rubydir}/lib/ruby/gems/?.?.?/gems").last
  bundler_path = gembin.sub(/gem$/, "bundle")
  bash "fix #{rubydir} gem permissions" do
    code <<-EOH
      find -P #{rubydir}/lib/ruby/gems/?.?.?/ #{rubydir}/lib/ruby/site_ruby/ -type d -exec chmod go+rx {} \\;
      find -P #{rubydir}/lib/ruby/gems/?.?.?/ #{rubydir}/lib/ruby/site_ruby/ -type f -exec chmod go+r {} \\;
      find -P #{rubydir}/bin -type f -exec chmod go+rx {} \\;
    EOH
    action :nothing
  end
  gem_package bundler_path do
    gem_binary gembin
    package_name "bundler"
    action :upgrade if rubydir == "/usr/local/ruby-current"
    notifies :run, "bash[fix #{rubydir} gem permissions]", :delayed
  end
  execute "#{bundler_path} install" do
    cwd "#{MU_BASE}/lib/modules"
    umask 0022
    not_if "#{bundler_path} check"
    notifies :run, "bash[fix #{rubydir} gem permissions]", :delayed
    notifies :restart, "service[chef-server]", :delayed if rubydir == "/opt/opscode/embedded"
    # XXX notify mommacat if we're *not* in chef-apply... RUNNING_STANDALONE
  end
  # Expunge old versions of knife-windows
  if !gemdir.nil?
    Dir.glob("#{gemdir}/knife-windows-*").each { |dir|
      next if dir.match(/\/knife-windows-(#{Regexp.quote(KNIFE_WINDOWS)})$/)
      dir.match(/\/knife-windows-([^\/]+)$/)
      gem_package "purge #{rubydir} knife windows #{Regexp.last_match[1]} #{gembin}" do
        gem_binary gembin
        package_name "knife-windows"
        version Regexp.last_match[1]
        action :remove
        only_if { ::Dir.exists?(dir) }
        only_if { ::Dir.exists?(gemdir) }
      end
      execute "rm -rf #{gemdir}/knife-windows-#{Regexp.last_match[1]}"
    }

# XXX rely on bundler to get this right for us
#    gem_package "#{rubydir} knife-windows #{KNIFE_WINDOWS} #{gembin}" do
#      gem_binary gembin
#      package_name "knife-windows"
#      version KNIFE_WINDOWS
#      notifies :restart, "service[chef-server]", :delayed if rubydir == "/opt/opscode/embedded"
#      # XXX notify mommacat if we're *not* in chef-apply... RUNNING_STANDALONE
#    end

#    execute "Patch #{rubydir}'s knife-windows for Cygwin SSH bootstraps" do
#      cwd "#{gemdir}/knife-windows-#{KNIFE_WINDOWS}"
#      command "patch -p1 < #{MU_BASE}/lib/install/knife-windows-cygwin-#{KNIFE_WINDOWS}.patch"
#      not_if "grep -i 'locate_config_value(:cygwin)' #{gemdir}/knife-windows-#{KNIFE_WINDOWS}/lib/chef/knife/bootstrap_windows_base.rb"
#      notifies :restart, "service[chef-server]", :delayed if rubydir == "/opt/opscode/embedded"
#      only_if { ::Dir.exists?(gemdir) }
      # XXX notify mommacat if we're *not* in chef-apply... RUNNING_STANDALONE
#    end
  end
}


# Get a 'mu' Chef org in place and populate it with artifacts
directory "/root/.chef"
execute "knife ssl fetch" do
  action :nothing
end
execute "initial Chef artifact upload" do
  command "MU_INSTALLDIR=#{MU_BASE} MU_LIBDIR=#{MU_BASE}/lib MU_DATADIR=#{MU_BASE}/var #{MU_BASE}/lib/bin/mu-upload-chef-artifacts"
  action :nothing
  notifies :run, "execute[stop iptables]", :before
  notifies :run, "execute[knife ssl fetch]", :before
  notifies :run, "execute[start iptables]", :immediately
  only_if { RUNNING_STANDALONE }
end
chef_gem "simple-password-gen" do
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
# TODO copy in ~/.chef/mu.*.key to /opt/mu/var/users/mu if the stuff already exists
file "initial root knife.rb" do
  path "/root/.chef/knife.rb"
  content "
  node_name 'mu'
  client_key '#{MU_BASE}/var/users/mu/mu.user.key'
  validation_client_name 'mu-validator'
  validation_key '#{MU_BASE}/var/orgs/mu/mu.org.key'
  chef_server_url 'https://127.0.0.1:7443/organizations/mu'
  chef_server_root 'https://127.0.0.1:7443/organizations/mu'
  syntax_check_cache_path  '/root/.chef/syntax_check_cache'
  cookbook_path [ '/root/.chef/cookbooks', '/root/.chef/site_cookbooks' ]
  ssl_verify_mode :verify_none
  knife[:vault_mode] = 'client'
  knife[:vault_admins] = ['mu']\n"
  only_if { !::File.size?("/root/.chef/knife.rb") }
  notifies :run, "execute[initial Chef artifact upload]", :immediately
end


# Rig us up for a knife bootstrap
SSH_DIR = "#{Etc.getpwnam(SSH_USER).dir}/.ssh"
ROOT_SSH_DIR = "#{Etc.getpwuid(0).dir}/.ssh"
directory SSH_DIR do
  mode 0700
  user SSH_USER
end
if SSH_DIR != ROOT_SSH_DIR
  directory ROOT_SSH_DIR do
    mode 0700
  end
end
bash "add localhost ssh to authorized_keys and config" do
  code <<-EOH
    cat #{ROOT_SSH_DIR}/id_rsa.pub >> #{SSH_DIR}/authorized_keys
    echo "Host localhost" >> #{ROOT_SSH_DIR}/config
    echo "  IdentityFile #{ROOT_SSH_DIR}/id_rsa" >> #{ROOT_SSH_DIR}/config
  EOH
  action :nothing
end
execute "ssh-keygen -N '' -f #{ROOT_SSH_DIR}/id_rsa" do
  umask 0177
  not_if { ::File.exists?("#{ROOT_SSH_DIR}/id_rsa") }
  notifies :run, "bash[add localhost ssh to authorized_keys and config]", :immediately
end
file "/etc/chef/client.pem" do
  action :nothing
end
file "/etc/chef/validation.pem" do
  action :nothing
end

execute "create MU-MASTER Chef client" do
  if SSH_USER == "root"
    command "/opt/chef/bin/knife bootstrap -N MU-MASTER --no-node-verify-api-cert --node-ssl-verify-mode=none 127.0.0.1"
  else
    command "/opt/chef/bin/knife bootstrap -N MU-MASTER --no-node-verify-api-cert --node-ssl-verify-mode=none -x #{SSH_USER} --sudo 127.0.0.1"
  end
  not_if "/opt/chef/bin/knife node list | grep '^MU-MASTER$'"
  only_if "/opt/chef/bin/knife ssl check" # make sure we don't wipe ourselves due to unrelated SSL issues
  notifies :delete, "file[/etc/chef/client.pem]", :before
  notifies :delete, "file[/etc/chef/validation.pem]", :before
  only_if { RUNNING_STANDALONE }
end

# Community cookbooks keep touching gems, and none of them are smart about our
# default umask. We have to clean up after them every time.
["/usr/local/ruby-current", "/opt/chef/embedded", "/opt/opscode/embedded"].each { |rubydir|
  execute "trigger permission fix in #{rubydir}" do
    command "ls /etc/motd > /dev/null"
    notifies :run, "bash[fix #{rubydir} gem permissions]", :delayed
  end
}
