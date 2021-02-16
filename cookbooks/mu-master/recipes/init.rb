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

# If we're invoked with a stripped-down environment, many of our guards and
# execs will fail. Append the stuff that's typically missing. Note that even
# if we hardcode all of our own paths to commands things still break, due to
# things that spawn commands of their own with the environment they inherit
# from us.
ENV['PATH'] = ENV['PATH']+":/bin:/opt/opscode/embedded/bin"

# XXX We want to be able to override these things when invoked from chef-apply,
# but, like, how?
CHEF_SERVER_VERSION="14.0.65-1"
CHEF_CLIENT_VERSION="16.9.29"
KNIFE_WINDOWS="1.9.0"
MU_BASE="/opt/mu"

MU_BRANCH = if ENV.key?('MU_BRANCH')
  ENV['MU_BRANCH']
elsif $?.exitstatus == 0
  realbranch=`cd #{MU_BASE}/lib && git rev-parse --abbrev-ref HEAD` # ~FC048
  realbranch.chomp
else
  "master"
end

begin
  resources('service[sshd]')
rescue Chef::Exceptions::ResourceNotFound
  service "sshd" do
    action :nothing
  end
end

if File.read("/etc/ssh/sshd_config").match(/^AllowUsers\s+([^\s]+)(?:\s|$)/)
  SSH_USER = Regexp.last_match[1].chomp
else
  execute "sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config" do
    only_if "grep 'PermitRootLogin no' /etc/ssh/sshd_config"
    notifies :restart, "service[sshd]", :immediately
  end
  SSH_USER="root"
  execute "/sbin/service sshd start" do # ~FC004
    ignore_failure true # the service restart often fails to leave sshd alive
  end
end
RUNNING_STANDALONE=node['application_attributes'].nil?

service "iptables" do
  ignore_failure true
  action :nothing
  only_if "( /bin/systemctl -l --no-pager | grep iptables.service ) || ( /sbin/chkconfig --list | grep ^iptables )"
end

service "firewalld" do
  ignore_failure true
  action :nothing
  only_if "/bin/systemctl -l --no-pager | grep firewalld.service"
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
#  only_if { !::File.exist?("/tmp/.s.PGSQL.5432") }
#  only_if { ::File.exist?("/var/run/postgresql/.s.PGSQL.5432") }
#end
link "/var/run/postgresql/.s.PGSQL.5432" do
  to "/tmp/.s.PGSQL.5432"
#  owner "opscode-pgsql"
#  group "opscode-pgsql"
  notifies :create, "directory[/var/run/postgresql]", :before
  only_if { !::File.exist?("/var/run/postgresql/.s.PGSQL.5432") }
#  only_if { ::File.exist?("/tmp/.s.PGSQL.5432") }
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
  not_if { ::Dir.exist?("#{MU_BASE}/lib/.git") }
end

execute "modprobe br_netfilter" do
  action :nothing
end

execute "reconfigure Chef server" do
  command "CHEF_LICENSE=\"accept\" /opt/opscode/bin/chef-server-ctl reconfigure"
  action :nothing
  notifies :stop, "service[iptables]", :before
  notifies :stop, "service[firewalld]", :before
#  notifies :create, "link[/tmp/.s.PGSQL.5432]", :before
  notifies :create, "link[/var/run/postgresql/.s.PGSQL.5432]", :before
  notifies :restart, "service[chef-server]", :immediately
  if !RUNNING_STANDALONE
    notifies :start, "service[iptables]", :immediately
    notifies :start, "service[firewalld]", :immediately
  else
    notifies :run, "execute[Chef Server rabbitmq workaround]", :before
  end
  only_if { RUNNING_STANDALONE }
end
execute "upgrade Chef server" do
  command "CHEF_LICENSE=\"accept\" /opt/opscode/bin/chef-server-ctl upgrade"
  action :nothing
  timeout 1200 # this can take a while
  notifies :stop, "service[iptables]", :before
  notifies :stop, "service[firewalld]", :before
  notifies :run, "execute[modprobe br_netfilter]", :before
  notifies :run, "execute[Chef Server rabbitmq workaround]", :before
#  notifies :create, "link[/tmp/.s.PGSQL.5432]", :before
  notifies :create, "link[/var/run/postgresql/.s.PGSQL.5432]", :before
  if !RUNNING_STANDALONE
    notifies :start, "service[iptables]", :immediately
    notifies :start, "service[firewalld]", :immediately
  end
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
  notifies :stop, "service[iptables]", :before
  notifies :stop, "service[firewalld]", :before
  if !RUNNING_STANDALONE
    notifies :start, "service[iptables]", :immediately
    notifies :start, "service[firewalld]", :immediately
  end
  only_if { RUNNING_STANDALONE }
end

basepackages = []
removepackages = []
rpms = {}
dpkgs = {}

elversion = node['platform_version'].split('.')[0]

rhelbase = ["git", "curl", "diffutils", "patch", "gcc", "gcc-c++", "make", "postgresql-devel", "libyaml", "libffi-devel", "tcl", "tk", "xfsprogs"]

case node['platform_family']
when 'rhel'

  basepackages = rhelbase

  case node['platform_version'].split('.')[0].to_i
  when 6
    basepackages.concat(["cryptsetup-luks", "mysql-devel", "centos-release-scl", "perl-WWW-Curl"])
    removepackages = ["nagios"]

  when 7
    basepackages.concat(['policycoreutils-python', 'libX11', 'mariadb-devel', 'cryptsetup', 'tcl-devel', 'gdbm-devel', 'sqlite-devel', 'tk-devel', 'perl-CGI', 'perl-DBI', 'perl-Data-Dumper', 'perl-Digest-MD5', 'perl-Git-SVN', 'perl-YAML', 'nvme-cli'])
    removepackages = ['nagios', 'firewalld']

  when 8
    raise "Mu currently does not support RHEL 8... but I assume it will in the future... But I am Bill and I am hopeful about the future."
  else
    raise "Mu does not support RHEL #{node['platform_version']} (matched on #{node['platform_version'].split('.')[0]})"
  end

when 'amazon'
  basepackages = rhelbase
  rpms.delete('epel-release')
  
  case node['platform_version'].split('.')[0]
  when '1', '6' #REALLY THIS IS AMAZON LINUX 1, BUT IT IS BASED OFF OF RHEL 6
    basepackages.concat(['mysql-devel', 'libffi-devel'])
    basepackages.delete('tk')
    removepackages = ["nagios"]

  when '2'
    basepackages.concat(['libX11', 'mariadb-devel', 'cryptsetup', 'ncurses-devel', 'ncurses-compat-libs', 'iptables-services'])
    removepackages = ['nagios', 'firewalld']
    elversion = '7' #HACK TO FORCE AMAZON LINUX 2 TO BE TREATED LIKE RHEL 7

  else
    raise "Mu Masters on Amazon-family hosts must be equivalent to Amazon Linux 1 or 2 (got #{node['platform_version'].split('.')[0]})"
  end
else
  raise "Mu Masters are currently only supported on RHEL and Amazon family hosts (got #{node['platform_family']})."
end

rpms = {
  "epel-release" => "http://dl.fedoraproject.org/pub/epel/epel-release-latest-#{elversion}.noarch.rpm",
  "chef-server-core" => "https://packages.chef.io/files/stable/chef-server/#{CHEF_SERVER_VERSION.sub(/\-\d+$/, "")}/el/#{elversion}/chef-server-core-#{CHEF_SERVER_VERSION}.el#{elversion}.x86_64.rpm"
}

rpms["ruby27"] = "https://s3.amazonaws.com/cloudamatic/muby-2.7.2-1.el#{elversion}.x86_64.rpm"
if elversion.to_i == 6
  rpms["openssl"] = "https://s3.amazonaws.com/cloudamatic/mussl-1.1.1h-1.el6.x86_64.rpm"
  rpms["sqlite"] = "https://s3.amazonaws.com/cloudamatic/muqlite-3.33-1.el6.x86_64.rpm"
end
if elversion.to_i == 7
  rpms["mugit"] = "https://s3.amazonaws.com/cloudamatic/mugit-2.30.0-1.el7.x86_64.rpm"
end
# this takes up a huge amount of space, save it until we're fully operational
if !RUNNING_STANDALONE
  rpms["python38"] = "https://s3.amazonaws.com/cloudamatic/muthon-3.8.3-1.el#{elversion}.x86_64.rpm"
end

package basepackages

directory MU_BASE do
  recursive true
  mode 0755
end
bash "set git default branch to #{MU_BRANCH}" do
  cwd "#{MU_BASE}/lib"
  code <<-EOH
    git config branch.#{MU_BRANCH}.remote origin
    git config branch.#{MU_BRANCH}.merge refs/heads/#{MU_BRANCH}
    git checkout #{MU_BRANCH}
  EOH
  action :nothing
end
git "#{MU_BASE}/lib" do
  repository "git://github.com/cloudamatic/mu.git"
  revision MU_BRANCH
  checkout_branch MU_BRANCH
  enable_checkout false
  not_if { ::Dir.exist?("#{MU_BASE}/lib/.git") }
  notifies :run, "bash[set git default branch to #{MU_BRANCH}]", :immediately
end

# Enable some git hook weirdness for Mu developers
["post-merge", "post-checkout", "post-rewrite"].each { |hook|
  remote_file "#{MU_BASE}/lib/.git/hooks/#{hook}" do
    source "file://#{MU_BASE}/lib/extras/git-fix-permissions-hook"
    mode 0755
  end
}
file  "#{MU_BASE}/lib/.git/hooks/pre-commit" do
  action :delete
end

[MU_BASE+"/var", MU_BASE+"/var/ssl"].each do |dir|
  directory dir do
    recursive true
    mode 0755
  end
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

execute "clean up old ruby-2.3.1 package" do
  command "yum erase ruby23-2.3.1-1.el7.centos.x86_64 -y; rpm -e ruby23"
  ignore_failure true
  only_if { ::Dir.exist?("/opt/rubies/ruby-2.3.1") }
end
execute "clean up old muby-2.5.3 package" do
  command "yum erase muby-2.5.3-1.el7.x86_64 -y"
  ignore_failure true
  only_if "rpm -q muby-2.5.3"
end

%w{2.1.6 2.3.1 2.5.3}.each { |v|
  execute "clean up old ruby-#{v} directory" do
    command "rm -rf /opt/rubies/ruby-#{v}"
    ignore_failure true
    only_if { ::Dir.exist?("/opt/rubies/ruby-#{v}") }
  end
}

execute "yum makecache" do
  action :nothing
end

# Regular old rpm-based installs
rpms.each_pair { |pkg, src|
  rpm_package pkg do
    source src
    if pkg == "ruby27" 
      options '--prefix=/opt/rubies/'
    end
    if pkg == "epel-release" 
      notifies :run, "execute[yum makecache]", :immediately
      if elversion.to_i == 6
        not_if "rpm -q epel-release"
      end
    end
    if pkg == "chef-server-core"
      notifies :stop, "service[iptables]", :before
      if File.size?("/etc/opscode/chef-server.rb")
        # On a normal install this will execute when we set up chef-server.rb,
        # but on a reinstall or an install on an image where that file already
        # exists, we need to invoke this some other way.
        notifies :run, "execute[reconfigure Chef server]", :immediately
        only_if { RUNNING_STANDALONE }
      end
    end
  end
}

package ["jq"] do
  ignore_failure true # sometimes we can't see EPEL immediately
end
package removepackages do
  action :remove
end


if rpms["mugit"]
  ENV['PATH'] = "/usr/local/git-current/bin:"+ENV['PATH']
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
bookshelf['vip'] = server_name
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
  if $MU_CFG
    content "#{$MU_CFG['mu_admin_email']}\n"
  else
    content "root@example.com\n"
    action :create_if_missing
  end
end
file "#{MU_BASE}/var/users/mu/realname" do
  if $MU_CFG
    content "#{$MU_CFG['mu_admin_name']}\n"
  else
    content "Mu Administrator\n"
    action :create_if_missing
  end
end

["mu-cleanup", "mu-configure", "mu-deploy", "mu-firewall-allow-clients", "mu-gen-docs", "mu-load-config.rb", "mu-node-manage", "mu-tunnel-nagios", "mu-upload-chef-artifacts", "mu-user-manage", "mu-ssh", "mu-adopt", "mu-azure-setup", "mu-gcp-setup", "mu-aws-setup"].each { |exe|
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

# Skip this during initial installs, it's space-hungry
if !RUNNING_STANDALONE
  bash "install modules for our built-in Python" do
    code <<-EOH
      /usr/local/python-current/bin/pip install -r #{MU_BASE}/lib/requirements.txt
    EOH
  end
end

# bundle a less heavy version of our Gemfile during initial installation, so we
# can actually fit on normal root disks until we have enough code and
# credentials to roll a dedicated /opt.
TMPDIR = Dir.mktmpdir
gemfile_dir = if RUNNING_STANDALONE and !File.readlines("/etc/mtab").grep(/\s\/opt\s/).any?
  ruby_block "set up alternate install-time Gemfile" do # ~FC014
    block do
      exclude_gems = %w{aws-sdk azure_sdk google-api-client}

      ["/sys/hypervisor/uuid",
       "/sys/devices/virtual/dmi/id/product_uuid",
       "/sys/devices/virtual/dmi/id/board_asset_tag"].each { |src|
        if File.exists?(src)
          uuid = File.read(src).chomp
          if uuid and uuid =~ /^ec2/i
            exclude_gems.delete("aws-sdk")
          end
          break
        end
      }
      dmiout = %x{PATH=/sbin:/usr/sbin:/bin:/usr/bin dmidecode}
      if dmiout.match(/Google/)
        exclude_gems.delete("google-api-client")
      end
      # XXX Azure check

      f = File.open("#{TMPDIR}/cloud-mu.gemspec", "w")
      File.read("#{MU_BASE}/lib/cloud-mu.gemspec").each_line { |l|
        skipme = false
        if l=~ /s\.add_runtime_dependency/
          exclude_gems.each { |gem|
            if l =~ /\b#{gem}\b/
              skipme = true
            end
          }
          next if skipme
        end
        f.puts l.chomp
      }
      f.close

      Dir.mkdir("#{TMPDIR}/modules")
      FileUtils.cp("#{MU_BASE}/lib/modules/Gemfile", "#{TMPDIR}/modules")
    end
  end
  "#{TMPDIR}/modules"
else
  "#{MU_BASE}/lib/modules"
end

rubies = ["/usr/local/ruby-current", "/opt/chef/embedded"]

rubies.each { |rubydir|
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

  gem_package "bundler for #{rubydir}" do
    gem_binary gembin
    package_name "bundler"
    if rubydir == "/usr/local/ruby-current" or File.exists?(bundler_path)
      action :upgrade
      ignore_failure true
    end
    version "~> 2.1.4"
    notifies :run, "bash[fix #{rubydir} gem permissions]", :delayed
  end
  execute "#{bundler_path} install from #{gemfile_dir} for #{rubydir}" do
    command "PATH=/usr/local/git-current/bin:/usr/local/git-current/libexec/git-core:${PATH} #{bundler_path} install"
    cwd gemfile_dir
    umask "0022"
    if !RUNNING_STANDALONE
      not_if { system("cd #{gemfile_dir} && #{bundler_path} check 2>&1"); $?.exitstatus }
    end
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
        only_if { ::Dir.exist?(dir) }
        only_if { ::Dir.exist?(gemdir) }
      end
      execute "rm -rf #{gemdir}/knife-windows-#{Regexp.last_match[1]}"
    }

  end
}

# This is mostly to make sure Berkshelf has a clean and current environment to
# live with.
execute "/usr/local/ruby-current/bin/bundle clean --force" do
  cwd gemfile_dir
  only_if { RUNNING_STANDALONE }
end

# Get a 'mu' Chef org in place and populate it with artifacts
directory "/root/.chef"
execute "knife ssl fetch" do
  action :nothing
end
execute "initial Chef artifact upload" do
  command "MU_INSTALLDIR=#{MU_BASE} MU_LIBDIR=#{MU_BASE}/lib MU_DATADIR=#{MU_BASE}/var #{MU_BASE}/lib/bin/mu-upload-chef-artifacts"
  action :nothing
  notifies :stop, "service[iptables]", :before
  notifies :run, "execute[knife ssl fetch]", :before
  if !RUNNING_STANDALONE
    notifies :start, "service[iptables]", :immediately
  end
  only_if { RUNNING_STANDALONE }
end
chef_gem "simple-password-gen" do
  compile_time true
end
require "simple-password-gen"

# XXX this would make an awesome library
execute "create mu Chef user" do
  command "/opt/opscode/bin/chef-server-ctl user-create mu Mu Master root@example.com #{Password.pronounceable} -f #{MU_BASE}/var/users/mu/mu.user.key"
  umask "0277"
  not_if "/opt/opscode/bin/chef-server-ctl user-list | grep '^mu$'"
  notifies :start, "service[chef-server]", :before
end
execute "create mu Chef org" do
  command "/opt/opscode/bin/chef-server-ctl org-create mu mu -a mu -f #{MU_BASE}/var/orgs/mu/mu.org.key"
  umask "0277"
  not_if "/opt/opscode/bin/chef-server-ctl org-list | grep '^mu$'"
  notifies :start, "service[chef-server]", :before
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
bash "add localhost ssh to config" do
  code <<-EOH
    echo "Host localhost" >> #{ROOT_SSH_DIR}/config
    echo "  IdentityFile #{ROOT_SSH_DIR}/id_rsa" >> #{ROOT_SSH_DIR}/config
  EOH
  action :nothing
end
execute "ssh-keygen -N '' -f #{ROOT_SSH_DIR}/id_rsa" do
  umask "0177"
  not_if { ::File.exist?("#{ROOT_SSH_DIR}/id_rsa") }
  notifies :run, "bash[add localhost ssh to config]", :immediately
  notifies :run, "execute[add localhost key to authorized_keys]", :immediately
end
execute "add localhost key to authorized_keys" do
  command "cat #{ROOT_SSH_DIR}/id_rsa.pub >> #{SSH_DIR}/authorized_keys"
  only_if {
    found = false
    pubkey = if File.exists?("#{SSH_DIR}/authorized_keys")
      File.read("#{ROOT_SSH_DIR}/id_rsa.pub").chomp
    end
    if pubkey and File.exists?("#{SSH_DIR}/authorized_keys")
      authfile = File.read("#{ROOT_SSH_DIR}/authorized_keys")
      authfile.each_line { |l|
        if l =~ /#{Regexp.quote(pubkey)}/
          found = true
        end
      }
    end
    !found
  }
end
file "/etc/chef/client.pem" do
  action :nothing
end
file "/etc/chef/validation.pem" do
  action :nothing
end
file "/etc/chef/client.rb" do
  action :nothing
end

knife_cfg = "-c /root/.chef/knife.rb"

execute "create MU-MASTER Chef client" do
# XXX I dislike --ssh-verify-host-key=never intensely, but the CLI-documented 'accept_new' doesn't actually work
  if SSH_USER == "root"
    command "/opt/chef/bin/knife bootstrap #{knife_cfg} -N MU-MASTER --no-node-verify-api-cert --node-ssl-verify-mode=none -U #{SSH_USER} --ssh-identity-file=/root/.ssh/id_rsa --ssh-verify-host-key=never 127.0.0.1"
  else
    command "/opt/chef/bin/knife bootstrap #{knife_cfg} -N MU-MASTER --no-node-verify-api-cert --node-ssl-verify-mode=none -U #{SSH_USER} --ssh-identity-file=/root/.ssh/id_rsa --ssh-verify-host-key=never --sudo 127.0.0.1"
  end
  only_if "/opt/chef/bin/knife node #{knife_cfg} list" # don't do crazy stuff just because knife isn't working
  not_if "/opt/chef/bin/knife node #{knife_cfg} list | grep '^MU-MASTER$'"
  notifies :run, "execute[add localhost key to authorized_keys]", :before
  notifies :delete, "file[/etc/chef/client.rb]", :before
  notifies :delete, "file[/etc/chef/client.pem]", :before
  notifies :delete, "file[/etc/chef/validation.pem]", :before
  notifies :start, "service[chef-server]", :before
  only_if { RUNNING_STANDALONE }
end

file "#{MU_BASE}/etc/mu.rc" do
  content %Q{export MU_INSTALLDIR="#{MU_BASE}"
export MU_DATADIR="#{MU_BASE}/var"
export PATH="#{MU_BASE}/bin:/usr/local/ruby-current/bin:/usr/local/python-current/bin:${PATH}:/opt/opscode/embedded/bin"
}
  mode 0644
  action :create_if_missing
  not_if { ::File.size?("#{MU_BASE}/etc/mu.rc") }
end

# Community cookbooks keep touching gems, and none of them are smart about our
# default umask. We have to clean up after them every time.
rubies.each { |rubydir|
  execute "trigger permission fix in #{rubydir}" do
    command "ls /etc/motd > /dev/null"
    notifies :run, "bash[fix #{rubydir} gem permissions]", :delayed
  end
}
bash "fix misc permissions" do
  code <<-EOH
    find #{MU_BASE}/lib -not -path "#{MU_BASE}/.git" -type d -exec chmod go+r {} \\;
    find #{MU_BASE}/lib -not -path "#{MU_BASE}/.git/*" -type f -exec chmod go+r {} \\;
    chmod go+rx #{MU_BASE}/lib/bin/* #{MU_BASE}/lib/extras/*-stock-* #{MU_BASE}/lib/extras/vault_tools/*.sh
  EOH
end

directory TMPDIR do
  action :delete
  recursive true
end
