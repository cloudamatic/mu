#!/usr/local/ruby-current/bin/ruby
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
require 'yaml'
require 'etc'
require 'json'
require 'erubis'

# Locate and load the Mu Master's configuration, typically stored in
# /opt/mu/etc/mu.yaml. If ~/.mu.yaml exists, load that too and allow it to
# override values from the global config. Also puts Mu's /modules directory
# into the Ruby $LOAD_PATH.
# @return [Hash]
def loadMuConfig
  # Start with sane defaults
  default_cfg = {
    "installdir" => "/opt/mu",
    "libdir" => "/opt/mu/lib",
    "hostname" => "mu-master",
    "mu_admin_email" => "root@localhost",
    "jenkins_admin_email" => "root@localhost",
    "allow_invade_foreign_vpcs" => false,
    "mu_repo" => "cloudamatic/mu.git",
    "public_address" => "localhost",
    "banner" => "Mu Master",
    "scratchpad" => {
      "template_path" => "/opt/mu/lib/modules/scratchpad.erb"
    },
    "aws" => {
      "log_bucket_name" => "mu-master-logs"
    },
    "ldap" => {
      "type" => "389 Directory Services",
      "base_dn" => "OU=Mu,DC=platform-mu",
      "user_ou" => "OU=Users,OU=Mu,DC=platform-mu",
      "bind_creds" => {
        "vault" => "mu_ldap",
        "item" => "mu_bind_acct",
        "username_field" => "username",
        "password_field" => "password"
      },
      "join_creds" => {
        "vault" => "mu_ldap",
        "item" => "mu_join_acct",
        "username_field" => "username",
        "password_field" => "password"
      },
      "domain_name" => "platform-mu",
      "domain_netbios_name" => "mu",
      "user_group_dn" => "CN=Mu-Users,OU=Groups,OU=Mu,DC=platform-mu",
      "user_group_name" => "mu-users",
      "admin_group_dn" => "CN=Mu-Admins,OU=Groups,OU=Mu,DC=platform-mu",
      "admin_group_name" => "mu-admins",
      "dcs" => ["localhost"]
    }
  }
  ["HOSTNAME", "MU_ADMIN_EMAIL", "JENKINS_ADMIN_EMAIL"].each { |var|
    if ENV.has_key?(var) and !ENV[var].empty?
      default_cfg[var.downcase] = ENV[var]
    end
  }
  if ENV.has_key?("CHEF_PUBLIC_IP")
    default_cfg["public_address"] = ENV['CHEF_PUBLIC_IP']
  end
  if ENV.has_key?("ALLOW_INVADE_FOREIGN_VPCS") and !ENV['ALLOW_INVADE_FOREIGN_VPCS'].empty?
    default_cfg["allow_invade_foreign_vpcs"] = true
  end
  if ENV.include?('MU_INSTALLDIR')
    cfg_file = ENV['MU_INSTALLDIR']+"/etc/mu.yaml"
    default_cfg["installdir"] = ENV['MU_INSTALLDIR']
    if !File.exists?(cfg_file)
      puts "**** Master config #{cfg_file} does not exist, initializing *****"
      File.open(cfg_file, File::CREAT|File::TRUNC|File::RDWR, 0644){ |f|
        f.puts default_cfg.to_yaml
      }
    end
    global_cfg = YAML.load(File.read(cfg_file))
    global_cfg["config_files"] = [cfg_file]
  elsif File.readable?("/opt/mu/etc/mu.yaml")
    global_cfg = YAML.load(File.read("/opt/mu/etc/mu.yaml"))
    global_cfg["config_files"] = ["/opt/mu/etc/mu.yaml"]
    global_cfg["installdir"] = "/opt/mu"
# XXX have more guesses, e.g. assume this file's being loaded from somewhere in the install. That's mean picking where this thing lives, deciding whether's a stub or the full library...
  end

  home = Etc.getpwuid(Process.uid).dir
  username = Etc.getpwuid(Process.uid).name
  global_cfg["config_files"] = [] if !global_cfg["config_files"]
  if File.readable?("#{home}/.mu.yaml")
    global_cfg.merge!(YAML.load(File.read("#{home}/.mu.yaml")))
    global_cfg["config_files"] << "#{home}/.mu.yaml"
  end
  if !global_cfg.has_key?("libdir")
    global_cfg["libdir"] = ENV['MU_INSTALLDIR']+"/lib"
  end
  if !global_cfg.has_key?("datadir")
    if username != "root"
      global_cfg["datadir"] = home+"/.mu"
    else
      global_cfg["datadir"] = ENV['MU_INSTALLDIR']+"/var"
    end
  end

  $LOAD_PATH << "#{global_cfg["libdir"]}/modules"
  return default_cfg.merge(global_cfg).freeze
end

$MU_CFG = loadMuConfig
