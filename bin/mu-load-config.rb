#!/usr/bin/env PATH="/usr/local/ruby-current/bin/ruby:${PATH}" ruby
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
def loadMuConfig(default_cfg_overrides = nil)
  # Start with sane defaults
  default_cfg = {
    "installdir" => "/opt/mu",
    "libdir" => "/opt/mu/lib",
    "hostname" => "mu-master",
    "ssl" => {
      "cert" => "/opt/mu/var/ssl/mommacat.crt",
      "key" => "/opt/mu/var/ssl/mommacat.key",
      "chain" => "/opt/mu/var/ssl/Mu_CA.pem"
    },
    "mu_admin_email" => "root@localhost",
    "jenkins_admin_email" => "root@localhost",
    "allow_invade_foreign_vpcs" => false,
    "mu_repo" => "cloudamatic/mu.git",
    "public_address" => "localhost",
    "banner" => "Mu Master",
    "scratchpad" => {
      "template_path" => "/opt/mu/lib/modules/scratchpad.erb",
      "max_age" => 3600
    },
    "ldap" => {
      "type" => "389 Directory Services",
      "base_dn" => "OU=Mu,DC=platform-mu",
      "user_ou" => "OU=Users,OU=Mu,DC=platform-mu",
      "group_ou" => "OU=Groups,OU=Mu,DC=platform-mu",
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
      "user_group_dn" => "CN=mu-users,OU=Groups,OU=Mu,DC=platform-mu",
      "user_group_name" => "mu-users",
      "admin_group_dn" => "CN=mu-admins,OU=Groups,OU=Mu,DC=platform-mu",
      "admin_group_name" => "mu-admins",
      "dcs" => ["127.0.0.1"]
    }
  }
  default_cfg.merge!(default_cfg_overrides) if default_cfg_overrides
  cfg_file = nil
  if ENV.include?('MU_INSTALLDIR')
    cfg_file = ENV['MU_INSTALLDIR']+"/etc/mu.yaml"
    default_cfg["installdir"] = ENV['MU_INSTALLDIR']
  else
    cfg_file = "/opt/mu/etc/mu.yaml"
    default_cfg["installdir"] = "/opt/mu"
  end

  if !File.exists?(cfg_file) and Process.uid == 0
    puts "**** Master config #{cfg_file} does not exist, initializing *****"
    File.open(cfg_file, File::CREAT|File::TRUNC|File::RDWR, 0644){ |f|
      f.puts default_cfg.to_yaml
    }
  end

  global_cfg = { "config_files" => [] }
  if File.exists?(cfg_file)
    global_cfg = YAML.load(File.read(cfg_file))
    global_cfg["config_files"] = [cfg_file]
  end

  home = Etc.getpwuid(Process.uid).dir
  username = Etc.getpwuid(Process.uid).name
  if File.readable?("#{home}/.mu.yaml")
    global_cfg.merge!(YAML.load(File.read("#{home}/.mu.yaml")))
    global_cfg["config_files"] << "#{home}/.mu.yaml"
  end
  if !global_cfg.has_key?("installdir")
    if ENV['MU_INSTALLDIR']
      global_cfg["installdir"] = ENV['MU_INSTALLDIR']
    elsif Gem.paths and Gem.paths.home
      global_cfg["installdir"] = File.realpath(File.expand_path(File.dirname(Gem.paths.home))+"/../../../")
    else
      global_cfg["installdir"] = "/opt/mu"
    end
  end
  if !global_cfg.has_key?("libdir")
    if ENV['MU_INSTALLDIR']
      global_cfg["libdir"] = ENV['MU_INSTALLDIR']+"/lib"
    else
      global_cfg["libdir"] = File.realpath(File.expand_path(File.dirname(__FILE__))+"/..")
    end
  end
  if !global_cfg.has_key?("datadir")
    if username != "root"
      global_cfg["datadir"] = home+"/.mu"
    elsif global_cfg.has_key?("installdir")
      global_cfg["datadir"] = global_cfg["installdir"]+"/var"
    else
      global_cfg["datadir"] = "/opt/mu/var"
    end
  end

  $LOAD_PATH << "#{global_cfg["libdir"]}/modules"
  return default_cfg.merge(global_cfg).freeze
end

def cfgPath
  if Process.uid == 0
    if ENV.include?('MU_INSTALLDIR')
      ENV['MU_INSTALLDIR']+"/etc/mu.yaml"
    else
      "/opt/mu/etc/mu.yaml"
    end
  else
    home = Etc.getpwuid(Process.uid).dir
    username = Etc.getpwuid(Process.uid).name
    "#{home}/.mu.yaml"
  end
end

def cfgExists?
  File.exists?(cfgPath)
end

# Output an in-memory configuration hash to the standard config file location,
# in YAML.
# @param cfg [Hash]: The configuration to dump
def saveMuConfig(cfg)
  puts "**** Saving master config to #{cfgPath} *****"
  File.open(cfgPath, File::CREAT|File::TRUNC|File::RDWR, 0644){ |f|
    f.puts cfg.to_yaml
  }
end

$MU_CFG = loadMuConfig($MU_SET_DEFAULTS)
