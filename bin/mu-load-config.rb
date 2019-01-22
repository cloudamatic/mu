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
require 'socket'

# Make sure things make sense in our various cloud subsections, which are more
# complicated than the rest. May alter the hash it's passed.
def validateClouds(cfg)
  ok = true

  ['aws', 'google', 'azure'].each { |cloud|
    if cfg[cloud]
      found_default = false
      # Muddle up old-style single-account cloud configs into an array of
      # named accounts, which is what we're expecting to see nowadays.
      if cfg[cloud] and cfg[cloud].values.any? { |h| !h.is_a?(Hash) }
        puts "Converting single #{cloud} #{cfgPath} account entry to default alias"
        cfg[cloud] = {
          "default" => cfg[cloud]
        }
        cfg[cloud]["default"]["default"] = true
        found_default = true
      else
        missing_alias = false
        cfg[cloud].each_pair { |acctalias, acct|
          if acct["default"]
            if found_default
              puts "Multiple accounts have 'default' set in #{cloud}"
              ok = false
            end
            found_default = true
          end
        }
      end
      if !found_default
        first = cfg[cloud].keys.first
        puts "No default #{cloud} credentials specified in #{cfgPath}, arbitrarily designating '#{first}'"
        cfg[cloud][first]["default"] = true
      end
    end
  }

  ok
end

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
    "public_address" => Socket.gethostname || "localhost",
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

  if !File.exists?(cfgPath) and Process.uid == 0
    puts "**** Master config #{cfgPath} does not exist, initializing *****"
    File.open(cfgPath, File::CREAT|File::TRUNC|File::RDWR, 0644){ |f|
      f.puts default_cfg.to_yaml
    }
  end

  global_cfg = { "config_files" => [] }
  if File.exists?(cfgPath)
    global_cfg = YAML.load(File.read(cfgPath))
    global_cfg["config_files"] = [cfgPath]
  end

  home = Etc.getpwuid(Process.uid).dir
  username = Etc.getpwuid(Process.uid).name
  if File.readable?("#{home}/.mu.yaml") and cfgPath != "#{home}/.mu.yaml"
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

  exit 1 if !validateClouds(global_cfg)

  $LOAD_PATH << "#{global_cfg["libdir"]}/modules"
  return default_cfg.merge(global_cfg).freeze
end

# Shorthand for locating the path to mu.yaml
def cfgPath
  home = Etc.getpwuid(Process.uid).dir
  username = Etc.getpwuid(Process.uid).name
  if Process.uid == 0
    if ENV.include?('MU_INSTALLDIR')
      ENV['MU_INSTALLDIR']+"/etc/mu.yaml"
    elsif Dir.exists?("/opt/mu")
      File.realpath(File.expand_path(File.dirname(__FILE__)+"/../../etc/mu.yaml"))
    else
      "#{home}/.mu.yaml"
    end
  else
    "#{home}/.mu.yaml"
  end
end

def cfgExists?
  File.exists?(cfgPath)
end

# Output an in-memory configuration hash to the standard config file location,
# in YAML.
# @param cfg [Hash]: The configuration to dump
# @param comment [Hash]: A configuration blob that will be appended as a commented block
def saveMuConfig(cfg, comment = nil)
  exit 1 if !validateClouds(cfg)
  puts "**** Saving master config to #{cfgPath} *****"
  File.open(cfgPath, File::CREAT|File::TRUNC|File::RDWR, 0644){ |f|
    f.puts cfg.to_yaml
    if comment and comment.size > 0
      f.puts comment.to_yaml.sub(/^---$/, "EXAMPLE CLOUD LAYERS").gsub(/^/, "# ")
    end
  }
end

$MU_CFG = loadMuConfig($MU_SET_DEFAULTS)
