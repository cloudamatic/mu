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
        cfg[cloud].values.each { |acct|
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
    "disable_nagios" => false,
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

  in_gem = (Gem.paths and Gem.paths.home and File.dirname(__FILE__).match(/^#{Gem.paths.home}/))

  if in_gem
    default_cfg.delete("ldap")
    default_cfg.delete("ssl")
    default_cfg.delete("scratchpad")
    default_cfg.delete("libdir")
    default_cfg.delete("installdir")
  else
    if File.exist?("/opt/mu/etc/mu.yaml")
      default_cfg.merge!(YAML.load(File.read("/opt/mu/etc/mu.yaml")))
      default_cfg["config_files"] = ["/opt/mu/etc/mu.yaml"]
    end
  end

  default_cfg.merge!(default_cfg_overrides) if default_cfg_overrides

  if !File.exist?(cfgPath) and Process.uid == 0
    puts "**** Master config #{cfgPath} does not exist, initializing *****"
    File.open(cfgPath, File::CREAT|File::TRUNC|File::RDWR, 0644){ |f|
      f.puts default_cfg.to_yaml
    }
  end

  global_cfg = { "config_files" => [], "overridden_keys" => [] }
  if File.exist?(cfgPath)
    global_cfg = YAML.load(File.read(cfgPath))
    global_cfg["config_files"] = [cfgPath]
  end

  home = Etc.getpwuid(Process.uid).dir
  username = Etc.getpwuid(Process.uid).name
  if File.readable?("#{home}/.mu.yaml") and cfgPath != "#{home}/.mu.yaml"
    localfile = YAML.load(File.read("#{home}/.mu.yaml"))
    if localfile
      global_cfg.merge!(localfile)
      global_cfg["config_files"] << "#{home}/.mu.yaml"
      global_cfg["overridden_keys"] = localfile.keys
    end
  end
  if !global_cfg.has_key?("installdir")
    if ENV['MU_INSTALLDIR']
      global_cfg["installdir"] = ENV['MU_INSTALLDIR']
    elsif !in_gem
      global_cfg["installdir"] = "/opt/mu"
    end
  end
  if !global_cfg.has_key?("libdir")
    if ENV['MU_INSTALLDIR']
      global_cfg["libdir"] = ENV['MU_INSTALLDIR']+"/lib"
    elsif !in_gem
      global_cfg["libdir"] = File.realpath(File.expand_path(File.dirname(__FILE__))+"/..")
    end
  end
  if !global_cfg.has_key?("datadir")
    if username != "root"
      global_cfg["datadir"] = home+"/.mu/var"
    elsif global_cfg.has_key?("installdir")
      global_cfg["datadir"] = global_cfg["installdir"]+"/var"
    else
      global_cfg["datadir"] = "/opt/mu/var"
    end
    default_cfg["ssl"] = {
      "cert" => global_cfg["datadir"]+"/ssl/mommacat.crt",
      "key" => global_cfg["datadir"]+"/ssl/mommacat.key",
      "chain" => global_cfg["datadir"]+"/ssl/Mu_CA.pem"
    }
  end

  exit 1 if !validateClouds(global_cfg)

  $LOAD_PATH << "#{global_cfg["libdir"]}/modules"
  return default_cfg.merge(global_cfg).freeze
end

# Shorthand for locating the path to mu.yaml
def cfgPath
  in_gem = false
  gemwhich = %x{gem which mu 2>&1}.chomp
  gemwhich = nil if $?.exitstatus != 0
  mypath = File.realpath(File.expand_path(File.dirname(__FILE__)))
  if !mypath.match(/^\/opt\/mu/)
    if Gem.paths and Gem.paths.home and
       (mypath.match(/^#{Gem.paths.home}/) or gemwhich.match(/^#{Gem.paths.home}/))
      in_gem = true
    elsif $?.exitstatus == 0 and gemwhich and !gemwhich.empty?
      $LOAD_PATH.each { |path|
        if path.match(/\/cloud-mu-[^\/]+\/modules/) or
           path.match(/#{Regexp.quote(gemwhich)}/)
          in_gem = true
        end
      }
    end
  end
  home = Etc.getpwuid(Process.uid).dir
  Etc.getpwuid(Process.uid).name # validates existence of a username
  if Process.uid == 0 and !in_gem
    if ENV.include?('MU_INSTALLDIR')
      ENV['MU_INSTALLDIR']+"/etc/mu.yaml"
    elsif Dir.exist?("/opt/mu")
      "/opt/mu/etc/mu.yaml"
    else
      "#{home}/.mu.yaml"
    end
  else
    "#{home}/.mu.yaml"
  end
end

def cfgExists?
  File.exist?(cfgPath)
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
