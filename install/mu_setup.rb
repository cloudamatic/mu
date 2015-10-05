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
require 'pp'
require 'erubis'

# Locate and load the Mu Master's configuration, typically stored in
# /opt/mu/etc/mu.yaml. If ~/.mu.yaml exists, load that too and allow it to
# override values from the global config. Also puts Mu's /modules directory
# into the Ruby $LOAD_PATH.
# @return [Hash]
def loadMuConfig
  global_cfg = local_cfg = {}
  if ENV.include?('MU_INSTALLDIR')
    global_cfg = YAML.load(File.read(ENV['MU_INSTALLDIR']+"/etc/mu.yaml"))
  elsif File.readable?("/opt/mu/etc/mu.yaml")
    global_cfg = YAML.load(File.read("/opt/mu/etc/mu.yaml"))
# XXX have more guesses, e.g. assume this file's being loaded from somewhere in the install. That's mean picking where this thing lives, deciding whether's a stub or the full library...
  end
  
  home = Etc.getpwuid(Process.uid).dir
  if File.readable?("#{home}/.mu.yaml")
    global_cfg.merge!(YAML.load(File.read("#{home}/.mu.yaml")))
  end
  if !global_cfg.has_key?("libdir")
    global_cfg["libdir"] = ENV['MU_INSTALLDIR']+"/lib"
  end

  $LOAD_PATH << "#{global_cfg["libdir"]}/modules"
  return global_cfg.freeze
end

$MU_CFG = loadMuConfig
require 'mu'

def createChefUser(user)
  rest = Chef::REST.new("https://"+$MU_CFG["public_address"], "pivotal", "/etc/opscode/pivotal.pem", {:api_version => "1"})
#  rest = Chef::ServerAPI.new("https://"+$MU_CFG["public_address"], "pivotal", "/etc/opscode/pivotal.pem", {:api_version => "1"})
  begin
    # Check for existence
    rest.get("users/#{user}")
    MU.log "Chef user #{user} already exists"
    return
  rescue Net::HTTPServerException
  end
  MU.log "Creating Chef user #{user}"
#  if user.gsub!(/\./, "")
#    MU.log "Stripped . from username to #{user}, because Chef is stupid.", MU::NOTICE
#  end
  user_data = {
    :username => user,
    :first_name => "John",
    :middle_name => "LDAP",
    :last_name => "Stange",
    :display_name => "John Stange LDAP",
    :email => "john.stange@eglobaltech.com",
    :password => "somedamnnonsense"
  }
  begin
    puts rest.post("users", user_data)
  rescue Net::HTTPServerException => e
    # Work around Chef's baffling inability to use the same email address for
    # more than one user.
    # https://github.com/chef/chef-server/issues/59
    if e.message.match(/409/) and !user_data[:email].match(/\+/)
      user_data[:email].sub!(/@/, "+"+(0...8).map { ('a'..'z').to_a[rand(26)] }.join+"@")
      retry
    else
      MU.log "Bad response when creating Chef user #{user}: #{e.message}", MU::ERR, details: user_data
    end
  end
end


if $MU_CFG.has_key?("ldap")
  bind_creds = MU::Groomer::Chef.getSecret(vault: $MU_CFG["ldap"]["svc_acct_vault"], item: $MU_CFG["ldap"]["svc_acct_item"])
  vars = {
    "server_url" => $MU_CFG["public_address"],
    "ldap" => true,
    "base_dn" => $MU_CFG["ldap"]["base_dn"],
    "group_dn" => $MU_CFG["ldap"]["group_dn"],
    "dc" => $MU_CFG["ldap"]["dcs"].first,
    "bind_dn" => bind_creds["dn"],
    "bind_pw" => bind_creds["password"],
  }
  chef_cfgfile = "/etc/opscode/chef-server.rb"
  chef_tmpfile = "#{chef_tmpfile}.tmp.#{Process.pid}"
  File.open(chef_tmpfile, File::CREAT|File::RDWR, 0644) { |f|
    f.puts Erubis::Eruby.new(File.read("chef-server.rb.erb")).result(vars)
  }
  new = File.read(chef_tmpfile)
  current = File.read(chef_cfgfile)
  if new != current
    MU.log "Updating #{chef_cfgfile}", MU::NOTICE
    File.rename(chef_tmpfile, chef_cfgfile)
    system("/opt/opscode/bin/chef-server-ctl reconfigure")
  end
  createChefUser("john.stange.admin")
end
