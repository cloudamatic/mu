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
  global_cfg = local_cfg = {}
  if ENV.include?('MU_INSTALLDIR')
    global_cfg = YAML.load(File.read(ENV['MU_INSTALLDIR']+"/etc/mu.yaml"))
    global_cfg["installdir"] = ENV['MU_INSTALLDIR']
  elsif File.readable?("/opt/mu/etc/mu.yaml")
    global_cfg = YAML.load(File.read("/opt/mu/etc/mu.yaml"))
    global_cfg["installdir"] = "/opt/mu"
# XXX have more guesses, e.g. assume this file's being loaded from somewhere in the install. That's mean picking where this thing lives, deciding whether's a stub or the full library...
  end
  
  home = Etc.getpwuid(Process.uid).dir
  username = Etc.getpwuid(Process.uid).name
  if File.readable?("#{home}/.mu.yaml")
    global_cfg.merge!(YAML.load(File.read("#{home}/.mu.yaml")))
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
  return global_cfg.freeze
end

$MU_CFG = loadMuConfig
