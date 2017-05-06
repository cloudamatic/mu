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

require 'etc'

# Load our configuration settings directly, rather than depending on our
# invoking environment having been completely sane. Really we shouldn't be
# doing much with the environment at all...
# @param path [String]: The path to a .murc file to load.
# @return [void]
def parseRCFile(path)
  if File.readable?(path)
    File.readlines(path).each { |line|
      line.strip!
      next if !line.match(/^export.*?=/)
      name, value = line.split(/=/, 2)
      name.sub!(/^export /, "")
      if !value.nil? and !value.empty?
        value.gsub!(/(^"|"$)/, "")
        ENV[name] = value if !value.match(/\$/)
      end
    }
  end
end

if ENV.include?('MU_INSTALLDIR')
  parseRCFile ENV['MU_INSTALLDIR']+"/etc/mu.rc"
elsif File.readable?("/opt/mu/etc/mu.rc")
  parseRCFile "/opt/mu/etc/mu.rc"
end

home = Etc.getpwuid(Process.uid).dir
parseRCFile "#{home}/.murc"

if !ENV.include?('MU_INSTALLDIR')
  ENV['MU_INSTALLDIR'] = "/opt/mu"
  puts "Environment isn't set, guessing that maybe Mu is in /opt/mu"
end

if !ENV.include?('MU_LIBDIR')
  ENV['MU_LIBDIR'] = ENV['MU_INSTALLDIR']+"/lib"
end

$MUDIR = ENV['MU_LIBDIR']

$LOAD_PATH << "#{$MUDIR}/modules"
