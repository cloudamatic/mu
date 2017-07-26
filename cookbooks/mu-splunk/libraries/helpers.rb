#
# Cookbook Name:: splunk
# Libraries:: helpers
#
# Author: Joshua Timberman <joshua@getchef.com>
# Copyright (c) 2014, Chef Software, Inc <legal@getchef.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

def splunk_file(uri)
  require 'pathname'
  require 'uri'
  if URI.parse(uri).query.to_s.match(/filename=/)
    Pathname.new(URI.parse(uri).query).to_s.gsub(/^.*?filename=(.*?)\&.*/, '\1')
  else
    Pathname.new(URI.parse(uri).path).basename.to_s
  end
end

def splunk_cmd
  case node['platform_family']
    when 'windows'
      "#{splunk_dir}\\bin\\splunk.exe"
    else
      "#{splunk_dir}/bin/splunk"
  end
end

def splunk_dir
  # Splunk Enterprise (Server) will install in /opt/splunk.
  # Splunk Universal Forwarder (not Server) will install in /opt/splunkforwarder
  case node['platform_family']
    when 'windows'
      node['splunk']['is_server'] ? '/opt/splunk' : 'C:\\Program Files\\SplunkUniversalForwarder'
    else
      node['splunk']['is_server'] ? '/opt/splunk' : '/opt/splunkforwarder'
  end
end

def splunk_auth(auth)
  # if auth is a string, we assume it's correctly
  # defined as a splunk authentication string, like:
  #
  # admin:changeme
  #
  # if it is an array, we assume it has two elements that should be
  # joined with a : to make it defined as a splunk authentication
  # string (as above.
  case auth
    when String
      auth
    when Array
      auth.join(':')
  end
end

def chown_r_splunk(triggerfile, user)
  if ::File.stat(triggerfile).uid.eql?(0)
    FileUtils.chown_R(user, user, splunk_dir)
  end
end
