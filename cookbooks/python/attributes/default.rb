#
# Author:: Seth Chisamore (<schisamo@chef.io>)
# Cookbook Name:: python
# Attribute:: default
#
# Copyright 2011, Chef Software, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

default['python']['install_method'] = 'package'

if node['python']['install_method'] == 'package'
  case node['platform']
    when "windows"
      default['python']['prefix_dir'] = 'c:\\bin\\python'
    when "smartos"
      default['python']['prefix_dir'] = '/opt/local'
    else
      default['python']['prefix_dir'] = '/usr'
  end
else
  default['python']['prefix_dir'] = '/usr/local'
end


default['python']['url'] = 'http://www.python.org/ftp/python'
default['python']['version'] = '2.7.9'
major_version = node['python']['version'].split('.')
major_version.pop()
default['python']['major_version'] = major_version.join()
default['python']['checksum'] = '1d8728eb0dfcac72a0fd99c17ec7f386'
default['python']['configure_options'] = %W{--prefix=#{node['python']['prefix_dir']}}
default['python']['make_options'] = %W{install}

case node[:platform]
  when "windows"
    default['python']['binary'] = "#{node['python']['prefix_dir']}\\python#{node['python']['major_version']}\\python"
    default['python']['pip_location'] = "#{node['python']['prefix_dir']}\\python#{node['python']['major_version']}\\Scripts\\pip"
    default['python']['virtualenv_location'] = "#{node['python']['prefix_dir']}\\python#{node['python']['major_version']}\\Scripts\\virtualenv"
  else
    default['python']['binary'] = "#{node['python']['prefix_dir']}/bin/python"
    default['python']['pip_location'] = "#{node['python']['prefix_dir']}/bin/pip"
    default['python']['virtualenv_location'] = "#{node['python']['prefix_dir']}/bin/virtualenv"
end

default['python']['setuptools_version'] = nil # defaults to latest
default['python']['virtualenv_version'] = nil

if node['python']['install_method'] == 'source'
  default['python']['pip_binary'] = "#{node['python']['prefix_dir']}/bin/pip"
elsif platform_family?("rhel", "fedora")
  default['python']['pip_binary'] = "/usr/bin/pip"
elsif platform_family?("smartos")
  default['python']['pip_binary'] = "/opt/local/bin/pip"
elsif platform_family?("windows")
  default['python']['pip_binary'] = node['python']['pip_location']
else
  default['python']['pip_binary'] = "/usr/local/bin/pip"
end
