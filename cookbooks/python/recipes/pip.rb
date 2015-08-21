#
# Author:: Seth Chisamore <schisamo@chef.io>
# Cookbook Name:: python
# Recipe:: pip
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

# Where does pip get installed?
# platform/method: path (proof)
# redhat/package: /usr/bin/pip (sha a8a3a3)
# omnibus/source: /opt/local/bin/pip (sha 29ce9874)

cookbook_file "#{Chef::Config[:file_cache_path]}/get-pip.py" do
  source 'get-pip.py'
  mode "0644"
  not_if { ::File.exists?(node['python']['pip_binary']) }
end

execute "install-pip" do
  cwd Chef::Config[:file_cache_path]
  command <<-EOF
#{node['python']['binary']} get-pip.py
  EOF
  not_if { ::File.exists?(node['python']['pip_binary']) }
end

case node[:platform]
  when "windows"
    execute "upgrade setuptools using pip full path" do
      not_if "echo %path% | find /I \"#{node.python.prefix_dir}\\python#{node.python.major_version}\\Scripts\""
      command "#{node['python']['pip_binary']} install setuptools --upgrade"
    end
    python_pip 'setuptools' do
      only_if "echo %path% | find /I \"#{node.python.prefix_dir}\\python#{node.python.major_version}\\Scripts\""
      action :upgrade
      version node['python']['setuptools_version'] if !node['python']['setuptools_version'].nil?
    end
  else
    python_pip 'setuptools' do
      action :upgrade
      version node['python']['setuptools_version'] if !node['python']['setuptools_version'].nil?
    end
end
