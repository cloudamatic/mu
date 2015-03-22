#
# Author:: Seth Chisamore <schisamo@opscode.com>
# Cookbook Name:: python
# Recipe:: virtualenv
#
# Copyright 2011, Opscode, Inc.
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
include_recipe "python::pip"

case node[:platform]
  when "windows"
    execute "Upgrade virtualenv using pip full path" do
      not_if "echo %path% | find /I \"#{node.python.prefix_dir}\\python#{node.python.major_version}\\Scripts\""
        command "#{node['python']['pip_binary']} install virtualenv --upgrade"
    end
    python_pip 'virtualenv' do
      only_if "echo %path% | find /I \"#{node.python.prefix_dir}\\python#{node.python.major_version}\\Scripts\""
      action :upgrade
      version node.python.virtualenv_version if !node.python.virtualenv_version.nil?
    end
  else
    # No idea why but naked python_pip install fails, so install then update
    # Only failed once so probably not needed
    package "python-virtualenv"

    # Fail on Ubuntu becuase of a bug in setuptools, commenting out
    # execute "easy_install -U setuptools"

    # This is already done in the pip recipe, so is shouldn't be here. 
    # There was an issue with package installation only working on the second run using pip. leaving this in for now. Trying without version
    python_pip 'setuptools' do
      action :upgrade
      version node['python']['setuptools_version'] if !node['python']['setuptools_version'].nil?
    end

    python_pip 'virtualenv' do
      action :upgrade
      retries 4
      version node['python']['virtualenv_version'] if !node['python']['virtualenv_version'].nil?
    end

end
