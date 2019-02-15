# ~FC015
#
# Cookbook Name:: splunk
# Definition:: installer
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
define :splunk_installer, :url => nil do
  cache_dir = Chef::Config[:file_cache_path]
  package_file = splunk_file(params[:url])
  cached_package = ::File.join(cache_dir, package_file)

  begin
    resources('remote_file['+cached_package+']')
  rescue Chef::Exceptions::ResourceNotFound
    remote_file cached_package do
      source params[:url]
      action :nothing
    end
  end
  file "#{cached_package} cleanup" do
    path cached_package
    action :nothing
  end

  if %w( omnios ).include?(node['platform'])
    pkgopts = [
        "-a #{cache_dir}/#{params[:name]}-nocheck",
        "-r #{cache_dir}/splunk-response"
    ]

    execute "uncompress #{cached_package}" do
      not_if { ::File.exist?("#{cache_dir}/#{package_file.gsub(/\.Z/, '')}") }
    end

    cookbook_file "#{cache_dir}/#{params[:name]}-nocheck" do
      source 'splunk-nocheck'
    end

    file "#{cache_dir}/splunk-response" do
      content 'BASEDIR=/opt'
    end

    execute "usermod -d #{node['splunk']['user']['home']} splunk" do
      only_if 'grep -q /home/splunk /etc/passwd'
    end
  elsif %w( windows ).include?(node['platform'])
    pkgopts = [
        'AGREETOLICENSE=Yes'
    ]
  end

  begin
    resources('execute[accept license]')
  rescue Chef::Exceptions::ResourceNotFound
    execute "accept license" do
      command "/opt/splunkforwarder/bin/splunk enable boot-start --accept-license --answer-yes"
      action :nothing
    end
  end

  begin
    resources('package['+params[:name]+']')
  rescue Chef::Exceptions::ResourceNotFound
    package params[:name] do # ~FC109
      source cached_package.gsub(/\.Z/, '')
      notifies :create, "remote_file[#{cached_package}]", :before
      notifies :delete, "file[#{cached_package} cleanup]", :immediately
      case node['platform_family']
        when 'rhel'
          not_if { ::Dir.glob("/opt/splunkforwarder/splunkforwarder-#{node['splunk']['preferred_version']}-*").size > 0 }
          provider Chef::Provider::Package::Rpm
          notifies :run, "execute[accept license]", :immediately if node['splunk']['accept_license']
        when 'debian'
          not_if { ::Dir.glob("/opt/splunkforwarder/splunkforwarder-#{node['splunk']['preferred_version']}-*").size > 0 }
          provider Chef::Provider::Package::Dpkg
          notifies :run, "execute[accept license]", :immediately if node['splunk']['accept_license']
        when 'omnios'
          not_if { ::Dir.glob("/opt/splunkforwarder/splunkforwarder-#{node['splunk']['preferred_version']}-*").size > 0 }
          provider Chef::Provider::Package::Solaris
          notifies :run, "execute[accept license]", :immediately if node['splunk']['accept_license']
          options pkgopts.join(' ')
        when 'windows'
          not_if { ::Dir.glob("c:/Program Files/SplunkUniversalForwarder/splunkforwarder-#{node['splunk']['preferred_version']}-*").size > 0 }
          provider Chef::Provider::Package::Windows
          options pkgopts.join(' ')
      end
    end
  end
end
