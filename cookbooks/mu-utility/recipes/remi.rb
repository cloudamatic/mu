#
# Cookbook Name:: mu-utility
# Recipe:: remi
#
# Install the REMI yum repository for CentOS.
#
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

case node[:platform]
  when "centos"
    if node['platform_version'].to_i < 6
      raise "Centos #{node['platform_version']} not supported"
    end

    remirepo=yum_repository "remi" do
      description "Les RPM de Remi"
      mirrorlist "http://rpms.famillecollet.com/enterprise/#{node['platform_version'].to_i.to_s}/remi/mirror"
      enabled false
      gpgkey "http://rpms.famillecollet.com/RPM-GPG-KEY-remi"
      if node[:cap_global_compile_run] then
        action :nothing
      else
        action :create
      end
    end

    # Doing this with run_action causes us to be invoked early, at
    # compile time instead of converge time.
    remirepo.run_action(:create) if node[:cap_global_compile_run]
  else
    Chef::Log.info("Unsupported platform #{node[:platform]}")
end
