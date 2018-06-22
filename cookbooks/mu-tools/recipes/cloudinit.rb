#
# Cookbook Name:: mu-utility
# Recipe:: cloudinit
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
#
# Make sure cloud-init or equivalent gets installed. Kind of trivial for the
# common Linux platforms.
 
if !node['application_attributes']['skip_recipes'].include?('epel') and !node['application_attributes']['skip_recipes'].include?('base_repositories')
  if platform_family?("rhel")
    include_recipe "yum-epel"
    package "cloud-init" do
      ignore_failure true
    end
  
    if node['platform_version'].to_i == 6
      bash "allow ssh as root" do
        only_if "grep 'disable_root: 1' /etc/cloud/cloud.cfg"
        code <<-EOH
          sed -i 's/disable_root: 1/disable_root: 0/' /etc/cloud/cloud.cfg
        EOH
      end
      ["puppet", "chef", "salt-minion", "mcollective", "disable-ec2-metadata"].each { |cfgline|
        bash "disabled cloudinit #{cfgline} module" do
          only_if "grep '^ - #{cfgline}$' /etc/cloud/cloud.cfg"
          code <<-EOH
            sed -i 's/^ - #{cfgline}$//' /etc/cloud/cloud.cfg
          EOH
        end
      }
    elsif node['platform_version'].to_i == 7
      # making sure hostname  is kept across reboot
      execute "sed -i '/ssh_pwauth/a preserve_hostname: true' /etc/cloud/cloud.cfg" do
        not_if "grep 'preserve_hostname: true' /etc/cloud/cloud.cfg"
      end
    end
  
  elsif platform_family?("debian")
    package "cloud-init"
  elsif platform_family?("windows")
    Chef::Log.info ("Windows use ec2config, no cloud-init package is necessary")
  else
    Chef::Log.info("Unsupported platform #{node['platform']}")
  end
end
