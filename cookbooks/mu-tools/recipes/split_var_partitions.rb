#
# Cookbook Name:: mu-tools
# Recipe:: default
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

# This recipe attempts to create a series of separate partitions to be mounted
# in lieu of having /var be part of your root volume. It makes a lot of brittle
# assumptions and is overall a dodgy procedure. If you find it useful, it is
# recommended you only use this when building new baseline images, rather than
# make it part of your regular build process.

if !node['application_attributes']['skip_recipes'].include?('split_var_partitions')
  case node['platform']
    when "redhat", "rhel", "centos", "amazon"

      include_recipe "mu-tools::aws_api"
      include_recipe "mu-tools::google_api"
  
      # Moving /var data around and setting up the mounts means interfering
      # with a bunch of stuff writing /var. Make an attempt to turn the stuff
      # off.
      execute "make auditd stoppable" do
        command "sed -i s/RefuseManualStop=yes/RefuseManualStop=no/ /usr/lib/systemd/system/auditd.service"
        only_if "grep ^RefuseManualStop=yes /usr/lib/systemd/system/auditd.service"
        action :nothing
      end
      services = ["rsyslog", "postfix", "acpid", "NetworkManager", "dbus", "auditd"]
      services.each { |svc|
        begin
          resources("service[#{svc}]")
        rescue Chef::Exceptions::ResourceNotFound
          service svc do
            action :nothing
            ignore_failure true
            if svc == "auditd"
              notifies :run, "execute[make auditd stoppable]", :before
            end
          end
        end
      }

      execute "umount /var/tmp" do
        ignore_failure true
        action :nothing
      end
      ["var_log_audit", "var_log", "var"].each { |volume|
        mu_tools_disk node['application_attributes'][volume]['mount_directory'] do
          device node['application_attributes'][volume]['mount_device']
          size node['application_attributes'][volume]['volume_size_gb']
          preserve_data true
          reboot_after_create true
          services.each { |svc|
            notifies :stop, "service[#{svc}]", :before
          }
          notifies :run, "execute[umount /var/tmp]", :before if volume == "var"
        end
      }
      ["var", "var_log", "var_log_audit"].each { |volume|
        mu_tools_disk "properly mount #{volume}" do
          mountpoint node['application_attributes'][volume]['mount_directory']
          device node['application_attributes'][volume]['mount_device']
          not_if "awk '{print $2}' < /etc/mtab | grep '^#{node['application_attributes'][volume]['mount_directory']}$'"
        end
      }
      execute "restorecon -Rv /var" do
        not_if "ls -aZ /var | grep ':var_t:'"
      end
  
    else
      Chef::Log.info("Unsupported platform #{node['platform']}")
  end
end
