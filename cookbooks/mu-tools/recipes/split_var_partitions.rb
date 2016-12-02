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

if !node[:application_attributes][:skip_recipes].include?('split_var_partitions')
  case node[:platform]
    when "centos", "redhat"
  
      include_recipe "mu-tools::aws_api"
  
      execute "reboot for /var" do
        command "/sbin/shutdown -r +1 'Adjusting partitions under /var' > /dev/null < /dev/null &"
        action :nothing
      end
  
      # Create the volumes here. Moving data around and setting up the mounts will
      # require us to be in single-user mode, however.
      ["var", "var_log", "var_log_audit"].each { |volume|
        params = Base64.urlsafe_encode64(JSON.generate(
          {
            :dev => node[:application_attributes][volume][:mount_device],
            :size => node[:application_attributes][volume][:volume_size_gb]
          }
        ))
# XXX would rather exec this inside a resource, guard it, etc
        mommacat_request("add_volume", params)
  
        if node.platform_version.to_i == 6
          execute "mkfs.ext4 #{node[:application_attributes][volume][:mount_device]}" do
            not_if "tune2fs -l #{node[:application_attributes][volume][:mount_device]}"
            notifies :run, "execute[reboot for /var]", :delayed
          end
        elsif node.platform_version.to_i == 7
          execute "mkfs.xfs -i size=512 #{node[:application_attributes][volume][:mount_device]}" do
            not_if "xfs_info #{node[:application_attributes][volume][:mount_device]}"
            notifies :run, "execute[reboot for /var]", :delayed
          end
  
          # doing something stoopid because CentOS7 dosen't like our init.d script. Should fix that instead
          directory "/mnt#{node[:application_attributes][volume][:mount_directory]}" do
            recursive true
          end
  
          execute "mount #{node[:application_attributes][volume][:mount_device]} /mnt#{node[:application_attributes][volume][:mount_directory]}" do
            not_if "df -h | grep #{node[:application_attributes][volume][:mount_device]}"
          end
        end
      }
  
      if node.platform_version.to_i == 7
        # Copying var on a live system, should refactor mu-migrate-var-partitions to work on CentOS7
        execute "cd /var && tar -cpf - . | ( cd /mnt/var && tar -xvpf - )" do
          only_if "df -h | grep /dev/xvdo | grep /mnt/var"
        end
  
        %w{/mnt/var/log/audit /mnt/var/log /mnt/var}.each { |mount_point|
          execute "umount #{mount_point}" do
            only_if "df -h | grep #{mount_point}"
          end
        }
  
        %w{var var_log var_log_audit}.each { |volume|
          mount node[:application_attributes][volume][:mount_directory] do
            device node[:application_attributes][volume][:mount_device]
            fstype "xfs"
            options "defaults"
            action [:mount, :enable]
          end
        }
  
        execute "restorecon -Rv /var" do
          not_if "ls -aZ /var | grep ':var_t:'"
        end
      end
  
      if node.platform_version.to_i == 6
        # CentOS 7 seems to be freaking out on this, even when changing fstab to xfs and UUID
        package "lsof"
  
        file "/etc/init.d/mu-migrate-var-partitions" do
          mode 0755
          content '#!/bin/sh
# mu-migrate-var-partitions Move /var and friends off of the root partition and onto their own
#
# chkconfig: 12345 00 99
# description: Move /var and friends off of the root par
# tition and onto their own
#

if [ "`egrep \' /var \' /etc/fstab`" != "" ];then
exit 0
fi

if [ "`/usr/sbin/lsof | egrep \' /var/[^[:space:]]+$\'`" != "" ];then
echo "Services still have files open in /var, forcing init to single-user"
/sbin/init 1
sleep 30
fi

mkdir -p /mnt5
/bin/mount '+node[:application_attributes][:var][:mount_device]+' /mnt5
mkdir -p /mnt5/log
/bin/mount '+node[:application_attributes][:var_log][:mount_device]+' /mnt5/log
mkdir -p /mnt5/log/audit
/bin/mount '+node[:application_attributes][:var_log_audit][:mount_device]+' /mnt5/log/audit

/bin/umount /var/tmp
cd /var && tar -cpf - . | ( cd /mnt5 && tar -xvpf - )

rm -rf /var/*

/bin/umount /mnt5/log/audit
/bin/umount /mnt5/log
/bin/umount /mnt5

echo "'+node[:application_attributes][:var][:mount_device]+' /var ext4 defaults 0 0" >> /etc/fstab
echo "'+node[:application_attributes][:var_log][:mount_device]+' /var/log ext4 defaults 0 0" >> /etc/fstab
echo "'+node[:application_attributes][:var_log_audit][:mount_device]+' /var/log/audit ext4 defaults 0 0" >> /etc/fstab

/bin/mount /var
/bin/mount /var/log
/bin/mount /var/log/audit
/bin/mount /var/tmp
/sbin/restorecon -Rv /var

init 3

'

        end
  
        execute "/sbin/chkconfig --add mu-migrate-var-partitions && /sbin/chkconfig mu-migrate-var-partitions on"
        # XXX Trigger a reboot! Ye gods, we're basically Windows now.
      end
    else
      Chef::Log.info("Unsupported platform #{node[:platform]}")
  end
end
