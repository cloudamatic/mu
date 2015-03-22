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

case node[:platform]
	when "centos"

	include_recipe "mu-tools::aws_api"

	execute "reboot for /var" do
		command "/sbin/shutdown -r +1 'Adjusting partitions under /var' > /dev/null < /dev/null &"
		action :nothing
	end

	# Create the volumes here. Moving data around and setting up the mounts will
	# require us to be in single-user mode, however.
	["var", "var_log", "var_log_audit"].each { |volume|
		ruby_block "create #{volume}" do
			extend CAPVolume
			block do
				require 'aws-sdk-core'
				if !File.open("/etc/mtab").read.match(/ #{node[:application_attributes][volume][:mount_directory]} /) and !volume_attached(node[:application_attributes][volume][:mount_device])
					create_node_volume(volume)
					result = attach_node_volume(volume)
				end
			end
			not_if "tune2fs -l #{node[:application_attributes][volume][:mount_device]}"
		end

		ruby_block "label #{volume} as #{node.application_attributes[volume].label}" do
			extend CAPVolume
			block do
			  tags = [ { key: "Name", value: node.application_attributes[volume].label } ]
			  if node.tags.is_a?(Hash)
			    node.tags.each_pair { |key, value|
			      tags << { key: key, value: value }
			    }
			  end
			  tag_volume(node.application_attributes[volume].mount_device, tags)
			end
		end rescue NoMethodError

	  execute "mkfs.ext4 #{node[:application_attributes][volume][:mount_device]}" do
			not_if "tune2fs -l #{node[:application_attributes][volume][:mount_device]}"
			notifies :run, "execute[reboot for /var]", :delayed
		end
	}

	package "lsof"

	file "/etc/init.d/mu-migrate-var-partitions" do
		mode 0755
		content '#!/bin/sh

	# mu-migrate-var-partitions          Move /var and friends off of the root partition and onto their own
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
	else
		Chef::Log.info("Unsupported platform #{node[:platform]}")
end
