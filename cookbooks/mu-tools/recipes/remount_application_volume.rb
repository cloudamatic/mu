# Cookbook Name::mu-tools
# Recipe::remount_application_volume
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
# Respects all mu-tools conventions and remounts an application volume after reboot
# or as desired
#
include_recipe "mu-tools::aws_api"

Chef::Log.info("Dumping node #{node[:application_attributes][:application_volume]}")
mount_device = node[:application_attributes][:application_volume][:mount_device]
mount_directory = node[:application_attributes][:application_volume][:mount_directory]
mount_volume = node[:application_attributes][:application_volume][:volume_id]

ruby_block "remount_app_volume" do
  extend CAPVolume
  block do
      Chef::Log.info("Dumping node #{node[:application_attributes][:application_volume]}")

      Chef::Log.info("Figuring out volume format enc or no")
      ebs_keyfile = node[:application_attributes][:application_volume][:ebs_keyfile]
      ebs_key_location=nil
      if ebs_keyfile.nil?
        Chef::Log.warn("No ebs_keyfile from creds store, UNENCRYPTED VOLUME REMOUNT")
        `mount #{mount_device} #{mount_directory}`
      else
          temp_mount = "/tmp/ram3"
          unless is_mounted?(temp_mount) 
            make_temp_disk!("/dev/ram3", temp_mount)
          end
          ebs_keyfile = node[:application_attributes][:application_volume][:ebs_keyfile]
          command = "aws s3 cp #{node[:application_attributes][:secure_location]}/#{ebs_keyfile} #{temp_mount}/#{ebs_keyfile}"
          Chef::Log.info("Will execute #{command}")
          `#{command}`
          Chef::Log.info("Waking and remounting encrypted volume")
           if volume_attached(mount_device)
              alias_device = mount_directory.gsub("/","") #by convention
              `cryptsetup luksOpen #{mount_device} #{alias_device} --key-file #{temp_mount}/#{ebs_keyfile}`
              `mount "/dev/mapper/#{alias_device}" #{mount_directory}`
          end
      end
      action :create
      not_if { is_mounted?(mount_directory) }
    end
end
