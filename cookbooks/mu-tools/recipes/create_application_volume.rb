#
# Cookbook Name::mu-tools
# Recipe::create_application_volume
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
# This is the prototypical secure application volume creation.  Can create more app-specific versions
# in application cookbooks by depending on mu-tools
#

Chef::Log.info("Dumping node #{node[:application_attributes][:application_volume]}")
mount_device = node[:application_attributes][:application_volume][:mount_device]
mount_volume = node[:application_attributes][:application_volume][:volume_id]
mount_directory = node[:application_attributes][:application_volume][:mount_directory]

include_recipe "mu-tools::aws_api"

# Set defaults, because awscli is silly.
#service_name = node.service_name
#if ENV['AWS_DEFAULT_REGION'].nil? and
#		!service_name.nil? and
#		!node[:deployment][service_name].nil? and
#		!node[:deployment][:servers][service_name][Chef::Config[:chef_node_name]][:region].nil?
#	region = node[:deployment][:servers][service_name][Chef::Config[:chef_node_name]][:region]
#	ENV['AWS_DEFAULT_REGION'] = region
#end

ENV.each { |e| Chef::Log.info(e.join(': ')) }

ruby_block "create_apps_volume" do
  extend CAPVolume
  block do
    result=create_node_volume(:application_volume)
  end
  only_if {
    create = true
    device_status = check_device_status(mount_device)
    Chef::Log.info "device_status is #{device_status}"
    if device_status != "unattached"
      Chef::Log.info "Not executing because #{mount_device} is #{device_status}"
      create = false
    end
    unless mount_volume.nil?
      Chef::Log.info "Not executing because #{mount_volume} is already assigned to application_volume"
      create = false
    end
    create
  }
  notifies :create, "ruby_block[attach_apps_volume]", :immediately
end
ruby_block "attach_apps_volume" do
  extend CAPVolume
  block do
    result=attach_node_volume(:application_volume)
  end
  action :nothing
  notifies :create, "directory[mount_apps_dir]", :immediately
  notifies :create, "ruby_block[format_default_volume]", :immediately
end
# Make the mountpoint, create encrypted volume and mount it
directory "mount_apps_dir" do
  owner "root"
  group "root"
  mode 00644
  path mount_directory
  action :nothing
end

ruby_block "format_default_volume" do
  # Encrypt if you can, warn and create unencrypted if not.  Encryption requires credentials secret
  extend CAPVolume
  block do
    require 'aws-sdk-core'
    Chef::Log.info("Figuring out volume format enc or no")
    ebs_keyfile = node[:application_attributes][:application_volume][:ebs_keyfile]
    ebs_key_location=nil
    if ebs_keyfile.nil?
      Chef::Log.warn("No ebs_keyfile from creds store, UNENCRYPTED VOLUME MOUNT")
    else
      #replace with fetch
      #`dd if=/dev/random of=/root/mykeyfile bs=1 count=32`
      Chef::Log.info("ebs_keyfile detected, encrypting from creds store")
      temp_mount = "/tmp/ram3"
      make_temp_disk!("/dev/ram3", temp_mount)
      ebs_key_location = temp_mount+"/"+ebs_keyfile
      command = "aws s3 cp #{node[:application_attributes][:secure_location]}/#{ebs_keyfile} #{ebs_key_location}"
      Chef::Log.info("Will execute #{command}")
      `#{command}`
    end

    Chef::Log.info("Probing for attached volume then formatting")
    if volume_attached(mount_device)
      mount_default_volume(ebs_key_location)
    end

    #clean up creds
    unless ebs_keyfile.nil?
      destroy_temp_disk("/dev/ram3")
    end

  end
  action :nothing
end
