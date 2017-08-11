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
volume_size_gb = node[:application_attributes][:application_volume][:volume_size_gb]

include_recipe "mu-tools::aws_api"
include_recipe "mu-tools::google_api"


params = Base64.urlsafe_encode64(JSON.generate(
  {
    :dev => mount_device,
    :size => volume_size_gb
  }
))
# XXX would rather exec this inside a resource, guard it, etc
mommacat_request("add_volume", params)

# Make the mountpoint, create encrypted volume and mount it
directory "mount_apps_dir" do
  owner "root"
  group "root"
  mode 00644
  path mount_directory
  not_if { ::Dir.exists?(mount_directory+"/lost+found") } # XXX smarter guard?
end

ruby_block "format_default_volume" do
  not_if { ::Dir.exists?(mount_directory+"/lost+found") } # XXX smarter guard?
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
    mount_default_volume(ebs_key_location)

    #clean up creds
    unless ebs_keyfile.nil?
      destroy_temp_disk("/dev/ram3")
    end

  end
end
