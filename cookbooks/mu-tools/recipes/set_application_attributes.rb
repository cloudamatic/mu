#
# Cookbook Name::mu-tools
# Recipe::set_application_attributes
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
# Idempotent set_app_structures from s3.  Reads properties from encrypted s3,and sets its data intact into the node structure.  Use it
# with care
# This resource always runs at compile time so attributes will be present to
# allow other recipes to compile

require "rubygems"
require "json"
include_recipe "mu-tools::aws_api"
include_recipe "mu-tools::google_api"

attribute_setter = ruby_block "set_application_attributes" do
  extend CAPVolume
  block do
    secure_location = node[:application_attributes][:secure_location]
    attributes_file = node[:application_attributes][:attributes_file]
    temp_mount = "/tmp/ram3"
    make_temp_disk!("/dev/ram3", temp_mount)
    local_secret = "#{temp_mount}/tmpattributes"
    Chef::Log.info("Fetching from #{secure_location}/#{attributes_file} to #{local_secret}")
    fetch_cmd = "aws s3 cp #{secure_location}/#{attributes_file} #{local_secret}"
    Chef::Log.info ("Command will be #{fetch_cmd}")
    copyresult = `#{fetch_cmd}`
    file = open(local_secret)
    structures = file.read
    parsed = JSON.parse(structures)
    file.close
    node.set['application_attributes'] = parsed
    node.save
    # Chef::Log.info("I am a message from the land of nodez with #{node['application_attributes']}")
    destroy_temp_disk("/dev/ram3")
  end
  action :nothing
end
attribute_setter.run_action (:run)
