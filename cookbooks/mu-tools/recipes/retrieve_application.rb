#
# Cookbook Name:: mu-tools
# Recipe:: retrieve_application
#
# This recipe implements the standard method for retrieving an application and placing it on the 
# designated application_volume location.  It depends upon the application_attributes node structure
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

$project_id = node['application_attributes']['project']['id']
$application_repo_password = node['application_attributes']['git']['password']
$application_repo_name = node['application_attributes']['git']['repo_name']
$application_repo_username = node['application_attributes']['git']['username']
$application_repo = node['application_attributes']['git']['repo']
$application_mount_device = node['application_attributes']['application_volume']['mount_device']
$application_mount_directory = node['application_attributes']['application_volume']['mount_directory']
$application_repo_branch = node['application_attributes']['git']['branch']

ruby_block "Pull App from Repo" do
  block do
    #we can assume the app directory is present now, from create_application_volume
    Dir.chdir($application_mount_directory)
    git_clone = "git clone https://#{$application_repo_username}:#{$application_repo_password}@#{$application_repo}"
    cmd = Mixlib::ShellOut.new(git_clone)
    cmd.run_command
    # `#{git_clone}`
    unless $application_repo_branch == "master"
      Chef::Log.info("Branching to #{$application_repo_branch}")
      Dir.chdir("#{$application_mount_directory}/#{$application_repo_name}")
      cmd = Mixlib::ShellOut.new("git checkout -b remotes/origin/#{$application_repo_branch}")
      cmd.run_command
      cmd = Mixlib::ShellOut.new("git pull origin #{$application_repo_branch}")
      cmd.run_command
      # `git checkout -b remotes/origin/#{$application_repo_branch}`
      # `git pull origin #{$application_repo_branch}`
    end
  end
  action :run
end
