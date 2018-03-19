#
# Cookbook Name::mu-tools
# Recipe::ebs_rolling_snapshots
#
# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#	  http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Install/upgrade Python if missing on both Windows and Linux as well as install/upgrade Boto and Requests
# Works on both Windows and Linux, runs nightly on both.
# Unless -d/--device_name is specified will snapshot all volumes except for the following:
# On Windows /dev/sda1. On Linux /dev/sda1,/dev/sda, /dev/xvdn, /dev/xvdo, /dev/xvdp, /dev/xvdq, xvdn, xvdo, xvdp, xvdq

include_recipe "poise-python"
snap_string = "--num_snaps_keep #{node['ebs_snapshots']['days_to_keep']}"
snap_string << " --device_name #{node['ebs_snapshots']['device_name']}" if node['ebs_snapshots']['device_name']
snap_string << " --exclude_devices '#{node['ebs_snapshots']['exclude_devices'].join(', ')}'" if !node['ebs_snapshots']['exclude_devices'].empty?

case node['platform']
when "windows"
  cookbook_file "#{Chef::Config[:file_cache_path]}/ebs_snpashots.py" do
    source 'ebs_snpashots.py'
  end

  ['boto', 'requests'].each do |pkg|
    execute "Installing #{pkg}" do
      command "#{node['python']['pip_binary']} install #{pkg} --upgrade"
      not_if "echo %path% | find /I \"#{node['python']['prefix_dir']}\\python#{node['python']['major_version']}\\Scripts\""
    end
  end

  ['boto', 'requests'].each do |pkg|
    python_package pkg do
      action :upgrade
      only_if "echo %path% | find /I \"#{node['python']['prefix_dir']}\\python#{node['python']['major_version']}\\Scripts\""
    end
  end

  windows_task 'daily-snapshots' do
    user "SYSTEM"
    command "python #{Chef::Config[:file_cache_path]}\\ebs_snpashots.py #{snap_string}"
    run_level :highest
    frequency :daily
    start_time "06:00"
  end
else
  cookbook_file "/opt/ebs_snapshots.py" do
    source 'ebs_snapshots.py'
  end

  ['boto', 'requests'].each do |pkg|
    python_package pkg do
      action :upgrade
    end
  end

  snap_string << " --logfile /var/log/ebs_snapshots.log"
  cron "Nightly rotate snapshot" do
    action :create
    minute "10"
    hour "6"
    user "root"
    command "python /opt/ebs_snpashots.py #{snap_string}"
  end
end
