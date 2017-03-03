#
# Cookbook Name:: splunk
# Recipe:: user
#
# Author: Joshua Timberman <joshua@getchef.com>
# Copyright (c) 2014, Chef Software, Inc <legal@getchef.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

if node['platform_family'] != 'windows'
  group node['splunk']['user']['username'] do
    gid node['splunk']['user']['uid'].to_i # CHEF-4927
    system true if %w(linux).include?(node['os'])
  end

  user node['splunk']['user']['username'] do
    comment node['splunk']['user']['comment']
    shell node['splunk']['user']['shell']
    gid node['splunk']['user']['username']
    uid node['splunk']['user']['uid']
    system true if %w(linux).include?(node['os'])
  end
end
