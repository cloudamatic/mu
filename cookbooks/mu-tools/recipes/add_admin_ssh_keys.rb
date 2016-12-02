#
# Cookbook Name:: mu-tools
# Recipe:: add_admin_ssh_keys
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

if node['deployment']['admins']
  if !node['service_name'].nil?
    if !node['deployment']['servers'][node['service_name']]['config']['ssh_user'].nil?
      ssh_user = node['deployment']['servers'][node['service_name']]['config']['ssh_user']
    end rescue NoMethodError
  end rescue NoMethodError
  ssh_user = 'root' if ssh_user.nil?
  ssh_dir = "#{Etc.getpwnam(ssh_user).dir}/.ssh"
  node['deployment']['admins'].each_pair { |name, admin|
    if !admin['public-key'].nil?
      execute "Add #{admin.name}'s ssh key to #{ssh_dir}/authorized_keys" do
        not_if "grep '^#{admin['public-key']}$' #{ssh_dir}/authorized_keys"
        command "echo '#{admin['public-key']}' >> #{ssh_dir}/authorized_keys"
      end
    end rescue NoMethodError
  }
end rescue NoMethodError
