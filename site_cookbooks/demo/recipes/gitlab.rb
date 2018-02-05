#
# Cookbook Name:: demo
# Recipe:: gitlab
#
# Copyright:: Copyright (c) 2017 eGlobalTech, Inc., all rights reserved
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

require 'securerandom'
include_recipe 'chef-vault'
#DO CONFIG HERE

# Set an attribute to identify the node as a GitLab Server
node.override['gitlab']['is_server'] = true
node.override['gitlab']['endpoint'] = 'http://'+node['ec2']['public_dns_name']+'/'


# GENERATE A RUNNERTOKEN AND A ROOT PASSWORD
runnerToken = SecureRandom.urlsafe_base64
rootPWD = 'superman'
# TODO SAVE THEM TO A VAULT FOR FUTURE ACCESS

# SETUP VARIABLES FOR GITLAB.RB CONFIGURATION
node.override['omnibus-gitlab']['gitlab_rb']['external_url'] = node['gitlab']['endpoint']

# SET ENV VARIABLES TO PASS TO GITLAB AND TO THE GITLAB RUNNER
ENV['GITLAB_ENDPOINT'] = node['gitlab']['endpoint']
ENV['GITLAB_ROOT_PASSWORD'] = rootPWD
ENV['GITLAB_SHARED_RUNNERS_REGISTRATION_TOKEN'] = runnerToken


include_recipe 'omnibus-gitlab::default'

# Notify Users of GITLAB instalation
ruby_block "gitlabNotify" do
    block do
        puts "\n######################################## End of Run Information ########################################"
        puts "# Your Gitlab Server is running at #{node['omnibus-gitlab']['gitlab_rb']['external_url']}"
        puts "########################################################################################################\n\n"
    end
end