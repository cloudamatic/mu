# Cookbook Name:: mu-master
# Provider:: mu_user
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


require 'mu'

action :add do
  allusers = MU::Master.listUsers
  password = nil
  if !allusers.has_key?(new_resource.username)
    password = new_resource.password || MU.generateWindowsPassword
  end
  ::MU::Master.manageUser(
    new_resource.username,
    name: new_resource.realname,
    password: password,
    email: new_resource.email,
    admin: new_resource.admin,
    orgs: new_resource.orgs,
    remove_orgs: new_resource.remove_orgs
  )
end

action :delete do
  ::MU::Master.deleteUser(new_resource.username)
end
