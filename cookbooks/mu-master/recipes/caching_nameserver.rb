#
# Cookbook Name:: mu-master
# Recipe:: caching_nameserver
#
# Copyright:: Copyright (c) 2015 eGlobalTech, Inc., all rights reserved
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

package "bind"
package "bind-devel"
package "bind-utils"

include_recipe 'bind'

# XXX THIS RECIPE IS INCOMPLETE. DON'T INVOKE IT AND EXPECT ANYTHING USEFUL xxx

hosts = {
  "master" => "127.0.0.1",
  "mu-master" => "127.0.0.1",
  $MU_CFG['hostname'] => "127.0.0.1"
}

bind9_ng_zone "platform-mu" do
  email $MU_CFG['mu_admin_email'].gsub(/@/, ".")
  nameserver ["127.0.0.1"]
  hosts hosts
end
