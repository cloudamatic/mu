#
# Cookbook Name:: mu-master
# Recipe:: firewall-holes
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

include_recipe 'mu-firewall'

# TODO Move all mu firewall rules to a mu specific chain
firewall_rule "MU Master default ports" do
  port [2260, 8443, 9443, 10514, 443, 80, 25]
end
# TODO tighten the local-only ones to appropriate IP blocks
firewall_rule "Chef Server default ports" do
  port [4321, 7443, 9463, 16379, 8983, 8000, 9683, 9090, 5432, 5672]
end
firewall_rule "Mu Master LDAP ports" do
  port [389, 636]
end
