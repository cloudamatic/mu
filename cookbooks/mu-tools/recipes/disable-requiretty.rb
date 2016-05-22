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

case node.platform
when "centos", "redhat"
  execute "sed -i 's/^Defaults.*requiretty$/Defaults   !requiretty/' /etc/sudoers" do
    not_if "grep '!requiretty' /etc/sudoers"
  end
else
  Chef::Log.info("Unsupported platform #{node.platform}")
end
