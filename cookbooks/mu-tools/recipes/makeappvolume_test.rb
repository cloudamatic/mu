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

include_recipe "mu-tools::aws_api"

# Test Harness
ruby_block "create_data_volume" do
        extend CAPVolume
        block do
        result=create_volume('datavolume', 1)
        end
        notifies :create, "ruby_block[attach_data_volume]"
end
ruby_block "attach_data_volume" do
        extend CAPVolume
        block do
                result=attach_node_volume('datavolume')
        end
        action :nothing
end
ruby_block "create_apps_volume" do
        extend CAPVolume
        block do
        result=create_node_volume('application_volume')
        end
        notifies :create, "ruby_block[attach_apps_volume]"      
end
ruby_block "attach_apps_volume" do
        extend CAPVolume
        block do
                result=attach_node_volume('application_volume')
        end
        action :nothing
end
ruby_block "create_arbitrary_volume" do
        extend CAPVolume
        block do
        $arbitrary_volume_id=create_volume('arbitrary_volume', 3)
        Chef::Log.info("Created #{$arbitrary_volume_id}")
        end
        notifies :create, "ruby_block[attach_arbitrary_volume]"
end
ruby_block "attach_arbitrary_volume" do
        extend CAPVolume
        block do
                result=attach_volume('arbitrary_volume', $arbitrary_volume_id, '/dev/xvdh')
        end
        action :nothing
end
