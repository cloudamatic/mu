# Copyright:: Copyright (c) 2018 eGlobalTech, Inc., all rights reserved
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

module MU
  class Config
    class ContainerPool

      def self.schema
        {
          "type" => "object",
          "title" => "ContainerPool", # XXX get from class name
          "description" => "Create a pool of container hosts.",
          "required" => ["name", "cloud", "instance_type", "instance_count"],
          "additionalProperties" => false,
          "properties" => {
            "name" => { "type" => "string" },
            "cloud" => MU::Config.cloud_primitive,
            "region" => MU::Config.region_primitive,
            "vpc" => MU::Config::VPC.reference(MU::Config::VPC::ONE_SUBNET + MU::Config::VPC::MANY_SUBNETS, MU::Config::VPC::NO_NAT_OPTS, "all_private"),
            "tags" => MU::Config.tags_primitive,
            "optional_tags" => {
              "type" => "boolean",
              "description" => "Tag the resource with our optional tags (MU-HANDLE, MU-MASTER-NAME, MU-OWNER). Defaults to true",
            },
            "instance_count" => {
              "type" => "integer",
              "default" => 2
            },
            "instance_type" => {
              "type" => "string",
              "description" => "Type of container host instances to use. Equivalent to 'size' parameter in Server or ServerPool"
            }
          }
        }
      end

    end
  end
end
