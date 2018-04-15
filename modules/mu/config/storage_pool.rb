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
    class StoragePool

      def self.schema
        {
          "type" => "object",
          "title" => "Storage Pool",
          "description" => "Create a storage pool.",
          "required" => ["name", "cloud"],
          "additionalProperties" => false,
          "properties" => {
            "cloud" => MU::Config.cloud_primitive,
            "name" => {"type" => "string"},
            "region" => MU::Config.region_primitive,
            "tags" => MU::Config.tags_primitive,
            "optional_tags" => {
              "type" => "boolean",
              "description" => "Tag the resource with our optional tags (MU-HANDLE, MU-MASTER-NAME, MU-OWNER). Defaults to true",
              "default" => true
            },
            "dependencies" => MU::Config.dependencies_primitive,
            "storage_type" => {
              "type" => "string",
              "enum" => ["generalPurpose", "maxIO"],
              "description" => "The storage type / performance mode of this storage pool. Defaults to generalPurpose",
              "default" => "generalPurpose"
            },
            "mount_points" => {
              "type" => "array",
              "minItems" => 1,
              "items" => {
                "type" => "object",
                "required" => ["name"],
                "additionalProperties" => false,
                "description" => "Mount points for AWS EFS.",
                "properties" => {
                  "name" => {
                    "type" => "string"
                  },
                  "directory" => {
                    "type" => "string",
                    "description" => "The local directory this mount point will be mounted to",
                    "default" => "/efs"
                  },
                  "vpc" => MU::Config::VPC.reference(MU::Config::VPC::ONE_SUBNET+MU::Config::VPC::MANY_SUBNETS, MU::Config::VPC::NO_NAT_OPTS, "all_private"),
                  "add_firewall_rules" => MU::Config::FirewallRule.reference,
                  "ingress_rules" => {
                    "type" => "array",
                    "items" => MU::Config::FirewallRule.ruleschema
                  },
                  "ip_address" => {
                    "type" => "string",
                    "pattern" => "^\\d+\\.\\d+\\.\\d+\\.\\d+$",
                    "description" => "The private IP address to assign to the mount point."
                  }
                }
              }
            }
          }
        }
      end

    end
  end
end
