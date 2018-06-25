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
    # Basket of Kittens config schema and parser logic. See modules/mu/clouds/*/storage_pool.rb
    class StoragePool

      # Base configuration schema for a StoragePool
      # @return [Hash]
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
                    "description" => "Firewall rules to apply to our mountpoints",
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

      # Generic pre-processing of {MU::Config::BasketofKittens::storage_pools}, bare and unvalidated.
      # @param pool [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(pool, configurator)
        ok = true
        if pool['mount_points']
          new_mount_points = []
          pool['mount_points'].each{ |mp|
            if mp["vpc"] and !mp["vpc"].empty?
              if !mp["vpc"]["vpc_name"].nil? and
                 siblingvpc = configurator.haveLitterMate?(mp["vpc"]["vpc_name"], "vpcs") and
                 mp["vpc"]['deploy_id'].nil? and
                 mp["vpc"]['vpc_id'].nil?
      
                if !MU::Config::VPC.processReference(mp['vpc'],
                                        "storage_pools",
                                        "storagepool '#{pool['name']}'",
                                        configurator,
                                        dflt_region: pool['region'],
                                        is_sibling: true,
                                        sibling_vpcs: [siblingvpc])
                  ok = false
                end
              else
                if !MU::Config::VPC.processReference(mp["vpc"],
                                        "storage_pools",
                                        "storagepool #{pool['name']}",
                                        configurator,
                                        dflt_region: pool['region'])
                  ok = false
                end
              end
              if mp['vpc']['subnets'] and mp['vpc']['subnets'].size > 1
                seen_azs = []
                count = 0
                mp['vpc']['subnets'].each { |subnet|
                  if subnet['az'] and seen_azs.include?(subnet['az'])
                    MU.log "VPC config for Storage Pool #{pool['name']} has multiple matching subnets per Availability Zone. Only one mount point per AZ is allowed, so you must explicitly declare which subnets to use.", MU::ERR
                    ok = false
                    break
                  end
                  seen_azs << subnet['az']
                  subnet.delete("az")
                  newmp = Marshal.load(Marshal.dump(mp))
                  ["subnets", "subnet_pref", "az"].each { |field|
                    newmp['vpc'].delete(field)
                  }
                  newmp['vpc'].merge!(subnet)
                  newmp['name'] = newmp['name']+count.to_s
                  count = count + 1
                  new_mount_points << newmp
                }
              else
                new_mount_points << mp
              end
            end
          }
          pool['mount_points'] = new_mount_points
        end

        ok
      end

    end
  end
end
