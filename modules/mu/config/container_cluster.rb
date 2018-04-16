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
    class ContainerCluster

      def self.schema
        {
          "type" => "object",
          "description" => "Create a cluster of container hosts.",
          "required" => ["name", "cloud", "instance_type", "instance_count"],
          "additionalProperties" => false,
          "properties" => {
            "name" => { "type" => "string" },
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
            "flavor" => {
              "type" => "string",
              "description" => "Container clusters in Amazon can be ECS, EKS, or Fargate; Google supports GKE only"
            },
            "platform" => {
              "type" => "string",
              "default" => "linux",
# XXX change to reflect available keys in mu/defaults/amazon_images.yaml and mu/defaults/google_images.yaml
              "enum" => ["linux", "windows", "centos", "ubuntu", "centos6", "ubuntu14", "win2k12", "win2k12r2", "win2k16", "centos7", "rhel7", "rhel71", "amazon"],
              "description" => "Helps select default AMIs, and enables correct grooming behavior based on operating system type.",
            },
            "instance_type" => {
              "type" => "string",
              "description" => "Type of container host instances to use. Equivalent to 'size' parameter in Server or ServerPool"
            }
          }
        }
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::container_clusters}, bare and unvalidated.
      # @param cluster [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(cluster, configurator)
        ok = true
        ok
      end

      def self.insert_host_pool(configurator, name, count, size, vpc, image_id)
        base = {
          "name" => name,
          "min_size" => count,
          "max_size" => count,
          "basis" => {
            "launch_config" => {
              "name" => name,
              "size" => size
            }
          }
        }
        base["vpc"] = vpc if vpc
#        base["vpc"] = vpc if vpc
        configurator.insertKitten(base, "server_pools")
      end

    end
  end
end
