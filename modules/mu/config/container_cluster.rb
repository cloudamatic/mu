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
    # Basket of Kittens config schema and parser logic. See modules/mu/clouds/*/container_cluster.rb
    class ContainerCluster

      # Base configuration schema for a ContainerCluster
      # @return [Hash]
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
            "kubernetes" => {
              "type" => "object",
              "description" => "Deploy to a managed Kubernetes service, such as EKS or GKE",
              "properties" => {
                "version" => {
                  "type" => "string",
                  "default" => "1.10",
                  "description" => "Version of Kubernetes control plane to deploy",
                },
                "max_pods" => {
                  "type" => "integer",
                  "default" => 5,
                  "description" => "Maximum number of pods that can be deployed on any given worker node",
                }
              }
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

      # Generate a ServerPool for a set of container hosts.
      # @param configurator [MU::Config]: The MU::Config object into which we're injecting
      # @param name [String]: The name parameter for the ServerPool
      # @param count [Integer]: The number of nodes for the ServerPool
      # @param vpc [Hash]: Optional VPC reference block for the ServerPool
      # @param image_id [String]: Optional image id on which to base the ServerPool's nodes
      def self.insert_host_pool(configurator, name, count, size, vpc: nil, image_id: nil, ssh_user: "root", recipes: [], depends: [], platform: nil)
        base = {
          "name" => name,
          "min_size" => count,
          "max_size" => count,
          "wait_for_nodes" => count,
          "ssh_user" => ssh_user,
          "basis" => {
            "launch_config" => {
              "name" => name,
              "size" => size
            }
          }
        }
        base["platform"] = platform if platform
        if recipes.size > 0
          base["run_list"] = recipes
        end
        if depends.size > 0
          base["dependencies"] = depends
        end
        base["vpc"] = vpc if vpc
        base["basis"]["launch_config"]["image_id"] = image_id if image_id
        configurator.insertKitten(base, "server_pools")
      end

    end
  end
end
