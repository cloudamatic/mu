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
        base = {
          "type" => "object",
          "description" => "Create a cluster of container hosts.",
          "required" => ["name", "cloud", "instance_type"],
          "properties" => {
            "name" => { "type" => "string" },
            "region" => MU::Config.region_primitive,
            "vpc" => MU::Config::VPC.reference(MU::Config::VPC::ONE_SUBNET + MU::Config::VPC::MANY_SUBNETS, MU::Config::VPC::NO_NAT_OPTS, "all"),
            "tags" => MU::Config.tags_primitive,
            "optional_tags" => MU::Config.optional_tags_primitive,
            "instance_count" => {
              "type" => "integer",
              "default" => 2
            },
            "min_size" => {
              "type" => "integer",
              "description" => "Enable worker cluster scaling and set the minimum number of workers to this value. This value is ignored for platforms which abstract scaling activity, such as AWS Fargate."
            },
            "max_size" => {
              "type" => "integer",
              "description" => "Enable worker cluster scaling and set the maximum number of workers to this value. This value is ignored for platforms which abstract scaling activity, such as AWS Fargate."
            },
            "kubernetes" => {
              "type" => "object",
              "description" => "Kubernetes-specific options",
              "properties" => {
                "version" => {
                  "type" => "string",
                  "default" => "1.14",
                  "description" => "Version of Kubernetes control plane to deploy",
                },
                "max_pods" => {
                  "type" => "integer",
                  "default" => 30,
                  "description" => "Maximum number of pods that can be deployed on any given worker node",
                }
              }
            },
            "kubernetes_resources" => {
              "type" => "array",
              "items" => {
                "type" => "object",
                "description" => "Optional Kubernetes-specific resource descriptors to run with kubectl create|replace when grooming this cluster. See https://kubernetes.io/docs/concepts/overview/working-with-objects/kubernetes-objects/#understanding-kubernetes-objects"
              }
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
            },
            "instance_subnet_pref" => {
              "type" => "string",
              "default" => "all_private",
              "description" => "Worker nodes inherit the main cluster VPC configuration by default. This parameter allows targeting the worker node-cluster to a different class of subnets"
            }
          }
        }
        MU::Config::Server.common_properties.keys.each { |k|
          if !base["properties"][k]
            base["properties"][k] = MU::Config::Server.common_properties[k].dup
          end
        }

        base
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::container_clusters}, bare and unvalidated.
      # @param cluster [Hash]: The resource to process and validate
      # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(cluster, _configurator)
        ok = true

        if cluster["max_size"] or cluster["min_size"]
          cluster["max_size"] ||= [cluster["instance_count"], cluster["min_size"]].reject { |c| c.nil? }.max
          cluster["min_size"] ||= [cluster["instance_count"], cluster["min_size"]].reject { |c| c.nil? }.min
        end

        if cluster['kubernetes_resources'] and !MU::Master.kubectl
          MU.log "Cannot apply kubernetes resources without a working kubectl executable", MU::ERR
          ok = false
        end

        ok
      end

    end
  end
end
