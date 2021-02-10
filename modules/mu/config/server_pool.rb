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
    # Basket of Kittens config schema and parser logic. See modules/mu/providers/*/server_pool.rb
    class ServerPool

      # Base configuration schema for a ServerPool
      # @return [Hash]
      def self.schema
        base = {
          "type" => "object",
          "additionalProperties" => false,
          "description" => "Create scalable pools of identical servers.",
          "required" => ["name", "min_size", "max_size", "basis", "cloud"],
          "properties" => {
            "dns_records" => MU::Config::DNSZone.records_primitive(need_target: false, default_type: "A", need_zone: true),
            "scrub_mu_isms" => {
                "type" => "boolean",
                "default" => false,
                "description" => "When 'cloud' is set to 'CloudFormation,' use this flag to strip out Mu-specific artifacts (tags, standard userdata, naming conventions, etc) to yield a clean, source-agnostic template."
            },
            "wait_for_nodes" => {
                "type" => "integer",
                "description" => "Use this parameter to force a certain number of nodes to come up and be fully bootstrapped before the rest of the pool is initialized.",
                "default" => 0,
            },
            "vpc" => MU::Config::VPC.reference(MU::Config::VPC::MANY_SUBNETS, MU::Config::VPC::NAT_OPTS, "all_private"),
            "min_size" => {"type" => "integer"},
            "max_size" => {"type" => "integer"},
            "tags" => MU::Config.tags_primitive,
            "optional_tags" => MU::Config.optional_tags_primitive,
            "desired_capacity" => {
                "type" => "integer",
                "description" => "The number of Amazon EC2 instances that should be running in the group. Should be between min_size and max_size."
            },
            "default_cooldown" => {
                "type" => "integer",
                "default" => 300
            },
            "health_check_type" => {
                "type" => "string",
                "enum" => ["EC2", "ELB"],
                "default" => "EC2",
            },
            "health_check_grace_period" => {
                "type" => "integer",
                "default" => 0
            },
            "vpc_zone_identifier" => {
                "type" => "string",
                "description" => "A comma-separated list of subnet identifiers of Amazon Virtual Private Clouds (Amazon VPCs).

          If you specify subnets and Availability Zones with this call, ensure that the subnets' Availability Zones match the Availability Zones specified."
            },
            #XXX this needs its own primitive and discovery mechanism
            "zones" => {
              "type" => "array",
              "minItems" => 1,
              "items" => {
                "type" => "string",
              }
            },
            "basis" => {
              "type" => "object",
              "minProperties" => 1,
              "maxProperties" => 1,
              "additionalProperties" => false,
              "description" => "The baseline for new servers created within this Autoscale Group.",
              "properties" => {
                "instance_id" => {
                    "type" => "string",
                    "description" => "The AWS instance ID of an existing instance to use as the base image for this Autoscale Group.",
                },
                "server" => {
                    "type" => "string",
                    "description" => "Build a server defined elsewhere in this stack, then use it as the base image for this Autoscale Group.",
                },
                "launch_config" => {
                  "type" => "object",
                  "required" => ["name", "size"],
                  "minProperties" => 3,
                  "additionalProperties" => false,
                  "description" => "An Amazon Launch Config for an Autoscale Group.",
                  "properties" => {
                    "name" => {"type" => "string"},
                    "instance_id" => {
                      "type" => "string",
                      "description" => "The AWS instance ID of an existing instance to use as the base image in this Launch Config.",
                    },
                    "storage" => MU::Config::Server.storage_primitive,
                    "server" => {
                      "type" => "string",
                      "description" => "Build a server defined elsewhere in this stack, create an AMI from it, then use it as the base image in this Launch Config.",
                    },
                    "ami_id" => {
                      "type" => "string",
                      "description" => "The Amazon EC2 AMI to use as the base image in this Launch Config. Will use the default for platform if not specified.",
                    },
                    "image_id" => {
                      "type" => "string",
                      "description" => "The Google Cloud Platform Image on which to base this autoscaler. Will use the default appropriate for the platform, if not specified.",
                    },
                    "monitoring" => {
                      "type" => "boolean",
                      "default" => true,
                      "description" => "Enable instance monitoring?",
                    },
                    "ebs_optimized" => {
                      "type" => "boolean",
                      "default" => false,
                      "description" => "EBS optimized?",
                    },
                    "iam_role" => {
                      "type" => "string",
                      "description" => "An Amazon IAM instance profile, from which to harvest role policies to merge into this node's own instance profile. If generate_iam_role is false, will simple use this profile.",
                    },
                    "generate_iam_role" => {
                      "type" => "boolean",
                      "default" => true,
                      "description" => "Generate a unique IAM profile for this Server or ServerPool.",
                    },
                    "iam_policies" => {
                      "type" => "array",
                      "items" => {
                        "description" => "Amazon-compatible role policies which will be merged into this node's own instance profile.  Not valid with generate_iam_role set to false. Our parser expects the role policy document to me embedded under a named container, e.g. { 'name_of_policy':'{ <policy document> } }",
                        "type" => "object"
                      }
                    },
                    "spot_price" => {
                      "type" => "string",
                    },
                    "kernel_id" => {
                      "type" => "string",
                      "description" => "Kernel to use with servers created from this Launch Configuration.",
                    },
                    "ramdisk_id" => {
                      "type" => "string",
                      "description" => "Kernel to use with servers created from this Launch Configuration.",
                    },
                    "size" => {
                      "description" => "The Amazon EC2 instance type to use when creating this server.",
                      "type" => "string"
                    }
                  }
                }
              }
            }
          }
        }
        base["properties"].merge!(MU::Config::Server.common_properties)
        base
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::server_pools}, bare and unvalidated.
      # @param pool [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(pool, configurator)
        ok = true
        if configurator.haveLitterMate?(pool["name"], "servers")
          MU.log "Can't use name #{pool['name']} more than once in pools/pool_pools"
          ok = false
        end
        pool['skipinitialupdates'] = true if configurator.skipinitialupdates
        pool['ingress_rules'] ||= []
        pool['vault_access'] ||= []
        pool['vault_access'] << {"vault" => "splunk", "item" => "admin_user"}
        ok = false if !MU::Config::Server.checkVaultRefs(pool)

        if !pool['scrub_mu_isms'] and pool["cloud"] != "Azure"
          pool['dependencies'] << configurator.adminFirewallRuleset(vpc: pool['vpc'], region: pool['region'], cloud: pool['cloud'], credentials: pool['credentials'])
        end

        if !pool["vpc"].nil?
          if !pool["vpc"]["subnet_name"].nil? and configurator.nat_routes.has_key?(pool["vpc"]["subnet_name"])
            MU::Config.addDependency(pool, configurator.nat_routes[pool["vpc"]["subnet_name"]], "server", their_phase: "groom", my_phase: "groom")
          end
        end
# TODO make sure this is handled... somewhere
#        if pool["alarms"] && !pool["alarms"].empty?
#          pool["alarms"].each { |alarm|
#            alarm["name"] = "server-#{pool['name']}-#{alarm["name"]}"
#            alarm["namespace"] = "AWS/EC2" if alarm["namespace"].nil?
#            alarm['cloud'] = pool['cloud']
#            ok = false if !insertKitten(alarm, "alarms")
#          }
#        end
        if pool["basis"] and pool["basis"]["server"]
          MU::Config.addDependency(pool, pool["basis"]["server"], "server", their_phase: "groom")
        end
        if !pool['static_ip'].nil? and !pool['ip'].nil?
          ok = false
          MU.log "Server Pools cannot assign specific static IPs.", MU::ERR
        end

        ok
      end

    end
  end
end
