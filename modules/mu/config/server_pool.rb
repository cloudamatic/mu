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
    class ServerPool

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
            "optional_tags" => {
                "type" => "boolean",
                "description" => "Tag the resource with our optional tags (MU-HANDLE, MU-MASTER-NAME, MU-OWNER). Defaults to true",
                "default" => true
            },
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
            "scaling_policies" => {
                "type" => "array",
                "minItems" => 1,
                "items" => {
                    "type" => "object",
                    "required" => ["name", "type"],
                    "additionalProperties" => false,
                    "description" => "A custom AWS Autoscale scaling policy for this pool.",
                    "properties" => {
                        "name" => {
                            "type" => "string"
                        },
                        "alarms" => MU::Config::Alarm.inline,
                        "type" => {
                            "type" => "string",
                            "enum" => ["ChangeInCapacity", "ExactCapacity", "PercentChangeInCapacity"],
                            "description" => "Specifies whether 'adjustment' is an absolute number or a percentage of the current capacity. Valid values are ChangeInCapacity, ExactCapacity, and PercentChangeInCapacity."
                        },
                        "adjustment" => {
                            "type" => "integer",
                            "description" => "The number of instances by which to scale. 'type' determines the interpretation of this number (e.g., as an absolute number or as a percentage of the existing Auto Scaling group size). A positive increment adds to the current capacity and a negative value removes from the current capacity. Used only when policy_type is set to 'SimpleScaling'"
                        },
                        "cooldown" => {
                            "type" => "integer",
                            "default" => 1,
                            "description" => "The amount of time, in seconds, after a scaling activity completes and before the next scaling activity can start."
                        },
                        "min_adjustment_magnitude" => {
                            "type" => "integer",
                            "description" => "Used when 'type' is set to 'PercentChangeInCapacity', the scaling policy changes the DesiredCapacity of the Auto Scaling group by at least the number of instances specified in the value."
                        },
                        "policy_type" => {
                          "type" => "string",
                          "enum" => ["SimpleScaling", "StepScaling"],
                          "description" => "'StepScaling' will add capacity based on the magnitude of the alarm breach, 'SimpleScaling' will add capacity based on the 'adjustment' value provided. Defaults to 'SimpleScaling'.",
                          "default" => "SimpleScaling"
                        },
                        "metric_aggregation_type" => {
                          "type" => "string",
                          "enum" => ["Minimum", "Maximum", "Average"],
                          "description" => "Defaults to 'Average' if not specified. Required when policy_type is set to 'StepScaling'",
                          "default" => "Average"
                        },
                        "step_adjustments" => {
                          "type" => "array",
                          "minItems" => 1,
                          "items" => {
                            "type" => "object",
                            "title" => "admin",
                            "description" => "Requires policy_type 'StepScaling'",
                            "required" => ["adjustment"],
                            "additionalProperties" => false,
                            "properties" => {
                              "adjustment" => {
                                  "type" => "integer",
                                  "description" => "The number of instances by which to scale at this specific step. Postive value when adding capacity, negative value when removing capacity"
                              },
                              "lower_bound" => {
                                  "type" => "integer",
                                  "description" => "The lower bound value in percentage points above/below the alarm threshold at which to add/remove capacity for this step. Positive value when adding capacity and negative when removing capacity. If this is the first step and capacity is being added this value will most likely be 0"
                              },
                              "upper_bound" => {
                                  "type" => "integer",
                                  "description" => "The upper bound value in percentage points above/below the alarm threshold at which to add/remove capacity for this step. Positive value when adding capacity and negative when removing capacity. If this is the first step and capacity is being removed this value will most likely be 0"
                              }
                            }
                          }
                        },
                        "estimated_instance_warmup" => {
                          "type" => "integer",
                          "description" => "Required when policy_type is set to 'StepScaling'"
                        }
                    }
                }
            },
            "termination_policies" => {
                "type" => "array",
                "minItems" => 1,
                "items" => {
                    "type" => "String",
                    "default" => "Default",
                    "enum" => ["Default", "OldestInstance", "NewestInstance", "OldestLaunchConfiguration", "ClosestToNextInstanceHour"]
                }
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
        ok = false if !MU::Config.check_vault_refs(pool)

        pool['dependencies'] << configurator.adminFirewallRuleset(vpc: pool['vpc'], region: pool['region'], cloud: pool['cloud']) if !pool['scrub_mu_isms']

        if !pool["vpc"].nil?
          if !pool["vpc"]["subnet_name"].nil? and configurator.nat_routes.has_key?(pool["vpc"]["subnet_name"])
            pool["dependencies"] << {
              "type" => "pool",
              "name" => configurator.nat_routes[pool["vpc"]["subnet_name"]],
              "phase" => "groom"
            }
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
        if pool["basis"]["server"] != nil
          pool["dependencies"] << {"type" => "server", "name" => pool["basis"]["server"]}
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