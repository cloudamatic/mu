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
    class CacheCluster

      def self.schema
        {
          "type" => "object",
          "title" => "Cache Cluster",
          "description" => "Create cache cluster(s).",
          "required" => ["name", "engine", "size", "cloud"],
          "additionalProperties" => false,
          "properties" => {
            "cloud" => MU::Config.cloud_primitive,
            "name" => {"type" => "string"},
            "scrub_mu_isms" => {
                "type" => "boolean",
                "default" => false,
                "description" => "When 'cloud' is set to 'CloudFormation,' use this flag to strip out Mu-specific artifacts (tags, standard userdata, naming conventions, etc) to yield a clean, source-agnostic template."
            },
            "region" => MU::Config.region_primitive,
            "tags" => MU::Config.tags_primitive,
            "optional_tags" => {
                "type" => "boolean",
                "description" => "Tag the resource with our optional tags (MU-HANDLE, MU-MASTER-NAME, MU-OWNER). Defaults to true",
                "default" => true
            },
            "engine_version" => {"type" => "string"},
            "node_count" => {
              "type" => "integer",
                "description" => "The number of cache nodes in a cache cluster (memcached), or the number of cache clusters in a cache group (redis)",
                "default" => 1
            },
            "add_firewall_rules" => MU::Config::FirewallRule.reference,
            "ingress_rules" => {
              "type" => "array",
              "items" => MU::Config::FirewallRule.ruleschema
            },
            "engine" => {
                "enum" => ["memcached", "redis"],
                "type" => "string",
                "default" => "redis"
            },
            "dns_records" => MU::Config::DNSZone.records_primitive(need_target: false, default_type: "CNAME", need_zone: true),
            "dns_sync_wait" => {
                "type" => "boolean",
                "description" => "Wait for DNS record to propagate in DNS Zone.",
                "default" => true
            },
            "alarms" => MU::Config::Alarm.inline,
            "dependencies" => MU::Config.dependencies_primitive,
            "size" => { # XXX this is AWS-specific, and should be done via API check anyway
              "pattern" => "^cache\.(t|m|c|i|g|hi|hs|cr|cg|cc){1,2}[0-9]\\.(micro|small|medium|[248]?x?large)$",
              "type" => "string",
              "description" => "The Amazon EleastiCache instance type to use when creating this cache cluster.",
            },
            "port" => {
                "type" => "integer",
                "default" => 6379,
                "default_if" => [
                    {
                        "key_is" => "engine",
                        "value_is" => "memcached",
                        "set" => 11211
                    },
                    {
                      "key_is" => "engine",
                        "value_is" => "redis",
                        "set" => 6379
                    }
                ]
            },
            "vpc" => MU::Config::VPC.reference(MU::Config::VPC::MANY_SUBNETS, MU::Config::VPC::NAT_OPTS, "all_public"),
            "multi_az" => {
                "type" => "boolean",
                "description" => "Rather to deploy the cache cluster/cache group in Multi AZ or Single AZ",
                "default" => false
            },
            "snapshot_arn" => {
                "type" => "string",
                "description" => "The ARN (Resource Name) of the redis backup stored in S3. Applies only to redis"
            },
            "snapshot_retention_limit" => {
                "type" => "integer",
                "description" => "The number of days to retain an automatic cache cluster snapshot. Applies only to redis"
            },
            "snapshot_window" => {
                "type" => "string",
                "description" => "The preferred time range to perform automatic cache cluster backups. Time is in UTC. Applies only to redis. Window must be at least 60 minutes long - 05:00-06:00."
            },
            "preferred_maintenance_window" => {
                "type" => "string",
                "description" => "The preferred data/time range to perform cache cluster maintenance. Window must be at least 60 minutes long - sun:06:00-sun:07:00. "
            },
            "auto_minor_version_upgrade" => {
                "type" => "boolean",
                "default" => true
            },
            "creation_style" => {
                "type" => "string",
                "enum" => ["new", "new_snapshot", "existing_snapshot"],
                "description" => "'new' - create a new cache cluster; 'new_snapshot' - create a snapshot of of an existing cache cluster, and build a new cache cluster from that snapshot; 'existing_snapshot' - create a cache cluster from an existing snapshot.",
                "default" => "new"
            },
            "identifier" => {
                "type" => "string",
                "description" => "For any creation_style other than 'new' this parameter identifies the cache cluster to use. In the case of new_snapshot it will create a snapshot from that cache cluster first; in the case of existing_snapshot, it will use the latest avaliable snapshot."
            },
            "notification_arn" => {
                "type" => "string",
                "description" => "The AWS resource name of the AWS SNS notification topic notifications will be sent to.",
            },
            "parameter_group_parameters" => {
              "type" => "array",
              "minItems" => 1,
              "items" => {
                "description" => "The cache cluster parameter group parameter to change and when to apply the change.",
                "type" => "object",
                "title" => "Cache Cluster Parameter",
                "required" => ["name", "value"],
                "additionalProperties" => false,
                "properties" => {
                  "name" => {
                    "type" => "string"
                  },
                  "value" => {
                    "type" => "string"
                  }
                }
              }
            },
            "parameter_group_family" => {
                "type" => "String",
                "enum" => ["memcached1.4", "redis2.6", "redis2.8"],
                "description" => "The cache cluster family to create the Parameter Group for. The family type must be the same type as the cache cluster major version - eg if you set engine_version to 2.6 this parameter must be set to redis2.6."
            }
          }
        }
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::cache_clusters}, bare and unvalidated.
      # @param cache [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(cache, configurator)
        ok = true
        if cluster["creation_style"] != "new" && cluster["identifier"].nil?
          MU.log "CacheCluster #{cluster['name']}'s creation_style is set to #{cluster['creation_style']} but no identifier was provided. Either set creation_style to new or provide an identifier", MU::ERR
          ok = false
        end
        if !cluster.has_key?("node_count") or cluster["node_count"] < 1
          MU.log "CacheCluster node_count must be >=1.", MU::ERR
          ok = false
        end
        cluster["multi_az"] = true if cluster["node_count"] > 1

        cluster['dependencies'] << adminFirewallRuleset(vpc: cluster['vpc'], region: cluster['region'], cloud: cluster['cloud']) if !cluster['scrub_mu_isms']

        ok
      end
    end
  end
end
