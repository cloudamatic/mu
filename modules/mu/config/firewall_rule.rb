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
    # Basket of Kittens config schema and parser logic. See modules/mu/clouds/*/firewall_rule.rb
    class FirewallRule

      # Base configuration schema for a FirewallRule
      # @return [Hash]
      def self.schema
        {
          "type" => "object",
          "required" => ["name"],
          "additionalProperties" => false,
          "description" => "Create network-level access controls.",
          "properties" => {
            "name" => {"type" => "string"},
            "vpc_name" => {
                "type" => "string",
                "description" => "Backwards-compatibility means of identifying a VPC; see {MU::Config::BasketofKittens::firewall_rules::vpc}"
            },
            "vpc_id" => {
                "type" => "string",
                "description" => "Backwards-compatibility means of identifying a VPC; see {MU::Config::BasketofKittens::firewall_rules::vpc}"
            },
            "vpc" => MU::Config::VPC.reference(MU::Config::VPC::NO_SUBNETS, MU::Config::VPC::NO_NAT_OPTS),
            "tags" => MU::Config.tags_primitive,
            "optional_tags" => MU::Config.optional_tags_primitive,
            "self_referencing" => {
                "type" => "boolean",
                "default" => false
            },
            "admin" => {
              "type" => "boolean",
              "description" => "Internal use only. Flag generic administrative firewall rulesets for use by the Mu Master",
              "default" => false
            },
            "rules" => {
              "type" => "array",
              "items" => ruleschema
            }
          }
        }
      end

      # Generate schema for an individual firewall rule
      # @return [Hash]
      def self.ruleschema
        {
          "type" => "object",
          "description" => "Network ingress and/or egress rules.",
#          "additionalProperties" => false, # inline ingress_rules can have cloud-specific attributes, and this trips those up
          "properties" => {
            "port_range" => {"type" => "string"},
            "port" => {"type" => "integer"},
            "proto" => {
              "enum" => ["udp", "tcp", "icmp"],
              "default" => "tcp",
              "type" => "string"
            },
            "ingress" => {
              "type" => "boolean"
            },
            "egress" => {
              "type" => "boolean",
              "default" => false
            },
            "comment" => {
              "type" => "string",
              "description" => "String description of this firewall rule, where supported"
            },
            "hosts" => {
              "type" => "array",
              "items" => MU::Config::CIDR_PRIMITIVE
            }
          }
        }
      end

      # Schema block for other resources to use when referencing a sibling FirewallRule
      # @return [Hash]
      def self.reference
        schema_aliases = [
          { "rule_id" => "id" },
          { "rule_name" => "name" }
        ]
        MU::Config::Ref.schema(schema_aliases, type: "firewall_rules")
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::firewall_rules}, bare and unvalidated.
      # @param _acl [Hash]: The resource to process and validate
      # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(_acl, _configurator)
        ok = true
        ok
      end

    end
  end
end
