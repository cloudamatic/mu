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
    # Basket of Kittens config schema and parser logic. See modules/mu/providers/*/firewall_rule.rb
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

    # FirewallRules can reference other FirewallRules, which means we need to do
    # an extra pass to make sure we get all intra-stack dependencies correct.
    # @param acl [Hash]: The configuration hash for the FirewallRule to check
    # @return [Hash]
    def resolveIntraStackFirewallRefs(acl, delay_validation = false)
      acl["rules"].each { |acl_include|
        if acl_include['sgs']
          acl_include['sgs'].each { |sg_ref|
            if haveLitterMate?(sg_ref, "firewall_rules")
              MU::Config.addDependency(acl, sg_ref, "firewall_rule", my_phase: "groom")
              siblingfw = haveLitterMate?(sg_ref, "firewall_rules")
              if !siblingfw["#MU_VALIDATED"]
# XXX raise failure somehow
                insertKitten(siblingfw, "firewall_rules", delay_validation: delay_validation)
              end
            end
          }
        end
      }
      acl
    end

    # Generate configuration for the general-purpose admin firewall rulesets
    # (security groups in AWS). Note that these are unique to regions and
    # individual VPCs (as well as Classic, which is just a degenerate case of
    # a VPC for our purposes.
    # @param vpc [Hash]: A VPC reference as defined in our config schema. This originates with the calling resource, so we'll peel out just what we need (a name or cloud id of a VPC).
    # @param admin_ip [String]: Optional string of an extra IP address to allow blanket access to the calling resource.
    # @param cloud [String]: The parent resource's cloud plugin identifier
    # @param region [String]: Cloud provider region, if applicable.
    # @return [Hash<String>]: A dependency description that the calling resource can then add to itself.
    def adminFirewallRuleset(vpc: nil, admin_ip: nil, region: nil, cloud: nil, credentials: nil, rules_only: false)
      if !cloud or (cloud == "AWS" and !region)
        raise MuError, "Cannot call adminFirewallRuleset without specifying the parent's region and cloud provider"
      end
      hosts = Array.new
      hosts << "#{MU.my_public_ip}/32" if MU.my_public_ip
      hosts << "#{MU.my_private_ip}/32" if MU.my_private_ip
      hosts << "#{MU.mu_public_ip}/32" if MU.mu_public_ip
      hosts << "#{admin_ip}/32" if admin_ip
      hosts.uniq!

      rules = []
      if cloud == "Google"
        rules = [
          { "ingress" => true, "proto" => "all", "hosts" => hosts },
          { "egress" => true, "proto" => "all", "hosts" => hosts }
        ]
      else
        rules = [
          { "proto" => "tcp", "port_range" => "0-65535", "hosts" => hosts },
          { "proto" => "udp", "port_range" => "0-65535", "hosts" => hosts },
          { "proto" => "icmp", "port_range" => "-1", "hosts" => hosts }
        ]
      end

      if rules_only
        return rules
      end

      name = "admin"
      name += credentials.to_s if credentials
      realvpc = nil
      if vpc
        realvpc = {}
        ['vpc_name', 'vpc_id'].each { |p|
          if vpc[p]
            vpc[p.sub(/^vpc_/, '')] = vpc[p] 
            vpc.delete(p)
          end
        }
        ['cloud', 'id', 'name', 'deploy_id', 'habitat', 'credentials'].each { |field|
          realvpc[field] = vpc[field] if !vpc[field].nil?
        }
        if !realvpc['id'].nil? and !realvpc['id'].empty?
          # Stupid kludge for Google cloud_ids which are sometimes URLs and
          # sometimes not. Requirements are inconsistent from scenario to
          # scenario.
          name = name + "-" + realvpc['id'].gsub(/.*\//, "")
          realvpc['id'] = getTail("id", value: realvpc['id'], prettyname: "Admin Firewall Ruleset #{name} Target VPC",  cloudtype: "AWS::EC2::VPC::Id") if realvpc["id"].is_a?(String)
        elsif !realvpc['name'].nil?
          name = name + "-" + realvpc['name']
        end
      end


      acl = {"name" => name, "rules" => rules, "vpc" => realvpc, "cloud" => cloud, "admin" => true, "credentials" => credentials }
      if cloud == "Google" and acl["vpc"] and acl["vpc"]["habitat"]
        acl['project'] = acl["vpc"]["habitat"]["id"] || acl["vpc"]["habitat"]["name"]
      end
      acl.delete("vpc") if !acl["vpc"]
      if !MU::Cloud.resourceClass(cloud, "FirewallRule").isGlobal? and !region.nil? and !region.empty?
        acl["region"] = region
      end
      @admin_firewall_rules << acl if !@admin_firewall_rules.include?(acl)
      return {"type" => "firewall_rule", "name" => name}
    end

  end
end
