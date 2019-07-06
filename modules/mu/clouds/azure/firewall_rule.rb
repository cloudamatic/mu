# Copyright:: Copyright (c) 2019 eGlobalTech, Inc., all rights reserved
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

  class Cloud
    class Azure
      # A firewall ruleset as configured in {MU::Config::BasketofKittens::firewall_rules}
      class FirewallRule < MU::Cloud::FirewallRule

        @admin_sgs = Hash.new
        @admin_sg_semaphore = Mutex.new

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::firewall_rules}
        def initialize(**args)
          super

          if !mu_name.nil?
            @mu_name = mu_name
          else
            @mu_name = @deploy.getResourceName(@config['name'], max_length: 61)
          end

        end

        attr_reader :rulesets

        # Called by {MU::Deploy#createResources}
        def create
          create_update
        end

        # Called by {MU::Deploy#createResources}
        def groom
          create_update

          oldrules = {}
          newrules = {}

          cloud_desc.security_rules.each { |rule|
            if rule.description and rule.description.match(/^#{Regexp.quote(@mu_name)} \d+:/)
              oldrules[rule.name] = rule
            end
          }
          used_priorities = oldrules.values.map { |r| r.priority }

          num = 0

          @config['rules'].each { |rule|
            
            rule_obj = MU::Cloud::Azure.network(:SecurityRule).new
            resolved_sgs = []
# XXX these are *Application* Security Groups, which are a different kind of
# artifact. They take no parameters. Are they essentially a stub that can be
# attached to certain artifacts to allow them to be referenced here?
# http://54.175.86.194/docs/azure/Azure/Network/Mgmt/V2019_02_01/ApplicationSecurityGroups.html#create_or_update-instance_method
            if rule["sgs"]
              rule["sgs"].each { |sg|
# look up cloud id for... whatever these are
              }
            end

            resolved_lbs = []
            if rule["lbs"]
              rule["lbs"].each { |lbs|
# TODO awaiting LoadBalancer implementation
              }
            end

            if rule["egress"]
              rule_obj.direction = MU::Cloud::Azure.network(:SecurityRuleDirection)::Outbound
              if rule["hosts"] and !rule["hosts"].empty?
                rule_obj.source_address_prefix = "*"
                if rule["hosts"] == ["*"]
                  rule_obj.destination_address_prefix = "*"
                else
                  rule_obj.destination_address_prefixes = rule["hosts"]
                end
              end
              if !resolved_sgs.empty?
                rule_obj.destination_application_security_groups = resolved_sgs
              end
            else
              rule_obj.direction = MU::Cloud::Azure.network(:SecurityRuleDirection)::Inbound
              if rule["hosts"] and !rule["hosts"].empty?
                if rule["hosts"] == ["*"]
                  rule_obj.source_address_prefix = "*"
                else
                  rule_obj.source_address_prefixes = rule["hosts"]
                end
                rule_obj.destination_address_prefix = "*"
              end
              if !resolved_sgs.empty?
                rule_obj.source_application_security_groups = resolved_sgs
              end
            end

            rname_port = "port-"
            if rule["port"] 
              rule_obj.destination_port_range = rule["port"].to_s
              rname_port += rule["port"].to_s
            elsif rule["port_range"]
              rule_obj.destination_port_range = rule["port_range"]
              rname_port += rule["port_range"]
            else
              rule_obj.destination_port_range = "*"
              rname_port += "all"
            end

            # We don't bother supporting restrictions on originating ports,
            # because practically nobody does that.
            rule_obj.source_port_range = "*"

            rule_obj.protocol = MU::Cloud::Azure.network(:SecurityRuleProtocol).const_get(rule["proto"].capitalize)
            rname_proto = "proto-"+ (rule["proto"] == "asterisk" ? "all" : rule["proto"])

            if rule["deny"]
              rule_obj.access = MU::Cloud::Azure.network(:SecurityRuleAccess)::Deny
            else
              rule_obj.access = MU::Cloud::Azure.network(:SecurityRuleAccess)::Allow
            end

            rname = rule_obj.access.downcase+"-"+rule_obj.direction.downcase+"-"+rname_proto+"-"+rname_port+"-"+num.to_s

            if rule["weight"]
              rule_obj.priority = rule["weight"]
            elsif oldrules[rname]
              rule_obj.priority = oldrules[rname].priority
            else
              default_priority = 999
              begin
                default_priority += 1
                rule_obj.priority = default_priority
              end while used_priorities.include?(default_priority)
            end
            used_priorities << rule_obj.priority

            rule_obj.description = "#{@mu_name} #{num.to_s}: #{rname}"
         
            # Now compare this to existing rules, and see if we need to update
            # anything.
            need_update = false
            if oldrules[rname]
              rule_obj.instance_variables.each { |var|
                oldval = oldrules[rname].instance_variable_get(var)
                newval = rule_obj.instance_variable_get(var)
                need_update = true if oldval != newval
              }

              [:@destination_address_prefix, :@destination_address_prefixes,
               :@destination_application_security_groups,
               :@destination_address_prefix,
               :@destination_address_prefixes,
               :@destination_application_security_groups].each { |var|
                next if !oldrules[rname].instance_variables.include?(var)
                oldval = oldrules[rname].instance_variable_get(var)
                newval = rule_obj.instance_variable_get(var)
                if newval.nil? and !oldval.nil? and !oldval.empty?
                  need_update = true
                end
              }
            else
              need_update = true
            end

            if need_update
              if oldrules[rname]
                MU.log "Updating rule #{rname} in #{@mu_name}", MU::NOTICE, details: rule_obj
              else
                MU.log "Creating rule #{rname} in #{@mu_name}", details: rule_obj
              end
              resp = MU::Cloud::Azure.network(credentials: @config['credentials']).security_rules.create_or_update(@resource_group, @mu_name, rname, rule_obj)
              newrules[rname] = resp
            else
              newrules[rname] = oldrules[rname]
            end

            num += 1
          }

          # Purge old rules that we own (according to the description) but
          # which are not part of our current configuration.
          (oldrules.keys - newrules.keys).each { |oldrule|
            MU.log "Dropping unused rule #{oldrule} from #{@mu_name}", MU::NOTICE
            MU::Cloud::Azure.network(credentials: @config['credentials']).security_rules.delete(@resource_group, @mu_name, oldrule)
          }

        end

        # Log metadata about this ruleset to the currently running deployment
        def notify
          MU.structToHash(cloud_desc)
        end

        # Insert a rule into an existing security group.
        #
        # @param hosts [Array<String>]: An array of CIDR network addresses to which this rule will apply.
        # @param proto [String]: One of "tcp," "udp," or "icmp"
        # @param port [Integer]: A port number. Only valid with udp or tcp.
        # @param egress [Boolean]: Whether this is an egress ruleset, instead of ingress.
        # @param port_range [String]: A port range descriptor (e.g. 0-65535). Only valid with udp or tcp.
        # @return [void]
        def addRule(hosts, proto: "tcp", port: nil, egress: false, port_range: "0-65535")
        end

        # Locate an existing security group or groups and return an array containing matching AWS resource descriptors for those that match.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region
        # @param tag_key [String]: A tag key to search.
        # @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
        # @param flags [Hash]: Optional flags
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching FirewallRules
#        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil, flags: {}, credentials: nil)
        def self.find(**args)
          found = {}

          # Azure resources are namedspaced by resource group. If we weren't
          # told one, we may have to search all the ones we can see.
          resource_groups = if args[:resource_group]
            [args[:resource_group]]
          elsif args[:cloud_id] and args[:cloud_id].is_a?(MU::Cloud::Azure::Id)
            [args[:cloud_id].resource_group]
          else
            MU::Cloud::Azure.resources(credentials: args[:credentials]).resource_groups.list.map { |rg| rg.name }
          end

          if args[:cloud_id]
            id_str = args[:cloud_id].is_a?(MU::Cloud::Azure::Id) ? args[:cloud_id].name : args[:cloud_id]
            resource_groups.each { |rg|
              begin
                resp = MU::Cloud::Azure.network(credentials: args[:credentials]).network_security_groups.get(rg, id_str)
                found[Id.new(resp.id)] = resp
              rescue MU::Cloud::Azure::APIError => e
                # this is fine, we're doing a blind search after all
              end
            }
          else
            if args[:resource_group]
              MU::Cloud::Azure.network(credentials: args[:credentials]).network_security_groups.list(args[:resource_group]).each { |net|
                found[Id.new(net.id)] = net
              }
            else
              MU::Cloud::Azure.network(credentials: args[:credentials]).network_security_groups.list_all.each { |net|
                found[Id.new(net.id)] = net
              }
            end
          end

          found
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          false
        end

        # Denote whether this resource implementation is experiment, ready for
        # testing, or ready for production use.
        def self.quality
          MU::Cloud::ALPHA
        end

        # Stub method. Azure cleanup is handled by deletion of the Resource Group, which we always use a container for our deploys.
        def self.cleanup(**args)
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(rootparent: nil, billing: nil)
          bok = {}

          bok
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config = nil)
          toplevel_required = []
          schema = {
            "rules" => {
              "items" => {
                "properties" => {
                  "weight" => {
                    "type" => "integer",
                    "description" => "Explicitly set a priority for this firewall rule, between 100 and 2096, with lower numbered priority rules having greater precedence."
                  },
                  "deny" => {
                    "type" => "boolean",
                    "default" => false,
                    "description" => "Set this rule to +DENY+ traffic instead of +ALLOW+"
                  },
                  "proto" => {
                    "description" => "The protocol to allow with this rule. The +standard+ keyword will expand to a series of identical rules covering +tcp+ and +udp; the +all+ keyword will allow all supported protocols. Currently only +tcp+ and +udp+ are supported by Azure, so the end result of these two keywords is identical.",
                    "enum" => ["all", "standard", "tcp", "udp"],
                    "default" => "standard"
                  },
#                  "source_tags" => {
#                    "type" => "array",
#                    "description" => "VMs with these tags, from which traffic will be allowed",
#                    "items" => {
#                      "type" => "string"
#                    }
#                  },
#                  "source_service_accounts" => {
#                    "type" => "array",
#                    "description" => "Resources using these service accounts, from which traffic will be allowed",
#                    "items" => {
#                      "type" => "string"
#                    }
#                  },
#                  "target_tags" => {
#                    "type" => "array",
#                    "description" => "VMs with these tags, to which traffic will be allowed",
#                    "items" => {
#                      "type" => "string"
#                    }
#                  },
#                  "target_service_accounts" => {
#                    "type" => "array",
#                    "description" => "Resources using these service accounts, to which traffic will be allowed",
#                    "items" => {
#                      "type" => "string"
#                    }
#                  }
                }
              }
            },
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::firewall_rules}, bare and unvalidated.
        # @param acl [Hash]: The resource to process and validate
        # @param config [MU::Config]: The overall deployment config of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(acl, config)
          ok = true
          acl['region'] ||= MU::Cloud::Azure.myRegion(acl['credentials'])

          append = []
          delete = []
          acl['rules'].each { |r|
            if r["weight"] and (r["weight"] < 100 or r["weight"] > 4096)
              MU.log "FirewallRule #{acl['name']} weight must be between 100 and 4096", MU::ERR
              ok = false
            end
            if r["hosts"]
              r["hosts"].each { |cidr|
                r["hosts"] << "*" if cidr == "0.0.0.0/0"
              }
              r["hosts"].delete("0.0.0.0/0")
            end

            if (!r['hosts'] or r['hosts'].empty?) and
               (!r['lbs'] or r['lbs'].empty?) and
               (!r['sgs'] or r['sgs'].empty?)
              r["hosts"] = "*"
              MU.log "FirewallRule #{acl['name']} did not specify any hosts, sgs or lbs, defaulting this rule to allow 0.0.0.0/0", MU::NOTICE
            end


            if r['proto'] == "standard"
              ["tcp", "udp"].each { |p|
                newrule = r.dup
                newrule['proto'] = p
                append << newrule
              }
              delete << r
            elsif r['proto'] == "all" or !r['proto']
              r['proto'] = "asterisk" # legit, the name of the constant
            end
          }
          delete.each { |r|
            acl['rules'].delete(r)
          }
          acl['rules'].concat(append)

          ok
        end

        private

        def create_update
          @config['region'] ||= MU::Cloud::Azure.myRegion(@config['credentials'])

          fw_obj = MU::Cloud::Azure.network(:NetworkSecurityGroup).new
          fw_obj.location = @config['region']
          fw_obj.tags = @tags

          need_apply = false
          ext_ruleset = MU::Cloud::Azure.network(credentials: @config['credentials']).network_security_groups.get(
            @resource_group,
            @mu_name
          )
          if ext_ruleset
            @cloud_id = MU::Cloud::Azure::Id.new(ext_ruleset.id)
          end

          if !ext_ruleset
            MU.log "Creating Network Security Group #{@mu_name} in #{@config['region']}", details: fw_obj
            need_apply = true
          elsif ext_ruleset.location != fw_obj.location or
                ext_ruleset.tags != fw_obj.tags
            MU.log "Updating Network Security Group #{@mu_name} in #{@config['region']}", MU::NOTICE, details: fw_obj
            need_apply = true
          end

          if need_apply
            resp = MU::Cloud::Azure.network(credentials: @config['credentials']).network_security_groups.create_or_update(
              @resource_group,
              @mu_name,
              fw_obj
            )

            @cloud_id = MU::Cloud::Azure::Id.new(resp.id)
          end
        end

      end #class
    end #class
  end
end #module
