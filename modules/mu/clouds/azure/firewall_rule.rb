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

        @deploy = nil
        @config = nil
        @admin_sgs = Hash.new
        @admin_sg_semaphore = Mutex.new
        PROTOS = ["udp", "tcp", "icmp", "esp", "ah", "sctp", "ipip"]
        STD_PROTOS = ["icmp", "tcp", "udp"]

        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::firewall_rules}
        def initialize(**args)
          setInstanceVariables(args) # set things like @deploy, @config, @cloud_id...

#          if @cloud_id
#            desc = cloud_desc
#            @url = desc.self_link if desc and desc.self_link
#          end

          if !mu_name.nil?
            @mu_name = mu_name
          else
            @mu_name = @deploy.getResourceName(@config['name'], max_length: 61)
          end

        end

        attr_reader :rulesets

        # Called by {MU::Deploy#createResources}
        def create
#          MU.log "AZURE FW RULE CFG KEYS", MU::WARN, details: @config.keys
          create_update
        end

        # Called by {MU::Deploy#createResources}
        def groom
          create_update
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
              rescue MsRestAzure::AzureOperationError => e
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

        # Remove all security groups (firewall rulesets) associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
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
#            "rules" => {
#              "items" => {
#                "properties" => {
#                  "weight" => {
#                    "type" => "integer",
#                    "description" => "Explicitly set a priority for this firewall rule, between 0 and 65535, with lower numbered priority rules having greater precedence."
#                  },
#                  "deny" => {
#                    "type" => "boolean",
#                    "default" => false,
#                    "description" => "Set this rule to +DENY+ traffic instead of +ALLOW+"
#                  },
#                  "proto" => {
#                    "description" => "The protocol to allow with this rule. The +standard+ keyword will expand to a series of identical rules covering +icmp+, +tcp+, and +udp; the +all+ keyword will expand to a series of identical rules for all supported protocols.",
#                    "enum" => PROTOS + ["all", "standard"]
#                  },
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
#                }
#              }
#            },
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::firewall_rules}, bare and unvalidated.
        # @param acl [Hash]: The resource to process and validate
        # @param config [MU::Config]: The overall deployment config of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(acl, config)
          ok = true

          ok
        end

        private

        def create_update
          @config['region'] ||= MU::Cloud::Azure.myRegion(@config['credentials'])
          tags = {}
          if !@config['scrub_mu_isms']
            tags = MU::MommaCat.listStandardTags
          end
          if @config['tags']
            @config['tags'].each { |tag|
              tags[tag['key']] = tag['value']
            }
          end

          rgroup_name = @deploy.deploy_id+"-"+@config['region'].upcase

          fw_obj = MU::Cloud::Azure.network(:NetworkSecurityGroup).new
          fw_obj.location = @config['region']
          fw_obj.tags = tags

          ext_ruleset = nil
          need_apply = false
          begin
            ext_ruleset = MU::Cloud::Azure.network(credentials: @config['credentials']).network_security_groups.get(
              rgroup_name,
              @mu_name
            )
            @cloud_id = MU::Cloud::Azure::Id.new(ext_ruleset.id)
          rescue ::MsRestAzure::AzureOperationError => e
            if e.message.match(/: ResourceNotFound: /)
              need_apply = true
            else
              raise e
            end
          end

          if !ext_ruleset
            MU.log "Creating Network Security Group #{@mu_name} in #{@config['region']}", details: fw_obj
          elsif ext_ruleset.location != fw_obj.location or
                ext_ruleset.tags != fw_obj.tags
            MU.log "Updating Network Security Group #{@mu_name} in #{@config['region']}", MU::NOTICE, details: fw_obj
            need_apply = true
          end

          if need_apply
            resp = MU::Cloud::Azure.network(credentials: @config['credentials']).network_security_groups.create_or_update(
              rgroup_name,
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
