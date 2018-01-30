# Copyright:: Copyright (c) 2017 eGlobalTech, Inc., all rights reserved
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
    class Google
      # A firewall ruleset as configured in {MU::Config::BasketofKittens::firewall_rules}
      class FirewallRule < MU::Cloud::FirewallRule

        @deploy = nil
        @config = nil
        @admin_sgs = Hash.new
        @admin_sg_semaphore = Mutex.new

        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::firewall_rules}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          if !mu_name.nil?
            @mu_name = mu_name
          else
            if !@vpc.nil?
              @mu_name = @deploy.getResourceName(@config['name'], need_unique_string: true)
            else
              @mu_name = @deploy.getResourceName(@config['name'])
            end
          end

        end

        attr_reader :rulesets

        # Called by {MU::Deploy#createResources}
        def create
          vpc_id = @vpc.cloudobj.url if !@vpc.nil?

          allrules = {}
# XXX source_ranges
# XXX source_tags
# XXX target_tags
          # The set of rules might actually compose into multiple firewall
          # objects, so figure that out.
          @config['rules'].each { |rule|
            srcs = []
            ruleobj = nil
            if ["tcp", "udp"].include?(rule['proto']) and (rule['port_range'] or rule['port'])
              ruleobj = MU::Cloud::Google.compute(:Firewall)::Allowed.new(
                ip_protocol: rule['proto'],
                ports: [rule['port_range'] || rule['port']]
              )
            else
              ruleobj = MU::Cloud::Google.compute(:Firewall)::Allowed.new(
                ip_protocol: rule['proto']
              )
            end
            if rule['hosts']
              rule['hosts'].each { |cidr| srcs << cidr }
            end
            ["ingress", "egress"].each { |dir|
              if rule[dir] or (dir == "ingress" and !rule.has_key?("egress"))
                setname = MU::Cloud::Google.nameStr(@mu_name+"-"+dir+"-"+(rule['deny'] ? "deny" : "allow"))
                allrules[setname] ||= {
                  :name => setname,
                  :description => @deploy.deploy_id,
                  :direction => dir.upcase,
                  :network => vpc_id
                }
                action = rule['deny'] ? :denied : :allowed
                allrules[setname][action] ||= []
                allrules[setname][action] << ruleobj
                ipparam = dir == "ingress" ? :source_ranges : :destination_ranges
                allrules[setname][ipparam] ||= []
                allrules[setname][ipparam].concat(srcs)
                allrules[setname][:priority] = rule['weight'] if rule['weight']
              end
            }
          }

          parent_thread_id = Thread.current.object_id
          threads = []

          allrules.each_value { |fwdesc|
            threads << Thread.new { 
              fwobj = MU::Cloud::Google.compute(:Firewall).new(fwdesc)
              MU.log "Creating firewall #{fwdesc[:name]} in project #{@config['project']}", details: fwobj
              resp = MU::Cloud::Google.compute.insert_firewall(@config['project'], fwobj)
# XXX Check for empty (no hosts) sets
#  MU.log "Can't create empty firewalls in Google Cloud, skipping #{@mu_name}", MU::WARN
            }
          }

          threads.each do |t|
            t.join
          end
        end

        # Called by {MU::Deploy#createResources}
        def groom
        end

        # Log metadata about this ruleset to the currently running deployment
        def notify
          sg_data = MU.structToHash(
              MU::Cloud::FirewallRule.find(cloud_id: @cloud_id, region: @config['region'])
          )
          sg_data ||= {}
          sg_data["group_id"] = @cloud_id
          return sg_data
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
        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil, flags: {})
          flags["project"] ||= MU::Cloud::Google.defaultProject

          found = {}
          resp = MU::Cloud::Google.compute.list_firewalls(flags["project"])
          if resp and resp.items
            resp.items.each { |fw|
              found[fw.name] = fw
            }
          end
          found
        end

        # Remove all security groups (firewall rulesets) associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          flags["project"] ||= MU::Cloud::Google.defaultProject

          MU::Cloud::Google.compute.delete(
            "firewall",
            flags["project"],
            nil,
            noop
          )
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "rules" => {
              "items" => {
                "properties" => {
                  "proto" => {
                    "enum" => ["udp", "tcp", "icmp", "all"]
                  },
                  "source_tags" => {
                    "type" => "array",
                    "description" => "VMs with these tags from which traffic will be allowed",
                    "items" => {
                      "type" => "string"
                    }
                  }
                }
              }
            },
            "project" => {
              "type" => "string",
              "description" => "The project into which to deploy resources"
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::firewall_rules}, bare and unvalidated.
        # @param acl [Hash]: The resource to process and validate
        # @param config [MU::Config]: The overall deployment config of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(acl, config)
          ok = true
        end

        private

        ########################################################################
        # Manufacture an EC2 security group. The second parameter, rules, is an
        # "ingress_rules" structure parsed and validated by MU::Config.
        ########################################################################
        def setRules(rules, add_to_self: false, ingress: true, egress: false)
        end

        ########################################################################
        # Convert our config languages description of firewall rules into
        # Amazon's.  This rule structure is as defined in MU::Config.
        ########################################################################
        def convertToEc2(rules)
        end

      end #class
    end #class
  end
end #module
