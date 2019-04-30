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
        @project_id = nil
        @admin_sgs = Hash.new
        @admin_sg_semaphore = Mutex.new
        PROTOS = ["udp", "tcp", "icmp", "esp", "ah", "sctp", "ipip"]

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
            # This is really a placeholder, since we "own" multiple rule sets
            @cloud_id ||= MU::Cloud::Google.nameStr(@mu_name+"-ingress-allow")
            @config['project'] ||= MU::Cloud::Google.defaultProject(@config['credentials'])
            if !@project_id
              project = MU::Cloud::Google.projectLookup(@config['project'], @deploy, sibling_only: true, raise_on_fail: false)
              @project_id = project.nil? ? @config['project'] : project.cloudobj.cloud_id
            end
          else
            if !@vpc.nil?
              @mu_name = @deploy.getResourceName(@config['name'], need_unique_string: true, max_length: 61)
            else
              @mu_name = @deploy.getResourceName(@config['name'], max_length: 61)
            end
          end

        end

        attr_reader :rulesets

        # Called by {MU::Deploy#createResources}
        def create
          @project_id = MU::Cloud::Google.projectLookup(@config['project'], @deploy).cloudobj.cloud_id

          vpc_id = @vpc.cloudobj.url if !@vpc.nil? and !@vpc.cloudobj.nil?
          vpc_id ||= @config['vpc']['vpc_id'] if @config['vpc'] and @config['vpc']['vpc_id']

          allrules = {}
          # The set of rules might actually compose into multiple firewall
          # objects, so figure that out.
          @config['rules'].each { |rule|
            srcs = []
            ruleobj = nil
# XXX 'all' and 'standard' keywords
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
                setname = @deploy.getResourceName(@mu_name+"-"+dir+"-"+(rule['deny'] ? "deny" : "allow"), max_length: 61).downcase
                @cloud_id ||= setname
                allrules[setname] ||= {
                  :name => setname,
                  :direction => dir.upcase,
                  :network => vpc_id
                }
                if @deploy
                  allrules[setname][:description] = @deploy.deploy_id
                end
                ['source_service_accounts', 'source_tags', 'target_tags', 'target_service_accounts'].each { |filter|
                  if config[filter] and config[filter].size > 0
                    allrules[setname][filter.to_sym] = config[filter].dup
                  end
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
              MU.log "Creating firewall #{fwdesc[:name]} in project #{@project_id}", details: fwobj
              resp = MU::Cloud::Google.compute(credentials: @config['credentials']).insert_firewall(@project_id, fwobj)
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
          @project_id = MU::Cloud::Google.projectLookup(@config['project'], @deploy).cloudobj.cloud_id
        end

        # Log metadata about this ruleset to the currently running deployment
        def notify
          sg_data = MU.structToHash(
            MU::Cloud::Google::FirewallRule.find(cloud_id: @cloud_id, region: @config['region'])
          )
          sg_data ||= {}
          sg_data["group_id"] = @cloud_id
          sg_data["project_id"] = @project_id
          sg_data["cloud_id"] = @cloud_id

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
#        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil, flags: {}, credentials: nil)
        def self.find(**args)
          args[:project] ||= MU::Cloud::Google.defaultProject(args[:credentials])

          found = {}
          resp = MU::Cloud::Google.compute(credentials: args[:credentials]).list_firewalls(args[:project])
          if resp and resp.items
            resp.items.each { |fw|
              next if !args[:cloud_id].nil? and fw.name != args[:cloud_id]
              found[fw.name] = fw
            }
          end

          found
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          true
        end

        # Denote whether this resource implementation is experiment, ready for
        # testing, or ready for production use.
        def self.quality
          MU::Cloud::RELEASE
        end

        # Remove all security groups (firewall rulesets) associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          flags["project"] ||= MU::Cloud::Google.defaultProject(credentials)
          MU::Cloud::Google.compute(credentials: credentials).delete(
            "firewall",
            flags["project"],
            nil,
            noop
          )
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(strip_name: true)
          schema, valid = MU::Config.loadResourceSchema("FirewallRule", cloud: "Google")
          return [nil, nil] if !valid or !cloud_desc

          bok = {
            "cloud" => "Google",
            "project" => @project_id,
            "credentials" => @config['credentials']
          }

          bok['rules'] = []
          bok['name'] = cloud_desc[:name].dup

          if strip_name
            bok['name'].gsub!(/(^(sg|firewall)-|-(sg|firewall)$)/i, '')
          end

          host_field = :source_ranges
          if cloud_desc[:direction] == "EGRESS"
            bok['egress'] = true
            bok['ingress'] = false
            host_field = :destination_ranges
          end

          [:source_service_accounts, :source_tags, :target_service_accounts, :target_tags].each { |field|
            if cloud_desc[field]
              bok[field.to_s] = cloud_desc[field].dup
            end
          }

          byport = {}

          if cloud_desc[:allowed]
            cloud_desc[:allowed].each { |rule|
              hosts = cloud_desc[host_field] ? cloud_desc[host_field] : "0.0.0.0/0"
              proto = rule[:ip_protocol] ? rule[:ip_protocol] : "all"

              if rule[:ports]
                rule[:ports].each { |ports|
                  ports = "0-65535" if ["1-65535", "1-65536", "0-65536"].include?(ports)
                  byport[ports] ||= {}
                  byport[ports][hosts] ||= []
                  byport[ports][hosts] << proto
                }
              else
                byport["0-65535"] ||= {}
                byport["0-65535"][hosts] ||= []
                byport["0-65535"][hosts] << proto
              end
            }
          elsif cloud_desc[:denied]
            MU.log "XXX #{bok['name']} is a DENY rule", MU::WARN
          else
            MU.log "FW CLOUD_DESC #{bok['name']}", MU::WARN, details: cloud_desc
            raise MuError, "FUCK OFF"
          end

          byport.each_pair { |ports, hostlist|
            hostlist.each_pair { |hostlist, protos|
              protolist = if protos.sort.uniq == PROTOS.sort.uniq
                ["all"]
              elsif protos.sort.uniq == ["icmp", "tcp", "udp"]
                ["standard"]
              else
                protos
              end
              protolist.each { |proto|
                rule = {
                  "proto" => proto,
                  "hosts" => hostlist,
                }
                if ports.match(/-/)
                  rule["port_range"] = ports
                else
                  rule["port"] = ports.to_i
                end
                bok['rules'] << rule
              }
            }
          }

          bok
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config = nil)
          toplevel_required = []
#                ['source_ranges', 'source_service_accounts', 'source_tags', 'target_ranges', 'target_service_accounts'].each { |filter|
          schema = {
            "rules" => {
              "items" => {
                "properties" => {
                  "proto" => {
                    "description" => "The protocol to allow with this rule. The +standard+ keyword will expand to a series of identical rules covering +icmp+, +tcp+, and +udp; the +all+ keyword will expand to a series of identical rules for all supported protocols.",
                    "enum" => PROTOS + ["all", "standard"]
                  },
                  "source_tags" => {
                    "type" => "array",
                    "description" => "VMs with these tags, from which traffic will be allowed",
                    "items" => {
                      "type" => "string"
                    }
                  },
                  "source_service_accounts" => {
                    "type" => "array",
                    "description" => "Resources using these service accounts, from which traffic will be allowed",
                    "items" => {
                      "type" => "string"
                    }
                  },
                  "target_tags" => {
                    "type" => "array",
                    "description" => "VMs with these tags, to which traffic will be allowed",
                    "items" => {
                      "type" => "string"
                    }
                  },
                  "target_service_accounts" => {
                    "type" => "array",
                    "description" => "Resources using these service accounts, to which traffic will be allowed",
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

      end #class
    end #class
  end
end #module
