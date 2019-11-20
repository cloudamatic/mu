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
        @admin_sgs = Hash.new
        @admin_sg_semaphore = Mutex.new

        # Firewall protocols supported by GCP as of early 2019
        PROTOS = ["udp", "tcp", "icmp", "esp", "ah", "sctp", "ipip"]

        # Our default subset of supported firewall protocols
        STD_PROTOS = ["icmp", "tcp", "udp"]

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super

          if !@vpc.nil?
            @mu_name ||= @deploy.getResourceName(@config['name'], need_unique_string: true, max_length: 61)
          else
            @mu_name ||= @deploy.getResourceName(@config['name'], max_length: 61)
          end
        end

        attr_reader :rulesets

        # Called by {MU::Deploy#createResources}
        def create
          @cloud_id = @mu_name.downcase.gsub(/[^-a-z0-9]/, "-")

          vpc_id = @vpc.url if !@vpc.nil?
          vpc_id ||= @config['vpc']['vpc_id'] if @config['vpc'] and @config['vpc']['vpc_id']

          if vpc_id.nil?
            raise MuError, "Failed to resolve VPC for #{self}"
          end

          params = {
            :name => @cloud_id,
            :network => vpc_id
          }

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

            dir = (rule["ingress"] or !rule["egress"]) ? "INGRESS" : "EGRESS"
            if params[:direction] and params[:direction] != dir
              MU.log "Google Cloud firewalls cannot mix ingress and egress rules", MU::ERR, details: @config['rules']
              raise MuError, "Google Cloud firewalls cannot mix ingress and egress rules"
            end

            params[:direction] = dir

            if @deploy
              params[:description] = @deploy.deploy_id
            end
            filters = if dir == "INGRESS"
              ['source_service_accounts', 'source_tags']
            else
              ['target_service_accounts', 'target_tags']
            end
            filters.each { |filter|
              if config[filter] and config[filter].size > 0
                params[filter.to_sym] = config[filter].dup
              end
            }
            action = rule['deny'] ? :denied : :allowed
            params[action] ||= []
            params[action] << ruleobj
            ipparam = dir == "INGRESS" ? :source_ranges : :destination_ranges
            params[ipparam] ||= []
            params[ipparam].concat(srcs)
            params[:priority] = rule['weight'] if rule['weight']
          }

          fwobj = MU::Cloud::Google.compute(:Firewall).new(params)
          MU.log "Creating firewall #{@cloud_id} in project #{@project_id}", details: fwobj
begin
  MU::Cloud::Google.compute(credentials: @config['credentials']).insert_firewall(@project_id, fwobj)
rescue ::Google::Apis::ClientError => e
  MU.log @config['project']+"/"+@config['name']+": "+@cloud_id, MU::ERR, details: @config['vpc']
  MU.log e.inspect, MU::ERR, details: fwobj
  if e.message.match(/Invalid value for field/)
    dependencies(use_cache: false, debug: true)
  end
  raise e
end
          # Make sure it actually got made before we move on
          desc = nil
          begin
            desc = MU::Cloud::Google.compute(credentials: @config['credentials']).get_firewall(@project_id, @cloud_id)
            sleep 1
          end while desc.nil?
          desc
        end

        # Called by {MU::Deploy#createResources}
        def groom
        end

        # Log metadata about this ruleset to the currently running deployment
        def notify
          sg_data = MU.structToHash(
            MU::Cloud::Google::FirewallRule.find(cloud_id: @cloud_id, region: @config['region'])
          )
          sg_data ||= {}
          sg_data["group_id"] = @cloud_id
          sg_data["project_id"] = habitat_id
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

        # Locate and return cloud provider descriptors of this resource type
        # which match the provided parameters, or all visible resources if no
        # filters are specified. At minimum, implementations of +find+ must
        # honor +credentials+ and +cloud_id+ arguments. We may optionally
        # support other search methods, such as +tag_key+ and +tag_value+, or
        # cloud-specific arguments like +project+. See also {MU::MommaCat.findStray}.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching resources
        def self.find(**args)
          args[:project] ||= args[:habitat]
          args[:project] ||= MU::Cloud::Google.defaultProject(args[:credentials])

          found = {}
          resp = begin
            MU::Cloud::Google.compute(credentials: args[:credentials]).list_firewalls(args[:project])
          rescue  ::Google::Apis::ClientError => e
            raise e if !e.message.match(/^(?:notFound|forbidden): /)
          end
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
          return if !MU::Cloud::Google::Habitat.isLive?(flags["project"], credentials)

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
        def toKitten(rootparent: nil, billing: nil, habitats: nil)

          if cloud_desc.name.match(/^[a-f0-9]+$/)
            gke_ish = true
            cloud_desc.target_tags.each { |tag|
              gke_ish = false if !tag.match(/^gke-/)
            }
            if gke_ish
              MU.log "FirewallRule #{cloud_desc.name} appears to belong to a ContainerCluster, skipping adoption", MU::DEBUG
              return nil
            end
          end

          bok = {
            "cloud" => "Google",
            "project" => @config['project'],
            "credentials" => @config['credentials']
          }

          bok['rules'] = []
          bok['name'] = cloud_desc.name.dup
          bok['cloud_id'] = cloud_desc.name.dup


          cloud_desc.network.match(/(?:^|\/)projects\/(.*?)\/.*?\/networks\/([^\/]+)(?:$|\/)/)
          vpc_proj = Regexp.last_match[1]
          vpc_id = Regexp.last_match[2]

          if vpc_id == "default" and !@config['project']
            raise MuError, "FirewallRule toKitten: I'm in 'default' VPC but can't figure out what project I'm in"
          end

          # XXX make sure this is sane (that these rules come with default VPCs)
          if vpc_id == "default" and ["default-allow-icmp", "default-allow-http"].include?(cloud_desc.name)
            return nil
          end

          if vpc_id != "default"
            bok['vpc'] = MU::Config::Ref.get(
              id: vpc_id,
              habitat: MU::Config::Ref.get(
                id: vpc_proj,
                cloud: "Google",
                credentials: @credentials,
                type: "habitats"
              ),
              cloud: "Google",
              credentials: @config['credentials'],
              type: "vpcs"
            )
          end

          byport = {}

          rule_list = []
          is_deny = false
          if cloud_desc.denied
            rule_list = cloud_desc.denied
            is_deny = true
          else
            rule_list = cloud_desc.allowed
          end

          rule_list.each { |rule|
            hosts = if cloud_desc.direction == "INGRESS"
              cloud_desc.source_ranges ? cloud_desc.source_ranges : ["0.0.0.0/0"]
            else
              cloud_desc.destination_ranges ? cloud_desc.destination_ranges : ["0.0.0.0/0"]
            end
            hosts.map! { |h|
              h = h+"/32" if h.match(/^\d+\.\d+\.\d+\.\d+$/)
              h
            }
            proto = rule.ip_protocol ? rule.ip_protocol : "all"

            if rule.ports
              rule.ports.each { |ports|
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

          byport.each_pair { |ports, hostlists|
            hostlists.each_pair { |hostlist, protos|
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
                  "hosts" => hostlist
                }
                rule["deny"] = true if is_deny
                if cloud_desc.priority and cloud_desc.priority != 1000
                  rule["weight"] = cloud_desc.priority
                end
                if ports.match(/-/)
                  rule["port_range"] = ports
                else
                  rule["port"] = ports.to_i
                end
                if cloud_desc.source_service_accounts
                  rule["source_service_accounts"] = cloud_desc.source_service_accounts
                end
                if cloud_desc.source_tags
                  rule["source_tags"] = cloud_desc.source_tags
                end
                if cloud_desc.target_service_accounts
                  rule["target_service_accounts"] = cloud_desc.target_service_accounts
                end
                if cloud_desc.target_tags
                  rule["target_tags"] = cloud_desc.target_tags
                end
                if cloud_desc.direction == "EGRESS"
                  rule['egress'] = true
                  rule['ingress'] = false
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
          schema = {
            "rules" => {
              "items" => {
                "properties" => {
                  "weight" => {
                    "type" => "integer",
                    "description" => "Explicitly set a priority for this firewall rule, between 0 and 65535, with lower numbered priority rules having greater precedence."
                  },
                  "deny" => {
                    "type" => "boolean",
                    "default" => false,
                    "description" => "Set this rule to +DENY+ traffic instead of +ALLOW+"
                  },
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
          acl['project'] ||= MU::Cloud::Google.defaultProject(acl['credentials'])

          if acl['vpc']
            acl['vpc']['project'] ||= acl['project']
            acl['vpc'] = MU::Cloud::Google::VPC.pickVPC(
              acl['vpc'],
              acl,
              "firewall_rule",
              config
            )
          end

          acl['rules'] ||= []

          # Firewall entries without rules are illegal in GCP, so insert a
          # default-deny placeholder.
          if acl['rules'].empty?
            acl['rules'] << {
              "deny" => true,
              "proto" => "all",
              "hosts" => ["0.0.0.0/0"],
              "weight" => 65535
            }
          end

          # First, expand some of our protocol shorthand into a real list
          append = []
          delete = []
          acl['rules'].each { |r|
            if !r['egress']
              if !r['source_tags'] and !r['source_service_accounts'] and
                 (!r['hosts'] or r['hosts'].empty?)
                r['hosts'] = ['0.0.0.0/0']
              end
            else
              if !r['destination_tags'] and !r['destination_service_accounts'] and
                 (!r['hosts'] or r['hosts'].empty?)
                r['hosts'] = ['0.0.0.0/0']
              end
            end

            if r['proto'] == "standard"
              STD_PROTOS.each { |p|
                newrule = r.dup
                newrule['proto'] = p
                append << newrule
              }
              delete << r
            elsif r['proto'] == "all"
              PROTOS.each { |p|
                newrule = r.dup
                newrule['proto'] = p
                append << newrule
              }
              delete << r
            end

          }
          delete.each { |r|
            acl['rules'].delete(r)
          }
          acl['rules'].concat(append)

          # Next, bucket these by what combination of allow/deny and
          # ingress/egress rule they are. If we have more than one
          # classification
          rules_by_class = {
            "allow-ingress" => [],
            "allow-egress" => [],
            "deny-ingress" => [],
            "deny-egress" => [],
          }

          acl['rules'].each { |rule|
            if rule['deny']
              if rule['egress']
                rules_by_class["deny-egress"] << rule
              else
                rules_by_class["deny-ingress"] << rule
              end
            else
              if rule['egress']
                rules_by_class["allow-egress"] << rule
              else
                rules_by_class["allow-ingress"] << rule
              end
            end
          }

          rules_by_class.reject! { |k, v| v.size == 0 }

          # Generate other firewall rule objects to cover the other behaviors
          # we've requested, if indeed we've done so.
          if rules_by_class.size > 1
            keep = rules_by_class.keys.first
            acl['rules'] = rules_by_class[keep]
            rules_by_class.delete(keep)
            rules_by_class.each_pair { |behaviors, rules|
              newrule = acl.dup
              newrule['name'] += "-"+behaviors
              newrule['rules'] = rules
              ok = false if !config.insertKitten(newrule, "firewall_rules")

            }
          end

          ok
        end

        private

      end #class
    end #class
  end
end #module
