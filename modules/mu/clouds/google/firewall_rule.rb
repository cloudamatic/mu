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
            @mu_name = mu_name.downcase
          else
            if !@vpc.nil?
              @mu_name = @deploy.getResourceName(@config['name'], need_unique_string: true).downcase
            else
              @mu_name = @deploy.getResourceName(@config['name']).downcase
            end
          end

        end

        # Called by {MU::Deploy#createResources}
        def create
          allowed = []
          srcs = []

          @config['rules'].each { |rule|
            if ["tcp", "udp"].include?(rule['proto'])
              allowed << ::Google::Apis::ComputeV1::Firewall::Allowed.new(
                ip_protocol: rule['proto'],
                ports: [rule['port_range'] || rule['port']]
              )
            else
              allowed << ::Google::Apis::ComputeV1::Firewall::Allowed.new(
                ip_protocol: rule['proto']
              )
            end
            if rule['hosts']
              rule['hosts'].each { |cidr| srcs << cidr }
            end
          }
          fwobj = ::Google::Apis::ComputeV1::Firewall.new(
            name: @mu_name,
            allowed: allowed,
            description: @deploy.deploy_id,
            source_ranges: srcs
          )

if allowed.size > 0
          MU.log "Creating firewall #{@mu_name}"
          resp = MU::Cloud::Google.compute.insert_firewall(@config['project'], fwobj)
else
  MU.log "Can't create empty firewalls (like #{@mu_name})  in Google Cloud", MU::WARN
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
        # @param opts [Hash]: Optional flags
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching FirewallRules
        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil, opts: {})
          opts["project"] ||= MU::Cloud::Google.defaultProject
# XXX project flag has to get passed from somewheres
          resp = MU::Cloud::Google.compute.list_firewalls(opts["project"])

        end

        # Remove all security groups (firewall rulesets) associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          flags["project"] ||= MU::Cloud::Google.defaultProject
# XXX project flag has to get passed from somewheres
          resp = MU::Cloud::Google.compute.list_firewalls(
            flags["project"],
            filter: "description eq #{MU.deploy_id}"
          )
          return if resp.nil? or resp.items.nil?
          
          resp.items.each { |firewall|
            MU.log "Removing firewall #{firewall.name}", details: firewall
            if !noop
              begin
                MU::Cloud::Google.compute.delete_firewall(flags["project"], firewall.name)
              rescue ::Google::Apis::ClientError => e
                if e.message.match(/^notFound:/)
                  MU.log "#{firewall.name} has already been deleted", MU::NOTICE
                elsif e.message.match(/^resourceNotReady:/)
                  MU.log "Got #{e.message} deleting #{firewall.name}, may already be deleting", MU::NOTICE
                  sleep 5
                  retry
                end
              end
            end
          }
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
