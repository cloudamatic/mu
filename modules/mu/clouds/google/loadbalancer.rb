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
      # A load balancer as configured in {MU::Config::BasketofKittens::loadbalancers}
      class LoadBalancer < MU::Cloud::LoadBalancer

        @deploy = nil
        @lb = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id
        attr_reader :targetgroups

        @cloudformation_data = {}
        attr_reader :cloudformation_data

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::loadbalancers}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          if !mu_name.nil?
            @mu_name = mu_name
          elsif @config['scrub_mu_isms']
            @mu_name = @config['name']
          else
            @mu_name = @deploy.getResourceName(@config["name"]).downcase
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
# XXX need stuff
#          ruleobj = ::Google::Apis::ComputeBeta::ForwardingRule.new(
#            name: @mu_name,
#            description: @deploy.deploy_id,
#            target: somebody
#          )
#          MU.log "Creating Forwarding Rule #{@mu_name}", details: ruleobj
#          resp = MU::Cloud::Google.compute.insert_forwarding_rule(@config['project'], @config['region'], ruleobj)
          raise MuError, "NAH"
        end

        # Wrapper that fetches the API's description of one of these things
        def cloud_desc
        end

        # Return the metadata for this LoadBalancer
        # @return [Hash]
        def notify
        end

        # Register a Server node with an existing LoadBalancer.
        #
        # @param instance_id [String] A node to register.
        # @param targetgroups [Array<String>] The target group(s) of which this node should be made a member. Not applicable to classic LoadBalancers. If not supplied, the node will be registered to all available target groups on this LoadBalancer.
        def registerNode(instance_id, targetgroups: nil)
        end

        # Remove all load balancers associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::loadbalancers}, bare and unvalidated.
        # @param lb [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(lb, configurator)
          true
        end

        # Locate an existing LoadBalancer or LoadBalancers and return an array containing matching Google resource descriptors for those that match.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region
        # @param tag_key [String]: A tag key to search.
        # @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
        # @param flags [Hash]: Optional flags
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching LoadBalancers
        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil, flags: {})
        end
      end
    end
  end
end
