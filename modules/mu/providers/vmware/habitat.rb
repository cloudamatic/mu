# Copyright:: Copyright (c) 2020 eGlobalTech, Inc., all rights reserved
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
    class VMWare
      # Creates an VMWare SDDC as configured in {MU::Config::BasketofKittens::habitats}
      class Habitat < MU::Cloud::Habitat

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super

          @mu_name ||= @deploy.getResourceName(@config['name'])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
        end

        @cached_cloud_desc = nil
        # Return the cloud descriptor for the Habitat
        # @return [VMWare::Apis::Core::Hashable]
        def cloud_desc(use_cache: true)
          return @cached_cloud_desc if @cached_cloud_desc and use_cache
          @cached_cloud_desc = MU::Cloud::VMWare::Habitat.find(cloud_id: @cloud_id).values.first
          if @cached_cloud_desc and @cached_cloud_desc.parent
            @habitat_id ||= @cached_cloud_desc.parent.id
          end
          @cached_cloud_desc
        end

        # Return the metadata for this SDDC's configuration
        # @return [Hash]
        def notify
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
          MU::Cloud::ALPHA
        end

        # Check whether is in the +ACTIVE+ state and has billing enabled.
        # @param sddc_id [String]
        # @return [Boolean]
        def self.isLive?(sddc_id, credentials = nil)

          true
        end

        # Remove all VMWare SDDCs associated with the currently loaded deployment. Try to, anyway.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, credentials: nil, flags: {})
        end

        # Locate an existing SDDC
        # @return [Hash<Hash>]: The cloud provider's complete descriptions of matching project
        def self.find(**args)
          found = {}

          my_org = MU::Cloud::VMWare::VMC.getOrg(args[:credentials])

          sddcs = MU::Cloud::VMWare::VMC.callAPI("orgs/"+my_org['id']+"/sddcs", credentials: args[:credentials])
          sddcs.each { |sddc|
            if args[:cloud_id] 
              if [sddc['id'], sddc['name']].include?(args[:cloud_id])
                found[args[:cloud_id]] = sddc
              end
              next
            end

            found[sddc['id']] = sddc
          }

          found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
#        def toKitten(**args)
#          bok = {
#            "cloud" => "VMWare",
#            "credentials" => @config['credentials']
#          }

#          bok
#        end


        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = { }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::habitats}, bare and unvalidated.
        # @param habitat [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(habitat, configurator)
          ok = true

          ok
        end

      end
    end
  end
end
