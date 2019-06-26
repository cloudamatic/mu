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
      # Creates an Azure directory as configured in {MU::Config::BasketofKittens::habitats}
      class Habitat < MU::Cloud::Habitat
        @deploy = nil
        @config = nil

        attr_reader :mu_name
        attr_reader :habitat_id # misnomer- it's really a parent folder, which may or may not exist
        attr_reader :config
        attr_reader :cloud_id
        attr_reader :url

        def self.testcalls

pp MU::Cloud::Azure::Habitat.find

          pp MU::Cloud::Azure.billing.enrollment_accounts.list

          pp MU::Cloud::Azure.subfactory.api.class.name

          pp MU::Cloud::Azure.subfactory.subscription_factory.create_subscription_in_enrollment_account # this should barf
        end

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::habitats}
        def initialize(**args)
          setInstanceVariables(args) # set things like @deploy, @config, @cloud_id...

          cloud_desc if @cloud_id # XXX why don't I have this on regroom?
          if !@cloud_id and cloud_desc and cloud_desc.project_id
            @cloud_id = cloud_desc.project_id
          end

          if !mu_name.nil?
            @mu_name = mu_name
          elsif @config['scrub_mu_isms']
            @mu_name = @config['name']
          else
            @mu_name = @deploy.getResourceName(@config['name'])
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
        end

        # Return the cloud descriptor for the Habitat
        def cloud_desc
          @cached_cloud_desc ||= MU::Cloud::Azure::Habitat.find(cloud_id: @cloud_id).values.first
#          @habitat_id ||= @cached_cloud_desc.parent.id if @cached_cloud_desc
          @cached_cloud_desc
        end

        # Return the metadata for this project's configuration
        # @return [Hash]
        def notify
#          MU.structToHash(MU::Cloud::Google.resource_manager(credentials: @config['credentials']).get_project(@cloud_id))
          {}
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
        # @param project_id [String]
        # @return [Boolean]
        def self.isLive?(project_id, credentials = nil)
          true
        end

        # Remove all Azure directories associated with the currently loaded deployment. Try to, anyway.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
        end

        @@list_projects_cache = nil

        # Locate an existing project
        # @return [Hash<OpenStruct>]: The cloud provider's complete descriptions of matching project
        def self.find(**args)
#MU.log "habitat.find called by #{caller[0]}", MU::WARN, details: args
          found = {}

          args[:cloud_id] ||= args[:project]
# XXX we probably want to cache this
# XXX but why are we being called over and over?

          if args[:cloud_id]
            found[args[:cloud_id]] = MU::Cloud::Azure.subs.subscriptions.get(args[:cloud_id])
          else
            MU::Cloud::Azure.subs.subscriptions.list.each { |sub|
              found[sub.subscription_id] = sub
            }
          end

          found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(rootparent: nil, billing: nil)
          bok = {
            "cloud" => "Azure",
            "credentials" => @config['credentials']
          }

          bok
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
          }
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
