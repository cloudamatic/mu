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
    class AWS
      # A scheduled task facility as configured in {MU::Config::BasketofKittens::cdns}
      class CDN < MU::Cloud::CDN

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          cloud_desc ? cloud_desc.arn : nil
        end

        # Return the metadata for this cdn
        # @return [Hash]
        def notify
          MU.structToHash(cloud_desc, stringify_keys: true)
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

        # Remove all cdns associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
        end

        # Locate an existing event.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching CloudWatch Event
        def self.find(**args)
          found = {}

          MU::Cloud::AWS.cloudfront(credentials: args[:credentials]).list_distributions.distribution_list.items.each { |d|
            next if args[:cloud_id] and ![d.id, d.arn].include?(args[:cloud_id])
            found[d.id] = d
          }

          found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(**_args)
          bok = {
            "cloud" => "AWS",
            "credentials" => @config['credentials'],
            "cloud_id" => @cloud_id
          }

          if !cloud_desc
            MU.log "toKitten failed to load a cloud_desc from #{@cloud_id}", MU::ERR, details: @config
            return nil
          end

          resp = MU::Cloud::AWS.cloudfront(credentials: @credentials).list_tags_for_resource(resource: arn)
          if resp and resp.tags and resp.tags.items
            tags = MU.structToHash(resp.tags.items, stringify_keys: true)
            bok['name'] = MU::Adoption.tagsToName(tags)
            bok['tags'] = tags
          end

          if !bok['name'] 
            bok['name'] = if cloud_desc.domain_name !~ /\.cloudfront\.net$/
              cloud_desc.domain_name.sub(/\..*/, '')
            elsif cloud_desc.aliases and !cloud_desc.aliases.items.empty?
              cloud_desc.aliases.items.first.sub(/\..*/, '')
            # XXX maybe try to guess from the name of an origin resource?
            else
              @cloud_id
            end
          end

          MU.log @cloud_id+" cloud_desc", MU::NOTICE, details: cloud_desc
          MU.log @cloud_id+" bok", MU::NOTICE, details: bok

          bok
        end


        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []

          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::cdns}, bare and unvalidated.
        # @param cdn [Hash]: The resource to process and validate
        # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(cdn, _configurator)
          ok = true

          ok
        end

        private

      end
    end
  end
end
