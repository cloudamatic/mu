module MU
  class Cloud
    class AWS
      # An API as configured in {MU::Config::BasketofKittens::apis}
      class Api < MU::Cloud::Api
        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        @cloudformation_data = {}
        attr_reader :cloudformation_data

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::apis}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          resp = MU::Cloud::AWS.apig(@config['region']).create_rest_api(
            name: @mu_name,
            description: @deploy.deploy_id
          )
          @cloud_id = resp.id
        end

        # @return [Struct]
        def cloud_desc
          MU::Cloud::AWS.apig(@config['region']).get_rest_api(
            rest_api_id: @cloud_id
          )
        end

        # Return the metadata for this API
        # @return [Hash]
        def notify
          deploy_struct = MU.structToHash(cloud_desc)
# XXX stages and whatnot
          return deploy_struct
        end

        # Remove all APIs associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          resp = MU::Cloud::AWS.apig(region).get_rest_apis
          if resp and resp.items
            resp.items.each { |api|
              # The stupid things don't have tags
              if api.description == MU.deploy_id
                MU.log "Deleting API Gateway #{api.name} (#{api.id})"
                if !noop
                  MU::Cloud::AWS.apig(region).delete_rest_api(
                    rest_api_id: api.id
                  )
                end
              end
            }
          end
        end

        # Locate an existing API.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @param flags [Hash]: Optional flags
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching API.
        def self.find(cloud_id: nil, region: MU.curRegion, flags: {})
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {}
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::apis}, bare and unvalidated.
        # @param api [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(api, configurator)
          ok = true
#          if something_bad
#            ok = false
#          end

          ok
        end

      end
    end
  end
end
