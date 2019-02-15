module MU
  class Cloud
    class AWS
      # An API as configured in {MU::Config::BasketofKittens::endpoints}
      class Endpoint < MU::Cloud::Endpoint
        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        @cloudformation_data = {}
        attr_reader :cloudformation_data

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::endpoints}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          resp = MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).create_rest_api(
            name: @mu_name,
            description: @deploy.deploy_id,
            endpoint_configuration: {
              types: ["PRIVATE"]
            }
          )
          @cloud_id = resp.id
          generate_methods


        end

        # Create/update all of the methods declared for this endpoint
        def generate_methods
          resp = MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).get_resources(
            rest_api_id: @cloud_id,
          )
          root_resource = resp.items.first.id

          # TODO guard this crap so we don't touch it if there are no changes
          @config['methods'].each { |m|
            resp = MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).get_resources(
              rest_api_id: @cloud_id
            )
            ext_resource = nil
            resp.items.each { |resource|
              if resource.path_part == m['path']
                ext_resource = resource.id
              end
            }

            if ext_resource
              MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).delete_resource(
                rest_api_id: @cloud_id,
                resource_id: ext_resource
              )
            end

            resp = MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).create_resource(
              rest_api_id: @cloud_id,
              parent_id: root_resource,
              path_part: m['path']
            )

            parent_id = resp.id
            resp = MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).put_method(
              rest_api_id: @cloud_id,
              resource_id: parent_id,
              authorization_type: m['auth'],
              http_method: m['type']
            )
            
            pp m

# "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:616552976502:function:m3api/invocations",

#            resp = MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).put_integration(
#              rest_api_id: @cloud_id,
#              resource_id: parent_id,
#              type: "AWS",
#              http_method: m['type'],
#              integration_http_method: m['type'],
#              uri: ""
#            )
          }
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          generate_methods

#          resp = MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).create_deployment(
#            rest_api_id: @cloud_id,
#            stage_name: @deploy.environment,
##            cache_cluster_enabled: false,
##            cache_cluster_size: 0.5,
#          )
#          deployment_id = resp.id
#
#          resp = MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).create_stage(
#            rest_api_id: @cloud_id,
#            stage_name: @deploy.environment,
#            deployment_id: deployment_id,
##            cache_cluster_enabled: false,
##            cache_cluster_size: 0.5,
#          )

# deployment => stage
#          resp = MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).create_authorizer(
#            rest_api_id: @cloud_id,
#          )

#          resp = MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).create_vpc_link(
#          )
 
        end

        # @return [Struct]
        def cloud_desc
          MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).get_rest_api(
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
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          resp = MU::Cloud::AWS.apig(region: region, credentials: credentials).get_rest_apis
          if resp and resp.items
            resp.items.each { |api|
              # The stupid things don't have tags
              if api.description == MU.deploy_id
                MU.log "Deleting API Gateway #{api.name} (#{api.id})"
                if !noop
                  MU::Cloud::AWS.apig(region: region, credentials: credentials).delete_rest_api(
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
        def self.find(cloud_id: nil, region: MU.curRegion, credentials: nil, flags: {})
          if cloud_id
            return MU::Cloud::AWS.apig(region: region, credentials: credentials).get_rest_api(
              rest_api_id: cloud_id
            )
          end
#          resp = MU::Cloud::AWS.apig(region: region, credentials: credentials).get_rest_apis
#          if resp and resp.items
#            resp.items.each { |api|
#            }
#          end
          nil
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "methods" => {
              "items" => {
                "required" => ["integrate_with"],
                "properties" => {
                  "integrate_with" => {
                    "type" => "object",
                    "description" => "Specify what application backend to invoke under this path/method combination",
                    "properties" => {
                      "proxy" => {
                        "type" => "boolean",
                        "default" => false,
                        "description" => "For HTTP or AWS integrations, specify whether the target is a proxy (((docs unclear, is that actually what this means?)))" # XXX is that actually what this means?
                      },
                      "url" => {
                        "type" => "string",
                        "description" => "For HTTP or HTTP_PROXY integrations, this should be a fully-qualified URL"
                      },
                      "arn" => {
                        "type" => "string",
                        "description" => "For AWS or AWS_PROXY integrations with a compatible Amazon resource outside of Mu, a full-qualified ARN such as `arn:aws:apigateway:us-west-2:s3:action/GetObject&Bucket=`bucket&Key=key`"
                      },
                      "name" => {
                        "type" => "string",
                        "description" => "A Mu resource name, for integrations with a sibling resource (e.g. a Function)"
                      },
                      "type" => {
                        "type" => "string",
                        "description" => "A Mu resource type, for integrations with a sibling resource (e.g. a Function)",
                        "enum" => MU::Cloud.resource_types.values.map { |t| t[:cfg_name] }.sort
                      },
                      "deploy_id" => {
                        "type" => "string",
                        "description" => "A Mu deploy id (e.g. DEMO-DEV-2014111400-NG), for integrations with a sibling resource (e.g. a Function)"
                      }
                    }
                  },
                  "auth" => {
                    "type" => "string",
                    "enum" => ["NONE", "CUSTOM", "AWS_IAM", "COGNITO_USER_POOLS"],
                    "default" => "NONE"
                  }
                }
              }
            }
          }
          [toplevel_required, schema]
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          false
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          nil
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::endpoints}, bare and unvalidated.
        # @param endpoint [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(endpoint, configurator)
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
