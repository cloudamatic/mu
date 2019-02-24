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
              types: ["REGIONAL"] # XXX expose in BoK ["REGIONAL", "EDGE", "PRIVATE"]
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
            method_arn = "arn:#{MU::Cloud::AWS.isGovCloud?(@config["region"]) ? "aws-us-gov" : "aws"}:execute-api:#{@config["region"]}:#{MU::Cloud::AWS.credToAcct(@config['credentials'])}:#{@cloud_id}/*/#{m['type']}/#{m['path']}"

            resp = MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).get_resources(
              rest_api_id: @cloud_id
            )
            ext_resource = nil
            resp.items.each { |resource|
              if resource.path_part == m['path']
                ext_resource = resource.id
              end
            }

            resp = if ext_resource
MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).get_resource(
  rest_api_id: @cloud_id,
  resource_id: ext_resource,
)
#              MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).update_resource(
#                rest_api_id: @cloud_id,
#                resource_id: ext_resource,
#                patch_operations: [
#                  {
#                    op: "replace",
#                    path: "XXX ??",
#                    value: m["path"]
#                  }
#                ]
#              )
            else
              MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).create_resource(
                rest_api_id: @cloud_id,
                parent_id: root_resource,
                path_part: m['path']
              )
            end

            parent_id = resp.id

            resp = begin
              MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).get_method(
                rest_api_id: @cloud_id,
                resource_id: parent_id,
                http_method: m['type']
              )
            rescue Aws::APIGateway::Errors::NotFoundException
              resp = MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).put_method(
                rest_api_id: @cloud_id,
                resource_id: parent_id,
                authorization_type: m['auth'],
                http_method: m['type']
              )
            end

            # XXX effectively a placeholder default
            begin
              MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).put_method_response(
                rest_api_id: @cloud_id,
                resource_id: parent_id,
                http_method: m['type'],
                status_code: "200"
              )
            rescue Aws::APIGateway::Errors::ConflictException
              # fine to ignore
            end

            if m['integrate_with']
              role_arn = if m['iam_role']
                if m['iam_role'].match(/^arn:/)
                  m['iam_role']
                else
                  sib_role = @deploy.findLitterMate(name: m['iam_role'], type: "roles")
                  sib_role.cloudobj.arn
# XXX make this more like get_role_arn in Function, or just use Role.find?
                end
              end

              function_obj = nil

              uri = if m['integrate_with']['type'] == "aws_generic"
                svc, action = m['integrate_with']['aws_generic_action'].split(/:/)
                "arn:aws:apigateway:"+@config['region']+":#{svc}:action/#{action}"
              elsif m['integrate_with']['type'] == "function"
                function_obj = @deploy.findLitterMate(name: m['integrate_with']['name'], type: "functions").cloudobj
                "arn:aws:apigateway:"+@config['region']+":lambda:path/2015-03-31/functions/"+function_obj.arn+"/invocations"
              end

#                resp = MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).put_integration(
#                  rest_api_id: @cloud_id,
#                  resource_id: parent_id,
#                  type: "AWS",
#                  http_method: m['type'],
#                  integration_http_method: m['type'],
#                  content_handling: "CONVERT_TO_TEXT", # XXX expose in BoK
##acm:ListCertificates
#                  uri: "arn:aws:apigateway:"+@config['region']+":#{svc}:action/#{action}",
#                  credentials: role_arn
#                )
#                MU.log ".put_integration_response(rest_api_id: #{@cloud_id}, resource_id: #{parent_id}, http_method: #{m['type']}, status_code: '200')"
#                MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).put_integration_response(
#                  rest_api_id: @cloud_id,
#                  resource_id: parent_id,
#                  http_method: m['type'],
#                  status_code: "200",
#                  selection_pattern: ""
#                )

              params = {
                :rest_api_id => @cloud_id,
                :resource_id => parent_id,
                :type => "AWS", # XXX Lambda and Firehose can do AWS_PROXY
                :http_method => m['type'],
                :integration_http_method => "POST", # XXX expose in BoK
                :content_handling => "CONVERT_TO_TEXT", # XXX expose in BoK
                :uri => uri
#                  credentials: role_arn
              }
              if m['integrate_with']['passthrough_behavior']
                params[:passthrough_behavior] = m['integrate_with']['passthrough_behavior']
              end
              if m['integrate_with']['request_templates']
                params[:request_templates] = {}
                m['integrate_with']['request_templates'].each { |rt|
                  params[:request_templates][rt['content_type']] = rt['template']
                }
              end

pp params
              resp = MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).put_integration(params)

              if m['integrate_with']['type'] == "function"
                function_obj.addTrigger(method_arn, "apigateway", @config['name'])
              end

              MU::Cloud::AWS.apig(region: @config['region'], credentials: @config['credentials']).put_integration_response(
                rest_api_id: @cloud_id,
                resource_id: parent_id,
                http_method: m['type'],
                status_code: "200",
                selection_pattern: ""
              )

            end

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
                        "description" => "A Mu resource type, for integrations with a sibling resource (e.g. a function), or the string +aws_generic+, which we can use in combination with +aws_generic_action+ to integrate with arbitrary AWS services.",
                        "enum" => ["aws_generic"].concat(MU::Cloud.resource_types.values.map { |t| t[:cfg_name] }.sort)
                      },
                      "aws_generic_action" => {
                        "type" => "string",
                        "description" => "For use when +type+ is set to +aws_generic+, this should specify the action to be performed in the style of an IAM policy action, e.g. +acm:ListCertificates+ for this integration to return a list of Certificate Manager SSL certificates." 
                      },
                      "deploy_id" => {
                        "type" => "string",
                        "description" => "A Mu deploy id (e.g. DEMO-DEV-2014111400-NG), for integrations with a sibling resource (e.g. a Function)"
                      },
                      "iam_role" => {
                        "type" => "string",
                        "description" => "The name of an IAM role used to grant usage of other AWS artifacts for this integration. If not specified, we will automatically generate an appropriate role."
                      },
                      "passthrough_behavior" => {
                        "type" => "string",
                        "description" => "Specifies the pass-through behavior for incoming requests based on the +Content-Type+ header in the request, and the available mapping templates specified in +request_templates+. +WHEN_NO_MATCH+ passes the request body for unmapped content types through to the integration back end without transformation. +WHEN_NO_TEMPLATES+ allows pass-through when the integration has NO content types mapped to templates. +NEVER+ rejects unmapped content types with an HTTP +415+.",
                        "enum" => ["WHEN_NO_MATCH", "WHEN_NO_TEMPLATES", "NEVER"],
                        "default" => "WHEN_NO_MATCH"
                      },
                      "request_templates" => {
                        "type" => "array",
                        "description" => "A JSON-encoded string which represents a map of Velocity templates that are applied on the request payload based on the value of the +Content-Type+ header sent by the client. The content type value is the key in this map, and the template (as a String) is the value.",
                        "items" => {
                          "type" => "object",
                          "description" => "A JSON-encoded string which represents a map of Velocity templates that are applied on the request payload based on the value of the +Content-Type+ header sent by the client. The content type value is the key in this map, and the template (as a String) is the value.",
                          "require" => ["content_type", "template"],
                          "properties" => {
                            "content_type" => {
                              "type" => "string",
                              "description" => "An HTTP content type to match with a template, such as +application/json+."
                            },
                            "template" => {
                              "type" => "string",
                              "description" => "A Velocity template to apply to our reques payload, encoded as a one-line string, like: "+'<tt>"#set($allParams = $input.params())\\n{\\n\\"url_data_json_encoded\\":\\"$input.params(\'url\')\\"\\n}"</tt>'
                            }
                          }
                        }
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

          endpoint['methods'].each { |m|
            if m['integrate_with'] and m['integrate_with']['name']
              if m['integrate_with']['type'] != "aws_generic"
                endpoint['dependencies'] ||= []
                endpoint['dependencies'] << {
                  "type" => m['integrate_with']['type'],
                  "name" => m['integrate_with']['name']
                }
              end

              if !m['iam_role']
                m['uri'] ||= "*" if m['integrate_with']['type'] == "aws_generic"

                roledesc = {
                  "name" => endpoint['name']+"-"+m['integrate_with']['name'],
                  "credentials" => endpoint['credentials'],
                  "can_assume" => [
                    {
                      "entity_id" => "apigateway.amazonaws.com",
                      "entity_type" => "service"
                    }
                  ],
                }
                if m['integrate_with']['type'] == "aws_generic"
                  roledesc["policies"] = [
                    {
                      "name" => m['integrate_with']['aws_generic_action'].gsub(/[^a-z]/i, ""),
                      "permissions" => [m['integrate_with']['aws_generic_action']],
                      "targets" => [{ "identifier" => m['uri'] }]
                    }
                  ]
                elsif m['integrate_with']['type'] == "function"
                  roledesc["import"] = ["AWSLambdaBasicExecutionRole"]
                end
                configurator.insertKitten(roledesc, "roles")

                endpoint['dependencies'] ||= []
                m['iam_role'] = endpoint['name']+"-"+m['integrate_with']['name']

                endpoint['dependencies'] << {
                  "type" => "role",
                  "name" => endpoint['name']+"-"+m['integrate_with']['name']
                }
              end
            end
          }
#          if something_bad
#            ok = false
#          end

          ok
        end

      end
    end
  end
end
