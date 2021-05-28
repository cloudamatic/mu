module MU
  class Cloud
    class AWS
      # An API as configured in {MU::Config::BasketofKittens::endpoints}
      class Endpoint < MU::Cloud::Endpoint

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          desc = {
            name: @mu_name,
            description: @deploy.deploy_id,
            endpoint_configuration: {
              types: [@config['endpoint_type']]
            },
            tags: @tags
          }

# XXX NLB? what the fork?
#          if @vpc
#            MU::Cloud::AWS.apig(region: @region, credentials: @credentials).create_vpc_link(
#              name: @mu_name,
#              target_arns: [Required] The ARN of the network load balancer of the VPC targeted by the VPC link. The network load balancer must be owned by the same AWS account of the API owner.
#              tags: @tags
#            )  
#          end

# XXX this is incomplete; need to cover non-VPC case, IP ranges, and fall back on account number if all else fails
          if @config['endpoint_type'] == "PRIVATE"
            desc[:policy] = JSON.generate(
              {
                "Version" => "2012-10-17",
                "Statement" => [
                  {
                    "Effect" => "Deny",
                    "Principal" => "*",
                    "Action" => "execute-api:Invoke",
                    "Resource" => "arn:aws:execute-api:#{@region}:#{MU::Cloud::AWS.credToAcct(@credentials)}:*/*/*/*",
                    "Condition" => {
                      "StringNotEquals" => {
                        "aws =>sourceVpc": @vpc.cloud_id
                      }
                    }
                  },
                  {
                    "Effect" => "Allow",
                    "Principal" => "*",
                    "Action" => "execute-api:Invoke",
                    "Resource" => "arn:aws:execute-api:#{@region}:#{MU::Cloud::AWS.credToAcct(@credentials)}:*/*/*/*"
                  }
                ]
              }
            )
          end

          resp = MU::Cloud::AWS.apig(region: @region, credentials: @credentials).create_rest_api(desc)

          @cloud_id = resp.id
          generate_methods(false)
        end

        # Create/update all of the methods declared for this endpoint
        def generate_methods(integrations = true)
          resp = MU::Cloud::AWS.apig(region: @region, credentials: @credentials).get_resources(
            rest_api_id: @cloud_id,
          )
          root_resource = resp.items.first.id

          # TODO guard this crap so we don't touch it if there are no changes
          @config['methods'].each { |m|
            m["auth"] ||= m["iam_role"] ? "AWS_IAM" : "NONE"

            method_arn = "arn:#{MU::Cloud::AWS.isGovCloud?(@region) ? "aws-us-gov" : "aws"}:execute-api:#{@region}:#{MU::Cloud::AWS.credToAcct(@credentials)}:#{@cloud_id}/*/#{m['type']}/#{m['path']}"
            path_part = ["", "/"].include?(m['path']) ? nil : m['path']
            method_arn.sub!(/\/\/$/, '/')

            resp = MU::Cloud::AWS.apig(region: @region, credentials: @credentials).get_resources(
              rest_api_id: @cloud_id
            )
            ext_resource = nil
            resp.items.each { |resource|
              if resource.path_part == path_part
                ext_resource = resource.id
              end
            }

            resp = if ext_resource
MU::Cloud::AWS.apig(region: @region, credentials: @credentials).get_resource(
  rest_api_id: @cloud_id,
  resource_id: ext_resource,
)
#              MU::Cloud::AWS.apig(region: @region, credentials: @credentials).update_resource(
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
              MU::Cloud::AWS.apig(region: @region, credentials: @credentials).create_resource(
                rest_api_id: @cloud_id,
                parent_id: root_resource,
                path_part: path_part
              )
            end
            parent_id = resp.id

            resp = begin
              MU::Cloud::AWS.apig(region: @region, credentials: @credentials).get_method(
                rest_api_id: @cloud_id,
                resource_id: parent_id,
                http_method: m['type']
              )
            rescue Aws::APIGateway::Errors::NotFoundException
              resp = MU::Cloud::AWS.apig(region: @region, credentials: @credentials).put_method(
                rest_api_id: @cloud_id,
                resource_id: parent_id,
                authorization_type: m['auth'],
                http_method: m['type']
              )
            end

            # XXX effectively a placeholder default
            begin
              m['responses'].each { |r|
                params = {
                  :rest_api_id => @cloud_id,
                  :resource_id => parent_id,
                  :http_method => m['type'],
                  :status_code => r['code'].to_s
                }
                if r['headers']
                  params[:response_parameters] = r['headers'].map { |h|
                    h['required'] ||= false
                    ["method.response.header."+h['header'], h['required']]
                  }.to_h
                end

                if r['body']
# XXX I'm guessing we can also have arbirary user-defined models somehow, so is_error is probably inadequate to the demand of the times
                  params[:response_models] = r['body'].map { |b| [b['content_type'], b['is_error'] ? "Error" : "Empty"] }.to_h
                end

                MU::Cloud::AWS.apig(region: @region, credentials: @credentials).put_method_response(params)
              }
            rescue Aws::APIGateway::Errors::ConflictException
              # fine to ignore
            end

            if integrations and m['integrate_with']
#              role_arn = if m['iam_role']
#                if m['iam_role'].match(/^arn:/)
#                  m['iam_role']
#                else
#                  sib_role = @deploy.findLitterMate(name: m['iam_role'], type: "roles")
#                  sib_role.cloudobj.arn
# XXX make this more like get_role_arn in Function, or just use Role.find?
#                end
#              end

              function_obj = nil
              aws_int_type = m['integrate_with']['proxy'] ? "AWS_PROXY" : "AWS"

              uri, type = if m['integrate_with']['type'] == "aws_generic"
                svc, action = m['integrate_with']['aws_generic_action'].split(/:/)
                ["arn:aws:apigateway:"+@region+":#{svc}:action/#{action}", aws_int_type]
              elsif m['integrate_with']['type'] == "functions"
                function_obj = nil
                MU.retrier([], max: 5, wait: 9, loop_if: Proc.new { function_obj.nil? }) {
                  function_obj = @deploy.findLitterMate(name: m['integrate_with']['name'], type: "functions")
                }
                ["arn:aws:apigateway:"+@region+":lambda:path/2015-03-31/functions/"+function_obj.cloudobj.arn+"/invocations", aws_int_type]
              elsif m['integrate_with']['type'] == "mock"
                [nil, "MOCK"]
              end

              params = {
                :rest_api_id => @cloud_id,
                :resource_id => parent_id,
                :type => type, # XXX Lambda and Firehose can do AWS_PROXY
                :content_handling => "CONVERT_TO_TEXT", # XXX expose in BoK
                :http_method => m['type'],
                :timeout_in_millis => m['timeout_in_millis']
#                  credentials: role_arn
              }
              params[:uri] = uri if uri

              if m['integrate_with']['type'] != "mock"
                params[:integration_http_method] = m['integrate_with']['backend_http_method']
              else
                params[:integration_http_method] = nil
              end

              if m['integrate_with']['passthrough_behavior']
                params[:passthrough_behavior] = m['integrate_with']['passthrough_behavior']
              end
              if m['integrate_with']['request_templates']
                params[:request_templates] = {}
                m['integrate_with']['request_templates'].each { |rt|
                  params[:request_templates][rt['content_type']] = rt['template']
                }
              end
              if m['integrate_with']['parameters']
                params[:request_parameters] = Hash[m['integrate_with']['parameters'].map { |p|
                  ["integration.request.#{p['type']}.#{p['name']}", p['value']]
                }]
              end

              resp = MU::Cloud::AWS.apig(region: @region, credentials: @credentials).put_integration(params)

              if m['integrate_with']['type'] =~ /^functions?$/
                function_obj.addTrigger(method_arn, "apigateway", @config['name'])
              end

              m['responses'].each { |r|
                params = {
                  :rest_api_id => @cloud_id,
                  :resource_id => parent_id,
                  :http_method => m['type'],
                  :status_code => r['code'].to_s,
                  :selection_pattern => ".*"
                }
                if r['headers']
                  params[:response_parameters] = r['headers'].map { |h|
                    ["method.response.header."+h['header'], "'"+h['value']+"'"]
                  }.to_h
                end

                MU::Cloud::AWS.apig(region: @region, credentials: @credentials).put_integration_response(params)

              }

            end

          }
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          generate_methods

          deployment = MU::Cloud::AWS.apig(region: @region, credentials: @credentials).get_deployments(
            rest_api_id: @cloud_id
          ).items.sort { |a, b| a.created_date <=> b.created_date }.last

          if !deployment
            MU.log "Deploying API Gateway #{@config['name']} to #{@config['deploy_to']}"
            deployment = MU::Cloud::AWS.apig(region: @region, credentials: @credentials).create_deployment(
              rest_api_id: @cloud_id,
              stage_name: @config['deploy_to']
#            cache_cluster_enabled: false,
#            cache_cluster_size: 0.5,
            )
          end
          # this automatically creates a stage with the same name, so we don't
          # have to deal with that

          my_hostname = @cloud_id+".execute-api."+@region+".amazonaws.com"
          my_url = "https://"+my_hostname+"/"+@config['deploy_to']
          MU.log "API Endpoint #{@config['name']}: "+my_url, MU::SUMMARY

          print_dns_alias = Proc.new { |rec|
            rec['name'] ||= @mu_name.downcase
            dnsname = MU::Cloud.resourceClass("AWS", "DNSZone").recordToName(rec)
            dnsname
          }

          # if we have any placeholder DNS records that are intended to be
          # filled out with our runtime @mu_name, do so, and add an alias if
          # applicable
          if @config['dns_records'] and !MU::Cloud::AWS.isGovCloud?
            @config['dns_records'].each { |rec|
              dnsname = print_dns_alias.call(rec)
              MU.log "Alias for API Endpoint #{@config['name']}: https://"+dnsname+"/"+@config['deploy_to'], MU::SUMMARY
            }
            MU::Cloud.resourceClass("AWS", "DNSZone").createRecordsFromConfig(@config['dns_records'], target: my_hostname)
          end

          if @config['domain_names']
            @config['domain_names'].each { |dom|
              dnsname = if dom['dns_record']
                print_dns_alias.call(dom['dns_record'])
              else
                dom['unmanaged_name']
              end
              MU.log "Alias for API Endpoint #{@config['name']}: https://"+dnsname, MU::SUMMARY

              certfield, dnsfield = if dom['endpoint_type'] == "EDGE"
                [:certificate_arn, :distribution_domain_name]
              else
                [:regional_certificate_arn, :regional_domain_name]
              end

              dom_desc = begin
                MU::Cloud::AWS.apig(region: @region, credentials: @credentials).get_domain_name(domain_name: dnsname)
              rescue ::Aws::APIGateway::Errors::NotFoundException

                params = {
                  domain_name: dnsname,
                  endpoint_configuration: {
                    types: [dom['endpoint_type']]
                  },
                  security_policy: dom['security_policy'],
                  tags: @tags
                }
                if dom['certificate']
                  params[certfield] = dom['certificate']['id']
                end

                MU.log "Creating API Gateway Domain Name #{dnsname}", MU::NOTICE, details: params
                MU::Cloud::AWS.apig(region: @region, credentials: @credentials).create_domain_name(params)
              end

              mappings = MU::Cloud::AWS.apig(region: @region, credentials: @credentials).get_base_path_mappings(domain_name: dnsname, limit: 500).items
              found = false
              if mappings
                mappings.each { |m|
                  if m.rest_api_id == @cloud_id and m.stage == @config['deploy_to']
                    found = true
                    break
                  end
                }
              end
              if !found
                MU.log "Mapping #{dnsname} to API Gateway #{@mu_name}"
                MU::Cloud::AWS.apig(region: @region, credentials: @credentials).create_base_path_mapping(
                  domain_name: dnsname,
                  rest_api_id: @cloud_id,
                  stage: @config['deploy_to']
                )
              end

              if dom['dns_record']
                MU::Cloud.resourceClass("AWS", "DNSZone").createRecordsFromConfig([dom['dns_record']], target: dom_desc.send(dnsfield))
              end
            }
          end

          # The creation of our deployment should have created a matching stage,
          # which we're now going to mess with.
          stage = MU::Cloud::AWS.apig(region: @region, credentials: @credentials).get_stage(
            rest_api_id: @cloud_id,
            stage_name: @config['deploy_to']
          )

          if @config['access_logs'] and !stage.access_log_settings
            log_ref = MU::Config::Ref.get(@config['access_logs'])
            MU.log "Enabling API Gateway access logs to CloudWatch Log Group #{log_ref.cloud_id}"
            stage = MU::Cloud::AWS.apig(region: @region, credentials: @credentials).update_stage(
              rest_api_id: @cloud_id,
              stage_name: @config['deploy_to'],
              patch_operations: [
                {
                  op: "replace",
                  path: "/accessLogSettings/destinationArn",
                  value: log_ref.kitten.arn.sub(/:\*$/, '')
                },
                {
                  op: "replace",
                  path: "/accessLogSettings/format",
                  value: '$context.identity.sourceIp $context.identity.caller $context.identity.user [$context.requestTime] "$context.httpMethod $context.resourcePath $context.protocol" $context.status $context.responseLength $context.requestId'
                },
                {
                  op: "replace",
                  path: "/description",
                  value: @deploy.deploy_id
                },
                {
                  op: "replace",
                  path: "/*/*/logging/dataTrace",
                  value: "true"
                },
                {
                  op: "replace",
                  path: "/*/*/logging/loglevel",
                  value: "INFO"
                }
              ]
            )
          end


#          resp = MU::Cloud::AWS.apig(region: @region, credentials: @credentials).create_authorizer(
#            rest_api_id: @cloud_id,
#          )

#          resp = MU::Cloud::AWS.apig(region: @region, credentials: @credentials).create_vpc_link(
#          )
 
        end

        @cloud_desc_cache = nil
        # @return [Struct]
        def cloud_desc(use_cache: true)
          return @cloud_desc_cache if @cloud_desc_cache and use_cache
          return nil if !@cloud_id
          @cloud_desc_cache = MU::Cloud::AWS.apig(region: @region, credentials: @credentials).get_rest_api(
            rest_api_id: @cloud_id
          )
          @cloud_desc_cache
        end

        # Return the metadata for this API
        # @return [Hash]
        def notify
          return nil if !@cloud_id or !cloud_desc(use_cache: false)
          deploy_struct = MU.structToHash(cloud_desc, stringify_keys: true)
          deploy_struct['url'] = "https://"+@cloud_id+".execute-api."+@region+".amazonaws.com"
          deploy_struct['url'] += "/"+@config['deploy_to'] if @config['deploy_to']
# XXX stages and whatnot
          return deploy_struct
        end

        # Remove all APIs associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          MU.log "AWS::Endpoint.cleanup: need to support flags['known']", MU::DEBUG, details: flags
          MU.log "Placeholder: AWS Endpoint artifacts do not support tags, so ignoremaster cleanup flag has no effect", MU::DEBUG, details: ignoremaster

          resp = MU::Cloud::AWS.apig(region: region, credentials: credentials).get_domain_names(limit: 500)
          if resp and resp.items
            resp.items.each { |d|
              next if !d.tags
              if d.tags["MU-ID"] == deploy_id and 
                 (ignoremaster or d.tags["MU-MASTER-IP"] == MU.mu_public_ip)
                mappings = MU::Cloud::AWS.apig(region: region, credentials: credentials).get_base_path_mappings(domain_name: d.domain_name, limit: 500).items
                mappings.each { |m|
                  MU.log "Deleting API Gateway Domain Name mapping #{d.domain_name} => #{m.rest_api_id} path #{m.base_path}"
                  if !noop
                    MU::Cloud::AWS.apig(region: region, credentials: credentials).delete_base_path_mapping(domain_name: d.domain_name, base_path: m.base_path)
                  end
                }
                MU.log "Deleting API Gateway Domain Name #{d.domain_name}"
                if !noop
                  MU::Cloud::AWS.apig(region: region, credentials: credentials).delete_domain_name(domain_name: d.domain_name)
                end
              end
            }
          end

          resp = MU::Cloud::AWS.apig(region: region, credentials: credentials).get_rest_apis
          if resp and resp.items
            resp.items.each { |api|
              # The stupid things don't have tags
              if api.description == deploy_id
                logs = MU::Cloud.resourceClass("AWS", "Log").find(region: region, credentials: credentials)
                logs.each_pair { |log_id, log_desc|
                  if log_id =~ /^API-Gateway-Execution-Logs_#{api.id}\//
                    MU.log "Deleting CloudWatch Log Group #{log_id}"
                    if !noop
                      MU::Cloud::AWS.cloudwatchlogs(region: region, credentials: credentials).delete_log_group(log_group_name: log_id)
                    end
                  end
                }
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
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching APIs.
        def self.find(**args)
          found = {}

          if args[:cloud_id]
            found[args[:cloud_id]] = MU::Cloud::AWS.apig(region: args[:region], credentials: args[:credentials]).get_rest_api(
              rest_api_id: args[:cloud_id]
            )
          else
            resp = MU::Cloud::AWS.apig(region: args[:region], credentials: args[:credentials]).get_rest_apis
            if resp and resp.items
              resp.items.each { |api|
                found[api.id] = api
              }
            end
          end

          found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(**_args)
          bok = {
            "cloud" => "AWS",
            "credentials" => @credentials,
            "cloud_id" => @cloud_id,
            "region" => @region
          }

          if !cloud_desc
            MU.log "toKitten failed to load a cloud_desc from #{@cloud_id}", MU::ERR, details: @config
            return nil
          end

          bok['name'] = cloud_desc.name

          resources = MU::Cloud::AWS.apig(region: @region, credentials: @credentials).get_resources(
            rest_api_id: @cloud_id,
          ).items

          resources.each { |r|
            next if !r.respond_to?(:resource_methods) or r.resource_methods.nil?
            r.resource_methods.each_pair { |http_type, m|
              bok['methods'] ||= []
              method = {}
              m_desc = MU::Cloud::AWS.apig(region: @region, credentials: @credentials).get_method(
                rest_api_id: @cloud_id,
                resource_id: r.id,
                http_method: http_type 
              )

              method['type'] = http_type
              method['path'] = r.path_part || r.path
              if m_desc.method_responses
                m_desc.method_responses.each_pair { |code, resp_desc|
                  method['responses'] ||= []
                  resp = { "code" => code.to_i }
                  if resp_desc.response_parameters
                    resp_desc.response_parameters.each_pair { |hdr, reqd|
                      resp['headers'] ||= []
                      if hdr.match(/^method\.response\.header\.(.*)/)
                        resp['headers'] << {
                          "header" => Regexp.last_match[1],
                          "required" => reqd
                        }
                      else
                        MU.log "I don't know what to do with APIG response parameter #{hdr}", MU::ERR, details: resp_desc
                      end

                    }
                  end
                  if resp_desc.response_models
                    resp_desc.response_models.each_pair { |content_type, body|
                      resp['body'] ||= []
                      resp['body'] << {
                        "content_type" => content_type,
                        "is_error" => (body == "Error")
                      }
                    }

                  end
                  method['responses'] << resp

                }
              end

              if m_desc.method_integration
                if ["AWS", "AWS_PROXY"].include?(m_desc.method_integration.type)
                  if m_desc.method_integration.uri.match(/:lambda:path\/\d{4}-\d{2}-\d{2}\/functions\/arn:.*?:function:(.*?)\/invocations$/)
                    method['integrate_with'] = MU::Config::Ref.get(
                      id: Regexp.last_match[1],
                      type: "functions",
                      cloud: "AWS",
                      integration_http_method: m_desc.method_integration.http_method
                    )
                  elsif m_desc.method_integration.uri.match(/#{@region}:([^:]+):action\/(.*)/)
                    method['integrate_with'] = {
                      "type" => "aws_generic",
                      "integration_http_method" => m_desc.method_integration.http_method,
                      "aws_generic_action" => Regexp.last_match[1]+":"+Regexp.last_match[2]
                    }
                  else
                    MU.log "I don't know what to do with #{m_desc.method_integration.uri}", MU::ERR
                  end
                  if m_desc.method_integration.http_method
                    method['integrate_with']['backend_http_method'] = m_desc.method_integration.http_method
                  end
                  method['proxy'] = true if m_desc.method_integration.type == "AWS_PROXY"
                elsif m_desc.method_integration.type == "MOCK"
                  method['integrate_with'] = {
                    "type" => "mock"
                  }
                else
                  MU.log "I don't know what to do with this integration", MU::ERR, details: m_desc.method_integration
                  next
                end

                if m_desc.method_integration.passthrough_behavior
                  method['integrate_with']['passthrough_behavior'] = m_desc.method_integration.passthrough_behavior
                end

                if m_desc.method_integration.request_templates and
                   !m_desc.method_integration.request_templates.empty?
                   method['integrate_with']['request_templates'] = m_desc.method_integration.request_templates.keys.map { |rt_content_type, template|
                    { "content_type" => rt_content_type, "template" => template }
                   }
                end

                if m_desc.method_integration.request_parameters
                  m_desc.method_integration.request_parameters.each_pair { |k, v|
                    if !k.match(/^integration\.request\.(header|querystring|path)\.(.*)/)
                      MU.log "Don't know how to handle integration request parameter '#{k}', skipping", MU::WARN
                      next
                    end
                    if Regexp.last_match[1] == "header" and
                       Regexp.last_match[2] == "X-Amz-Invocation-Type" and
                       v == "'Event'"
                      method['integrate_with']['async'] = true
                    else
                      method['integrate_with']['parameters'] ||= []
                      method['integrate_with']['parameters'] << {
                        "type" => Regexp.last_match[1],
                        "name" => Regexp.last_match[2],
                        "value" => v
                      }
                    end
                  }
                end
              end

              bok['methods'] << method
            }
          }

          deployment = MU::Cloud::AWS.apig(region: @region, credentials: @credentials).get_deployments(
            rest_api_id: @cloud_id
          ).items.sort { |a, b| a.created_date <=> b.created_date }.last
          stages = MU::Cloud::AWS.apig(region: @region, credentials: @credentials).get_stages(
            rest_api_id: @cloud_id,
            deployment_id: deployment.id
          )

          # XXX we only support a single stage right now, which is a dumb
          # limitation
          stage = stages.item.first
          if stage
            bok['deploy_to'] = stage.stage_name
            if stage.access_log_settings
              bok['log_requests'] = true
              bok['access_logs'] = MU::Config::Ref.get(
                id: stage.access_log_settings.destination_arn.sub(/.*?:([^:]+)$/, '\1'),
                credentials: @credentials,
                region: @region,
                type: "logs",
                cloud: "AWS"
              )
            end
          end


          bok
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {
            "endpoint_type" => {
              "default" => "REGIONAL",
              "type" => "string",
              "enum" => ["REGIONAL", "EDGE", "PRIVATE"]
            },
            "domain_names" => {
              "type" => "array",
              "items" => {
                "description" => "Configure optional Custom Domain Names to map to this API endpoint.",
                "type" => "object",
                "properties" => {
                  "certificate" => MU::Config::Ref.schema(type: "certificate", desc: "An existing IAM or ACM SSL certificate to bind to this alternate name endpoint.", omit_fields: ["cloud", "tag", "deploy_id"]),
                  "dns_record" => MU::Config::DNSZone.records_primitive(need_target: false, default_type: "CNAME", need_zone: true, embedded_type: "endpoint")["items"],
                  "unmanaged_name" => {
                    "type" => "string",
                    "description" => "If +dns_record+ is not specified, we will map this string as a domain name and assume that an external DNS record will be created pointing to us at a later time."
                  },
                  "endpoint_type" => {
                    "type" => "string",
                    "description" => "The type of endpoint to create with this domain name.",
                    "default" => "REGIONAL",
                    "enum" => ["REGIONAL", "EDGE", "PRIVATE"]
                  },
                  "security_policy" => {
                    "type" => "string",
                    "default" => "TLS_1_2",
                    "enum" => ["TLS_1_0", "TLS_1_2"],
                    "description" => "Acceptable TLS cipher suites. +TLS_1_2+ is strongly recommended."
                  }
                }
              }
            },
            "deploy_to" => {
              "type" => "string",
              "description" => "The name of an environment under which to deploy our API. If not specified, will deploy to the name of the global Mu environment for this deployment."
            },
            "log_requests" => {
              "type" => "boolean",
              "description" => "Log custom access requests to CloudWatch Logs to the log group specified by +access_logs+, as well as enabling built-in CloudWatch Logs at +INFO+ level. If +access_logs+ is unspecified, a reasonable group will be created automatically.",
              "default" => true
            },
            "access_logs" => MU::Config::Ref.schema(type: "logs", desc: "A pre-existing or sibling Mu Cloudwatch Log group reference. If +log_requests+ is specified and this is not, a log group will be generated automatically. Setting this parameter explicitly automatically enables +log_requests+."),
            "methods" => {
              "items" => {
                "type" => "object",
                "description" => "Other cloud resources to integrate as a back end to this API Gateway",
                "required" => ["integrate_with"],
                "properties" => {
                  "integrate_with" => {
                    "type" => "object",
                    "description" => "Specify what application backend to invoke under this path/method combination",
                    "properties" => {
                      "async" => {
                        "type" => "boolean",
                        "default" => false,
                        "description" => "For non-proxy Lambda integrations, adds a static +X-Amz-Invocation-Type+ with value +'Event'+ to invoke the function asynchronously. See also https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-integration-async.html"
                      },
                      "parameters" => {
                        "type" => "array",
                        "items" => {
                          "description" => "One or headers, paths, or query string parameters to pass as request parameters to our back end. See also: https://docs.aws.amazon.com/apigateway/latest/developerguide/request-response-data-mappings.html",
                          "type" => "object",
                          "properties" => {
                            "name" => {
                              "type" => "string",
                              "description" => "A valid and unique integration request parameter name."
                            },
                            "value" => {
                              "type" => "string",
                              "description" => "The name of a method request parameter, or a static value contained in single quotes (+'foo'+)."
                            },
                            "type" => {
                              "type" => "string",
                              "description" => "Which HTTP artifact to use when presenting the parameter to the back end. ",
                              "enum" => ["header", "querystring", "path"]
                            }
                          }
                        }
                      },
                      "proxy" => {
                        "type" => "boolean",
                        "default" => false,
                        "description" => "Sets HTTP integrations to HTTP_PROXY and AWS/LAMBDA integrations to AWS_PROXY/LAMBDA_PROXY"
                      },
                      "backend_http_method" => {
                        "type" => "string",
                        "description" => "The HTTP method to use when contacting our integrated backend. If not specified, this will be set to match our front end.",
                        "enum" => ["GET", "POST", "PUT", "HEAD", "DELETE", "CONNECT", "OPTIONS", "TRACE"],
                      },
                      "timeout_in_millis" => {
                        "type" => "integer",
                        "description" => "Custom timeout between +50+ and +29,000+ milliseconds.",
                        "default" => 29000
                      },
                      "url" => {
                        "type" => "string",
                        "description" => "For HTTP or HTTP_PROXY integrations, this should be a fully-qualified URL"
                      },
                      "responses"=> {
                        "type" => "array",
                        "items" => {
                          "type" => "object",
                          "description" => "Customize the response to the client for this method, by adding headers or transforming through a template. If not specified, we will default to returning an un-transformed HTTP 200 for this method.",
                          "properties" => {
                            "code" => {
                              "type" => "integer",
                              "description" => "The HTTP status code to return",
                              "default" => 200
                            },
                            "headers" => {
                              "type" => "array",
                              "items" => {
                                "description" => "One or more headers, used by the API Gateway integration response and filtered through the method response before returning to the client",
                                "type" => "object",
                                "properties" => {
                                  "header" => {
                                    "type" => "string",
                                    "description" => "The name of a header to return, such as +Access-Control-Allow-Methods+"
                                  },
                                  "value" => {
                                    "type" => "string",
                                    "description" => "The string to map to this header (ex +GET,OPTIONS+)"
                                  },
                                  "required" => {
                                    "type" => "boolean",
                                    "description" => "Indicate whether this header is required in order to return a response",
                                    "default" => true
                                  }
                                }
                              }
                            },
                            "body" => {
                              "type" => "array",
                              "items" => {
                                "type" => "object",
                                "description" => "Model for the body of our backend integration's response",
                                "properties" => {
                                  "content_type" => {
                                    "type" => "string",
                                    "description" => "An HTTP content type to match to a response, such as +application/json+."
                                  },
                                  "is_error" => {
                                    "type" => "boolean",
                                    "description" => "Whether this response should be considered an error",
                                    "default" => false
                                  }
                                }
                              }
                            }
                          }
                        }
                      },
                      "arn" => {
                        "type" => "string",
                        "description" => "For AWS or AWS_PROXY integrations with a compatible Amazon resource outside of Mu, a full-qualified ARN such as `arn:aws:apigateway:us-west-2:s3:action/GetObject&Bucket=`bucket&Key=key`"
                      },
                      "name" => {
                        "type" => "string",
                        "description" => "A Mu resource name, for integrations with a sibling resource (e.g. a Function)"
                      },
                      "cors" => {
                        "type" => "string",
                        "description" => "When enabled, this will create an +OPTIONS+ method under this path with request and response header mappings that implement Cross-Origin Resource Sharing, setting +Access-Control-Allow-Origin+ to the specified value.",
                      },
                      "type" => {
                        "type" => "string",
                        "description" => "A Mu resource type, for integrations with a sibling resource (e.g. a function), or the string +aws_generic+, which we can use in combination with +aws_generic_action+ to integrate with arbitrary AWS services.",
                        "enum" => ["aws_generic", "mock"].concat(MU::Cloud.resource_types.values.map { |t| t[:cfg_plural] }.sort)
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

        # Denote whether this resource implementation is experiment, ready for
        # testing, or ready for production use.
        def self.quality
          MU::Cloud::BETA
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          "arn:#{MU::Cloud::AWS.isGovCloud?(@region) ? "aws-us-gov" : "aws"}:execute-api:#{@region}:#{MU::Cloud::AWS.credToAcct(@credentials)}:#{@cloud_id}"
        end

        # Go fish for the account-wide CloudWatch Logs role that grants APIG
        # permissions to generate logs. This appears to have disappeared from
        # the web console.
        def self.findCloudWatchLogsRole(credentials = nil)
          roles = MU::Cloud.resourceClass("AWS", "Role").find(credentials: credentials)
          roles.each_pair { |id, r|
            next if r.is_a?(Aws::IAM::Types::Policy)
            attached_policies = MU::Cloud::AWS.iam(credentials: @credentials).list_attached_role_policies(
              role_name: r.role_name
            ).attached_policies
            if attached_policies.size == 1 and attached_policies.first.policy_arn == "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
              return r.arn
            end
          }
          nil
        end


        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::endpoints}, bare and unvalidated.
        # @param endpoint [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(endpoint, configurator)
          ok = true

          if endpoint['log_requests'] and !endpoint['access_logs']
            logdesc = {
              "name" => endpoint['name']+"accesslogs",
            }
            logdesc["tags"] = endpoint["tags"] if endpoint['tags']
            configurator.insertKitten(logdesc, "logs")
            endpoint['access_logs'] = MU::Config::Ref.get(
              name: endpoint['name']+"accesslogs",
              type: "log",
              cloud: "AWS",
              credentials: endpoint['credentials'],
              region: endpoint['region']
            )
          end

          if endpoint['access_logs'] and endpoint["access_logs"]["name"]
            endpoint['log_requests'] = true
            MU::Config.addDependency(endpoint, endpoint["access_logs"]["name"], "log")
          end

          if endpoint['access_logs']
            resp = MU::Cloud::AWS.apig(credentials: endpoint['credentials'], region: endpoint['region']).get_account

            if !resp.cloudwatch_role_arn
              logs_role = findCloudWatchLogsRole
              if logs_role
                MU.log "Updating API Gateway account-wide to add log role #{logs_role}", MU::NOTICE
                MU::Cloud::AWS.apig(credentials: endpoint['credentials'], region: endpoint['region']).update_account(
                  patch_operations: [
                    op: "replace",
                    path: "/cloudwatchRoleArn",
                    value: logs_role
                  ]
                )
              else
                MU.log "Endpoint '#{endpoint['name']}' is configured to use CloudWatch Logs, but the account-wide API Gateway log role is not configured", MU::ERR, details: "https://aws.amazon.com/premiumsupport/knowledge-center/api-gateway-cloudwatch-logs/"
                ok = false
              end
            else
              roles = MU::Cloud::AWS::Role.find(cloud_id: resp.cloudwatch_role_arn, credentials: endpoint['credentials'], region: endpoint['region'])
              if roles.empty?
                MU.log "Endpoint '#{endpoint['name']}' is configured to use CloudWatch Logs, but the configured account-wide API Gateway log role does not exist", MU::ERR, details: resp.cloudwatch_role_arn
                ok = false
              end
            end
          end

          if endpoint['domain_names']
            endpoint['domain_names'].each { |dom|
              if dom['certificate']
                cert_arn, cert_domains = MU::Cloud::AWS.resolveSSLCertificate(dom['certificate'], region: dom['region'], credentials: dom['credentials'])
                if !cert_arn
                  MU.log "API Gateway #{endpoint['name']}: Failed to resolve SSL certificate in domain_name block", MU::ERR, details: dom
                  ok = false
                end
              end
              if !dom['unmanaged_name'] and !dom['dns_record']
                MU.log "API Gateway #{endpoint['name']}: Must specify either unmanaged_name or dns_record in domain_name block", MU::ERR, details: dom
                ok = false
              end

              # Make at least an attempt to catch when we've specified the same
              # DNS name to point to both the main gateway and this alternative
              # endpoint, because that ish won't work. This check will miss if
              # the end user specifies the zone in competing ways.
              if dom['dns_record'] and endpoint['dns_records']
                endpoint['dns_records'].each { |rec|
                  if rec['name'] == dom['dns_record']['name'] and
                     rec['zone'] == dom['dns_record']['zone']
                    MU.log "API Gateway #{endpoint['name']}: Cannot specify same entry in dns_records and domain_names", MU::ERR, details: rec
                    ok = false
                  end
                }
              end
            }
          end

          append = []
          endpoint['deploy_to'] ||= MU.environment || $environment || "dev"
          endpoint['methods'].each { |m|
            if m['integrate_with']['async']
              if m['integrate_with']['type'] == "functions" and
                 m['integrate_with']['async']
                m['integrate_with']['parameters'] ||= []
                m['integrate_with']['parameters'] << {
                  "name" => "X-Amz-Invocation-Type",
                  "value" => "'Event'", # yes the single quotes are required
                  "type" => "header"
                }
                if m['integrate_with']['proxy']
                  MU.log "Cannot specify both of proxy and async for API Gateway method integration", MU::ERR
                  ok = false
                end
              end
            end

            if m['integrate_with'] and m['integrate_with']['name']
              if m['integrate_with']['type'] != "aws_generic"
                MU::Config.addDependency(endpoint, m['integrate_with']['name'], m['integrate_with']['type'])
              end

              m['integrate_with']['backend_http_method'] ||= m['type']

              m['responses'] ||= [
                "code" => 200
              ]

              if m['cors']
                m['responses'].each { |r|
                  r['headers'] ||= []
                  r['headers'] << {
                    "header" => "Access-Control-Allow-Origin",
                    "value" => m['cors'],
                    "required" => true
                  }
                  r['headers'].uniq!
                }

                append << cors_option_integrations(m['path'], m['cors'])
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
                elsif m['integrate_with']['type'] == "functions"
                  roledesc["import"] = ["AWSLambdaBasicExecutionRole"]
                end
                configurator.insertKitten(roledesc, "roles")

                m['iam_role'] = endpoint['name']+"-"+m['integrate_with']['name']
                MU::Config.addDependency(endpoint, m['iam_role'], "role")
              end
            end
          }
          endpoint['methods'].concat(append.uniq) if endpoint['methods']
#          if something_bad
#            ok = false
#          end

          ok
        end

        def self.cors_option_integrations(path, origins)
          {
            "type" => "OPTIONS",
            "path" => path,
            "auth" => "NONE",
            "responses" => [
              {
                "code" => 200,
                "headers" => [
                  {
                    "header" => "Access-Control-Allow-Headers",
                    "value" => "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
                    "required" => true
                  },
                  {
                    "header" => "Access-Control-Allow-Methods",
                    "value" => "GET,OPTIONS",
                    "required" => true
                  },
                  {
                    "header" => "Access-Control-Allow-Origin",
                    "value" => origins,
                    "required" => true
                  }
                ],
                "body" => [
                  {
                    "content_type" => "application/json"
                  }
                ]
              }
            ],
            "integrate_with" => {
              "type" => "mock",
              "passthrough_behavior" => "WHEN_NO_MATCH",
              "backend_http_method" => "OPTIONS",
              "request_templates" => [
                {
                  "content_type" => "application/json",
                  "template" => '{"statusCode": 200}'
                }
              ]
            }
          }
        end
        private_class_method :cors_option_integrations

      end
    end
  end
end
