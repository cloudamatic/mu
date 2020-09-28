# Copyright:: Copyright (c) 2018 eGlobalTech, Inc., all rights reserved
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
      # A function as configured in {MU::Config::BasketofKittens::functions}
      class Function < MU::Cloud::Function

        # If we have sibling resources in our deployment, automatically inject
        # interesting things about them into our function's environment
        # variables.
        SIBLING_VARS = {
          "servers" => ["private_ip_address", "public_ip_address"],
          "search_domains" => ["endpoint"],
          "databases" => ["endpoint"],
          "endpoints" => ["url"],
          "notifiers" => ["TopicArn"],
          "nosqldbs" => ["table_arn"]
        }

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Tag this Lambda function
        def assign_tag(resource_arn, tag_list, region=@config['region'])
          begin
            tag_list.each do |each_pair|
              MU::Cloud::AWS.lambda(region: region, credentials: @config['credentials']).tag_resource({
                resource: resource_arn,
                tags: each_pair
              })
            end
          rescue StandardError => e
            MU.log e, MU::ERR
          end
        end


        # Called automatically by {MU::Deploy#createResources}
        def create
          
          lambda_properties = get_properties

          MU.retrier([Aws::Lambda::Errors::InvalidParameterValueException], max: 5, wait: 10) {
            resp = MU::Cloud::AWS.lambda(region: @config['region'], credentials: @config['credentials']).create_function(lambda_properties)
            @cloud_id = resp.function_name
          }

          # the console does this and docs expect it to be there, so mimic the
          # behavior
          MU::Cloud::AWS.cloudwatchlogs(region: @config["region"], credentials: @credentials).create_log_group(
            log_group_name: "/aws/lambda/#{@cloud_id}",
            tags: @tags
          )
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          old_props = MU.structToHash(cloud_desc)

          new_props = get_properties
          code_block = new_props[:code]
          new_props.reject! { |k, _v| [:code, :publish, :tags].include?(k) }
          changes = {}
          new_props.each_pair { |k, v|
            changes[k] = v if v != old_props[k]
          }
          if !changes.empty?
            MU.log "Updating Lambda #{@mu_name}", MU::NOTICE, details: changes
            MU::Cloud::AWS.lambda(region: @config['region'], credentials: @config['credentials']).update_function_configuration(new_props)
          end

          if @code_sha256 and @code_sha256 != cloud_desc.code_sha_256.chomp
            MU.log "Updating code in Lambda #{@mu_name}", MU::NOTICE, details: { "old" => @code_sha256, "new" => cloud_desc.code_sha_256 }
            code_block[:publish] = true
            code_block[:function_name] = @cloud_id
            MU::Cloud::AWS.lambda(region: @config['region'], credentials: @config['credentials']).update_function_code(code_block)
          end

#          tag_function = assign_tag(lambda_func.function_arn, @config['tags']) 
          
          ### The most common triggers can be ==> SNS, S3, Cron, API-Gateway
          ### API-Gateway => no direct way of getting api gateway id.
          ### API-Gateway => Have to create an api gateway first!
          ### API-Gateway => Using the creation object, get the api_gateway_id
          ### For other triggers => ?

          ### to add or to not add triggers
          ### triggers must exist prior
          if @config['triggers']
            @config['triggers'].each { |tr|
              trigger_arn = resolveARN(tr['service'], tr['name'])

              trigger_properties = {
                action: "lambda:InvokeFunction", 
                function_name: @mu_name, 
                principal: "#{tr['service'].downcase}.amazonaws.com", 
                source_arn: trigger_arn, 
                statement_id: "#{@mu_name}-ID-1",
              }

              MU.log "Adding #{tr['service']} #{tr['name']} trigger to Lambda function #{@cloud_id}", details: trigger_properties
              begin
                MU::Cloud::AWS.lambda(region: @config['region'], credentials: @config['credentials']).add_permission(trigger_properties)
              rescue Aws::Lambda::Errors::ResourceConflictException
                # just means the permission is already there
              end
              adjust_trigger(tr['service'], trigger_arn, arn, @mu_name) 
            }
          
          end 

          if @config['invoke_on_completion']
            invoke_params = {
              function_name: @cloud_id,
              invocation_type: @config['invoke_on_completion']['invocation_type'],
              log_type: "Tail"
            }
            if @config['invoke_on_completion']['payload']
              invoke_params[:payload] = JSON.generate(@config['invoke_on_completion']['payload'])
            end
            resp = MU::Cloud::AWS.lambda(region: @config['region'], credentials: @config['credentials']).invoke(invoke_params)
            if resp.status_code == 200
              MU.log "Invoked #{@cloud_id}", MU::NOTICE, details: Base64.decode64(resp.log_result)
            else
              MU.log "Invoked #{@cloud_id} and got #{resp.status_code} (#{resp.function_error})", MU::WARN, details: Base64.decode64(resp.log_result)
            end
          end
        end

        # Intended to be called by other Mu resources, such as Endpoints (API
        # Gateways) to add themselves as triggers for this Lambda function.
        def addTrigger(calling_arn, calling_service, calling_name)
          trigger = {
            action: "lambda:InvokeFunction", 
            function_name: @mu_name, 
            principal: "#{calling_service}.amazonaws.com", 
            source_arn: calling_arn, 
            statement_id: "#{calling_service}-#{calling_name.gsub(/[^a-z0-9\-_]/i, '_')}",
          }

          begin
            # XXX There doesn't seem to be an API call to list or view existing
            # permissions, wtaf. This means we can't intelligently guard this.
            MU::Cloud::AWS.lambda(region: @config['region'], credentials: @config['credentials']).add_permission(trigger)
          rescue Aws::Lambda::Errors::ValidationException => e
            MU.log e.message+" (calling_arn: #{calling_arn}, calling_service: #{calling_service}, calling_name: #{calling_name})", MU::ERR, details: trigger
            raise e
          rescue Aws::Lambda::Errors::ResourceConflictException => e
            if e.message.match(/already exists/)
              MU::Cloud::AWS.lambda(region: @config['region'], credentials: @config['credentials']).remove_permission(
                function_name: @mu_name,
                statement_id: "#{calling_service}-#{calling_name}"
              )
              retry
            else
              MU.log "Error trying to add trigger to Lambda #{@mu_name}: #{e.message}", MU::ERR, details: trigger
              raise e
            end
          end
        end

        # Look up an ARN for a given trigger type and resource name
        def resolveARN(svc, name)
          supported_triggers = %w(apigateway sns events event cloudwatch_event dynamodb)
          if supported_triggers.include?(svc.downcase)
            arn = nil
            case svc.downcase
            when 'sns'
              sib_sns = @deploy.findLitterMate(name: name, type: "notifiers")
              arn = sib_sns ? sib_sns.arn : "arn:aws:sns:#{@config['region']}:#{MU::Cloud::AWS.credToAcct(@config['credentials'])}:#{name}"
            when 'alarm','events', 'event', 'cloudwatch_event'
              sib_event = @deploy.findLitterMate(name: name, type: "job")
              arn = sib_event ? sib_event.arn : "arn:aws:events:#{@config['region']}:#{MU::Cloud::AWS.credToAcct(@config['credentials'])}:rule/#{name}"
            when 'dynamodb'
              sib_dynamo = @deploy.findLitterMate(name: name, type: "nosqldb")
              arn = sib_dynamo ? sib_dynamo.arn : "arn:aws:dynamodb:#{@config['region']}:#{MU::Cloud::AWS.credToAcct(@config['credentials'])}:table/#{name}"
            when 'apigateway'
              sib_apig = @deploy.findLitterMate(name: name, type: "endpoints")
              arn = sib_apig ? sib_apig.arn : "arn:aws:apigateway:#{@config['region']}:#{MU::Cloud::AWS.credToAcct(@config['credentials'])}:#{name}"
            when 's3'
              arn = ''
            end
          else
            raise MuError, "Trigger type not yet supported! => #{type}"
          end

          return arn
        end
        
        # XXX placeholder, really; this is going end up being done from Endpoint, Log and Notification resources, I think
        def adjust_trigger(trig_type, trig_arn, func_arn, func_id=nil, protocol='lambda',region=@config['region'])
          
          case trig_type
          
          when 'sns'
            MU::Cloud.resourceClass("AWS", "Notifier").subscribe(trig_arn, arn, "lambda", region: @config['region'], credentials: @credentials)
          when 'dynamodb'
            stream = MU::Cloud::AWS.dynamostream(region: @config['region'], credentials: @config['credentials']).list_streams(table_name: trig_arn.sub(/.*?:table\//, '')).streams.first
# XXX  guard this
            MU.log "Adding DynamoDB Stream from #{stream.stream_arn} as trigger for #{@cloud_id}"
            begin
            MU::Cloud::AWS.lambda(region: @config['region'], credentials: @config['credentials']).create_event_source_mapping(
              event_source_arn: stream.stream_arn,
              function_name: @cloud_id,
              starting_position: "TRIM_HORIZON" # ...whatever that is
            )
            rescue ::Aws::Lambda::Errors::ResourceConflictException
            end
            
#            MU::Cloud.resourceClass("AWS", "NoSQLDB").subscribe(trig_arn, arn, "lambda", region: @config['region'], credentials: @credentials)
          when 'event','cloudwatch_event', 'events'
           # XXX don't do this, use MU::Cloud::AWS::Log
            MU::Cloud::AWS.cloudwatch_events(region: region, credentials: @config['credentials']).put_targets({
              rule: @config['trigger']['name'],
              targets: [
                {
                  id: func_id,
                  arn: func_arn
                }
              ]
            })
          when 'apigateway'
            addTrigger(trig_arn, "lambda", trig_arn.sub(/.*?([a-z0-9\-_]+)$/i, '\1'))
          end 
        end


        # Return the metadata for this Function rule
        # @return [Hash]
        def notify
          return nil if !cloud_desc
          MU.structToHash(cloud_desc, stringify_keys: true)
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

        # Remove all functions associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          MU.log "AWS::Function.cleanup: need to support flags['known']", MU::DEBUG, details: flags

          MU::Cloud::AWS.lambda(credentials: credentials, region: region).list_functions.functions.each { |f|
            desc = MU::Cloud::AWS.lambda(credentials: credentials, region: region).get_function(
              function_name: f.function_name
            )
            if desc.tags and desc.tags["MU-ID"] == deploy_id and (desc.tags["MU-MASTER-IP"] == MU.mu_public_ip or ignoremaster)
              MU.log "Deleting Lambda function #{f.function_name}"
              if !noop
                MU::Cloud::AWS.lambda(credentials: credentials, region: region).delete_function(
                  function_name: f.function_name
                )
              end
            end
          }

        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          cloud_desc ? cloud_desc.function_arn : nil
        end

        # Locate an existing function.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching function.
        def self.find(**args)
          matches = {}

          all_functions = MU::Cloud::AWS.lambda(region: args[:region], credentials: args[:credentials]).list_functions
          all_functions.functions.each do |x|
            if !args[:cloud_id] or x.function_name == args[:cloud_id]
              matches[x.function_name] = x
              break if args[:cloud_id]
            end
          end

          return matches
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(**_args)
          bok = {
            "cloud" => "AWS",
            "credentials" => @config['credentials'],
            "cloud_id" => @cloud_id,
            "region" => @config['region']
          }

          if !cloud_desc
            MU.log "toKitten failed to load a cloud_desc from #{@cloud_id}", MU::ERR, details: @config
            return nil
          end

          bok['name'] = cloud_desc.function_name
          bok['handler'] = cloud_desc.handler
          bok['memory'] = cloud_desc.memory_size
          bok['runtime'] = cloud_desc.runtime
          bok['timeout'] = cloud_desc.timeout

          function = MU::Cloud::AWS.lambda(region: @config['region'], credentials: @credentials).get_function(function_name: bok['name'])
#          event_srcs = MU::Cloud::AWS.lambda(region: @config['region'], credentials: @credentials).list_event_source_mappings(function_name: @cloud_id)
#          if event_srcs and !event_srcs.event_source_mappings.empty?
#            MU.log "dem mappings tho #{@cloud_id}", MU::WARN, details: event_srcs
#          end

#          begin
#            invoke_cfg = MU::Cloud::AWS.lambda(region: @config['region'], credentials: @credentials).get_function_event_invoke_config(function_name: @cloud_id)
#            MU.log "invoke config #{@cloud_id}", MU::WARN, details: invoke_cfg
#          rescue ::Aws::Lambda::Errors::ResourceNotFoundException
#          end

#          MU.log @cloud_id, MU::WARN, details: cloud_desc if @cloud_id == "Espier-Scheduled-Scanner"
#          MU.log "configuration #{@cloud_id}", MU::WARN, details: MU::Cloud::AWS.lambda(region: @config['region'], credentials: @credentials).get_function_configuration(function_name: @cloud_id) if @cloud_id == "Espier-Scheduled-Scanner"


          if function.code.repository_type == "S3"
            bok['code'] = {}
            function.code.location.match(/^https:\/\/([^\.]+)\..*?\/([^?]+).*?(?:versionId=([^&]+))?/)
            bok['code']['s3_bucket'] = Regexp.last_match[1]
            bok['code']['s3_key'] = Regexp.last_match[2]
            if Regexp.last_match[3]
              bok['code']['s3_version'] = Regexp.last_match[3]
            end
          else
            MU.log "Don't know how to declare code block for Lambda function #{@cloud_id}", MU::ERR, details: function.code
            return nil
          end

          if function.tags
            bok['tags'] = function.tags.keys.map { |k|
              { "key" => k, "value" => function.tags[k] }
            }
            realname = MU::Adoption.tagsToName(bok['tags'])
            bok['name'] = realname if realname
          end

          if function.configuration.vpc_config and
             function.configuration.vpc_config.vpc_id and
             !function.configuration.vpc_config.vpc_id.empty?
            bok['vpc'] = MU::Config::Ref.get(
              id: function.configuration.vpc_config.vpc_id,
              cloud: "AWS",
              credentials: @credentials,
              type: "vpcs",
              subnets: function.configuration.vpc_config.subnet_ids.map { |s| { "subnet_id" => s } }
            )
            if !function.configuration.vpc_config.security_group_ids.empty?
              bok['add_firewall_rules'] = []
              function.configuration.vpc_config.security_group_ids.each { |fw|
                bok['add_firewall_rules'] << MU::Config::Ref.get(
                  id: fw,
                  cloud: "AWS",
                  credentials: @credentials,
                  type: "firewall_rules"
                )
              }
            end
          end

          if function.configuration.environment and
             function.configuration.environment.variables and
             !function.configuration.environment.variables.empty?
            bok['environment_variable'] = []
            function.configuration.environment.variables.each_pair { |k, v|
              bok['environment_variable'] << {
                "key" => k,
                "value" => v
              }
            }
          end

          if function.configuration.role
            shortname = function.configuration.role.sub(/.*?role\/([^\/]+)$/, '\1')
            bok['role'] = MU::Config::Ref.get(
              id: shortname,
              cloud: "AWS",
              type: "roles"
            )
          end

          begin
            pol = MU::Cloud::AWS.lambda(region: @config['region'], credentials: @credentials).get_policy(function_name: @cloud_id).policy
MU.log @cloud_id, MU::WARN, details: JSON.parse(pol) if @cloud_id == "ESPIER-DEV-2020080900-LN-ON-DEMAND-SCANNER"
            if pol
              bok['triggers'] ||= []
              JSON.parse(pol)["Statement"].each { |s|
                bok['triggers'] << {
                  "service" => s["Principal"]["Service"].sub(/\..*/, ''),
                  "name" => s["Resource"].sub(/.*?[:\/]([^:\/]+)$/, '\1')
                }
              }
            end
          rescue ::Aws::Lambda::Errors::ResourceNotFoundException
          end
#MU.log @cloud_id, MU::NOTICE, details: function
# XXX permissions

          bok
        end


        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = ["runtime"]
          schema = {
            "invoke_on_completion" => {
              "type" => "object",
              "description" => "Setting this will cause this Lambda function to be invoked when its groom phase is complete.",
              "required" => ["invocation_type"],
              "properties" => {
                "invocation_type" => {
                  "type" => "string",
                  "enum" => ["RequestResponse", "Event", "Dryrun"],
                  "default" => "RequestReponse"
                },
                "payload" => {
                  "type" => "object",
                  "description" => "Optional input to the function, which will be formatted as JSON and sent for execution"
                }
              }
            },
            "triggers" => {
              "type" => "array",
              "items" => {
                "type" => "object",
                "description" => "Trigger for lambda function",
                "required" => ["service"],
                "properties" => {
                  "service" => {
                    "type" => "string",
                    "enum" => %w{apigateway events s3 sns sqs dynamodb kinesis ses cognito alexa iot lex},
                    "description" => "The name of the AWS service that will trigger this function"
                  },
                  "name" => {
                    "type" => "string",
                    "description" => "The name of the API Gateway, Cloudwatch Event, or other event trigger object"
                  }
                }
              }
            },
            "runtime" => {
              "type" => "string",
              "enum" => %w{nodejs nodejs4.3 nodejs6.10 nodejs8.10 nodejs10.x nodejs12.x java8 java11 python2.7 python3.6 python3.7 python3.8 dotnetcore1.0 dotnetcore2.0 dotnetcore2.1 nodejs4.3-edge go1.x ruby2.5 provided},
            },
            "code" => {
              "type" => "object",  
              "description" => "Zipped deployment package to upload to our function.", 
              "properties" => {  
                "s3_bucket" => {
                  "type" => "string",
                  "description" => "An S3 bucket where the deployment package can be found. Must be used in conjunction with s3_key."
                }, 
                "s3_key" => {
                  "type" => "string",
                  "description" => "Key in s3_bucket where the deployment package can be found. Must be used in conjunction with s3_bucket."
                }, 
                "s3_object_version" => {
                  "type" => "string",
                  "description" => "Specify an S3 object version for the deployment package, instead of the current default"
                }, 
              }
            },
            "iam_role" => {
              "type" => "string",
              "description" => "Deprecated, +role+ is now preferred. The name of an IAM role for our Lambda function to assume. Can refer to an existing IAM role, or a sibling 'role' resource in Mu. If not specified, will create a default role with permissions listed in `permissions` (and if none are listed, we will set `AWSLambdaBasicExecutionRole`)."
            },
            "role" => MU::Config::Ref.schema(type: "roles", desc: "A sibling {MU::Config::BasketofKittens::roles} entry or the id of an existing IAM role to assign to this Lambda function.", omit_fields: ["region", "tag"]),
            "permissions" => {
              "type" => "array",
              "description" => "If +role+ is unspecified, we will create a default execution role for our function, and add one or more permissions to it.",
              "default" => ["basic"],
              "items" => {
                "type" => "string",
                "description" => "A permission to add to our Lambda function's default role, corresponding to standard AWS policies (see https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html)",
                "enum" => ["basic", "kinesis", "dynamo", "sqs", "network", "xray"]
              }
            },
# XXX add some canned permission sets here, asking people to get the AWS weirdness right and then translate it into Mu-speak is just too much. Think about auto-populating when a target log group is asked for, mappings for the AWS canned policies in the URL above, writes to arbitrary S3 buckets, etc
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::functions}, bare and unvalidated.
        # @param function [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(function, configurator)
          ok = true

          if function['triggers']
            function['triggers'].each { |t|
              mu_type = if t["service"] == "sns"
                "notifiers"
              elsif t["service"] == "apigateway"
                "endpoints"
              elsif t["service"] == "s3"
                "buckets"
              elsif t["service"] == "dynamodb"
                "nosqldbs"
              elsif t["service"] == "events"
                "jobs"
              elsif t["service"] == "sqs"
                "msg_queues"
              end

              if mu_type
                MU::Config.addDependency(function, t['name'], mu_type, no_create_wait: true)
              end
            }
          end

          if function['vpc']
            fwname = "lambda-#{function['name']}"
            # default to allowing pings, if no ingress_rules were specified
            function['ingress_rules'] ||= [ 
              {
                "proto" => "icmp",
                "hosts" => ["0.0.0.0/0"]
              }
            ]
            acl = {
              "name" => fwname,
              "rules" => function['ingress_rules'],
              "region" => function['region'],
              "credentials" => function['credentials'],
              "optional_tags" => function['optional_tags']
            }
            acl["tags"] = function['tags'] if function['tags'] && !function['tags'].empty?
            acl["vpc"] = function['vpc'].dup if function['vpc']
            ok = false if !configurator.insertKitten(acl, "firewall_rules")
            function["add_firewall_rules"] = [] if function["add_firewall_rules"].nil?
            function["add_firewall_rules"] << {"name" => fwname}
            function["permissions"] ||= []
            function["permissions"] << "network"
            MU::Config.addDependency(function, fwname, "firewall_rule")
          end

          function['role'] ||= function['iam_role']
          function.delete("iam_role")

          if !function['role']
            policy_map = {
              "basic" => "AWSLambdaBasicExecutionRole",
              "kinesis" => "AWSLambdaKinesisExecutionRole",
              "dynamo" => "AWSLambdaDynamoDBExecutionRole",
              "sqs" => "AWSLambdaSQSQueueExecutionRole ",
              "network" => "AWSLambdaVPCAccessExecutionRole",
              "xray" => "AWSXrayWriteOnlyAccess"
            }
            policies = if function['permissions']
              function['permissions'].map { |p|
                policy_map[p]
              }
            else
              ["AWSLambdaBasicExecutionRole"]
            end
            roledesc = {
              "name" => function['name']+"execrole",
              "credentials" => function['credentials'],
              "can_assume" => [
                {
                  "entity_id" => "lambda.amazonaws.com",
                  "entity_type" => "service"
                }
              ],
              "import" => policies
            }
            configurator.insertKitten(roledesc, "roles")

            function['role'] = function['name']+"execrole"

          end

          if function['role'].is_a?(String)
            function['role'] = MU::Config::Ref.get(
              name: function['role'],
              type: "roles",
              cloud: "AWS",
              credentials: function['credentials']
            )
          end

          if function['role']['name']
            MU::Config.addDependency(function, function['role']['name'], "role")
          end

          ok
        end

        private

        def get_properties
          role_obj = MU::Config::Ref.get(@config['role']).kitten(@deploy, cloud: "AWS")
          raise MuError.new "Failed to fetch object from role reference", details: @config['role'].to_h if !role_obj

          lambda_properties = {
            code: {},
            function_name: @mu_name,
            handler: @config['handler'],
            publish: true,
            role: role_obj.arn,
            runtime: @config['runtime'],
          }

          if @config['code']['zip_file'] or @config['code']['path']
            tempfile = nil
            if @config['code']['path']
              tempfile = Tempfile.new
              MU.log "#{@mu_name} using code at #{@config['code']['path']}"
              MU::Master.zipDir(@config['code']['path'], tempfile.path)
              @config['code']['zip_file'] = tempfile.path
            else
              MU.log "#{@mu_name} using code packaged at #{@config['code']['zip_file']}"
            end
            zip = File.read(@config['code']['zip_file'])
            @code_sha256 = Base64.encode64(Digest::SHA256.digest(zip)).chomp
            lambda_properties[:code][:zip_file] = zip
            if tempfile
              tempfile.close
              tempfile.unlink
            end
          else
            lambda_properties[:code][:s3_bucket] = @config['code']['s3_bucket']
            lambda_properties[:code][:s3_key] = @config['code']['s3_key']
            if @config['code']['s3_object_version']
              lambda_properties[:code][:s3_object_version] = @config['code']['s3_object_version']
            end
# XXX need to download to a temporarily file, read it in, and calculate the digest in order to trigger updates in groom
          end
           
          if @config.has_key?('timeout')
            lambda_properties[:timeout] = @config['timeout'].to_i ## secs
          end           
          
          if @config.has_key?('memory')
            lambda_properties[:memory_size] = @config['memory'].to_i
          end

          SIBLING_VARS.each_key { |sib_type|
            siblings = @deploy.findLitterMate(return_all: true, type: sib_type, cloud: "AWS")
            if siblings
              siblings.each_value { |sibling|
                metadata = sibling.notify
                if !metadata
                  MU.log "Failed to extract metadata from sibling #{sibling}", MU::WARN
                  next
                end
                SIBLING_VARS[sib_type].each { |var|
                  if metadata[var]
                    @config['environment_variables'] ||= []
                    @config['environment_variables'] << {
                      "key" => (sibling.config['name']+"_"+var).gsub(/[^a-z0-9_]/i, '_'),
                      "value" => metadata[var]
                    }
                  end
                }
              }
            end
          }

          if @config.has_key?('environment_variables') 
            lambda_properties[:environment] = { 
              variables: Hash[@config['environment_variables'].map { |v| [v['key'], v['value']] }]
            }
          end

          lambda_properties[:tags] = {}
          MU::MommaCat.listStandardTags.each_pair { |k, v|
            lambda_properties[:tags][k] = v
          }
          if @config['tags']
            @config['tags'].each { |tag|
              lambda_properties[:tags][tag['key']] = tag['value']
            }
          end

          if @config.has_key?('vpc')
            sgs = []
            if @config['add_firewall_rules']
              @config['add_firewall_rules'].each { |sg|
                sg = @deploy.findLitterMate(type: "firewall_rule", name: sg['name'])
                sgs << sg.cloud_id if sg and sg.cloud_id
              }
            end
            if !@vpc
              raise MuError, "Function #{@config['name']} had a VPC configured, but none was loaded"
            end
            lambda_properties[:vpc_config] = {
              :subnet_ids => @vpc.subnets.map { |s| s.cloud_id },
              :security_group_ids => sgs
            }
          end

          lambda_properties
        end

      end
    end
  end
end
