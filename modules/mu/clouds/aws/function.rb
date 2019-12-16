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
              tag_resp = MU::Cloud::AWS.lambda(region: region, credentials: @config['credentials']).tag_resource({
                resource: resource_arn,
                tags: each_pair
              })
            end
          rescue Exception => e
            MU.log e, MU::ERR
          end
        end


        # Called automatically by {MU::Deploy#createResources}
        def create
          role_arn = get_role_arn(@config['iam_role'])
          
          lambda_properties = {
            code: {},
            function_name: @mu_name,
            handler: @config['handler'],
            publish: true,
            role: role_arn,
            runtime: @config['runtime'],
          }

          if @config['code']['zip_file']
            zip = File.read(@config['code']['zip_file'])
            MU.log "Uploading deployment package from #{@config['code']['zip_file']}"
            lambda_properties[:code][:zip_file] = zip
          else
            lambda_properties[:code][:s3_bucket] = @config['code']['s3_bucket']
            lambda_properties[:code][:s3_key] = @config['code']['s3_key']
            if @config['code']['s3_object_version']
              lambda_properties[:code][:s3_object_version] = @config['code']['s3_object_version']
            end
          end
           
          if @config.has_key?('timeout')
            lambda_properties[:timeout] = @config['timeout'].to_i ## secs
          end           
          
          if @config.has_key?('memory')
            lambda_properties[:memory_size] = @config['memory'].to_i
          end
          
          if @config.has_key?('environment_variables') 
              lambda_properties[:environment] = { 
                variables: {@config['environment_variables'][0]['key'] => @config['environment_variables'][0]['value']}
              }
          end

          lambda_properties[:tags] = {}
          MU::MommaCat.listStandardTags.each_pair { |k, v|
            lambda_properties[:tags][k] = v
          }
          if @config['tags']
            @config['tags'].each { |tag|
              lambda_properties[:tags][tag.key.first] = tag.values.first
            }
          end

          if @config.has_key?('vpc')
            sgs = []
            if @config['add_firewall_rules']
              @config['add_firewall_rules'].each { |sg|
                sg = @deploy.findLitterMate(type: "firewall_rule", name: sg['rule_name'])
                sgs << sg.cloud_id if sg and sg.cloud_id
              }
            end
            lambda_properties[:vpc_config] = {
              :subnet_ids => @config['vpc']['subnets'].map { |s| s["subnet_id"] },
              :security_group_ids => sgs
            }
          end

          retries = 0
          resp = begin
            MU::Cloud::AWS.lambda(region: @config['region'], credentials: @config['credentials']).create_function(lambda_properties)
          rescue Aws::Lambda::Errors::InvalidParameterValueException => e
            # Freshly-made IAM roles sometimes aren't really ready
            if retries < 5
              sleep 10
              retries += 1
              retry
            end
            raise e
          end

          @cloud_id = resp.function_name
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          desc = MU::Cloud::AWS.lambda(region: @config['region'], credentials: @config['credentials']).get_function(
            function_name: @mu_name
          )
          func_arn = desc.configuration.function_arn if !desc.empty?

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
              trigger_arn = assume_trigger_arns(tr['service'], tr['name'])

              trigger_properties = {
                action: "lambda:InvokeFunction", 
                function_name: @mu_name, 
                principal: "#{tr['service'].downcase}.amazonaws.com", 
                source_arn: trigger_arn, 
                statement_id: "#{@mu_name}-ID-1",
              }

              MU.log trigger_properties, MU::DEBUG
              begin
                add_trigger = MU::Cloud::AWS.lambda(region: @config['region'], credentials: @config['credentials']).add_permission(trigger_properties)
              rescue Aws::Lambda::Errors::ResourceConflictException
              end
              adjust_trigger(tr['service'], trigger_arn, func_arn, @mu_name) 
            }
          
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
            statement_id: "#{calling_service}-#{calling_name}",
          }

          begin
            # XXX There doesn't seem to be an API call to list or view existing
            # permissions, wtaf. This means we can't intelligently guard this.
            add_trigger = MU::Cloud::AWS.lambda(region: @config['region'], credentials: @config['credentials']).add_permission(trigger)
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
        def assume_trigger_arns(svc, name)
          supported_triggers = %w(apigateway sns events event cloudwatch_event)
          if supported_triggers.include?(svc.downcase)
            arn = nil
            case svc.downcase
            when 'sns'
              arn = "arn:aws:sns:#{@config['region']}:#{MU::Cloud::AWS.credToAcct(@config['credentials'])}:#{name}"
            when 'alarm','events', 'event', 'cloudwatch_event'
              arn = "arn:aws:events:#{@config['region']}:#{MU::Cloud::AWS.credToAcct(@config['credentials'])}:rule/#{name}"
            when 'apigateway'
              arn = "arn:aws:apigateway:#{@config['region']}:#{MU::Cloud::AWS.credToAcct(@config['credentials'])}:#{name}"
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
           # XXX don't do this, use MU::Cloud::AWS::Notification 
            sns_client = MU::Cloud::AWS.sns(region: @config['region'], credentials: @config['credentials'])
            sub_to_what = sns_client.subscribe({
              topic_arn: trig_arn,
              protocol: protocol,
              endpoint: func_arn
            })
          when 'event','cloudwatch_event', 'events'
           # XXX don't do this, use MU::Cloud::AWS::Log
            client = MU::Cloud::AWS.cloudwatch_events(region: @config['region'], credentials: @config['credentials']).put_targets({
              rule: @config['trigger']['name'],
              targets: [
                {
                  id: func_id,
                  arn: func_arn
                }
              ]
            })
#          when 'apigateway'
# XXX this is actually happening in ::Endpoint... maybe...            
#            MU.log "Creation of API Gateway integrations not yet implemented, you'll have to do this manually", MU::WARN, details: "(because we'll basically have to implement all of APIG for this)"
          end 
        end


        # Return the metadata for this Function rule
        # @return [Hash]
        def notify
          deploy_struct = MU.structToHash(MU::Cloud::AWS::Function.find(cloud_id: @cloud_id, credentials: @config['credentials'], region: @config['region']).values.first)
          deploy_struct['mu_name'] = @mu_name
          return deploy_struct
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
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          MU::Cloud::AWS.lambda(credentials: credentials, region: region).list_functions.functions.each { |f|
            desc = MU::Cloud::AWS.lambda(credentials: credentials, region: region).get_function(
              function_name: f.function_name
            )
            if desc.tags and desc.tags["MU-ID"] == MU.deploy_id
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
          cloud_desc.function_arn
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
        def toKitten(rootparent: nil, billing: nil, habitats: nil)
          bok = {
            "cloud" => "AWS",
            "credentials" => @config['credentials'],
            "cloud_id" => @cloud_id
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
MU.log @cloud_id, MU::NOTICE, details: function
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
            bok['tags'] = function.tags
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

# XXX iam_role, triggers, permissions

          bok
        end


        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "iam_role" => {
              "type" => "string",
              "description" => "The name of an IAM role for our Lambda function to assume. Can refer to an existing IAM role, or a sibling 'role' resource in Mu. If not specified, will create a default role with permissions listed in `permissions` (and if none are listed, we will set `AWSLambdaBasicExecutionRole`)."
            },
            "permissions" => {
              "type" => "array",
              "description" => "if `iam_role` is unspecified, we will create a default execution role for our function, and add one or more permissions to it.",
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
            function["add_firewall_rules"] << {"rule_name" => fwname}
            function["permissions"] ||= []
            function["permissions"] << "network"
            function['dependencies'] ||= []
            function['dependencies'] << {
              "name" => fwname,
              "type" => "firewall_rule"
            }
          end

          if !function['iam_role']
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

            function['dependencies'] ||= []
            function['iam_role'] = function['name']+"execrole"

            function['dependencies'] << {
              "type" => "role",
              "name" => function['name']+"execrole"
            }
          end

          ok
        end

        private

        # Given an IAM role name, resolve to ARN. Will attempt to identify any
        # sibling Mu role resources by this name first, and failing that, will
        # do a plain get_role() to the IAM API for the provided name.
        # @param name [String]
        def get_role_arn(name)
          sib_role = @deploy.findLitterMate(name: name, type: "roles")
          return sib_role.cloudobj.arn if sib_role

          begin
            role = MU::Cloud::AWS.iam(credentials: @config['credentials']).get_role({
              role_name: name.to_s
            })
            return role['role']['arn']
          rescue Exception => e
            MU.log "#{e}", MU::ERR
          end
          nil
        end

      end
    end
  end
end
