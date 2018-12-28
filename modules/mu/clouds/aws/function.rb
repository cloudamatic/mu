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
        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        @cloudformation_data = {}
        attr_reader :cloudformation_data

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::functions}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        
        def get_role_arn(name)
          begin
            role = MU::Cloud::AWS.iam.get_role({
              role_name: name.to_s
            })
            return role['role']['arn']
          rescue Exception => e
            Mu.log "#{e}", MU::ERR
          end
        end

        def get_vpc_config(vpc_name, subnet_name, sg_name,region=@config['region'])
          if !subnet_name.nil? and !sg_name.nil? and !vpc_name.nil?
            ## get vpc_id
            ## get sub_id and verify its in the same vpc 
            ## get sg_id and verify its in the same vpc
            ec2_client = MU::Cloud::AWS.ec2(region: region)
            
            vpc_filter = ec2_client.describe_vpcs({
              filters: [{ name: 'tag-value', values: [vpc_name] }]
            })
            bok_vpc_id = vpc_filter.vpcs[0].vpc_id
            
            sub_filter = ec2_client.describe_subnets({
              filters: [{ name: 'tag-value', values: [subnet_name] }]
            })
            
            sub_id = nil 
            sub_filter.subnets.each do |each|
              if each.vpc_id == bok_vpc_id
                sub_id = each.subnet_id
                break
              end
            end
            
            sg_filter = ec2_client.describe_security_groups({
              filters: [{ name: 'group-name', values: [sg_name] }]
            })
            

            if sg_filter.security_groups[0].vpc_id.to_s != bok_vpc_id
              MU.log "Security Group: #{sg_name} is not part of the VPC: #{vpc_name}", MU::ERR
              raise MuError, "Please provide security group name that exists in the vpc"
            end

            #sub_id = sub_filter.subnets[0].subnet_id
            sg_id = sg_filter.security_groups[0].group_id
            return {subnet_ids: [sub_id], security_group_ids: [sg_id]}
          else
            MU.log "Function: #{@config['name']}, Missing either subnet_name or security_group_name or vpc_name in the vpc stanza!", MU::ERR
            raise MuError, "Insufficient parameters for locating vpc resource ids ==> #{@config['name']}"
          end
        end


        def assign_tag(resource_arn, tag_list, region=@config['region'])
          begin
            tag_list.each do |each_pair|
              tag_resp = MU::Cloud::AWS.lambda(region: region).tag_resource({
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
             ### get vpc and subnet_name
             ### find the subnet_id
             sub_name = @config['vpc']['subnet_name']
             vpc_name = @config['vpc']['vpc_name']
             sg_name =  @config['vpc']['security_group_name']
             vpc_conf = get_vpc_config(vpc_name,sub_name,sg_name)
             lambda_properties[:vpc_config] = vpc_conf
          end

          MU::Cloud::AWS.lambda(region: @config['region']).create_function(lambda_properties)
        end

        def groom
          desc = MU::Cloud::AWS.lambda(region: @config['region']).get_function(
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
              p trigger_arn
              p trigger_properties           

              MU.log trigger_properties, MU::DEBUG
              begin
                add_trigger = MU::Cloud::AWS.lambda(region: @config['region']).add_permission(trigger_properties)
              rescue Aws::Lambda::Errors::ResourceConflictException
# XXX check properly for existence
              end
              adjust_trigger(tr['service'], trigger_arn, func_arn, @mu_name) 
            }
          
          end 
        end


        def assume_trigger_arns(svc, name)
          supported_triggers = %w(apigateway sns events event cloudwatch_event)
          if supported_triggers.include?(svc.downcase)
            arn = nil
            case svc.downcase
            when 'sns'
              arn = "arn:aws:sns:#{@config['region']}:#{MU.account_number}:#{name}"
            when 'alarm','events', 'event', 'cloudwatch_event'
              arn = "arn:aws:events:#{@config['region']}:#{MU.account_number}:rule/#{name}"
            when 'apigateway'
              arn = "arn:aws:apigateway:#{@config['region']}:#{MU.account_number}:#{name}"
            when 's3'
              arn = ''
            end
          else
            raise MuError, "Trigger type not yet supported! => #{type}"
          end

          return arn
        end
        
        
        def adjust_trigger(trig_type, trig_arn, func_arn, func_id=nil, protocol='lambda',region=@config['region'])
          
          case trig_type
          
          when 'sns'
            
            sns_client = MU::Cloud::AWS.sns(region: @config['region'])
            sub_to_what = sns_client.subscribe({
              topic_arn: trig_arn,
              protocol: protocol,
              endpoint: func_arn
            })
          when 'event','cloudwatch_event', 'events'
            client = MU::Cloud::AWS.cloudwatch_events(region: @config['region']).put_targets({
              rule: @config['trigger']['name'],
              targets: [
                {
                  id: func_id,
                  arn: func_arn
                }
              ]
            })
          when 'apigateway'
            MU.log "Creation of API Gateway integrations not yet implemented, you'll have to do this manually", MU::WARN, details: "(because we'll basically have to implement all of APIG for this)"
          end 
        end


        # Return the metadata for this Function rule
        # @return [Hash]
        def notify
          deploy_struct = {
          }
          return deploy_struct
        end




        # Remove all functions associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          MU::Cloud::AWS.lambda(region: region).list_functions.functions.each { |f|
            desc = MU::Cloud::AWS.lambda(region: region).get_function(
              function_name: f.function_name
            )
            if desc.tags and desc.tags["MU-ID"] == MU.deploy_id
              MU.log "Deleting Lambda function #{f.function_name}"
              if !noop
                MU::Cloud::AWS.lambda(region: region).delete_function(
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
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @param flags [Hash]: Optional flags
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching function.
        def self.find(cloud_id: nil, func_name: nil, region: MU.curRegion, flags: {})
          func = nil
          if !func_name.nil?
            all_functions = MU::Cloud::AWS.lambda(region: region).list_functions
            if all_functions.include?(func_name)
              all_functions.functions.each do |x|
                if x.function_name == func_name
                  func = x
                  break
                end
              end
            end
          end

          return func
        end




        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {}
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::functions}, bare and unvalidated.
        # @param function [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(function, configurator)
          ok = true

          ok
        end

      end
    end
  end
end
