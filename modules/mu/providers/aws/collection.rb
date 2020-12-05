# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
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

      # An Amazon CloudFormation stack as configured in {MU::Config::BasketofKittens::collections}
      class Collection < MU::Cloud::Collection

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config['name'], need_unique_string: true)
          MU.setVar("curRegion", @region) if !@region.nil?
        end


        # Called automatically by {MU::Deploy#createResources}
        def create
          flag="SUCCESS"
          MU.setVar("curRegion", @region) if !@region.nil?
          region = @region
          server=@config["name"]
          stack_name = getStackName(@config["name"])

          if @config["type"] !=nil && @config["type"]=="existing" then
# XXX this isn't correct, need to go through and list its resources
            return @config
          end
          @config["time"]=@deploy.timestamp

          begin

            stack_descriptor = {
                :stack_name => stack_name,
                :on_failure => @config["on_failure"],
                :timeout_in_minutes => @config["timeout"],
                :tags => [
                    {
                        :key => "Name",
                        :value => MU.appname.upcase + "-" + MU.environment.upcase + "-" + MU.timestamp.upcase + "-" + @config['name'].upcase
                    },
                    {
                        :key => "MU-ID",
                        :value => MU.deploy_id
                    }
                ]
            }

            keypairname, _ssh_private_key, _ssh_public_key = @deploy.SSHKey

            parameters = Array.new
            if !@config["parameters"].nil?
              @config["parameters"].each { |parameter|
                parameters << {
                    :parameter_key => parameter["parameter_key"],
                    :parameter_value => parameter["parameter_value"]
                }
              }
            end
            if @config["pass_deploy_key_as"] != nil
              parameters << {
                  :parameter_key => @config["pass_deploy_key_as"],
                  :parameter_value => keypairname
              }
            end
            stack_descriptor[:parameters] = parameters

            if @config["template_file"] != nil then
              # pass absolute path
              if !@config["template_file"].nil?
                if @config["template_file"].match(/^\//)
                  MU.log "Loading Cloudformation template from #{@config["template_file"]}"
                  template_body = File.read(@config["template_file"])
                else
                  path = File.expand_path(File.dirname(MU::Config.config_path)+"/"+@config["template_file"])
                  MU.log "Loading Cloudformation template from #{path}"
                  template_body = File.read(path)
                end
              else
                # json file and template path is same
                file_dir =File.dirname(ARGV[0])
                if File.exist? file_dir+"/"+@config["template_file"] then
                  template_body=File.read(file_dir+"/"+@config["template_file"]);
                end
              end
              stack_descriptor[:template_body] = template_body.to_s
            end

            if @config["template_url"] != nil then
              if @config["template_file"] == nil then
                stack_descriptor[:template_url] = @config["template_url"]
              end
            end

            MU.log "Creating CloudFormation stack '#{@config['name']}'", details: stack_descriptor
            MU::Cloud::AWS.cloudformation(region: region, credentials: @credentials).create_stack(stack_descriptor);

            sleep(10);
            stack_response = MU::Cloud::AWS.cloudformation(region: region, credentials: @credentials).describe_stacks({:stack_name => stack_name}).stacks.first
            attempts = 0
            begin
              if attempts % 5 == 0
                MU.log "Waiting for CloudFormation stack '#{@config['name']}' to be ready...", MU::NOTICE
              else
                MU.log "Waiting for CloudFormation stack '#{@config['name']}' to be ready...", MU::DEBUG
              end
              stack_response =MU::Cloud::AWS.cloudformation(region: region, credentials: @credentials).describe_stacks({:stack_name => stack_name}).stacks.first
              sleep 60
            end while stack_response.stack_status == "CREATE_IN_PROGRESS"

            if stack_response.stack_status == "CREATE_FAILED" then
              showStackError server
              flag="FAIL"
            end
          rescue Aws::EC2::Errors::ServiceError => e

            flag="FAIL"
            MU.log "#{stack_name} creation failed (#{e.inspect})", MU::ERR, details: e.backtrace

          end

          if flag == "FAIL" then
            MU::Cloud::AWS.cloudformation(region: region, credentials: @credentials).delete_stack({:stack_name => stack_name})
            exit 1
          end

          MU.log "CloudFormation stack '#{@config['name']}' complete"

          begin
            resources = MU::Cloud::AWS.cloudformation(region: region, credentials: @credentials).describe_stack_resources(:stack_name => stack_name)

            resources[:stack_resources].each { |resource|

              case resource.resource_type
                when "AWS::EC2::Instance"
                  MU::Cloud::AWS.createStandardTags(resource.physical_resource_id)
                  instance_name = MU.deploy_id+"-"+@config['name']+"-"+resource.logical_resource_id
                  MU::Cloud::AWS.createTag(resource.physical_resource_id, "Name", instance_name, credentials: @credentials)

                  instance = MU::Cloud.resourceClass("AWS", "Server").notifyDeploy(
                      @config['name']+"-"+resource.logical_resource_id,
                      resource.physical_resource_id
                  )

                  MU::Master.addHostToSSHConfig(
                      instance_name,
                      instance["private_ip_address"],
                      instance["private_dns_name"],
                      # XXX this is a hack-around
                      user: "ec2-user",
                      public_dns: instance["public_ip_address"],
                      public_ip: instance["public_dns_name"],
                      key_name: instance["key_name"]
                  )

                  mu_zone, _junk = MU::Cloud::DNSZone.find(name: "mu")
                  if !mu_zone.nil?
                    MU::Cloud.resourceClass("AWS", "DNSZone").genericMuDNSEntry(instance_name, instance["private_ip_address"], MU::Cloud::Server)
                  else
                    MU::Master.addInstanceToEtcHosts(instance["public_ip_address"], instance_name)
                  end

                when "AWS::EC2::SecurityGroup"
                  MU::Cloud::AWS.createStandardTags(resource.physical_resource_id)
                  MU::Cloud::AWS.createTag(resource.physical_resource_id, "Name", MU.deploy_id+"-"+@config['name']+'-'+resource.logical_resource_id, credentials: @credentials)
                  MU::Cloud.resourceClass("AWS", "FirewallRule").notifyDeploy(
                      @config['name']+"-"+resource.logical_resource_id,
                      resource.physical_resource_id
                  )
                when "AWS::EC2::Subnet"
                  MU::Cloud::AWS.createStandardTags(resource.physical_resource_id)
                  MU::Cloud::AWS.createTag(resource.physical_resource_id, "Name", MU.deploy_id+"-"+@config['name']+'-'+resource.logical_resource_id, credentials: @credentials)
                  data = {
                      "collection" => @config["name"],
                      "subnet_id" => resource.physical_resource_id,
                  }
                  @deploy.notify("subnets", @config['name']+"-"+resource.logical_resource_id, data)
                when "AWS::EC2::VPC"
                  MU::Cloud::AWS.createStandardTags(resource.physical_resource_id)
                  MU::Cloud::AWS.createTag(resource.physical_resource_id, "Name", MU.deploy_id+"-"+@config['name']+'-'+resource.logical_resource_id, credentials: @credentials)
                  data = {
                      "collection" => @config["name"],
                      "vpc_id" => resource.physical_resource_id,
                  }
                  @deploy.notify("vpcs", @config['name']+"-"+resource.logical_resource_id, data)
                when "AWS::EC2::InternetGateway"
                  MU::Cloud::AWS.createStandardTags(resource.physical_resource_id)
                  MU::Cloud::AWS.createTag(resource.physical_resource_id, "Name", MU.deploy_id+"-"+@config['name']+'-'+resource.logical_resource_id, credentials: @credentials)
                when "AWS::EC2::RouteTable"
                  MU::Cloud::AWS.createStandardTags(resource.physical_resource_id)
                  MU::Cloud::AWS.createTag(resource.physical_resource_id, "Name", MU.deploy_id+"-"+@config['name']+'-'+resource.logical_resource_id, credentials: @credentials)

                # The rest of these aren't anything we act on
                when "AWS::EC2::Route"
                  MU.log resource.resource_type, MU::DEBUG
                when "AWS::EC2::EIP"
                  MU.log resource.resource_type, MU::DEBUG
                when "AWS::EC2::SecurityGroupIngress"
                  MU.log resource.resource_type, MU::DEBUG
                when "AWS::EC2::SubnetRouteTableAssociation"
                  MU.log resource.resource_type, MU::DEBUG
                when "AWS::EC2::VPCGatewayAttachment"
                  MU.log resource.resource_type, MU::DEBUG
                when "AWS::IAM::InstanceProfile"
                  MU.log resource.resource_type, MU::DEBUG
                when "AWS::IAM::Role"
                  MU.log resource.resource_type, MU::DEBUG
                else
                  MU.log "Don't know what to do with #{resource.resource_type}, skipping it", MU::WARN
              end
            }
          rescue Aws::CloudFormation::Errors::ValidationError => e
            MU.log "Error processing created resource in CloudFormation stack #{stack_name}: #{e.inspect}", MU::ERR, details: e.backtrace
          end
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          false
        end

        # Remove all CloudFormation stacks associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @param wait [Boolean]: Block on the removal of this stack; AWS deletion will continue in the background otherwise if false.
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, wait: false, credentials: nil, flags: {})
          MU.log "AWS::Collection.cleanup: need to support flags['known']", MU::DEBUG, details: flags
          MU.log "Placeholder: AWS Collection artifacts do not support tags, so ignoremaster cleanup flag has no effect", MU::DEBUG, details: ignoremaster

# XXX needs to check tags instead of name- possible?
          resp = MU::Cloud::AWS.cloudformation(credentials: credentials, region: region).describe_stacks
          resp.stacks.each { |stack|
            ok = false
            stack.tags.each { |tag|
              ok = true if (tag.key == "MU-ID") and tag.value == deploy_id
            }
            if ok
              MU.log "Deleting CloudFormation stack #{stack.stack_name})"
              next if noop
              if stack.stack_status != "DELETE_IN_PROGRESS"
                MU::Cloud::AWS.cloudformation(credentials: credentials, region: region).delete_stack(stack_name: stack.stack_name)
              end
              if wait
                max_retries = 10
                retries = 0
                mystack = nil
                begin
                  mystack = nil
                  sleep 30
                  retries = retries + 1
                  desc = MU::Cloud::AWS.cloudformation(credentials: credentials, region: region).describe_stacks(stack_name: stack.stack_name)
                  if desc.size > 0
                    mystack = desc.first.stacks.first
                    if mystack.size > 0 and mystack.stack_status == "DELETE_FAILED"
                      MU.log "Couldn't delete CloudFormation stack #{stack.stack_name}", MU::ERR, details: mystack.stack_status_reason
                      return
                    end
                    MU.log "Waiting for CloudFormation stack #{stack.stack_name} to delete (#{stack.stack_status})...", MU::NOTICE
                  end
                rescue Aws::CloudFormation::Errors::ValidationError
                  # this is ok, it means deletion finally succeeded

                end while !desc.nil? and desc.size > 0 and retries < max_retries

                if retries >= max_retries and !mystack.nil? and mystack.stack_status != "DELETED"
                  MU.log "Failed to delete CloudFormation stack #{stack.stack_name}", MU::ERR
                end
              end

            end
          }
          return nil
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          cloud_desc.role_arn
        end

        # placeholder
        def self.find(**args)
          found = nil
          resp = MU::Cloud::AWS.cloudformation(region: args[:region], credentials: args[:credentials]).describe_stacks(
            stack_name: args[:cloud_id]
          )
          if resp and resp.stacks
            found[args[:cloud_id]] = resp.stacks.first
          end

          found
        end

        # placeholder
        # @return [Hash]
        def notify
# XXX move those individual resource type notify calls into here
          @deploy.notify("collections", @config["name"], @config)
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {}
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::collections}, bare and unvalidated.
        # @param _stack [Hash]: The resource to process and validate
        # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(_stack, _configurator)
          true
        end

        private

        # Generate a MU-friendly name for a CloudFormation stack
        # @param stack [String]: The internal resource name of the stack
        # @return [String]
        def getStackName(stack)
          stack_name = MU.deploy_id + "-" + stack.upcase
          stack_name.gsub!(/[_\.]/, "-")
          return stack_name
        end

        # Log the Amazon-specific errors associated with a CloudFormation stack.
        # We have to query the AWS API explicitly to get this.
        # @param stack [String]: The internal resource name of the stack
        # @return [void]
        def showStackError(stack)
          region = stack['region']
          stack_name = getStackName(stack)
          begin
            resources = MU::Cloud::AWS.cloudformation(region: region).describe_stack_resources(:stack_name => stack_name)

            MU.log "CloudFormation stack #{stack_name} failed", MU::ERR

            resources[:stack_resources].each { |resource|
              MU.log "#{resource.resource_type} #{resource.resource_status} #{resource.resource_status_reason }", MU::ERR
            }
          rescue Aws::CloudFormation::Errors::ValidationError => e
            MU.log e.inspect, MU::ERR, details: e.backtrace
          end
        end

      end #class
    end #class
  end
end #module
