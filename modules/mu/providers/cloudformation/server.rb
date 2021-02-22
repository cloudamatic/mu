# Copyright:: Copyright (c) 2016 eGlobalTech, Inc., all rights reserved
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
    class CloudFormation

      # A server as configured in {MU::Config::BasketofKittens::servers}
      class Server < MU::Cloud::Server

        attr_reader :cfm_template
        attr_reader :cfm_name

        attr_reader :mu_name
        attr_reader :config
        attr_reader :deploy
        attr_reader :cloud_id
        attr_reader :cloud_desc
        attr_reader :groomer
        attr_accessor :mu_windows_name

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::servers}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          @cloud_id = cloud_id

          @userdata = MU::Cloud.fetchUserdata(
            platform: @config["platform"],
            template_variables: {
              "deployKey" => Base64.urlsafe_encode64(@deploy.public_key),
              "deploySSHKey" => @deploy.ssh_public_key,
              "muID" => MU.deploy_id,
              "muUser" => MU.chef_user,
              "publicIP" => MU.mu_public_ip,
              "mommaCatPort" => MU.mommaCatPort,
              "skipApplyUpdates" => @config['skipinitialupdates'],
              "windowsAdminName" => @config['windows_admin_username'],
              "resourceName" => @config["name"],
              "resourceType" => "server"
            },
            custom_append: @config['userdata_script'],
            scrub_mu_isms: @config['scrub_mu_isms']
          )

          @disk_devices = MU::Cloud.resourceClass("AWS", "Server").disk_devices
          @ephemeral_mappings = MU::Cloud.resourceClass("AWS", "Server").ephemeral_mappings

          if !mu_name.nil?
            @mu_name = mu_name
            @config['mu_name'] = @mu_name
            # describe
            @mu_windows_name = @deploydata['mu_windows_name'] if @mu_windows_name.nil? and @deploydata
          elsif @config['scrub_mu_isms']
            @mu_name = @config['name']
          else
            if kitten_cfg.has_key?("basis")
              @mu_name = @deploy.getResourceName(@config['name'], need_unique_string: true)
            else
              @mu_name = @deploy.getResourceName(@config['name'])
            end
            @config['mu_name'] = @mu_name

            @config['instance_secret'] = Password.random(50)
          end
          @groomer = MU::Groomer.new(self)

        end

        # Populate @cfm_template with a resource description for this server
        # in CloudFormation language.
        def create
          @cfm_name, @cfm_template = MU::Cloud::CloudFormation.cloudFormationBase(self.class.cfg_name, self, tags: @config['tags'], scrub_mu_isms: @config['scrub_mu_isms']) if @cfm_template.nil?
          @role_cfm_name = @prof_cfm_name = nil
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "SourceDestCheck", @config['src_dst_check'])
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "InstanceType", @config['size'])
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "ImageId", @config['ami_id'])
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "KeyName", { "Ref" => "SSHKeyName" })
          if @config['generate_iam_role'] and !@role_generated
            @config['iam_role'], @cfm_role_name, @cfm_prof_name = MU::Cloud::CloudFormation::Server.createIAMProfile(@mu_name, base_profile: @config['iam_role'], extra_policies: @config['iam_policies'], cloudformation_data: @cfm_template)
            @role_generated = true
          end
          if !@config["iam_role"].nil?
            MU::Cloud::CloudFormation::Server.addStdPoliciesToIAMProfile(@cfm_role_name, cloudformation_data: @cfm_template, region: @config['region']) if !@config['scrub_mu_isms']
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", @cfm_role_name)
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", @cfm_prof_name)
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "IamInstanceProfile", { "Ref" => @cfm_prof_name })
          end
          if @config['add_firewall_rules']
            @config['add_firewall_rules'].each { |acl|
              if acl["rule_id"]
                MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "SecurityGroupIds", acl["rule_id"])
              else
                MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "SecurityGroupIds", { "Ref" => @dependencies["firewall_rule"][acl["rule_name"]].cloudobj.cfm_name })
              end
            }
          end

          if !@config['private_ip'].nil?
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "PrivateIpAddress", config['private_ip'])
          end

          if !@vpc.nil? and @config.has_key?("vpc")
            if !@config["vpc"]["vpc_name"].nil? and @dependencies.has_key?("vpc") and @dependencies["vpc"].has_key?(@config["vpc"]["vpc_name"])
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", @dependencies["vpc"][@config["vpc"]["vpc_name"]].cloudobj.cfm_name)
            end

            if !@config['vpc']['subnet_id'].nil?
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "SubnetId", @config['vpc']['subnet_id'])
            elsif @dependencies.has_key?("vpc") and @dependencies["vpc"].has_key?(@config["vpc"]["vpc_name"])
              @dependencies["vpc"][@config["vpc"]["vpc_name"]].subnets.each { |subnet_obj|
                if subnet_obj.name == @config["vpc"]["subnet_name"]
                  MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", subnet_obj.cfm_name)
                  MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "SubnetId", { "Ref" => subnet_obj.cfm_name } )
                end
              }
            end
          end

          if !@config['static_ip'].nil?
            eip_name = eip_template = nil

            eipassoc_name, eipassoc_template = MU::Cloud::CloudFormation.cloudFormationBase("eipassoc", name: @config['name']+"EIP", scrub_mu_isms: @config['scrub_mu_isms'])

            if @config['static_ip']['ip'].nil?
              eip_name, eip_template = MU::Cloud::CloudFormation.cloudFormationBase("eip", name: @config['name']+"EIP", scrub_mu_isms: @config['scrub_mu_isms'])
              MU::Cloud::CloudFormation.setCloudFormationProp(eipassoc_template[eipassoc_name], "DependsOn", eip_name)
              if !@config['vpc'].nil?
                MU::Cloud::CloudFormation.setCloudFormationProp(eip_template[eip_name], "Domain", "vpc")
                MU::Cloud::CloudFormation.setCloudFormationProp(eipassoc_template[eipassoc_name], "AllocationId", { "Fn::GetAtt" => [eip_name, "AllocationId"] })
                if !@vpc.nil? and @config.has_key?("vpc")
                  if !@config["vpc"]["vpc_name"].nil? and @dependencies.has_key?("vpc") and @dependencies["vpc"].has_key?(@config["vpc"]["vpc_name"])
                    igw_name, igw_template = MU::Cloud::CloudFormation.cloudFormationBase("vpcgwattach", name: @dependencies["vpc"][@config["vpc"]["vpc_name"]].cloudobj.mu_name, scrub_mu_isms: @config['scrub_mu_isms'])
                    MU::Cloud::CloudFormation.setCloudFormationProp(eip_template[eip_name], "DependsOn", igw_name)
                  end
                end
#                @cfm_template[@cfm_name]["DependsOn"].dup.each { |parent_dep|
#                  MU::Cloud::CloudFormation.setCloudFormationProp(eip_template[eip_name], "DependsOn", parent_dep)
#
#                }
              else
                MU::Cloud::CloudFormation.setCloudFormationProp(eipassoc_template[eipassoc_name], "EIP", @config['static_ip']['ip'])
              end
            else
              MU.log "Cannot currently target a pre-existing EIP by name when targeting CloudFormation", MU::WARN
            end
            MU::Cloud::CloudFormation.setCloudFormationProp(eipassoc_template[eipassoc_name], "InstanceId", { "Ref" => @cfm_name })

#            MU::Cloud::CloudFormation.setCloudFormationProp(eip_template[eip_name], "EIP", @config['static_ip']['ip'])
            @cfm_template.merge!(eip_template) if !eip_template.nil?
            @cfm_template.merge!(eipassoc_template)
          end

          if !@userdata.nil? and !@userdata.empty?
            MU::Cloud::CloudFormation.setCloudFormationProp(
              @cfm_template[@cfm_name],
              "UserData",
              {
                "Fn::Base64" => {
                  "Fn::Join" => [
                    "",
                    [
                      "#!/bin/bash\n",
                      "echo '",
                      {
                        "Ref" => "AWS::StackName"
                      },
                      "' > /etc/aws_cloudformation_stack\n\n",
                      @userdata
                    ]
                  ]
                }
              }
            )
          end

          configured_storage = Array.new
          cfm_volume_map = {}
          if @config["storage"]
            @config["storage"].each { |vol|
              mapping, cfm_mapping = MU::Cloud.resourceClass("AWS", "Server").convertBlockDeviceMapping(vol)
              configured_storage << mapping
#                vol_name, vol_template = MU::Cloud::CloudFormation.cloudFormationBase("volume", name: "volume"+@cfm_name+mapping[:device_name])
#                MU::Cloud::CloudFormation.setCloudFormationProp(vol_template[vol_name], "Size", mapping[:ebs][:volume_size].to_s)
#                MU::Cloud::CloudFormation.setCloudFormationProp(vol_template[vol_name], "VolumeType", mapping[:ebs][:volume_type])
#                @cfm_template.merge!(vol_template)
#                cfm_volume_map[mapping[:device_name]] = { "Ref" => vol_name }
              if cfm_mapping.size > 0
                MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "BlockDeviceMappings", cfm_mapping)
              end
            }
          end

          cfm_volume_map.each_pair{ |dev, vol|
#            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "Volumes", { "Device" => dev, "VolumeId" => vol })
          }
          @ephemeral_mappings.each { |mapping|
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "BlockDeviceMappings", { "DeviceName" => mapping[:device_name], "VirtualName" => mapping[:virtual_name] })
          }

          return @config
        end

        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def groom
          return create
        end

        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def postBoot
        end

        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def getSSHConfig
        end

        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def canonicalIP
        end

        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def getWindowsAdminPassword
        end

        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def active?
        end

        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def reboot
        end

        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def notify
          {}
        end

        # Insert a Server's standard IAM role needs into an arbitrary IAM profile
        def self.addStdPoliciesToIAMProfile(rolename, cloudformation_data: {})
          policies = Hash.new
          aws_str = MU::Cloud::AWS.isGovCloud?(region) ? "aws-us-gov" : "aws"
          policies['Mu_Bootstrap_Secret_'+MU.deploy_id] ='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:'+aws_str+':s3:::'+MU.adminBucketName+'/'+"#{MU.deploy_id}-secret"+'"}]}'
# XXX this doesn't work unless we can deliver the stack name somehow, and also make the ARN look like arn:aws:cloudformation:us-east-1:144333873908:stack/CATAPULT/*
#          policies['Mu_Describe_Own_CloudFormation_Stack'] ='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudformation:DescribeStacks", "cloudformation:ListStacks"],"Resource": {"Ref":"AWS::StackId"}}]}'
          policies['Mu_Describe_Own_CloudFormation_Stack'] ='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudformation:DescribeStacks", "cloudformation:ListStacks"],"Resource": "*"}]}'
# XXX and then there's this. Doesn't seem to be an easy way to prevent an
# instance from just generating volumes at random, tagging other peoples'
# stuff, etc.
#          policies['Mu_Volume_Management'] ='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:CreateTags","ec2:CreateVolume","ec2:AttachVolume","ec2:DescribeInstanceAttribute","ec2:DescribeVolumeAttribute","ec2:DescribeVolumeStatus","ec2:DescribeVolumes"],"Resource":"*"}]}'
          policies.each_pair { |name, doc|
            MU::Cloud::CloudFormation.setCloudFormationProp(
              cloudformation_data[rolename],
              "Policies",
              {
                "PolicyName" => name,
                "PolicyDocument" => JSON.parse(doc)
              }
            )
          }
          return cloudformation_data
        end

        # Create an Amazon IAM instance profile. One of these should get created
        # for each class of instance (each {MU::Cloud::AWS::Server} or {MU::Cloud::AWS::ServerPool}),
        # and will include both baseline Mu policies and whatever other policies
        # are requested.
        # @param rolename [String]: The name of the role to create, generally a {MU::Cloud::AWS::Server} mu_name
        # @return [String]: The name of the instance profile.
        def self.createIAMProfile(rolename, base_profile: nil, extra_policies: nil, cloudformation_data: {})
          policies = Hash.new

          cfm_role_name, role_cfm_template = MU::Cloud::CloudFormation.cloudFormationBase("iamrole", name: rolename)
          cfm_prof_name, prof_cfm_template = MU::Cloud::CloudFormation.cloudFormationBase("iamprofile", name: rolename)
          cloudformation_data.merge!(role_cfm_template)
          cloudformation_data.merge!(prof_cfm_template)

          if base_profile
            MU.log "Incorporating policies from existing IAM profile '#{base_profile}'"
            resp = MU::Cloud::AWS.iam.get_instance_profile(instance_profile_name: base_profile)
            resp.instance_profile.roles.each { |baserole|
              role_policies = MU::Cloud::AWS.iam.list_role_policies(role_name: baserole.role_name).policy_names
              role_policies.each { |name|
                resp = MU::Cloud::AWS.iam.get_role_policy(
                    role_name: baserole.role_name,
                    policy_name: name
                )
                policies[name] = CGI.unescape(resp.policy_document)
              }
            }
          end
          if extra_policies
            MU.log "Incorporating other specified policies", details: extra_policies
            extra_policies.each { |policy_set|
              policy_set.each_pair { |name, policy|
                if policies.has_key?(name)
                  MU.log "Attempt to add duplicate node policy '#{name}' to '#{rolename}'", MU::WARN, details: policy
                  next
                end
                policies[name] = JSON.generate(policy)
              }
            }
          end
          policies.each_pair { |name, doc|
            MU::Cloud::CloudFormation.setCloudFormationProp(cloudformation_data[cfm_role_name], "Policies", { "PolicyName" => name, "PolicyDocument" => JSON.parse(doc) })
          }
          MU::Cloud::CloudFormation.setCloudFormationProp(cloudformation_data[cfm_prof_name], "Roles", { "Ref" => cfm_role_name } )
          MU::Cloud::CloudFormation.setCloudFormationProp(cloudformation_data[cfm_prof_name], "DependsOn", cfm_role_name)
            return [rolename, cfm_role_name, cfm_prof_name]
        end

        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def self.find(*args)
          MU.log "find() not implemented for CloudFormation layer", MU::DEBUG
          nil
        end
        # Placeholder. This is a NOOP for CloudFormation, which doesn't build
        # resources directly.
        def self.cleanup(*args)
          MU.log "cleanup() not implemented for CloudFormation layer", MU::DEBUG
          nil
        end

        # Return the date/time a machine image was created.
        # @param ami_id [String]: AMI identifier of an Amazon Machine Image
        # @param credentials [String]
        # @return [DateTime]
        def self.imageTimeStamp(ami_id, credentials: nil, region: nil)
          MU::Cloud::AWS.imageTimeStamp(ami_id, credentials: credentials, region: region)
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          MU::Cloud.resourceClass("AWS", "Server").schema(config)
        end

        # Confirm that the given instance size is valid for the given region.
        # If someone accidentally specified an equivalent size from some other cloud provider, return something that makes sense. If nothing makes sense, return nil.
        # @param size [String]: Instance type to check
        # @param region [String]: Region to check against
        # @return [String,nil]
        def self.validateInstanceType(size, region)
          MU::Cloud.resourceClass("AWS", "Server").validateInstanceType(size, region)
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::servers}, bare and unvalidated.
        # @param server [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(server, configurator)
          MU::Cloud.resourceClass("AWS", "Server").validateConfig(server, configurator)
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          MU::Cloud.resourceClass("AWS", "Server").isGlobal?
        end

      end #class
    end #class
  end
end #module
