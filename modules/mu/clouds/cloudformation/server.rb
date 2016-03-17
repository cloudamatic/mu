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
    class CloudFormation

      # A server as configured in {MU::Config::BasketofKittens::servers}
      class Server < MU::Cloud::Server

        # @return [Mutex]
        def self.userdata_mutex
          @userdata_mutex ||= Mutex.new
        end

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

          @userdata = MU::Cloud::AWS::Server.fetchUserdata(
            platform: @config["platform"],
            template_variables: {
              "deployKey" => Base64.urlsafe_encode64(@deploy.public_key),
              "deploySSHKey" => @deploy.ssh_public_key,
              "muID" => MU.deploy_id,
              "muUser" => MU.chef_user,
              "publicIP" => MU.mu_public_ip,
              "skipApplyUpdates" => @config['skipinitialupdates'],
              "windowsAdminName" => @config['windows_admin_username'],
              "resourceName" => @config["name"],
              "resourceType" => "server"
            },
            custom_append: @config['userdata_script']
          )

          @disk_devices = MU::Cloud::AWS::Server.disk_devices
          @ephemeral_mappings = MU::Cloud::AWS::Server.ephemeral_mappings

          if !mu_name.nil?
            @mu_name = mu_name
            @config['mu_name'] = @mu_name
            # describe
            @mu_windows_name = @deploydata['mu_windows_name'] if @mu_windows_name.nil? and @deploydata
          else
            if kitten_cfg.has_key?("basis")
              @mu_name = @deploy.getResourceName(@config['name'], need_unique_string: true)
            else
              @mu_name = @deploy.getResourceName(@config['name'])
            end
            @config['mu_name'] = @mu_name

            @config['instance_secret'] = Password.random(50)
            @cfm_name, @cfm_template = MU::Cloud::CloudFormation.cloudFormationBase(self.class.cfg_name, self, tags: @config['tags'])
            @role_cfm_name = @prof_cfm_name = nil
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "SourceDestCheck", @config['src_dst_check'].to_s)
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "InstanceType", @config['size'])
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "ImageId", @config['ami_id'])
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "KeyName", { "Ref" => "SSHKeyName" })
          end
          @groomer = MU::Groomer.new(self)

        end

        # Populate @cfm_template with a resource description for this server
        # in CloudFormation language.
        def create
          if @config['generate_iam_role'] and !@role_generated
            @config['iam_role'], @cfm_role_name, @cfm_prof_name = MU::Cloud::CloudFormation::Server.createIAMProfile(@mu_name, base_profile: @config['iam_role'], extra_policies: @config['iam_policies'], cloudformation_data: @cfm_template)
            @role_generated = true
          elsif @config['iam_role'].nil?
            raise MuError, "#{@mu_name} has generate_iam_role set to false, but no iam_role assigned."
          end
          MU::Cloud::CloudFormation::Server.addStdPoliciesToIAMProfile(@cfm_role_name, cloudformation_data: @cfm_template)
          if !@config["iam_role"].nil?
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", @cfm_role_name)
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", @cfm_prof_name)
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "IamInstanceProfile", { "Ref" => @cfm_prof_name })
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

            eipassoc_name, eipassoc_template = MU::Cloud::CloudFormation.cloudFormationBase("eipassoc", name: @config['name']+"EIP")

            if @config['static_ip']['ip'].nil?
              eip_name, eip_template = MU::Cloud::CloudFormation.cloudFormationBase("eip", name: @config['name']+"EIP")
              MU::Cloud::CloudFormation.setCloudFormationProp(eipassoc_template[eipassoc_name], "DependsOn", eip_name)
              if !@config['vpc'].nil?
                MU::Cloud::CloudFormation.setCloudFormationProp(eip_template[eip_name], "Domain", "vpc")
                MU::Cloud::CloudFormation.setCloudFormationProp(eipassoc_template[eipassoc_name], "AllocationId", { "Fn::GetAtt" => [eip_name, "AllocationId"] })
                if !@vpc.nil? and @config.has_key?("vpc")
                  if !@config["vpc"]["vpc_name"].nil? and @dependencies.has_key?("vpc") and @dependencies["vpc"].has_key?(@config["vpc"]["vpc_name"])
                    igw_name, igw_template = MU::Cloud::CloudFormation.cloudFormationBase("vpcgwattach", name: @dependencies["vpc"][@config["vpc"]["vpc_name"]].cloudobj.mu_name)
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
              raise MuError, "Cannot currently target a pre-existing EIP by name when targeting CloudFormation"
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
              mapping, cfm_mapping = MU::Cloud::AWS::Server.convertBlockDeviceMapping(vol)
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

        def groom
          return create
        end

        # Everything below here is essentially a dummy method that doesn't
        # apply because we don't groom or maintenance nodes in CloudFormation,
        # we simply "create" them (emit a chunk of code to create them later).

        def postBoot
        end

        def getSSHConfig
        end

        def canonicalIP
        end

        def getWindowsAdminPassword
        end

        def active?
        end

        def reboot
        end

        def notify
          {}
        end

        # Insert a Server's standard IAM role needs into an arbitrary IAM profile
        def self.addStdPoliciesToIAMProfile(rolename, cloudformation_data: {})
          policies = Hash.new
          policies['Mu_Bootstrap_Secret_'+MU.deploy_id] ='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::'+MU.adminBucketName+'/'+"#{MU.deploy_id}-secret"+'"}]}'
# XXX this doesn't work unless we can deliver the stack name somehow, and also make the ARN look like arn:aws:cloudformation:us-east-1:144333873908:stack/CATAPULT/*
#          policies['Mu_Describe_Own_CloudFormation_Stack'] ='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudformation:DescribeStacks", "cloudformation:ListStacks"],"Resource": {"Ref":"AWS::StackId"}}]}'
          policies['Mu_Describe_Own_CloudFormation_Stack'] ='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudformation:DescribeStacks", "cloudformation:ListStacks"],"Resource": "*"}]}'
          policies['Mu_Volume_Management'] ='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:CreateTags","ec2:CreateVolume","ec2:AttachVolume","ec2:DescribeInstanceAttribute","ec2:DescribeVolumeAttribute","ec2:DescribeVolumeStatus","ec2:DescribeVolumes"],"Resource":"*"}]}'
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
                policies[name] = URI.unescape(resp.policy_document)
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

      end #class
    end #class
  end
end #module
