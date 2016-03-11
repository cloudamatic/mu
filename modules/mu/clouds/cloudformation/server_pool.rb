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
      # A server pool as configured in {MU::Config::BasketofKittens::server_pools}
      class ServerPool < MU::Cloud::ServerPool

        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :cloud_id
        attr_reader :config

        attr_reader :cfm_name
        attr_reader :cfm_template

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::server_pools}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          @cloud_id ||= cloud_id
          if !mu_name.nil?
            @mu_name = mu_name
          else
            @mu_name = @deploy.getResourceName(@config['name'])
            @cfm_name, @cfm_template = MU::Cloud::CloudFormation.cloudFormationBase(self.class.cfg_name, self)
            @cfm_launch_name, launch_template = MU::Cloud::CloudFormation.cloudFormationBase("launch_config", name: @mu_name)
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "LaunchConfigurationName", { "Ref" => @cfm_launch_name } )
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", @cfm_launch_name)
            @cfm_template.merge!(launch_template)
          end
        end

        # Populate @cfm_template with a resource description for this server
        # pool in CloudFormation language.
        def create

          @config["cooldown"] = @config["default_cooldown"]
          ["min_size", "max_size", "cooldown", "desired_capacity", "health_check_type", "health_check_grace_period"].each { |arg|
            if !@config[arg].nil?
              key = ""
              arg.split(/_/).each { |chunk| key = key + chunk.capitalize }
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], key, @config[arg])
            end
          }

          basis = @config["basis"]

          if basis["launch_config"]
            nodes_name = @deploy.getResourceName(basis["launch_config"]["name"])
            launch_desc = basis["launch_config"]
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "KeyName", { "Ref" => "SSHKeyName" })
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "InstanceType", launch_desc['size'])
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "InstanceMonitoring", launch_desc["monitoring"])
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "EbsOptimized", launch_desc["ebs_optimized"])

            if !launch_desc["server"].nil?
# XXX this may or may not be a supported use case, figure it out
#                MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "Instance_Id", { "Ref" => } )
            elsif !launch_desc["instance_id"].nil?
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "InstanceId", @config['ami_id'])
            else
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "ImageId", launch_desc["ami_id"])
            end

            if launch_desc["storage"]
              launch_desc["storage"].each { |vol|
                mapping, cfm_mapping = MU::Cloud::AWS::Server.convertBlockDeviceMapping(vol)
                if cfm_mapping.size > 0
                  MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "BlockDeviceMappings", cfm_mapping)
                end
              }
            end
            MU::Cloud::AWS::Server.ephemeral_mappings.each { |mapping|
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "BlockDeviceMappings", { "DeviceName" => mapping[:device_name], "VirtualName" => mapping[:virtual_name] })
            }

            ["kernel_id", "ramdisk_id", "spot_price"].each { |arg|
              if launch_desc[arg]
                key = ""
                arg.split(/_/).each { |chunk| key = key + chunk.capitalize }
                MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], key, launch_desc[arg])
              end
            }

            if launch_desc['generate_iam_role']
              @config['iam_role'], @cfm_role_name, @cfm_prof_name = MU::Cloud::AWS::Server.createIAMProfile(@mu_name, base_profile: launch_desc['iam_role'], extra_policies: launch_desc['iam_policies'], cloudformation_data: @cfm_template)
            elsif launch_desc['iam_role'].nil?
              raise MuError, "#{@mu_name} has generate_iam_role set to false, but no iam_role assigned."
            else
              @config['iam_role'] = launch_desc['iam_role']
            end
            MU::Cloud::AWS::Server.addStdPoliciesToIAMProfile(@config['iam_role'], cloudformation_data: @cfm_template, cfm_role_name: @cfm_role_name)
            if !@config["iam_role"].nil?
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "DependsOn", @cfm_role_name)
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "DependsOn", @cfm_prof_name)
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "IamInstanceProfile", { "Ref" => @cfm_prof_name })
            end

            userdata = Base64.encode64(
              MU::Cloud::AWS::Server.fetchUserdata(
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
                  "resourceType" => "server_pool"
                },
                custom_append: @config['userdata_script']
              )
            )

            if launch_desc["user_data"]
              userdata = launch_desc["user_data"]
            end
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "UserData", userdata)

          elsif basis["server"]
# XXX cloudformation bits
          elsif basis["instance_id"]
# XXX cloudformation bits
          end

          set_public_ip_pref = true
          if @config["vpc_zone_identifier"]
            set_public_ip_pref = false
# XXX cloudformation bits bits
          elsif @config["vpc"]
            if !@config["vpc"]["subnets"].nil? and @config["vpc"]["subnets"].size > 0
              set_public_ip_pref = false
              @config["vpc"]["subnets"].each { |subnet|
                if !subnet["subnet_id"].nil?
                   MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "VPCZoneIdentifier", subnet["subnet_id"])
                elsif @dependencies.has_key?("vpc") and @dependencies["vpc"].has_key?(@config["vpc"]["vpc_name"])
                  @dependencies["vpc"][@config["vpc"]["vpc_name"]].subnets.each { |subnet_obj|
                    if subnet_obj.name == subnet['subnet_name']
                      MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", subnet_obj.cfm_name)
                      MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "VPCZoneIdentifier", { "Ref" => subnet_obj.cfm_name } )
                    end
                  }
                end
              }
            end
          end
          if set_public_ip_pref
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "AssociatePublicIpAddress", @config["associate_public_ip"])
          end

# XXX cloudformation bits
        end

        # This is a NOOP right now, because we're really an empty generator for
        # Servers, and that's what we care about having in deployment
        # descriptors. Should we log some stuff though?
        def notify
          return {}
        end

      end
    end
  end
end
