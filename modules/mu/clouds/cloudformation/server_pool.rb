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
          elsif @config['scrub_mu_isms']
            @mu_name = @config['name']
          else
            @mu_name = @deploy.getResourceName(@config['name'])
          end
        end

        # Populate @cfm_template with a resource description for this server
        # pool in CloudFormation language.
        def create
          @cfm_name, @cfm_template = MU::Cloud::CloudFormation.cloudFormationBase(self.class.cfg_name, self, tags: @config['tags'], scrub_mu_isms: @config['scrub_mu_isms']) if @cfm_template.nil?
          @cfm_launch_name, launch_template = MU::Cloud::CloudFormation.cloudFormationBase("launch_config", self, scrub_mu_isms: @config['scrub_mu_isms'])
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "LaunchConfigurationName", { "Ref" => @cfm_launch_name } )
          MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "DependsOn", @cfm_launch_name)
          if @config['add_firewall_rules']
            @config['add_firewall_rules'].each { |acl|
              if acl["rule_id"]
                MU::Cloud::CloudFormation.setCloudFormationProp(launch_template[@cfm_launch_name], "SecurityGroups", acl["rule_id"])
              else
                MU::Cloud::CloudFormation.setCloudFormationProp(launch_template[@cfm_launch_name], "SecurityGroups", { "Ref" => @dependencies["firewall_rule"][acl["rule_name"]].cloudobj.cfm_name })
              end
            }
          end
          @cfm_template.merge!(launch_template)

          ["min_size", "max_size", "cooldown", "desired_capacity", "health_check_type", "health_check_grace_period"].each { |arg|
            if !@config[arg].nil?
              key = ""
              arg.split(/_/).each { |chunk| key = key + chunk.capitalize }
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], key, @config[arg])
            end
          }


          if @config['termination_policies']
            @config['termination_policies'].each { |pol|
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "TerminationPolicies", pol)
            }
          end

          if @config["scaling_policies"] and @config["scaling_policies"].size > 0
            @config["scaling_policies"].each { |pol|
              pol_name, pol_template = MU::Cloud::CloudFormation.cloudFormationBase("scaling_policy", name: pol['name']+@mu_name, scrub_mu_isms: @config['scrub_mu_isms'])
              MU::Cloud::CloudFormation.setCloudFormationProp(pol_template[pol_name], "AdjustmentType", pol['type'])
              MU::Cloud::CloudFormation.setCloudFormationProp(pol_template[pol_name], "AutoScalingGroupName", @cfm_name)

              pol["scaling_adjustment"] = pol["adjustment"]
              pol.delete("cooldown") if pol["policy_type"] == "StepScaling"
              ["cooldown", "estimated_instance_warmup", "metric_aggregation_type", "min_adjustment_magnitude", "policy_type", "scaling_adjustment"].each { |arg|
                if !pol[arg].nil?
                  key = ""
                  arg.split(/_/).each { |chunk| key = key + chunk.capitalize }
                  MU::Cloud::CloudFormation.setCloudFormationProp(pol_template[pol_name], key, pol[arg])
                end
              }

              if pol['step_adjustments'] and pol['step_adjustments'].size > 0
                pol['step_adjustments'].each { |adj|
                  adjust = { "ScalingAdjustment" => adj['adjustment'] }
                  adjust["MetricIntervalLowerBound"] = adj['lower_bound'] if adj['lower_bound']
                  adjust["MetricIntervalUpperBound"] = adj['upper_bound'] if adj['upper_bound']
                  MU::Cloud::CloudFormation.setCloudFormationProp(pol_template[pol_name], "StepAdjustments", adjust)
                }
              end

              MU::Cloud::CloudFormation.setCloudFormationProp(pol_template[pol_name], "DependsOn", @cfm_name)
              @cfm_template.merge!(pol_template)
            }
          end

          basis = @config["basis"]

          if basis["launch_config"]
            nodes_name = @deploy.getResourceName(basis["launch_config"]["name"])
            launch_desc = basis["launch_config"]
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "KeyName", { "Ref" => "SSHKeyName" })
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "InstanceType", launch_desc['size'])
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "InstanceMonitoring", launch_desc["monitoring"])
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "EbsOptimized", launch_desc["ebs_optimized"])

            if !launch_desc["server"].nil?
              sibling = @deploy.findLitterMate(type: "server", name: launch_desc["server"])
              if sibling.nil? or sibling.cloudobj.nil? or sibling.cloudobj.cfm_name.nil?
                raise MuError, "ServerPool #{@config['name']} references a Server named #{aunch_desc["server"]}, but I can't find the appropriate CloudFormation name."
              end
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "Instance_Id", { "Ref" => sibling.cloudobj.cfm_name } )
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
              @config['iam_role'], @cfm_role_name, @cfm_prof_name = MU::Cloud::CloudFormation::Server.createIAMProfile(@mu_name, base_profile: launch_desc['iam_role'], extra_policies: launch_desc['iam_policies'], cloudformation_data: @cfm_template)
            elsif !launch_desc['iam_role'].nil?
              @config['iam_role'] = launch_desc['iam_role']
            end
            if !@config["iam_role"].nil?
              MU::Cloud::CloudFormation::Server.addStdPoliciesToIAMProfile(@cfm_role_name, cloudformation_data: @cfm_template) if !@config['scrub_mu_isms']
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "DependsOn", @cfm_role_name)
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "DependsOn", @cfm_prof_name)
              MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_launch_name], "IamInstanceProfile", { "Ref" => @cfm_prof_name })
            end

            userdata = MU::Cloud.fetchUserdata(
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
              custom_append: @config['userdata_script'],
              scrub_mu_isms: @config['scrub_mu_isms']
            )

            if launch_desc["user_data"]
              userdata = Base64.encode64(launch_desc["user_data"])
            end
            MU::Cloud::CloudFormation.setCloudFormationProp(
              @cfm_template[@cfm_launch_name],
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
                      userdata
                    ]
                  ]
                }
              }
            )

          elsif basis["server"]
            raise MuCloudFlagNotImplemented, "Basis 'server' not valid for CloudFormation target. Instead, use a launch_config with a 'server' argument."
          elsif basis["instance_id"]
            raise MuCloudFlagNotImplemented, "Basis 'instance_id' not valid for CloudFormation target. Instead, use a launch_config with an 'instance_id' argument."
          end

          public_ip_pref = true
          if @config["vpc_zone_identifier"]
            public_ip_pref = false
# XXX cloudformation bits
          elsif @config["vpc"]
            if !@config["vpc"]["subnets"].nil? and @config["vpc"]["subnets"].size > 0
              public_ip_pref = false
              @config["vpc"]["subnets"].each { |subnet|
                # XXX can we infer AssociatePublicIpAddress from here?
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
          else
            # Default to "sit in every possible AZ"
            public_ip_pref = false
            MU::Cloud::CloudFormation.setCloudFormationProp(@cfm_template[@cfm_name], "AvailabilityZones", { "Fn::GetAZs" => { "Ref" => "AWS::Region" } } )
          end
          if public_ip_pref
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

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          MU::Cloud::AWS::ServerPool.schema(config)
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::servers}, bare and unvalidated.
        # @param server [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(server, configurator)
          MU::Cloud::AWS::ServerPool.validateConfig(server, configurator)
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          MU::Cloud::AWS::ServerPool.isGlobal?
        end

      end
    end
  end
end
