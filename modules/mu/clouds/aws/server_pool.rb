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
      # A server pool as configured in {MU::Config::BasketofKittens::server_pools}
      class ServerPool < MU::Cloud::ServerPool

        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :cloud_id
        attr_reader :config

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::server_pools}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          if !mu_name.nil?
            @mu_name = mu_name
          elsif @config['scrub_mu_isms']
            @mu_name = @config['name']
          else
            @mu_name = @deploy.getResourceName(@config['name'])
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          MU.setVar("curRegion", @config['region']) if !@config['region'].nil?

          asg_options = {
            :auto_scaling_group_name => @mu_name,
            :default_cooldown => @config["default_cooldown"],
            :health_check_type => @config["health_check_type"],
            :health_check_grace_period => @config["health_check_grace_period"],
            :tags => []
          }

          MU::MommaCat.listStandardTags.each_pair { |name, value|
            asg_options[:tags] << {key: name, value: value, propagate_at_launch: true}
          }

          if @config['optional_tags']
            MU::MommaCat.listOptionalTags.each_pair { |name, value|
              asg_options[:tags] << {key: name, value: value, propagate_at_launch: true}
            }
          end

          if @config['tags']
            @config['tags'].each { |tag|
              asg_options[:tags] << {key: tag['key'], value: tag['value'], propagate_at_launch: true}
            }
          end

          if @config["wait_for_nodes"] > 0
            MU.log "Setting pool #{@mu_name} min_size and max_size to #{@config["wait_for_nodes"]} until bootstrapped"
            asg_options[:min_size] = @config["wait_for_nodes"]
            asg_options[:max_size] = @config["wait_for_nodes"]
          else
            asg_options[:min_size] = @config["min_size"]
            asg_options[:max_size] = @config["max_size"]
          end

          if @config["loadbalancers"]
            lbs = []
            tg_arns = []
# XXX refactor this into the LoadBalancer resource
            @config["loadbalancers"].each { |lb|
              if lb["existing_load_balancer"]
                lbs << lb["existing_load_balancer"]
                @deploy.deployment["loadbalancers"] = Array.new if !@deploy.deployment["loadbalancers"]
                @deploy.deployment["loadbalancers"] << {
                    "name" => lb["existing_load_balancer"],
                    "awsname" => lb["existing_load_balancer"]
                    # XXX probably have to query API to get the DNS name of this one
                }
              elsif lb["concurrent_load_balancer"]
                raise MuError, "No loadbalancers exist! I need one named #{lb['concurrent_load_balancer']}" if !@deploy.deployment["loadbalancers"]
                found = false
                @deploy.deployment["loadbalancers"].each_pair { |lb_name, deployed_lb|
                  if lb_name == lb['concurrent_load_balancer']
                    lbs << deployed_lb["awsname"]
                    if deployed_lb.has_key?("targetgroups")
                      deployed_lb["targetgroups"].each_pair { |tg_name, tg_arn|
                        tg_arns << tg_arn
                      }
                    end
                    found = true
                  end
                }
                raise MuError, "I need a loadbalancer named #{lb['concurrent_load_balancer']}, but none seems to have been created!" if !found
              end
            }
            if tg_arns.size > 0
              asg_options[:target_group_arns] = tg_arns
            else
              asg_options[:load_balancer_names] = lbs
            end
          end
          asg_options[:termination_policies] = @config["termination_policies"] if @config["termination_policies"]
          asg_options[:desired_capacity] = @config["desired_capacity"] if @config["desired_capacity"]

          basis = @config["basis"]

          if basis["launch_config"]
            nodes_name = @deploy.getResourceName(basis["launch_config"]["name"])
            launch_desc = basis["launch_config"]

            if !launch_desc["server"].nil?
              #XXX this isn't how we find these; use findStray or something
              if @deploy.deployment["images"].nil? or @deploy.deployment["images"][launch_desc["server"]].nil?
                raise MuError, "#{@mu_name} needs an AMI from server #{launch_desc["server"]}, but I don't see one anywhere"
              end
              launch_desc["ami_id"] = @deploy.deployment["images"][launch_desc["server"]]["image_id"]
              MU.log "Using AMI '#{launch_desc["ami_id"]}' from sibling server #{launch_desc["server"]} in ServerPool #{@mu_name}"
            elsif !launch_desc["instance_id"].nil?
              launch_desc["ami_id"] = MU::Cloud::AWS::Server.createImage(
                name: @mu_name,
                instance_id: launch_desc["instance_id"]
              )
            end
            MU::Cloud::AWS::Server.waitForAMI(launch_desc["ami_id"])

            launch_options = {
              :launch_configuration_name => @mu_name,
              :image_id => launch_desc["ami_id"],
              :instance_type => launch_desc["size"],
              :key_name => @deploy.ssh_key_name,
              :ebs_optimized => launch_desc["ebs_optimized"],
              :instance_monitoring => {:enabled => launch_desc["monitoring"]},
            }

            # Figure out which devices are embedded in the AMI already.
            image = MU::Cloud::AWS.ec2(@config['region']).describe_images(image_ids: [launch_desc["ami_id"]]).images.first
            ext_disks = {}
            if !image.block_device_mappings.nil?
              image.block_device_mappings.each { |disk|
                if !disk.device_name.nil? and !disk.device_name.empty? and !disk.ebs.nil? and !disk.ebs.empty?
                  ext_disks[disk.device_name] = MU.structToHash(disk.ebs)
                end
              }
            end

            launch_options[:block_device_mappings] = []
            if launch_desc["storage"]
              storage = Array.new
              launch_desc["storage"].each { |vol|
                # Drop the "encrypted" flag if a snapshot for this device exists
                # in the AMI, even if they both agree about the value of said
                # flag. Apparently that's a thing now.
                if ext_disks.has_key?(vol["device"])
                  if ext_disks[vol["device"]].has_key?(:snapshot_id)
                    vol.delete("encrypted")
                  end
                end
                mapping, cfm_mapping = MU::Cloud::AWS::Server.convertBlockDeviceMapping(vol)
                storage << mapping
              }
              launch_options[:block_device_mappings] = storage
            end

            # Map ephemeral disk devices too, in case our AMI wasn't smart
            # enough to do it for us.
            launch_options[:block_device_mappings].concat(MU::Cloud::AWS::Server.ephemeral_mappings)

            ["kernel_id", "ramdisk_id", "spot_price"].each { |arg|
              if launch_desc[arg]
                launch_options[arg.to_sym] = launch_desc[arg]
              end
            }

            rolename = nil
            if launch_desc['generate_iam_role']
              # Using ARN instead of IAM instance profile name to hopefully get around some random AWS failures
              rolename, cfm_role_name, cfm_prof_name, arn = MU::Cloud::AWS::Server.createIAMProfile(@mu_name, base_profile: launch_desc['iam_role'], extra_policies: launch_desc['iam_policies'])
              launch_options[:iam_instance_profile] = arn
            elsif launch_desc['iam_role'].nil?
              raise MuError, "#{@mu_name} has generate_iam_role set to false, but no iam_role assigned."
            else
              launch_options[:iam_instance_profile] = launch_desc['iam_role']
            end

            @config['iam_role'] = rolename ? rolename : launch_options[:iam_instance_profile]

            if rolename
              MU::Cloud::AWS::Server.addStdPoliciesToIAMProfile(rolename)
            else
              MU::Cloud::AWS::Server.addStdPoliciesToIAMProfile(@config['iam_role'])
            end

            instance_secret = Password.random(50)
            @deploy.saveNodeSecret("default", instance_secret, "instance_secret")

            launch_options[:user_data] = Base64.encode64(
              MU::Cloud.fetchUserdata(
                platform: @config["platform"],
                cloud: "aws",
                template_variables: {
                  "deployKey" => Base64.urlsafe_encode64(@deploy.public_key),
                  "deploySSHKey" => @deploy.ssh_public_key,
                  "muID" => MU.deploy_id,
                  "muUser" => MU.mu_user,
                  "publicIP" => MU.mu_public_ip,
                  "skipApplyUpdates" => @config['skipinitialupdates'],
                  "windowsAdminName" => @config['windows_admin_username'],
                  "resourceName" => @config["name"],
                  "resourceType" => "server_pool",
                  "platform" => @config["platform"]
                },
                custom_append: @config['userdata_script']
              )
            )

            if launch_desc["user_data"]
              launch_options[:user_data] = launch_desc["user_data"]
            end

          elsif basis["server"]
            nodes_name = @deploy.getResourceName(basis["server"])
            srv_name = basis["server"]
# XXX cloudformation bits
            if @deploy.deployment['servers'] != nil and
                @deploy.deployment['servers'][srv_name] != nil
              asg_options[:instance_id] = @deploy.deployment['servers'][srv_name]["instance_id"]
            end
          elsif basis["instance_id"]
            # TODO should go fetch the name tag or something
            nodes_name = @deploy.getResourceName(basis["instance_id"].gsub(/-/, ""))
# XXX cloudformation bits
            asg_options[:instance_id] = basis["instance_id"]
          end

          if @config["vpc_zone_identifier"]
            asg_options[:vpc_zone_identifier] = @config["vpc_zone_identifier"]
          elsif @config["vpc"]
            subnet_ids = []
            if !@config["vpc"]["subnets"].nil? and @config["vpc"]["subnets"].size > 0
              @config["vpc"]["subnets"].each { |subnet|
                subnet_obj = @vpc.getSubnet(cloud_id: subnet["subnet_id"], name: subnet["subnet_name"])
                subnet_ids << subnet_obj.cloud_id
              }
            else
              @vpc.subnets.each { |subnet_obj|
                next if subnet_obj.private? and ["all_public", "public"].include?(@config["vpc"]["subnet_pref"])
                next if !subnet_obj.private? and ["all_private", "private"].include?(@config["vpc"]["subnet_pref"])
                subnet_ids << subnet_obj.cloud_id
              }
            end
            if subnet_ids.size == 0
              raise MuError, "No valid subnets found for #{@mu_name} from #{@config["vpc"]}"
            end
            asg_options[:vpc_zone_identifier] = subnet_ids.join(",")
          end

          sgs = []
          if @dependencies.has_key?("firewall_rule")
            @dependencies['firewall_rule'].values.each { |sg|
              sgs << sg.cloud_id
            }
          end

          if !asg_options[:vpc_zone_identifier].nil? and asg_options[:vpc_zone_identifier].empty?
            asg_options.delete(:vpc_zone_identifier)
          end
          if !asg_options[:vpc_zone_identifier].nil?# or !@config["vpc"].nil?
            launch_options[:associate_public_ip_address] = @config["associate_public_ip"]
          end

          if launch_options
            launch_options[:security_groups] = sgs
            MU.log "Creating AutoScale Launch Configuration #{@mu_name}", details: launch_options
            retries = 0
            begin
              launch_config = MU::Cloud::AWS.autoscale.create_launch_configuration(launch_options)
            rescue Aws::AutoScaling::Errors::ValidationError => e
              # Retries 20 because can easily go over on a slow day, add retries to warn
              if retries < 20
                # Autoscale seems to lag behind the IAM endpoint in noticing that
                # a profile exists, so shut up about it and retry.
                if retries > 3 or !e.message.match(/Invalid IamInstanceProfile/)
                  MU.log "Got #{e.inspect} creating Launch Configuration #{@mu_name} with retries #{retries} of 20", MU::WARN
                end
                retries = retries + 1
                sleep 10
                retry
              else
                raise MuError, "Got #{e.inspect} creating Launch Configuration #{@mu_name}"
              end
            end
            asg_options[:launch_configuration_name] = @mu_name
          end

          # Do the dance of specifying individual zones if we haven't asked to
          # use particular VPC subnets.
          if @config['zones'].nil? and asg_options[:vpc_zone_identifier].nil?
            @config["zones"] = MU::Cloud::AWS.listAZs(@config['region'])
            MU.log "Using zones from #{@config['region']}", MU::DEBUG, details: @config['zones']
          end
          asg_options[:availability_zones] = @config["zones"] if @config["zones"] != nil

          MU.log "Creating AutoScale group #{@mu_name}", details: asg_options

          zones_to_try = @config["zones"]
          begin
            asg = MU::Cloud::AWS.autoscale.create_auto_scaling_group(asg_options)
          rescue Aws::AutoScaling::Errors::ValidationError => e
            if zones_to_try != nil and zones_to_try.size > 0
              MU.log "#{e.message}, retrying with individual AZs", MU::WARN
              asg_options[:availability_zones] = [zones_to_try.pop]
              retry
            else
              MU.log e.message, MU::ERR, details: asg_options
              raise MuError, "#{e.message} creating AutoScale group #{@mu_name}"
            end
          end

          if zones_to_try != nil and zones_to_try.size < @config["zones"].size
            zones_to_try.each { |zone|
              begin
                MU::Cloud::AWS.autoscale.update_auto_scaling_group(
                    auto_scaling_group_name: @mu_name,
                    availability_zones: [zone]
                )
              rescue Aws::AutoScaling::Errors::ValidationError => e
                MU.log "Couldn't enable Availability Zone #{zone} for AutoScale Group #{@mu_name} (#{e.message})", MU::WARN
              end
            }

          end

          @cloud_id = @mu_name

          if @config["scaling_policies"] and @config["scaling_policies"].size > 0
            @config["scaling_policies"].each { |policy|
              policy_params = {
                :auto_scaling_group_name => @mu_name,
                :policy_name => @deploy.getResourceName("#{@config['name']}-#{policy['name']}"),
                :adjustment_type => policy['type'],
                :policy_type => policy['policy_type']
              }

              if policy["policy_type"] == "SimpleScaling"
                policy_params[:cooldown] = policy['cooldown']
                policy_params[:scaling_adjustment] = policy['adjustment']
              elsif policy["policy_type"] == "StepScaling"
                step_adjustments = []
                policy['step_adjustments'].each{|step|
                  step_adjustments << {:metric_interval_lower_bound => step["lower_bound"], :metric_interval_upper_bound => step["upper_bound"], :scaling_adjustment => step["adjustment"]}
                }
                policy_params[:metric_aggregation_type] = policy['metric_aggregation_type']
                policy_params[:step_adjustments] = step_adjustments
                policy_params[:estimated_instance_warmup] = policy['estimated_instance_warmup']
              end

              policy_params[:min_adjustment_magnitude] = policy['min_adjustment_magnitude'] if !policy['min_adjustment_magnitude'].nil?
              resp = MU::Cloud::AWS.autoscale.put_scaling_policy(policy_params)

              # If we are creating alarms for scaling policies we need to have the autoscaling policy ARN
              # To make life easier we're creating the alarms here
              if policy.has_key?("alarms") && !policy["alarms"].empty?
                policy["alarms"].each { |alarm|
                  alarm["alarm_actions"] = [] if !alarm.has_key?("alarm_actions")
                  alarm["ok_actions"] = [] if !alarm.has_key?("ok_actions")
                  alarm["alarm_actions"] << resp.policy_arn
                  alarm["dimensions"] = [{name: "AutoScalingGroupName", value: asg_options[:auto_scaling_group_name]}]

                  if alarm["enable_notifications"]
                    topic_arn = MU::Cloud::AWS::Notification.createTopic(alarm["notification_group"], region: @config["region"])
                    MU::Cloud::AWS::Notification.subscribe(arn: topic_arn, protocol: alarm["notification_type"], endpoint: alarm["notification_endpoint"], region: @config["region"])
                    alarm["alarm_actions"] << topic_arn
                    alarm["ok_actions"] << topic_arn
                  end

                  MU::Cloud::AWS::Alarm.setAlarm(
                    name: "#{MU.deploy_id}-#{alarm["name"]}".upcase,
                    ok_actions: alarm["ok_actions"],
                    alarm_actions: alarm["alarm_actions"],
                    insufficient_data_actions: alarm["no_data_actions"],
                    metric_name: alarm["metric_name"],
                    namespace: alarm["namespace"],
                    statistic: alarm["statistic"],
                    dimensions: alarm["dimensions"],
                    period: alarm["period"],
                    unit: alarm["unit"],
                    evaluation_periods: alarm["evaluation_periods"],
                    threshold: alarm["threshold"],
                    comparison_operator: alarm["comparison_operator"],
                    region: @config["region"]
                  )
                }
              end
            }
          end

          # Wait and see if we successfully bring up some instances
          attempts = 0
          begin
            sleep 5
            desc = MU::Cloud::AWS.autoscale.describe_auto_scaling_groups(auto_scaling_group_names: [@mu_name]).auto_scaling_groups.first
            MU.log "Looking for #{desc.min_size} instances in #{@mu_name}, found #{desc.instances.size}", MU::DEBUG
            attempts = attempts + 1
            if attempts > 25 and desc.instances.size == 0
              MU.log "No instances spun up after #{5*attempts} seconds, something's wrong with Autoscale group #{@mu_name}", MU::ERR, details: MU::Cloud::AWS.autoscale.describe_scaling_activities(auto_scaling_group_name: @mu_name).activities
              raise MuError, "No instances spun up after #{5*attempts} seconds, something's wrong with Autoscale group #{@mu_name}"
            end
          end while desc.instances.size < desc.min_size
          MU.log "#{desc.instances.size} instances spinning up in #{@mu_name}"

          # If we're holding to bootstrap some nodes, do so, then set our min/max
          # sizes to their real values.
          if @config["wait_for_nodes"] > 0
            MU.log "Waiting for #{@config["wait_for_nodes"]} nodes to fully bootstrap before proceeding"
            parent_thread_id = Thread.current.object_id
            groomthreads = Array.new
            desc.instances.each { |member|
              begin
                groomthreads << Thread.new {
                  Thread.abort_on_exception = false
                  MU.dupGlobals(parent_thread_id)
                  MU.log "Initializing #{member.instance_id} in ServerPool #{@mu_name}"
                  MU::MommaCat.lock(member.instance_id+"-mommagroom")
                  kitten = MU::Cloud::Server.new(mommacat: @deploy, kitten_cfg: @config, cloud_id: member.instance_id)
                  MU::MommaCat.lock("#{kitten.cloudclass.name}_#{kitten.config["name"]}-dependencies")
                  MU::MommaCat.unlock("#{kitten.cloudclass.name}_#{kitten.config["name"]}-dependencies")
                  kitten.postBoot(member.instance_id)
                  kitten.groom
                  MU::MommaCat.unlockAll
                }
              rescue MU::Groomer::RunError => e
                MU.log "Proceeding after failed initial Groomer run, but #{member.instance_id} may not behave as expected!", MU::WARN, details: e.inspect
              rescue Exception => e
                if !member.nil? and !done
                  MU.log "Aborted before I could finish setting up #{@config['name']}, cleaning it up. Stack trace will print once cleanup is complete.", MU::WARN if !@deploy.nocleanup
                  MU::MommaCat.unlockAll
                  if !@deploy.nocleanup
                    Thread.new {
                      MU.dupGlobals(parent_thread_id)
                      MU::Cloud::AWS::Server.terminateInstance(id: member.instance_id)
                    }
                  end
                end
                raise MuError, e.inspect
              end
            }
            groomthreads.each { |t|
              t.join
            }
            MU.log "Setting min_size to #{@config['min_size']} and max_size to #{@config['max_size']}"
            MU::Cloud::AWS.autoscale.update_auto_scaling_group(
                auto_scaling_group_name: @mu_name,
                min_size: @config['min_size'],
                max_size: @config['max_size']
            )
          end
          MU.log "See /var/log/mu-momma-cat.log for asynchronous bootstrap progress.", MU::NOTICE

          return asg
        end

        # This is a NOOP right now, because we're really an empty generator for
        # Servers, and that's what we care about having in deployment
        # descriptors. Should we log some stuff though?
        def notify
          return {}
        end

        # Locate an existing ServerPool or ServerPools and return an array containing matching AWS resource descriptors for those that match.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region
        # @param tag_key [String]: A tag key to search.
        # @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
        # @param flags [Hash]: Optional flags
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching ServerPools
        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil, flags: {})
          MU.log "XXX ServerPool.find not yet implemented", MU::WARN
          return {}
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::server_pools}, bare and unvalidated.
        # @param pool [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(pool, configurator)
          ok = true

          if !pool["basis"]["launch_config"].nil?
            launch = pool["basis"]["launch_config"]
            if !launch['generate_iam_role']
              if !launch['iam_role'] and pool['cloud'] != "CloudFormation"
                MU.log "Must set iam_role if generate_iam_role set to false", MU::ERR
                ok = false
              end
              if !launch['iam_policies'].nil? and launch['iam_policies'].size > 0
                MU.log "Cannot mix iam_policies with generate_iam_role set to false", MU::ERR
                ok = false
              end
            end
            if launch["server"].nil? and launch["instance_id"].nil? and launch["ami_id"].nil?
              if MU::Config.amazon_images.has_key?(pool['platform']) and
                  MU::Config.amazon_images[pool['platform']].has_key?(pool['region'])
                launch['ami_id'] = getTail("pool"+pool['name']+"AMI", value: MU::Config.amazon_images[pool['platform']][pool['region']], prettyname: "pool"+pool['name']+"AMI", cloudtype: "AWS::EC2::Image::Id")
  
              else
                ok = false
                MU.log "One of the following MUST be specified for launch_config: server, ami_id, instance_id.", MU::ERR
              end
            end
            if launch["server"] != nil
              pool["dependencies"] << {"type" => "server", "name" => launch["server"]}
# XXX I dunno, maybe toss an error if this isn't done already
#              servers.each { |server|
#                if server["name"] == launch["server"]
#                  server["create_ami"] = true
#                end
#              }
            end
          end
  
          if !pool["scaling_policies"].nil?
            pool["scaling_policies"].each { |policy|
              if policy['type'] != "PercentChangeInCapacity" and !policy['min_adjustment_magnitude'].nil?
                MU.log "Cannot specify scaling policy min_adjustment_magnitude if type is not PercentChangeInCapacity", MU::ERR
                ok = false
              end
  
              if policy["policy_type"] == "SimpleScaling"
                unless policy["cooldown"] && policy["adjustment"]
                  MU.log "You must specify 'cooldown' and 'adjustment' when 'policy_type' is set to 'SimpleScaling'", MU::ERR
                  ok = false
                end
              elsif policy["policy_type"] == "StepScaling"
                if policy["step_adjustments"].nil? || policy["step_adjustments"].empty?
                  MU.log "You must specify 'step_adjustments' when 'policy_type' is set to 'StepScaling'", MU::ERR
                  ok = false
                end
  
                policy["step_adjustments"].each{ |step|
                  if step["adjustment"].nil?
                    MU.log "You must specify 'adjustment' for 'step_adjustments' when 'policy_type' is set to 'StepScaling'", MU::ERR
                    ok = false
                  end
  
                  if step["adjustment"] >= 1 && policy["estimated_instance_warmup"].nil?
                    MU.log "You must specify 'estimated_instance_warmup' when 'policy_type' is set to 'StepScaling' and adding capacity", MU::ERR
                    ok = false
                  end
  
                  if step["lower_bound"].nil? && step["upper_bound"].nil?
                    MU.log "You must specify 'lower_bound' and/or upper_bound for 'step_adjustments' when 'policy_type' is set to 'StepScaling'", MU::ERR
                    ok = false
                  end
                }
              end
  
              if policy["alarms"] && !policy["alarms"].empty?
                policy["alarms"].each { |alarm|
                  alarm["name"] = "scaling-policy-#{pool["name"]}-#{alarm["name"]}"
                  alarm['dimensions'] = [] if !alarm['dimensions']
                  alarm['dimensions'] << { "name" => pool["name"], "cloud_class" => "AutoScalingGroupName" }
                  alarm["namespace"] = "AWS/EC2" if alarm["namespace"].nil?
                  alarm['cloud'] = pool['cloud']
#                  ok = false if !insertKitten(alarm, "alarms")
                }
              end
            }
          end
          ok
        end

        # Remove all autoscale groups associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          filters = [{name: "key", values: ["MU-ID"]}]
          if !ignoremaster
            filters << {name: "key", values: ["MU-MASTER-IP"]}
          end
          resp = MU::Cloud::AWS.autoscale(region).describe_tags(
              filters: filters,
              max_records: 100
          )

          return nil if resp.tags.nil? or resp.tags.size == 0

          maybe_purge = []
          no_purge = []
          resp.data.tags.each { |asg|
            if asg.resource_type != "auto-scaling-group"
              no_purge << asg.resource_id
            end
            if asg.key == "MU-MASTER-IP" and asg.value != MU.mu_public_ip and !ignoremaster
              no_purge << asg.resource_id
            end
            if asg.key == "MU-ID" and asg.value == MU.deploy_id
              maybe_purge << asg.resource_id
            end
          }


          maybe_purge.each { |resource_id|
            next if no_purge.include?(resource_id)
            MU.log "Removing AutoScale group #{resource_id}"
            next if noop
            retries = 0
            begin
              MU::Cloud::AWS.autoscale(region).delete_auto_scaling_group(
                  auto_scaling_group_name: resource_id,
                  # XXX this should obey @force
                  force_delete: true
              )
            rescue Aws::AutoScaling::Errors::InternalFailure => e
              if retries < 5
                MU.log "Got #{e.inspect} while removing AutoScale group #{resource_id}.", MU::WARN
                sleep 10
                retry
              else
                MU.log "Failed to delete AutoScale group #{resource_id}", MU::ERR
              end
            end

            MU::Cloud::AWS::Server.removeIAMProfile(resource_id)

            # Generally there should be a launch_configuration of the same name
            # XXX search for these independently, too?
            retries = 0
            begin
              MU.log "Removing AutoScale Launch Configuration #{resource_id}"
              MU::Cloud::AWS.autoscale(region).delete_launch_configuration(
                  launch_configuration_name: resource_id
              )
            rescue Aws::AutoScaling::Errors::ValidationError => e
              MU.log "No such Launch Configuration #{resource_id}"
            rescue Aws::AutoScaling::Errors::InternalFailure => e
              if retries < 5
                MU.log "Got #{e.inspect} while removing Launch Configuration #{resource_id}.", MU::WARN
                sleep 10
                retry
              else
                MU.log "Failed to delete Launch Configuration #{resource_id}", MU::ERR
              end
            end
          }
          return nil
        end
      end
    end
  end
end
