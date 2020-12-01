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

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config['name'])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          MU.setVar("curRegion", @config['region']) if !@config['region'].nil?
          
          createUpdateLaunchConfig

          asg_options = buildOptionsHash

          MU.log "Creating AutoScale group #{@mu_name}", details: asg_options

          zones_to_try = @config["zones"]
          begin
            asg = MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).create_auto_scaling_group(asg_options)
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
                MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).update_auto_scaling_group(
                    auto_scaling_group_name: @mu_name,
                    availability_zones: [zone]
                )
              rescue Aws::AutoScaling::Errors::ValidationError => e
                MU.log "Couldn't enable Availability Zone #{zone} for AutoScale Group #{@mu_name} (#{e.message})", MU::WARN
              end
            }

          end

          @cloud_id = @mu_name


          # Wait and see if we successfully bring up some instances
          attempts = 0
          begin
            sleep 5
            desc = MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).describe_auto_scaling_groups(auto_scaling_group_names: [@mu_name]).auto_scaling_groups.first
            MU.log "Looking for #{desc.min_size} instances in #{@mu_name}, found #{desc.instances.size}", MU::DEBUG
            attempts = attempts + 1
            if attempts > 25 and desc.instances.size == 0
              MU.log "No instances spun up after #{5*attempts} seconds, something's wrong with Autoscale group #{@mu_name}", MU::ERR, details: MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).describe_scaling_activities(auto_scaling_group_name: @mu_name).activities
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
                  MU.dupGlobals(parent_thread_id)
                  MU.log "Initializing #{member.instance_id} in ServerPool #{@mu_name}"
                  MU::MommaCat.lock(member.instance_id+"-mommagroom")
                  begin
                    kitten = MU::Cloud::Server.new(mommacat: @deploy, kitten_cfg: @config, cloud_id: member.instance_id)
                  rescue RuntimeError => e
                    if e.message.match(/can't add a new key into hash during iteration/)
                      MU.log e.message+", retrying", MU::WARN
                      sleep 3
                      retry
                    else
                      raise e
                    end
                  end
                  MU::MommaCat.lock("#{kitten.cloudclass.name}_#{kitten.config["name"]}-dependencies")
                  MU::MommaCat.unlock("#{kitten.cloudclass.name}_#{kitten.config["name"]}-dependencies")
                  if !kitten.postBoot(member.instance_id)
                    raise MU::Groomer::RunError, "Failure grooming #{member.instance_id}"
                  end
                  kitten.groom
                  MU::MommaCat.unlockAll
                }
              rescue MU::Groomer::RunError => e
                MU.log "Proceeding after failed initial Groomer run, but #{member.instance_id} may not behave as expected!", MU::WARN, details: e.inspect
              rescue StandardError => e
                if !member.nil? and !done
                  MU.log "Aborted before I could finish setting up #{@config['name']}, cleaning it up. Stack trace will print once cleanup is complete.", MU::WARN if !@deploy.nocleanup
                  MU::MommaCat.unlockAll
                  if !@deploy.nocleanup
                    Thread.new {
                      MU.dupGlobals(parent_thread_id)
                      MU::Cloud.resourceClass("AWS", "Server").terminateInstance(id: member.instance_id)
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
            MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).update_auto_scaling_group(
              auto_scaling_group_name: @mu_name,
              min_size: @config['min_size'],
              max_size: @config['max_size']
            )
          end

          if @config['scale_in_protection']
            need_instances = @config['scale_in_protection'].match(/^\d+$/) ? @config['scale_in_protection'].to_i : @config['min_size']
            setScaleInProtection(need_instances)
          end

          return asg
        end

        # Make sure we have a set of instances with scale-in protection set which jives with our config
        # @param need_instances [Integer]: The number of instanceswhich must have scale-in protection set
        def setScaleInProtection(need_instances = @config['min_size'])
          live_instances = []
          begin
            desc = MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).describe_auto_scaling_groups(auto_scaling_group_names: [@mu_name]).auto_scaling_groups.first

            live_instances = desc.instances.map { |i| i.instance_id }
            already_set = 0
            desc.instances.each { |i|
              already_set += 1 if i.protected_from_scale_in
            }
            if live_instances.size < need_instances
              sleep 5
            elsif already_set > need_instances
              unset_me = live_instances.sample(already_set - need_instances)
              MU.log "Disabling scale-in protection for #{unset_me.size.to_s} instances in #{@mu_name}", MU::NOTICE, details: unset_me
              MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).set_instance_protection(
                auto_scaling_group_name: @mu_name,
                instance_ids: unset_me,
                protected_from_scale_in: false
              )
            elsif already_set < need_instances
              live_instances = live_instances.sample(need_instances)
              MU.log "Enabling scale-in protection for #{@config['scale_in_protection']} instances in #{@mu_name}", details: live_instances
              begin
                MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).set_instance_protection(
                  auto_scaling_group_name: @mu_name,
                  instance_ids: live_instances,
                  protected_from_scale_in: true
                )
              rescue Aws::AutoScaling::Errors::ValidationError => e
                if e.message.match(/not in InService/i)
                  sleep 5
                  retry
                else
                  raise e
                end
              end
            end
          end while live_instances.size < need_instances
        end

        # List out the nodes that are members of this pool
        # @return [Array<MU::Cloud::Server>]
        def listNodes
          nodes = []
          me = MU::Cloud::AWS::ServerPool.find(cloud_id: cloud_id).values.first
          if me and me.instances
            me.instances.each { |instance|
              found = MU::MommaCat.findStray("AWS", "server", cloud_id: instance.instance_id, region: @config["region"], dummy_ok: true)
              nodes.concat(found)
            }
          end
          nodes
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          if @config['notifications'] and @config['notifications']['topic']
# XXX expand to a full reference block for a Notification resource
            arn = if @config['notifications']['topic'].match(/^arn:/)
              @config['notifications']['topic']
            else
              "arn:#{MU::Cloud::AWS.isGovCloud?(@config['region']) ? "aws-us-gov" : "aws"}:sns:#{@config['region']}:#{MU::Cloud::AWS.credToAcct(@config['credentials'])}:#{@config['notifications']['topic']}"
            end
            eventmap = {
              "launch" => "autoscaling:EC2_INSTANCE_LAUNCH",
              "failed_launch" => "autoscaling:EC2_INSTANCE_LAUNCH_ERROR",
              "terminate" => "autoscaling:EC2_INSTANCE_TERMINATE",
              "failed_terminate" => "autoscaling:EC2_INSTANCE_TERMINATE_ERROR"
            }
            MU.log "Sending simple notifications (#{@config['notifications']['events'].join(", ")}) to #{arn}"
            MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).put_notification_configuration(
              auto_scaling_group_name: @mu_name,
              topic_arn: arn,
              notification_types: @config['notifications']['events'].map { |e|
                eventmap[e]
              }
            )
          end

          if @config['schedule']
            ext_actions = MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).describe_scheduled_actions(
              auto_scaling_group_name: @mu_name
            ).scheduled_update_group_actions


            @config['schedule'].each { |s|
              sched_config = {
                :auto_scaling_group_name => @mu_name,
                :scheduled_action_name => s['action_name']
              }
              ['max_size', 'min_size', 'desired_capacity', 'recurrence'].each { |flag|
                sched_config[flag.to_sym] = s[flag] if s[flag]
              }
              ['start_time', 'end_time'].each { |flag|
                sched_config[flag.to_sym] = Time.parse(s[flag]) if s[flag]
              }
              action_already_correct = false
              ext_actions.each { |ext|
                if s['action_name'] == ext.scheduled_action_name
                  if !MU.hashCmp(MU.structToHash(ext), sched_config, missing_is_default: true)
                    MU.log "Removing scheduled action #{s['action_name']} from AutoScale group #{@mu_name}"
                    MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).delete_scheduled_action(
                      auto_scaling_group_name: @mu_name,
                      scheduled_action_name: s['action_name']
                    )
                  else
                    action_already_correct = true
                  end
                  break
                end
              }
              if !action_already_correct
                MU.log "Adding scheduled action to AutoScale group #{@mu_name}", MU::NOTICE, details: sched_config
                MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).put_scheduled_update_group_action(
                  sched_config
                )
              end
            }
          end

          createUpdateLaunchConfig

          current = cloud_desc
          asg_options = buildOptionsHash

          need_tag_update = false
          oldtags = current.tags.map { |t|
            t.key+" "+t.value+" "+t.propagate_at_launch.to_s
          }
          tag_conf = { :tags => asg_options[:tags] }
          tag_conf[:tags].each { |t|
            if !oldtags.include?(t[:key]+" "+t[:value]+" "+t[:propagate_at_launch].to_s)
              need_tag_update = true
            end
            t[:resource_id] = @mu_name
            t[:resource_type] = "auto-scaling-group"
          }

          if need_tag_update
            MU.log "Updating ServerPool #{@mu_name} with new tags", MU::NOTICE, details: tag_conf[:tags]

            MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).create_or_update_tags(tag_conf)
            current.instances.each { |instance|
              tag_conf[:tags].each { |t|
                MU::Cloud::AWS.createTag(instance.instance_id, t[:key], t[:value], region: @config['region'], credentials: @config['credentials'])
              }
            }
          end

# XXX actually compare for changes instead of just blindly updating

          asg_options.delete(:tags)
          asg_options[:min_size] = @config["min_size"]
          asg_options[:max_size] = @config["max_size"]
          asg_options[:new_instances_protected_from_scale_in] = (@config['scale_in_protection'] == "all")
          if asg_options[:target_group_arns]
            MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).attach_load_balancer_target_groups(
              auto_scaling_group_name: @mu_name,
              target_group_arns: asg_options[:target_group_arns]
            )
            asg_options.delete(:target_group_arns)
          end

          MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).update_auto_scaling_group(asg_options)

          if @config['scale_in_protection']
            if @config['scale_in_protection'] == "all"
              setScaleInProtection(listNodes.size)
            elsif @config['scale_in_protection'] == "initial"
              setScaleInProtection(@config['min_size'])
            elsif @config['scale_in_protection'].match(/^\d+$/)
              setScaleInProtection(@config['scale_in_protection'].to_i)
            end
          else
            setScaleInProtection(0)
          end

          ext_pols = MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).describe_policies(
            auto_scaling_group_name: @mu_name
          ).scaling_policies
          if @config["scaling_policies"] and @config["scaling_policies"].size > 0
            legit_policies = []
            @config["scaling_policies"].each { |policy|
              legit_policies << @deploy.getResourceName("#{@config['name']}-#{policy['name']}")
            }
            # Delete any scaling policies we're not configured for
            ext_pols.each { |ext|
              if !legit_policies.include?(ext.policy_name)
                MU.log "Scaling policy #{ext.policy_name} is not named in scaling_policies, removing from #{@mu_name}", MU::NOTICE, details: ext
                MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).delete_policy(
                  auto_scaling_group_name: @mu_name,
                  policy_name: ext.policy_name
                )
              end
            }

            @config["scaling_policies"].each { |policy|
              policy_name = @deploy.getResourceName("#{@config['name']}-#{policy['name']}")
              policy_params = {
                :auto_scaling_group_name => @mu_name,
                :policy_name => policy_name,
                :policy_type => policy['policy_type']
              }

              if policy["policy_type"] == "SimpleScaling"
                policy_params[:cooldown] = policy['cooldown']
                policy_params[:scaling_adjustment] = policy['adjustment']
                policy_params[:adjustment_type] = policy['type']
              elsif policy["policy_type"] == "TargetTrackingScaling"
                policy_params[:target_tracking_configuration] = MU.strToSym(policy['target_tracking_configuration'])
                policy_params[:target_tracking_configuration].delete(:preferred_target_group)
                if policy_params[:target_tracking_configuration][:predefined_metric_specification] and
                   policy_params[:target_tracking_configuration][:predefined_metric_specification][:predefined_metric_type] == "ALBRequestCountPerTarget"
                  lb = @deploy.deployment["loadbalancers"].values.first
                  if @deploy.deployment["loadbalancers"].size > 1
                    MU.log "Multiple load balancers attached to Autoscale group #{@mu_name}, guessing wildly which one to use for TargetTrackingScaling policy", MU::WARN
                  end
                  lb_path = if lb["targetgroups"].size > 1
                    if policy['target_tracking_configuration']["preferred_target_group"] and
                       lb["targetgroups"][policy['target_tracking_configuration']["preferred_target_group"]]
                      lb["arn"].split(/:/)[5].sub(/^loadbalancer\//, "")+"/"+lb["targetgroups"][policy['target_tracking_configuration']["preferred_target_group"]].split(/:/)[5]
                    else
                      if policy['target_tracking_configuration']["preferred_target_group"]
                        MU.log "preferred_target_group was set to '#{policy["preferred_target_group"]}' but I don't see a target group by that name", MU::WARN
                      end
                      MU.log "Multiple target groups attached to Autoscale group #{@mu_name}, guessing wildly which one to use for TargetTrackingScaling policy", MU::WARN, details: lb["targetgroups"].keys
                      lb["arn"].split(/:/)[5].sub(/^loadbalancer\//, "")+"/"+lb["targetgroups"].values.first.split(/:/)[5]
                    end
                  end

                  policy_params[:target_tracking_configuration][:predefined_metric_specification][:resource_label] = lb_path
                end
                policy_params[:estimated_instance_warmup] = policy['estimated_instance_warmup']
              elsif policy["policy_type"] == "StepScaling"
                step_adjustments = []
                policy['step_adjustments'].each{|step|
                  step_adjustments << {:metric_interval_lower_bound => step["lower_bound"], :metric_interval_upper_bound => step["upper_bound"], :scaling_adjustment => step["adjustment"]}
                }
                policy_params[:metric_aggregation_type] = policy['metric_aggregation_type']
                policy_params[:step_adjustments] = step_adjustments
                policy_params[:estimated_instance_warmup] = policy['estimated_instance_warmup']
                policy_params[:adjustment_type] = policy['type']
              end

              policy_params[:min_adjustment_magnitude] = policy['min_adjustment_magnitude'] if !policy['min_adjustment_magnitude'].nil?

              policy_already_correct = false
              ext_pols.each { |ext|
                if ext.policy_name == policy_name
                  if !MU.hashCmp(MU.structToHash(ext), policy_params, missing_is_default: true)
                    MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).delete_policy(
                      auto_scaling_group_name: @mu_name,
                      policy_name: policy_name
                    )
                  else
                    policy_already_correct = true
                  end
                  break
                end
              }
              if !policy_already_correct
                MU.log "Putting scaling policy #{policy_name} for #{@mu_name}", MU::NOTICE, details: policy_params
                MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).put_scaling_policy(policy_params)
              end

            }
          end

        end

        @cloud_desc_cache = nil
        # Retrieve the AWS descriptor for this Autoscale group
        # @return [OpenStruct]
        def cloud_desc(use_cache: true)
          return @cloud_desc_cache if @cloud_desc_cache and use_cache
          return nil if !@cloud_id
          @cloud_desc_cache = MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).describe_auto_scaling_groups(
            auto_scaling_group_names: [@mu_name]
          ).auto_scaling_groups.first
          @cloud_desc_cache
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          cloud_desc.auto_scaling_group_arn
        end

        # Retrieve deployment metadata for this Autoscale group
        # @return [Hash]
        def notify
          return MU.structToHash(cloud_desc)
        end

        # Locate an existing ServerPool or ServerPools and return an array containing matching AWS resource descriptors for those that match.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching ServerPools
        def self.find(**args)
          found = {}

          if args[:cloud_id]
            resp = MU::Cloud::AWS.autoscale(region: args[:region], credentials: args[:credentials]).describe_auto_scaling_groups({
              auto_scaling_group_names: [
                args[:cloud_id]
              ], 
            })
            resp.auto_scaling_groups.each { |asg|
              found[asg.auto_scaling_group_name] = asg
            }
          elsif args[:instance_id]
            # try to reverse map from an instance id to an autoscale group
            resp = MU::Cloud::AWS.autoscale(region: args[:region], credentials: args[:credentials]).describe_auto_scaling_instances(instance_ids: [args[:instance_id]])
            if resp and resp.auto_scaling_instances
              asg_names = resp.auto_scaling_instances.map { |g|
                g.auto_scaling_group_name
              }.uniq
              asg_names.each { |asg_name|
                found.merge!(find(cloud_id: asg_name, credentials: args[:credentials], region: args[:region]))
              }
            end
          else
            next_token = nil
            begin
              resp = MU::Cloud::AWS.autoscale(region: args[:region], credentials: args[:credentials]).describe_auto_scaling_groups
              next_token = resp.next_token
              resp.auto_scaling_groups.each { |asg|
                found[asg.auto_scaling_group_name] = asg
              }
            end while next_token
          end

# TODO implement the tag-based search
          return found
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

        if cloud_desc.tags and !cloud_desc.tags.empty?
          cloud_desc.tags.each { |tag|
            bok['tags'] ||= []
            bok['tags'] << { "key" => tag.key, "value" => tag.value }
          }
          realname = MU::Adoption.tagsToName(bok['tags'], basename: @cloud_id)
          if realname
            bok['name'] = realname
            bok['name'].gsub!(/[^a-zA-Z0-9_\-]/, "_")
          end
        end
        bok['name'] ||= @cloud_id

        bok['min_size'] = cloud_desc.min_size
        bok['max_size'] = cloud_desc.max_size

        if cloud_desc.launch_configuration_name
          launch = MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @credentials).describe_launch_configurations(
            launch_configuration_names: [cloud_desc.launch_configuration_name]
          ).launch_configurations.first
          bok['basis'] = {
            "launch_config" => {
              "image_id" => launch.image_id,
              "name" => bok['name'],
              "size" => launch.instance_type
            }
          }
        end

        if cloud_desc.vpc_zone_identifier and
           !cloud_desc.vpc_zone_identifier.empty?
          nets = cloud_desc.vpc_zone_identifier.split(/,/)
          begin
            resp = MU::Cloud::AWS.ec2(region: @config['region'], credentials: @credentials).describe_subnets(subnet_ids: nets).subnets.first
            bok['vpc'] = MU::Config::Ref.get(
              id: resp.vpc_id,
              cloud: "AWS",
              credentials: @credentials,
              type: "vpcs",
              subnets: nets.map { |s| { "subnet_id" => s } }
            )
          rescue Aws::EC2::Errors::InvalidSubnetIDNotFound => e
            if e.message.match(/The subnet ID '(subnet-[a-f0-9]+)' does not exist/)
              nets.delete(Regexp.last_match[1])
              if nets.empty?
                MU.log "Autoscale Group #{@cloud_id} was configured for a VPC, but the configuration held no valid subnets", MU::WARN, details: cloud_desc.vpc_zone_identifier.split(/,/)
              end
            else
              raise e
            end
          end
        end

#        MU.log @cloud_id, MU::NOTICE, details: cloud_desc

        bok
      end


        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []

          term_policies = MU::Cloud::AWS.credConfig ? MU::Cloud::AWS.autoscale.describe_termination_policy_types.termination_policy_types : ["AllocationStrategy", "ClosestToNextInstanceHour", "Default", "NewestInstance", "OldestInstance", "OldestLaunchConfiguration", "OldestLaunchTemplate"]
          
          schema = {
            "role_strip_path" => {
              "type" => "boolean",
              "default" => false,
              "description" => "Normally we namespace IAM roles with a +path+ set to match our +deploy_id+; this disables that behavior. Temporary workaround for a bug in EKS/IAM integration."
            },
            "notifications" => {
              "type" => "object",
              "description" => "Send notifications to an SNS topic for basic AutoScaling events",
              "properties" => {
                "topic" => {
                  "type" => "string",
                  "description" => "The short name or ARN of an SNS topic which should receive notifications for basic Autoscaling events"
                },
               "events" => {
                  "type" => "array",
                  "description" => "The AutoScaling events which should generate a notification",
                  "items" => {
                    "type" => "string",
                    "description" => "The AutoScaling events which should generate a notification",
                    "enum" => ["launch", "failed_launch", "terminate", "failed_terminate"]
                  },
                  "default" => ["launch", "failed_launch", "terminate", "failed_terminate"]
                }
              }
            },
            "generate_iam_role" => {
              "type" => "boolean",
              "default" => true,
              "description" => "Generate a unique IAM profile for this Server or ServerPool.",
            },
            "iam_role" => {
              "type" => "string",
              "description" => "An Amazon IAM instance profile, from which to harvest role policies to merge into this node's own instance profile. If generate_iam_role is false, will simple use this profile.",
            },
            "iam_policies" => {
              "type" => "array",
              "items" => {
                "description" => "Amazon-compatible role policies which will be merged into this node's own instance profile.  Not valid with generate_iam_role set to false. Our parser expects the role policy document to me embedded under a named container, e.g. { 'name_of_policy':'{ <policy document> } }",
                "type" => "object"
              }
            },
            "canned_iam_policies" => {
              "type" => "array",
              "items" => {
                "description" => "IAM policies to attach, pre-defined by Amazon (e.g. AmazonEKSWorkerNodePolicy)",
                "type" => "string"
              }
            },
            "schedule" => {
              "type" => "array",
              "items" => {
                "type" => "object",
                "required" => ["action_name"],
                "description" => "Tell AutoScale to alter min/max/desired for this group at a scheduled time, optionally repeating.",
                "properties" => {
                  "action_name" => {
                    "type" => "string",
                    "description" => "A name for this scheduled action, e.g. 'scale-down-over-night'"
                  },
                  "start_time" => {
                    "type" => "string",
                    "description" => "When should this one-off scheduled behavior take effect? Times are UTC. Must be a valid Ruby Time.parse() string, e.g. '20:00' or '2014-05-12T08:00:00Z'. If declared along with 'recurrence,' AutoScaling performs the action at this time, and then performs the action based on the specified recurrence."
                  },
                  "end_time" => {
                    "type" => "string",
                    "description" => "When should this scheduled behavior end? Times are UTC. Must be a valid Ruby Time.parse() string, e.g. '20:00' or '2014-05-12T08:00:00Z'"
                  },
                  "recurrence" => {
                    "type" => "string",
                    "description" => "A recurring schedule for this action, in Unix cron syntax format (e.g. '0 20 * * *'). Times are UTC."
                  },
                  "min_size" => {"type" => "integer"},
                  "max_size" => {"type" => "integer"},
                  "desired_capacity" => {
                    "type" => "integer",
                    "description" => "The number of Amazon EC2 instances that should be running in the group. Should be between min_size and max_size."
                  },

                }
              }
            },
            "scale_in_protection" => {
              "type" => "string",
              "description" => "Protect instances from scale-in termination. Can be 'all', 'initial' (essentially 'min_size'), or an number; note the number needs to be a string, so put it in quotes",
              "pattern" => "^(all|initial|\\d+)$"
            },
            "scale_with_alb_traffic" => {
              "type" => "float",
              "description" => "Shorthand for creating a target_tracking_configuration to scale on ALBRequestCountPerTarget with some reasonable defaults"
            },
            "scale_with_cpu" => {
              "type" => "float",
              "description" => "Shorthand for creating a target_tracking_configuration to scale on ASGAverageCPUUtilization with some reasonable defaults"
            },
            "scale_with_network_in" => {
              "type" => "float",
              "description" => "Shorthand for creating a target_tracking_configuration to scale on ASGAverageNetworkIn with some reasonable defaults"
            },
            "scale_with_network_out" => {
              "type" => "float",
              "description" => "Shorthand for creating a target_tracking_configuration to scale on ASGAverageNetworkOut with some reasonable defaults"
            },
            "termination_policies" => {
              "type" => "array",
              "minItems" => 1,
              "items" => {
                "type" => "String",
                "default" => "Default",
                "enum" => term_policies
              }
            },
            "scaling_policies" => {
              "type" => "array",
              "minItems" => 1,
              "items" => {
                "type" => "object",
                "required" => ["name"],
                "additionalProperties" => false,
                "description" => "A custom AWS Autoscale scaling policy for this pool.",
                "properties" => {
                  "name" => {
                    "type" => "string"
                  },
                  "alarms" => MU::Config::Alarm.inline,
                  "type" => {
                    "type" => "string",
                    "enum" => ["ChangeInCapacity", "ExactCapacity", "PercentChangeInCapacity"],
                    "description" => "Specifies whether 'adjustment' is an absolute number or a percentage of the current capacity for SimpleScaling and StepScaling. Valid values are ChangeInCapacity, ExactCapacity, and PercentChangeInCapacity."
                  },
                  "adjustment" => {
                    "type" => "integer",
                    "description" => "The number of instances by which to scale. 'type' determines the interpretation of this number (e.g., as an absolute number or as a percentage of the existing Auto Scaling group size). A positive increment adds to the current capacity and a negative value removes from the current capacity. Used only when policy_type is set to 'SimpleScaling'"
                  },
                  "cooldown" => {
                    "type" => "integer",
                    "default" => 1,
                    "description" => "The amount of time, in seconds, after a scaling activity completes and before the next scaling activity can start."
                  },
                  "min_adjustment_magnitude" => {
                    "type" => "integer",
                    "description" => "Used when 'type' is set to 'PercentChangeInCapacity', the scaling policy changes the DesiredCapacity of the Auto Scaling group by at least the number of instances specified in the value."
                  },
                  "policy_type" => {
                    "type" => "string",
                    "enum" => ["SimpleScaling", "StepScaling", "TargetTrackingScaling"],
                    "description" => "'StepScaling' will add capacity based on the magnitude of the alarm breach, 'SimpleScaling' will add capacity based on the 'adjustment' value provided. Defaults to 'SimpleScaling'.",
                    "default" => "SimpleScaling"
                  },
                  "metric_aggregation_type" => {
                    "type" => "string",
                    "enum" => ["Minimum", "Maximum", "Average"],
                    "description" => "Defaults to 'Average' if not specified. Required when policy_type is set to 'StepScaling'",
                    "default" => "Average"
                  },
                  "step_adjustments" => {
                    "type" => "array",
                    "minItems" => 1,
                    "items" => {
                      "type" => "object",
                      "title" => "admin",
                      "description" => "Requires policy_type 'StepScaling'",
                      "required" => ["adjustment"],
                      "additionalProperties" => false,
                      "properties" => {
                        "adjustment" => {
                          "type" => "integer",
                          "description" => "The number of instances by which to scale at this specific step. Postive value when adding capacity, negative value when removing capacity"
                        },
                        "lower_bound" => {
                          "type" => "integer",
                          "description" => "The lower bound value in percentage points above/below the alarm threshold at which to add/remove capacity for this step. Positive value when adding capacity and negative when removing capacity. If this is the first step and capacity is being added this value will most likely be 0"
                        },
                        "upper_bound" => {
                          "type" => "integer",
                          "description" => "The upper bound value in percentage points above/below the alarm threshold at which to add/remove capacity for this step. Positive value when adding capacity and negative when removing capacity. If this is the first step and capacity is being removed this value will most likely be 0"
                        }
                      }
                    }
                  },
                  "estimated_instance_warmup" => {
                    "type" => "integer",
                    "description" => "Required when policy_type is set to 'StepScaling'"
                  },
                  "target_tracking_configuration" => {
                    "type" => "object",
                    "description" => "Required when policy_type is set to 'TargetTrackingScaling' https://docs.aws.amazon.com/sdkforruby/api/Aws/AutoScaling/Types/TargetTrackingConfiguration.html",
                    "required" => ["target_value"],
                    "additionalProperties" => false,
                    "properties" => {
                      "target_value" => {
                        "type" => "float",
                        "description" => "The target value for the metric."
                      },
                      "preferred_target_group" => {
                        "type" => "string",
                        "description" => "If our load balancer has multiple target groups, prefer the one with this name instead of choosing one arbitrarily"
                      },
                      "disable_scale_in" => {
                        "type" => "boolean",
                        "description" => "If set to true, new instances created by this policy will not be subject to termination by scaling in.",
                        "default" => false
                      },
                      "predefined_metric_specification" => {
                        "description" => "A predefined metric. You can specify either a predefined metric or a customized metric. https://docs.aws.amazon.com/sdkforruby/api/Aws/AutoScaling/Types/PredefinedMetricSpecification.html",
                        "type" => "string",
                        "enum" => ["ASGAverageCPUUtilization", "ASGAverageNetworkIn", "ASGAverageNetworkOut", "ALBRequestCountPerTarget"],
                        "default" => "ASGAverageCPUUtilization"
                      },
                      "customized_metric_specification" => {
                        "type" => "object",
                        "description" => "A customized metric. You can specify either a predefined metric or a customized metric. https://docs.aws.amazon.com/sdkforruby/api/Aws/AutoScaling/Types/TargetTrackingConfiguration.html#customized_metric_specification-instance_method",
                        "additionalProperties" => false,
                        "required" => ["metric_name", "namespace", "statistic"],
                        "properties" => {
                          "metric_name" => {
                            "type" => "string",
                            "description" => "The name of the attribute to monitor eg. CPUUtilization."
                          },
                          "namespace" => {
                            "type" => "string",
                            "description" => "The name of container 'metric_name' belongs to eg. 'AWS/ApplicationELB'"
                          },
                          "statistic" => {
                            "type" => "string",
                            "enum" => ["Average", "Minimum", "Maximum", "SampleCount", "Sum"]
                          },
                          "unit" => {
                            "type" => "string",
                            "description" => "Associated with the 'metric', usually something like Megabits or Seconds"
                          },
                          "dimensions" => {
                            "type" => "array",
                            "description" => "What resource to monitor with the alarm we are implicitly declaring",
                            "items" => {
                              "type" => "object",
                              "additionalProperties" => false,
                              "required" => ["name", "value"],
                              "description" => "What resource to monitor with the alarm we are implicitly declaring",
                              "properties" => {
                                "name" => {
                                  "type" => "string",
                                  "description" => "The type of resource we're monitoring, e.g. InstanceId or AutoScalingGroupName"
                                },
                                "value" => {
                                  "type" => "string",
                                  "description" => "The name or cloud identifier of the resource we're monitoring"
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            },
            "ingress_rules" => MU::Cloud.resourceClass("AWS", "FirewallRule").ingressRuleAddtlSchema
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::server_pools}, bare and unvalidated.
        # @param pool [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(pool, configurator)
          ok = true

          if pool["termination_policy"]
            valid_policies = MU::Cloud::AWS.autoscale(region: pool['region']).describe_termination_policy_types.termination_policy_types
            if !valid_policies.include?(pool["termination_policy"])
              ok = false
              MU.log "Termination policy #{pool["termination_policy"]} is not valid in region #{pool['region']}", MU::ERR, details: valid_policies
            end
          end

          if !pool["schedule"].nil?
            pool["schedule"].each { |s|
              if !s['min_size'] and !s['max_size'] and !s['desired_capacity']
                MU.log "Scheduled action for AutoScale group #{pool['name']} must declare at least one of min_size, max_size, or desired_capacity", MU::ERR
                ok = false
              end
              if !s['start_time'] and !s['recurrence']
                MU.log "Scheduled action for AutoScale group #{pool['name']} must declare at least one of start_time or recurrence", MU::ERR
                ok = false
              end
              ['start_time', 'end_time'].each { |time|
                next if !s[time]
                begin
                  Time.parse(s[time])
                rescue StandardError => e
                  MU.log "Failed to parse #{time} '#{s[time]}' in scheduled action for AutoScale group #{pool['name']}: #{e.message}", MU::ERR
                  ok = false
                end
              }
              if s['recurrence'] and !s['recurrence'].match(/^\s*[\d\-\*]+\s+[\d\-\*]+\s[\d\-\*]+\s[\d\-\*]+\s[\d\-\*]\s*$/)
                MU.log "Failed to parse recurrence '#{s['recurrence']}' in scheduled action for AutoScale group #{pool['name']}: does not appear to be a valid cron string", MU::ERR
                ok = false
              end
            }
          end

          scale_aliases = {
            "scale_with_alb_traffic" => "ALBRequestCountPerTarget",
            "scale_with_cpu" => "ASGAverageCPUUtilization",
            "scale_with_network_in" => "ASGAverageNetworkIn",
            "scale_with_network_out" => "ASGAverageNetworkOut"
          }

          scale_aliases.keys.each { |sp|
            if pool[sp]
              pool['scaling_policies'] ||= []
              pool['scaling_policies'] << {
                'name' => scale_aliases[sp],
                'adjustment' => 1,
                'policy_type' => "TargetTrackingScaling",
                'estimated_instance_warmup' => 60,
                'target_tracking_configuration' => {
                  'target_value' => pool[sp],
                  'predefined_metric_specification' => scale_aliases[sp]
                }
              }
            end
          }

          if !pool["basis"]["launch_config"].nil?
            launch = pool["basis"]["launch_config"]
            launch['iam_policies'] ||= pool['iam_policies']

            launch['size'] = MU::Cloud.resourceClass("AWS", "Server").validateInstanceType(launch["size"], pool["region"])
            ok = false if launch['size'].nil?
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

            ["generate_iam_role", "iam_role", "canned_iam_policies", "iam_policies"].each { |key|
              pool[key] = launch[key] if !launch[key].nil?
            }
            MU::Cloud.resourceClass("AWS", "Server").generateStandardRole(pool, configurator)

            launch["ami_id"] ||= launch["image_id"]
            if launch["server"].nil? and launch["instance_id"].nil? and launch["ami_id"].nil?
              img_id = MU::Cloud.getStockImage("AWS", platform: pool['platform'], region: pool['region'])
              if img_id
                launch['ami_id'] = configurator.getTail("pool"+pool['name']+"AMI", value: img_id, prettyname: "pool"+pool['name']+"AMI", cloudtype: "AWS::EC2::Image::Id")
  
              else
                ok = false
                MU.log "One of the following MUST be specified for launch_config: server, ami_id, instance_id.", MU::ERR
              end
            end
            if launch["server"] != nil
              MU::Config.addDependency(pool, launch["server"], "server", phase: "groom")
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
                unless policy['type']
                  MU.log "You must specify a 'type' when 'policy_type' is set to 'SimpleScaling'", MU::ERR
                  ok = false
                end
              elsif policy["policy_type"] == "TargetTrackingScaling"
                unless policy["target_tracking_configuration"]
                  MU.log "You must specify 'target_tracking_configuration' when 'policy_type' is set to 'TargetTrackingScaling'", MU::ERR
                  ok = false
                end
                unless policy["target_tracking_configuration"]["customized_metric_specification"] or
                       policy["target_tracking_configuration"]["predefined_metric_specification"]
                  MU.log "Your target_tracking_configuration must specify one of customized_metric_specification or predefined_metric_specification when 'policy_type' is set to 'TargetTrackingScaling'", MU::ERR
                  ok = false
                end
                # we gloss over an annoying layer of indirection in the API here
                if policy["target_tracking_configuration"]["predefined_metric_specification"]
                  policy["target_tracking_configuration"]["predefined_metric_specification"] = {
                    "predefined_metric_type" => policy["target_tracking_configuration"]["predefined_metric_specification"]
                  }
                end
              elsif policy["policy_type"] == "StepScaling"
                if policy["step_adjustments"].nil? || policy["step_adjustments"].empty?
                  MU.log "You must specify 'step_adjustments' when 'policy_type' is set to 'StepScaling'", MU::ERR
                  ok = false
                end
                unless policy['type']
                  MU.log "You must specify a 'type' when 'policy_type' is set to 'StepScaling'", MU::ERR
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
                  alarm["cloud"] = "AWS",
                  alarm['dimensions'] = [] if !alarm['dimensions']
                  alarm['dimensions'] << { "name" => pool["name"], "cloud_class" => "AutoScalingGroupName" }
                  alarm["namespace"] = "AWS/EC2" if alarm["namespace"].nil?
                  alarm['cloud'] = pool['cloud']
                  alarm['credentials'] = pool['credentials']
                  alarm['region'] = pool['region']
                  ok = false if !configurator.insertKitten(alarm, "alarms")
                }
              end
            }
          end
          ok
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
          MU::Cloud::RELEASE
        end

        # Remove all autoscale groups associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          MU.log "AWS::ServerPool.cleanup: need to support flags['known']", MU::DEBUG, details: flags

          filters = [{name: "key", values: ["MU-ID"]}]
          if !ignoremaster
            filters << {name: "key", values: ["MU-MASTER-IP"]}
          end
          resp = MU::Cloud::AWS.autoscale(credentials: credentials, region: region).describe_tags(
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
            if asg.key == "MU-ID" and asg.value == deploy_id
              maybe_purge << asg.resource_id
            end
          }


          maybe_purge.each { |resource_id|
            next if no_purge.include?(resource_id)
            MU.log "Removing AutoScale group #{resource_id}"
            next if noop
            retries = 0
            begin
              MU::Cloud::AWS.autoscale(credentials: credentials, region: region).delete_auto_scaling_group(
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

#            MU::Cloud.resourceClass("AWS", "Server").removeIAMProfile(resource_id)

            # Generally there should be a launch_configuration of the same name
            # XXX search for these independently, too?
            retries = 0
            begin
              MU.log "Removing AutoScale Launch Configuration #{resource_id}"
              MU::Cloud::AWS.autoscale(credentials: credentials, region: region).delete_launch_configuration(
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

        private

        def createUpdateLaunchConfig
          return if !@config['basis'] or !@config['basis']["launch_config"]

          instance_secret = Password.random(50)
          @deploy.saveNodeSecret("default", instance_secret, "instance_secret")

          if !@config['basis']['launch_config']["server"].nil?
            #XXX this isn't how we find these; use findStray or something
            if @deploy.deployment["images"].nil? or @deploy.deployment["images"][@config['basis']['launch_config']["server"]].nil?
              raise MuError, "#{@mu_name} needs an AMI from server #{@config['basis']['launch_config']["server"]}, but I don't see one anywhere"
            end
            @config['basis']['launch_config']["ami_id"] = @deploy.deployment["images"][@config['basis']['launch_config']["server"]]["image_id"]
            MU.log "Using AMI '#{@config['basis']['launch_config']["ami_id"]}' from sibling server #{@config['basis']['launch_config']["server"]} in ServerPool #{@mu_name}"
          elsif !@config['basis']['launch_config']["instance_id"].nil?
            @config['basis']['launch_config']["ami_id"] = MU::Cloud.resourceClass("AWS", "Server").createImage(
              name: @mu_name,
              instance_id: @config['basis']['launch_config']["instance_id"],
              credentials: @config['credentials'],
              region: @config['region']
            )[@config['region']]
          end
          MU::Cloud.resourceClass("AWS", "Server").waitForAMI(@config['basis']['launch_config']["ami_id"], credentials: @config['credentials'])

          oldlaunch = MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).describe_launch_configurations(
            launch_configuration_names: [@mu_name]
          ).launch_configurations.first

          userdata = MU::Cloud.fetchUserdata(
            platform: @config["platform"],
            cloud: "AWS",
            credentials: @config['credentials'],
            template_variables: {
              "deployKey" => Base64.urlsafe_encode64(@deploy.public_key),
              "deploySSHKey" => @deploy.ssh_public_key,
              "muID" => @deploy.deploy_id,
              "muUser" => MU.chef_user,
              "publicIP" => MU.mu_public_ip,
              "mommaCatPort" => MU.mommaCatPort,
              "chefVersion" => MU.chefVersion,
              "adminBucketName" => MU::Cloud::AWS.adminBucketName(@credentials),
              "windowsAdminName" => @config['windows_admin_username'],
              "skipApplyUpdates" => @config['skipinitialupdates'],
              "resourceName" => @config["name"],
              "resourceType" => "server_pool",
              "platform" => @config["platform"]
            },
            custom_append: @config['userdata_script']
          )

          # Figure out which devices are embedded in the AMI already.
          image = MU::Cloud::AWS.ec2.describe_images(image_ids: [@config["basis"]["launch_config"]["ami_id"]]).images.first

          if image.nil?
            raise "#{@config["basis"]["launch_config"]["ami_id"]} does not exist, cannot update/create launch config #{@mu_name}"
          end

          ext_disks = {}
          if !image.block_device_mappings.nil?
            image.block_device_mappings.each { |disk|
              if !disk.device_name.nil? and !disk.device_name.empty? and !disk.ebs.nil? and !disk.ebs.empty?
                ext_disks[disk.device_name] = MU.structToHash(disk.ebs)
                if ext_disks[disk.device_name].has_key?(:snapshot_id)
                  ext_disks[disk.device_name].delete(:encrypted)
                end
              end
            }
          end

          storage = []
          if !@config["basis"]["launch_config"]["storage"].nil?
            @config["basis"]["launch_config"]["storage"].each { |vol|
              if ext_disks.has_key?(vol["device"])
                if ext_disks[vol["device"]].has_key?(:snapshot_id)
                  vol.delete("encrypted")
                end
              end
              mapping, _cfm_mapping = MU::Cloud.resourceClass("AWS", "Server").convertBlockDeviceMapping(vol)
              storage << mapping
            }
          end

          storage.concat(MU::Cloud.resourceClass("AWS", "Server").ephemeral_mappings)

          if !oldlaunch.nil?
            olduserdata = Base64.decode64(oldlaunch.user_data)
            if userdata == olduserdata and
                oldlaunch.image_id == @config["basis"]["launch_config"]["ami_id"] and
                oldlaunch.ebs_optimized == @config["basis"]["launch_config"]["ebs_optimized"] and
                oldlaunch.instance_type == @config["basis"]["launch_config"]["size"] and
                oldlaunch.instance_monitoring.enabled == @config["basis"]["launch_config"]["monitoring"]
                # XXX check more things
#                launch.block_device_mappings != storage
#                XXX block device comparison isn't this simple
              return
            end

            # Put our Autoscale group onto a temporary launch config
            begin

              MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).create_launch_configuration(
                launch_configuration_name: @mu_name+"-TMP",
                user_data: Base64.encode64(olduserdata),
                image_id: oldlaunch.image_id,
                key_name: oldlaunch.key_name,
                security_groups: oldlaunch.security_groups,
                instance_type: oldlaunch.instance_type,
                block_device_mappings: storage,
                instance_monitoring: oldlaunch.instance_monitoring,
                iam_instance_profile: oldlaunch.iam_instance_profile,
                ebs_optimized: oldlaunch.ebs_optimized,
                associate_public_ip_address: oldlaunch.associate_public_ip_address
              )
            rescue ::Aws::AutoScaling::Errors::ValidationError => e
              if e.message.match(/Member must have length less than or equal to (\d+)/)
                MU.log "Userdata script too long updating #{@mu_name} Launch Config (#{Base64.encode64(userdata).size.to_s}/#{Regexp.last_match[1]} bytes)", MU::ERR
              else
                MU.log "Error updating #{@mu_name} Launch Config", MU::ERR, details: e.message
              end
              raise e.message
            end


            MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).update_auto_scaling_group(
              auto_scaling_group_name: @mu_name,
              launch_configuration_name: @mu_name+"-TMP"
            )
            # ...now back to an identical one with the "real" name
            MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).delete_launch_configuration(
              launch_configuration_name: @mu_name
            )
          end

          # Now to build the new one
          sgs = []
          if @dependencies.has_key?("firewall_rule")
            @dependencies['firewall_rule'].values.each { |sg|
              sgs << sg.cloud_id
            }
          end

          launch_options = {
            :launch_configuration_name => @mu_name,
            :user_data => Base64.encode64(userdata),
            :image_id => @config["basis"]["launch_config"]["ami_id"],
            :key_name => @deploy.ssh_key_name,
            :security_groups => sgs,
            :instance_type => @config["basis"]["launch_config"]["size"],
            :block_device_mappings => storage,
            :instance_monitoring => {:enabled => @config["basis"]["launch_config"]["monitoring"]},
            :ebs_optimized => @config["basis"]["launch_config"]["ebs_optimized"]
          }
          if @config["vpc"] or @config["vpc_zone_identifier"]
            launch_options[:associate_public_ip_address] = @config["associate_public_ip"]
          end
          ["kernel_id", "ramdisk_id", "spot_price"].each { |arg|
            if @config['basis']['launch_config'][arg]
              launch_options[arg.to_sym] = @config['basis']['launch_config'][arg]
            end
          }
          rolename = nil

          ['generate_iam_role', 'iam_policies', 'canned_iam_policies', 'iam_role'].each { |field|
            if !@config['basis']['launch_config'].nil?
              @config[field] = @config['basis']['launch_config'][field]
            else
              @config['basis']['launch_config'][field] = @config[field]
            end
          }

          @config['iam_role'] = @config['basis']['launch_config']['iam_role'] = launch_options[:iam_instance_profile] = MU::Cloud.resourceClass("AWS", "Server").getIAMProfile(
            @config['name'],
            @deploy,
            generated: @config['basis']['launch_config']['generate_iam_role'],
            role_name: @config['basis']['launch_config']['iam_role'],
            region: @config['region'],
            credentials: @credentials
          ).values.first

          lc_attempts = 0
          begin
            MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).create_launch_configuration(launch_options)
          rescue Aws::AutoScaling::Errors::ValidationError => e
            if lc_attempts > 3
              MU.log "Got error while creating #{@mu_name} Launch Config#{@config['credentials'] ? " with credentials #{@config['credentials']}" : ""}: #{e.message}, retrying in 10s", MU::WARN, details: launch_options.reject { |k,_v | k == :user_data }
            end
            sleep 5
            lc_attempts += 1
            retry
          end

          if !oldlaunch.nil?
            # Tell the ASG to use the new one, and nuke the old one
            MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).update_auto_scaling_group(
              auto_scaling_group_name: @mu_name,
              launch_configuration_name: @mu_name
            )
            MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).delete_launch_configuration(
              launch_configuration_name: @mu_name+"-TMP"
            )
            MU.log "Launch Configuration #{@mu_name} replaced"
          else
            MU.log "Launch Configuration #{@mu_name} created"
          end

        end

        def buildOptionsHash
          asg_options = {
            :auto_scaling_group_name => @mu_name,
            :launch_configuration_name => @mu_name,
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

          if @dependencies.has_key?("container_cluster")
            @dependencies['container_cluster'].values.each { |cc|
              if cc.config['flavor'] == "EKS"
                asg_options[:tags] << {
                  key: "kubernetes.io/cluster/#{cc.mu_name}",
                  value: "owned",
                  propagate_at_launch: true
                }
              end
            }
          end

          if @config["wait_for_nodes"] > 0
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
                lb = @deploy.findLitterMate(name: lb['concurrent_load_balancer'], type: "loadbalancers")
                raise MuError, "No loadbalancers exist! I need one named #{lb['concurrent_load_balancer']}" if !lb
                lbs << lb.mu_name
                if lb.targetgroups
                  tg_arns = lb.targetgroups.values.map { |tg| tg.target_group_arn }
                end
              end
            }
            if tg_arns.size > 0
              asg_options[:target_group_arns] = tg_arns
            end
            if lbs.size > 0
#              asg_options[:load_balancer_names] = lbs
            end
          end
          asg_options[:termination_policies] = @config["termination_policies"] if @config["termination_policies"]
          asg_options[:desired_capacity] = @config["desired_capacity"] if @config["desired_capacity"]

          if @config["vpc_zone_identifier"]
            asg_options[:vpc_zone_identifier] = @config["vpc_zone_identifier"]
          elsif @config["vpc"]
            if !@vpc and @config['vpc'].is_a?(MU::Config::Ref)
              @vpc = @config['vpc'].kitten
            end

            subnet_ids = []

            if !@vpc
              raise MuError, "Failed to load vpc for Autoscale Group #{@mu_name}"
            end
            if !@config["vpc"]["subnets"].nil? and @config["vpc"]["subnets"].size > 0
              @config["vpc"]["subnets"].each { |subnet|
                subnet_obj = @vpc.getSubnet(cloud_id: subnet["subnet_id"], name: subnet["subnet_name"])
                next if !subnet_obj
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


          if @config['basis']["server"]
            srv_name = @config['basis']["server"]
# XXX cloudformation bits
            if @deploy.deployment['servers'] != nil and
                @deploy.deployment['servers'][srv_name] != nil
              asg_options[:instance_id] = @deploy.deployment['servers'][srv_name]["instance_id"]
            end
          elsif @config['basis']["instance_id"]
            # TODO should go fetch the name tag or something
# XXX cloudformation bits
            asg_options[:instance_id] = @config['basis']["instance_id"]
          end

          if !asg_options[:vpc_zone_identifier].nil? and asg_options[:vpc_zone_identifier].empty?
            asg_options.delete(:vpc_zone_identifier)
          end

          # Do the dance of specifying individual zones if we haven't asked to
          # use particular VPC subnets.
          if @config['zones'].nil? and asg_options[:vpc_zone_identifier].nil?
            @config["zones"] = MU::Cloud::AWS.listAZs(region: @config['region'])
            MU.log "Using zones from #{@config['region']}", MU::DEBUG, details: @config['zones']
          end
          asg_options[:availability_zones] = @config["zones"] if @config["zones"] != nil
          asg_options
        end

      end
    end
  end
end
