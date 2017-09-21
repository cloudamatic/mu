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
      # A load balancer as configured in {MU::Config::BasketofKittens::loadbalancers}
      class LoadBalancer < MU::Cloud::LoadBalancer

        @deploy = nil
        @lb = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id
        attr_reader :targetgroups

        @cloudformation_data = {}
        attr_reader :cloudformation_data

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::loadbalancers}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          if !mu_name.nil?
            @mu_name = mu_name
          elsif @config['scrub_mu_isms']
            @mu_name = @config['name']
          else
            @mu_name = @deploy.getResourceName(@config["name"], max_length: 32, need_unique_string: true)
            @mu_name.gsub!(/[^\-a-z0-9]/i, "-") # AWS ELB naming rules
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          if @config["zones"] == nil
            @config["zones"] = MU::Cloud::AWS.listAZs(@config['region'])
            MU.log "Using zones from #{@config['region']}", MU::DEBUG, details: @config['zones']
          end

          lb_options = {
            tags: []
          }
          if @config['classic']
            lb_options[:load_balancer_name] = @mu_name
          else
            lb_options[:name] = @mu_name
          end

          MU::MommaCat.listStandardTags.each_pair { |name, value|
            lb_options[:tags] << {key: name, value: value}
          }

          if @config['optional_tags']
            MU::MommaCat.listOptionalTags.each_pair { |name, value|
              lb_options[:tags] << {key: name, value: value}
            }
          end

          if !@config['tags'].nil?
            @config['tags'].each { |tag|
              lb_options[:tags] << {key: tag['key'], value: tag['value']}
            }
          end

          sgs = []
          if @dependencies.has_key?("firewall_rule")
            @dependencies['firewall_rule'].values.each { |sg|
              sgs << sg.cloud_id
            }
          end
          if sgs.size > 0 and !@config['vpc'].nil?
            lb_options[:security_groups] = sgs
            @config['sgs'] = sgs
          end

          if @config["vpc"] != nil
            if @vpc.nil?
              raise MuError, "LoadBalancer #{@config['name']} is configured to use a VPC, but no VPC found"
            end
            lb_options[:subnets] = []
            @config["vpc"]["subnets"].each { |subnet|
              subnet_obj = @vpc.getSubnet(cloud_id: subnet["subnet_id"], name: subnet["subnet_name"])
              if subnet_obj.nil?
                raise MuError, "Failed to locate subnet from #{subnet} in LoadBalancer #{@config['name']}"
              end
              lb_options[:subnets] << subnet_obj.cloud_id
            }
            if @config["private"]
              lb_options[:scheme] = "internal"
            end
          else
            lb_options[:availability_zones] = @config["zones"]
          end

          listeners = Array.new
          if @config['classic']
            @config["listeners"].each { |listener|
              listen_struct = {
                :load_balancer_port => listener["lb_port"],
                :protocol => listener["lb_protocol"],
                :instance_port => listener["instance_port"],
                :instance_protocol => listener["instance_protocol"]
              }
              listen_struct[:ssl_certificate_id] = listener["ssl_certificate_id"] if !listener["ssl_certificate_id"].nil?

              listeners << listen_struct
            }
            lb_options[:listeners] = listeners
          end

          zones_to_try = @config["zones"]
          retries = 0
          lb = nil
          begin
            if @config['classic']
              MU.log "Creating Elastic Load Balancer #{@mu_name}", details: lb_options
              lb = MU::Cloud::AWS.elb(@config['region']).create_load_balancer(lb_options)
            else
              MU.log "Creating Application Load Balancer #{@mu_name}", details: lb_options
              lb = MU::Cloud::AWS.elb2(@config['region']).create_load_balancer(lb_options).load_balancers.first
              begin
                if lb.state.code != "active"
                  MU.log "Waiting for ALB #{@mu_name} to enter 'active' state", MU::NOTICE
                  sleep 20
                  lb = MU::Cloud::AWS.elb2(@config['region']).describe_load_balancers(
                    names: [@mu_name]
                  ).load_balancers.first
                end
              end while lb.state.code != "active"
            end
          rescue Aws::ElasticLoadBalancing::Errors::ValidationError, Aws::ElasticLoadBalancing::Errors::SubnetNotFound, Aws::ElasticLoadBalancing::Errors::InvalidConfigurationRequest => e
            if zones_to_try.size > 0 and lb_options.has_key?(:availability_zones)
              MU.log "Got #{e.inspect} when creating #{@mu_name} retrying with individual AZs in case that's the problem", MU::WARN
              lb_options[:availability_zones] = [zones_to_try.pop]
              retry
            else
              raise MuError, "#{e.inspect} when creating #{@mu_name}", e.backtrace
            end
          rescue Aws::ElasticLoadBalancing::Errors::InvalidSecurityGroup => e
            if retries < 5
              MU.log "#{e.inspect}, waiting then retrying", MU::WARN
              sleep 10
              retries = retries + 1
              retry
            else
              raise MuError, "#{e.inspect} when creating #{@mu_name}", e.backtrace
            end
          end
          @cloud_id = @mu_name
          MU.log "Load Balancer is at #{lb.dns_name}"

          parent_thread_id = Thread.current.object_id
          dnsthread = Thread.new {
            MU.dupGlobals(parent_thread_id)
            MU::Cloud::AWS::DNSZone.genericMuDNSEntry(name: @mu_name, target: "#{lb.dns_name}.", cloudclass: MU::Cloud::LoadBalancer, sync_wait: @config['dns_sync_wait'])
          }

          if zones_to_try.size < @config["zones"].size
            zones_to_try.each { |zone|
              begin
                MU::Cloud::AWS.elb(@config['region']).enable_availability_zones_for_load_balancer(
                  load_balancer_name: @mu_name,
                  availability_zones: [zone]
                )
              rescue Aws::ElasticLoadBalancing::Errors::ValidationError => e
                MU.log "Couldn't enable Availability Zone #{zone} for Load Balancer #{@mu_name} (#{e.message})", MU::WARN
              end
            }
          end

          @targetgroups = {}
          if !@config['healthcheck'].nil? and @config['classic']
            MU.log "Configuring custom health check for ELB #{@mu_name}", details: @config['healthcheck']
            MU::Cloud::AWS.elb(@config['region']).configure_health_check(
                load_balancer_name: @mu_name,
                health_check: {
                    target: @config['healthcheck']['target'],
                    interval: @config['healthcheck']['interval'],
                    timeout: @config['healthcheck']['timeout'],
                    unhealthy_threshold: @config['healthcheck']['unhealthy_threshold'],
                    healthy_threshold: @config['healthcheck']['healthy_threshold']
                }
            )
          elsif !@config['classic']
            if @config['targetgroups']
              MU.log "Configuring target groups and health checks check for ELB #{@mu_name}", details: @config['healthcheck']
              @config['targetgroups'].each { |tg|
                tg_name = @deploy.getResourceName(tg["name"], max_length: 32)
                tg_descriptor = {
                  :name => tg_name,
                  :protocol => tg['proto'],
                  :vpc_id => @vpc.cloud_id,
                  :port => tg['port']
                }
                if tg['httpcode']
                  tg_descriptor[:matcher] = {
                    :http_code => tg['httpcode']
                  }
                end
                if tg['healthcheck']
                  hc_target = tg['healthcheck']['target'].match(/^([^:]+):(\d+)(.*)/)
                  tg_descriptor[:health_check_protocol] = hc_target[1]
                  tg_descriptor[:health_check_port] = hc_target[2]
                  tg_descriptor[:health_check_path] = hc_target[3]
                  tg_descriptor[:health_check_interval_seconds] = tg['healthcheck']['interval']
                  tg_descriptor[:health_check_timeout_seconds] = tg['healthcheck']['timeout']
                  tg_descriptor[:healthy_threshold_count] = tg['healthcheck']['healthy_threshold']
                  tg_descriptor[:unhealthy_threshold_count] = tg['healthcheck']['unhealthy_threshold']
                  if tg['healthcheck']['httpcode'] and !tg_descriptor.has_key?(:matcher)
                    tg_descriptor[:matcher] = {
                      :http_code => tg['healthcheck']['httpcode']
                    }
                  end
                end

                tg_resp = MU::Cloud::AWS.elb2(@config['region']).create_target_group(tg_descriptor)
                @targetgroups[tg['name']] = tg_resp.target_groups.first
                MU::Cloud::AWS.elb2(@config['region']).add_tags(
                  resource_arns: [tg_resp.target_groups.first.target_group_arn],
                  tags: lb_options[:tags]
                )
              }
            end
          end

          if !@config['classic']
            @config["listeners"].each { |l|
              if !@targetgroups.has_key?(l['targetgroup'])
                raise MuError, "Listener in #{@mu_name} configured for target group #{l['targetgroup']}, but I don't have data on a targetgroup by that name"
              end
              listen_descriptor = {
                :default_actions => [{
                  :target_group_arn => @targetgroups[l['targetgroup']].target_group_arn,
                  :type => "forward"
                }], 
                :load_balancer_arn => lb.load_balancer_arn,
                :port => l['lb_port'], 
                :protocol => l['lb_protocol']
              }
              if l['ssl_certificate_id']
                listen_descriptor[:certificates] = [{
                  :certificate_arn => l['ssl_certificate_id']
                }]
                listen_descriptor[:ssl_policy] = case l['tls_policy']
                when "tls1.0"
                  "ELBSecurityPolicy-TLS-1-0-2015-04"
                when "tls1.1"
                  "ELBSecurityPolicy-TLS-1-1-2017-01"
                when "tls1.2"
                  "ELBSecurityPolicy-TLS-1-2-2017-01"
                end
              end
              listen_resp = MU::Cloud::AWS.elb2(@config['region']).create_listener(listen_descriptor).listeners.first
              if !l['rules'].nil?
                l['rules'].each { |rule|
                  rule_descriptor = {
                    :listener_arn => listen_resp.listener_arn,
                    :priority => rule['order'],
                    :conditions => rule['conditions'],
                    :actions => []
                  }
                  rule['actions'].each { |a|
                    rule_descriptor[:actions] << {
                      :target_group_arn => @targetgroups[a['targetgroup']].target_group_arn,
                      :type => a['action']
                    }
                  }
                  MU::Cloud::AWS.elb2(@config['region']).create_rule(rule_descriptor)
                }
              end
            }
          else
            @config["listeners"].each { |l|
              if l['ssl_certificate_id']
                resp = MU::Cloud::AWS.elb(@config['region']).set_load_balancer_policies_of_listener(
                  load_balancer_name: @cloud_id, 
                  load_balancer_port: l['lb_port'], 
                  policy_names: [
                    case l['tls_policy']
                    when "tls1.0"
                      "ELBSecurityPolicy-2016-08"
                    when "tls1.1"
                      # XXX This policy shows up in the console, but doesn't
                      # work there either. I think it's Amazon's bug, though we
                      # could get around it by creating a custom policy with all
                      # the bits we want. Ugh. Just use an ALB, man.
                      # "ELBSecurityPolicy-TLS-1-1-2017-01" 
                      MU.log "Correct TLS1.1 cipher policy for classic Load Balancers is currently not supported, falling back to ELBSecurityPolicy-2016-08", MU::WARN
                      "ELBSecurityPolicy-2016-08"
                    when "tls1.2"
                      # XXX This policy shows up in the console, but doesn't
                      # work there either. I think it's Amazon's bug, though we
                      # could get around it by creating a custom policy with all
                      # the bits we want. Ugh. Just use an ALB, man.
                      # "ELBSecurityPolicy-TLS-1-2-2017-01" 
                      MU.log "Correct TLS1.2 cipher policy for classic Load Balancers is currently not supported, falling back to ELBSecurityPolicy-2016-08", MU::WARN
                      "ELBSecurityPolicy-2016-08"
                    end
                  ]
                )
              end
            }
          end

          if @config['cross_zone_unstickiness'] 
            MU.log "Enabling cross-zone un-stickiness on #{lb.dns_name}"
            if @config['classic']
              MU::Cloud::AWS.elb(@config['region']).modify_load_balancer_attributes(
                load_balancer_name: @mu_name,
                load_balancer_attributes: {
                  cross_zone_load_balancing: {
                    enabled: true
                  }
                }
              )
            else
              @targetgroups.each_pair { |tg_name, tg|
                MU::Cloud::AWS.elb2(@config['region']).modify_target_group_attributes(
                  target_group_arn: tg.target_group_arn,
                  attributes: [
                    {
                      key: "stickiness.enabled",
                      value: "true"
                    }
                  ]
                )
              }
            end
          end

          if !@config['idle_timeout'].nil?
            MU.log "Setting idle timeout to #{@config['idle_timeout']} #{lb.dns_name}"
            if @config['classic']
              MU::Cloud::AWS.elb(@config['region']).modify_load_balancer_attributes(
                load_balancer_name: @mu_name,
                load_balancer_attributes: {
                  connection_settings: {
                    idle_timeout: @config['idle_timeout']
                  }
                }
              )
            else
              MU::Cloud::AWS.elb2(@config['region']).modify_load_balancer_attributes(
                load_balancer_arn: lb.load_balancer_arn,
                attributes: [
                  {
                    key: "idle_timeout.timeout_seconds",
                    value: @config['idle_timeout'].to_s
                  }
                ]
              )
            end
          end

          if !@config['connection_draining_timeout'].nil?
            if @config['classic']
              if @config['connection_draining_timeout'] >= 0
                MU.log "Setting connection draining timeout to #{@config['connection_draining_timeout']} on #{lb.dns_name}"
                MU::Cloud::AWS.elb(@config['region']).modify_load_balancer_attributes(
                    load_balancer_name: @mu_name,
                    load_balancer_attributes: {
                        connection_draining: {
                            enabled: true,
                            timeout: @config['connection_draining_timeout']
                        }
                    }
                )
              else
                MU.log "Disabling connection draining on #{lb.dns_name}"
                MU::Cloud::AWS.elb(@config['region']).modify_load_balancer_attributes(
                    load_balancer_name: @mu_name,
                    load_balancer_attributes: {
                        connection_draining: {
                            enabled: false
                        }
                    }
                )
              end
            else
              timeout = @config['connection_draining_timeout'].to_s
              if @config['connection_draining_timeout'] >= 0
                MU.log "Setting connection draining timeout to #{@config['connection_draining_timeout']} on #{lb.dns_name}"
              else
                timeout = 0
                MU.log "Disabling connection draining on #{lb.dns_name}"
              end
              @targetgroups.each_pair { |tg_name, tg|
                MU::Cloud::AWS.elb2(@config['region']).modify_target_group_attributes(
                  target_group_arn: tg.target_group_arn,
                  attributes: [
                    {
                      key: "deregistration_delay.timeout_seconds",
                      value: timeout.to_s
                    }
                  ]
                )
              }
            end
          end

          if !@config['access_log'].nil?
            MU.log "Setting access log params for #{lb.dns_name}", details: @config['access_log']
            if @config['classic']
              MU::Cloud::AWS.elb(@config['region']).modify_load_balancer_attributes(
                load_balancer_name: @mu_name,
                load_balancer_attributes: {
                  access_log: {
                    enabled: @config['access_log']['enabled'],
                    emit_interval: @config['access_log']['emit_interval'],
                    s3_bucket_name: @config['access_log']['s3_bucket_name'],
                    s3_bucket_prefix: @config['access_log']['s3_bucket_prefix']
                  }
                }
              )
            else
              MU::Cloud::AWS.elb2(@config['region']).modify_load_balancer_attributes(
                load_balancer_arn: lb.load_balancer_arn,
                attributes: [
                  {
                    key: "access_logs.s3.enabled",
                    value: "true"
                  },
                  {
                    key: "access_logs.s3.bucket",
                    value: @config['access_log']['s3_bucket_name']
                  },
                  {
                    key: "access_logs.s3.prefix",
                    value: @config['access_log']['s3_bucket_prefix']
                  }
                ]
              )
            end
          end

          if !@config['lb_cookie_stickiness_policy'].nil?
            MU.log "Setting ELB cookie stickiness policy for #{lb.dns_name}", details: @config['lb_cookie_stickiness_policy']
            if @config['classic']
              cookie_policy = {
                load_balancer_name: @mu_name,
                policy_name: @config['lb_cookie_stickiness_policy']['name']
              }
              if !@config['lb_cookie_stickiness_policy']['timeout'].nil?
                cookie_policy[:cookie_expiration_period] = @config['lb_cookie_stickiness_policy']['timeout']
              end
              MU::Cloud::AWS.elb(@config['region']).create_lb_cookie_stickiness_policy(cookie_policy)
              lb_policy_names = Array.new
              lb_policy_names << @config['lb_cookie_stickiness_policy']['name']
              listener_policy = {
                load_balancer_name: @mu_name,
                policy_names: lb_policy_names
              }
              lb_options[:listeners].each do |listener|
                if listener[:protocol].upcase == 'HTTP' or listener[:protocol].upcase == 'HTTPS'
                  listener_policy[:load_balancer_port] = listener[:load_balancer_port]
                  MU::Cloud::AWS.elb(@config['region']).set_load_balancer_policies_of_listener(listener_policy)
                end
              end
            else
              @targetgroups.each_pair { |tg_name, tg|
                MU::Cloud::AWS.elb2(@config['region']).modify_target_group_attributes(
                  target_group_arn: tg.target_group_arn,
                  attributes: [
                    {
                      key: "stickiness.type",
                      value: "lb_cookie"
                    },
                    {
                      key: "stickiness.enabled",
                      value: "true"
                    },
                    {
                      key: "stickiness.lb_cookie.duration_seconds",
                      value: @config['lb_cookie_stickiness_policy']['timeout'].to_s
                    }
                  ]
                )
              }
            end
          end

          if !@config['app_cookie_stickiness_policy'].nil? 
            if @config['classic']
              MU.log "Setting application cookie stickiness policy for #{lb.dns_name}", details: @config['app_cookie_stickiness_policy']
              cookie_policy = {
                load_balancer_name: @mu_name,
                policy_name: @config['app_cookie_stickiness_policy']['name'],
                cookie_name: @config['app_cookie_stickiness_policy']['cookie']
              }
              MU::Cloud::AWS.elb(@config['region']).create_app_cookie_stickiness_policy(cookie_policy)
              lb_policy_names = Array.new
              lb_policy_names << @config['app_cookie_stickiness_policy']['name']
              listener_policy = {
                load_balancer_name: @mu_name,
                policy_names: lb_policy_names
              }
              lb_options[:listeners].each do |listener|
                if listener[:protocol].upcase == 'HTTP' or listener[:protocol].upcase == 'HTTPS'
                  listener_policy[:load_balancer_port] = listener[:load_balancer_port]
                  MU::Cloud::AWS.elb(@config['region']).set_load_balancer_policies_of_listener(listener_policy)
                end
              end
            else
              MU.log "App cookie stickiness not supported in ALBs. Redeploy with 'classic' set to true if you need this functionality.", MU::WARN
            end
          end

          dnsthread.join # from genericMuDNS

# XXX fix for elb2
#          if !@config['dns_records'].nil?
            # XXX this should be a call to @deploy.nameKitten
#            @config['dns_records'].each { |dnsrec|
#              dnsrec['name'] = @mu_name.downcase if !dnsrec.has_key?('name')
#              dnsrec['name'] = "#{dnsrec['name']}.#{MU.environment.downcase}" if dnsrec["append_environment_name"] && !dnsrec['name'].match(/\.#{MU.environment.downcase}$/)
#            }
#            MU::Cloud::AWS::DNSZone.createRecordsFromConfig(@config['dns_records'], target: resp.dns_name)
#          end

          notify
        end

        # Wrapper for cloud_desc method that deals with elb vs. elb2 resources.
        def cloud_desc
          if @config['classic']
            resp = MU::Cloud::AWS.elb(@config['region']).describe_load_balancers(
              load_balancer_names: [@mu_name]
            ).load_balancer_descriptions.first
            return resp
          else
            resp = MU::Cloud::AWS.elb2(@config['region']).describe_load_balancers(
              names: [@mu_name]
            ).load_balancers.first
            if @targetgroups.nil? and !@deploy.nil? and
                @deploy.deployment['loadbalancers'].has_key?(@config['name']) and
                @deploy.deployment['loadbalancers'][@config['name']].has_key?("targetgroups")
              @targetgroups = {}
              @deploy.deployment['loadbalancers'][@config['name']]["targetgroups"].each_pair { |tg_name, tg_arn|
                @targetgroups[tg_name] = MU::Cloud::AWS.elb2(@config['region']).describe_target_groups(target_group_arns: [tg_arn]).target_groups.first
              }
            end

            return resp
          end
        end

        # Return the metadata for this LoadBalancer
        # @return [Hash]
        def notify
          deploy_struct = {
            "awsname" => @mu_name,
            "dns" => cloud_desc.dns_name,
            "targetgroups" => {}
          }
          deploy_struct["arn"] = cloud_desc.load_balancer_arn if !@config['classic']
          @targetgroups.each { |tgname, tg|
            deploy_struct["targetgroups"][tgname] = tg.target_group_arn
          }
          return deploy_struct
        end

        # Register a Server node with an existing LoadBalancer.
        #
        # @param instance_id [String] A node to register.
        # @param targetgroups [Array<String>] The target group(s) of which this node should be made a member. Not applicable to classic LoadBalancers. If not supplied, the node will be registered to all available target groups on this LoadBalancer.
        def registerNode(instance_id, targetgroups: nil)
          if @config['classic'] or !@config.has_key?("classic")
            MU::Cloud::AWS.elb(@config['region']).register_instances_with_load_balancer(
              load_balancer_name: @cloud_id,
              instances: [
                {instance_id: instance_id}
              ]
            )
          else
            if targetgroups.nil? or !targetgroups.is_a?(Array) or targetgroups.size == 0
              if @targetgroups.nil?
                cloud_desc
                return
              end
              targetgroups = @targetgroups.keys
            end
            targetgroups.each { |tg|
              MU::Cloud::AWS.elb2(@config['region']).register_targets(
                target_group_arn: @targetgroups[tg].target_group_arn,
                targets: [
                  {id: instance_id}
                ]
              )
            }
          end
        end

        # Remove all load balancers associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          raise MuError, "Can't touch ELBs without MU-ID" if MU.deploy_id.nil? or MU.deploy_id.empty?

          # Check for tags matching the current deploy identifier on an elb or 
          # elb2 resource.
          # @param arn [String]: The ARN of the resource to check
          # @param region [String]: The cloud provider region
          # @param ignoremaster [Boolean]: Whether to ignore the MU-MASTER-IP tag
          # @param classic [Boolean]: Whether to look for a classic ELB instead of an ALB (ELB2)
          def self.checkForTagMatch(arn, region, ignoremaster, classic = false)
            tags = []
            if classic
              tags = MU::Cloud::AWS.elb(region).describe_tags(
                load_balancer_names: [arn]
              ).tag_descriptions.first.tags
            else
              tags = MU::Cloud::AWS.elb2(region).describe_tags(
                resource_arns: [arn]
              ).tag_descriptions.first.tags
            end
            muid_match = false
            mumaster_match = false
            saw_tags = []
            if !tags.nil?
              tags.each { |tag|
                saw_tags << tag.key
                muid_match = true if tag.key == "MU-ID" and tag.value == MU.deploy_id
                mumaster_match = true if tag.key == "MU-MASTER-IP" and tag.value == MU.mu_public_ip
              }
            end
            if saw_tags.include?("MU-ID") and (saw_tags.include?("MU-MASTER-IP") or ignoremaster)
              if muid_match and (mumaster_match or ignoremaster)
                return true
              end
            end
            return false
          end


          resp = MU::Cloud::AWS.elb(region).describe_load_balancers
          resp2 = MU::Cloud::AWS.elb2(region).describe_load_balancers
          (resp.load_balancer_descriptions + resp2.load_balancers).each { |lb|
            classic = true
            if lb.class.name != "Aws::ElasticLoadBalancing::Types::LoadBalancerDescription" and !lb.type.nil? and lb.type == "application"
              classic = false
            end
            begin
              tags = []
              matched = false
              if classic
                matched = self.checkForTagMatch(lb.load_balancer_name, region, ignoremaster, classic)
              else
                matched = self.checkForTagMatch(lb.load_balancer_arn, region, ignoremaster, classic)
              end
              if matched
                MU::Cloud::AWS::DNSZone.genericMuDNSEntry(name: lb.load_balancer_name, target: lb.dns_name, cloudclass: MU::Cloud::LoadBalancer, delete: true) if !noop
                MU.log "Removing Elastic Load Balancer #{lb.load_balancer_name}"
                if classic
                  MU::Cloud::AWS.elb(region).delete_load_balancer(load_balancer_name: lb.load_balancer_name) if !noop
                else
                  MU::Cloud::AWS.elb2(region).describe_listeners(
                    load_balancer_arn: lb.load_balancer_arn
                  ).listeners.each { |l|
                    MU.log "Removing ALB Listener #{l.listener_arn}"
                    MU::Cloud::AWS.elb2(region).delete_listener(
                      listener_arn: l.listener_arn
                    ) if !noop
                  }
                  tgs = MU::Cloud::AWS.elb2(region).describe_target_groups.target_groups
                  begin
                    if lb.state.code == "provisioning"
                      MU.log "Waiting for ALB #{lb.load_balancer_name} to leave 'provisioning' state", MU::NOTICE
                      sleep 45
                      lb = MU::Cloud::AWS.elb2(region).describe_load_balancers(
                        load_balancer_arns: [lb.load_balancer_arn]
                      ).load_balancers.first
                    end
                  end while lb.state.code == "provisioning"
                  MU::Cloud::AWS.elb2(region).delete_load_balancer(load_balancer_arn: lb.load_balancer_arn) if !noop


                  tgs.each { |tg|
                    if self.checkForTagMatch(tg.target_group_arn, region, ignoremaster)
                      MU.log "Removing Load Balancer Target Group #{tg.target_group_name}"
                      retries = 0
                      begin
                        MU::Cloud::AWS.elb2(region).delete_target_group(target_group_arn: tg.target_group_arn) if !noop
                      rescue Aws::ElasticLoadBalancingV2::Errors::ResourceInUse => e
                        if retries < 6
                          retries = retries + 1
                          sleep 10
                          retry
                        else
                          MU.log "Failed to delete ALB targetgroup #{tg.target_group_arn}: #{e.message}", MU::WARN
                        end
                      end
                    end
                  }
                end
                next
              end
            rescue Aws::ElasticLoadBalancing::Errors::LoadBalancerNotFound, Aws::ElasticLoadBalancingV2::Errors::LoadBalancerNotFound
              MU.log "ELB #{lb.load_balancer_name} already deleted", MU::WARN
            end
          }
          return nil
        end

        # Locate an existing LoadBalancer or LoadBalancers and return an array containing matching AWS resource descriptors for those that match.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region
        # @param tag_key [String]: A tag key to search.
        # @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
        # @param opts [Hash]: Optional flags
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching LoadBalancers
        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil, opts: {})
          classic = opts['classic'] ? true : false

          matches = {}
          list = {}
          arn2name = {}
          resp = nil
          if classic
            resp = MU::Cloud::AWS.elb(region).describe_load_balancers().load_balancer_descriptions
          else
            resp = MU::Cloud::AWS.elb2(region).describe_load_balancers().load_balancers
          end

          resp.each { |lb|
            list[lb.load_balancer_name] = lb
            arn2name[lb.load_balancer_arn] = lb.load_balancer_name if !classic
            if !cloud_id.nil? and lb.load_balancer_name == cloud_id
              matches[cloud_id] = lb
            end
          }

          return matches if matches.size > 0

          if !tag_key.nil? and !tag_value.nil?
            tag_descriptions = nil
            if classic
              tag_descriptions = MU::Cloud::AWS.elb(region).describe_tags(
                load_balancer_names: list.keys
              ).tag_descriptions
            else
              tag_descriptions = MU::Cloud::AWS.elb2(region).describe_tags(
                resource_arns: list.values.map { |l| l.load_balancer_arn }
              ).tag_descriptions
            end
            if !resp.nil?
              tag_descriptions.each { |lb|
                lb_name = classic ? lb.load_balancer_name : arn2name[lb.resource_arn]
                lb.tags.each { |tag|
                  if tag.key == tag_key and tag.value == tag_value
                    matches[lb_name] = list[lb_name]
                  end
                }
              }
            end
          end

          return matches

        end
      end
    end
  end
end
