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

        @lb = nil
        attr_reader :targetgroups
        attr_reader :is_lambda

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super

          if args[:from_cloud_desc]
            if args[:from_cloud_desc].class.name == "Aws::ElasticLoadBalancing::Types::LoadBalancerDescription"
              @config['classic'] = true
            else
              @config['classic'] = false
            end
          end

          @mu_name ||= @deploy.getResourceName(@config["name"], max_length: 32, need_unique_string: true)
          @mu_name.gsub!(/[^\-a-z0-9]/i, "-") # AWS ELB naming rules
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          if @config["zones"] == nil
            @config["zones"] = MU::Cloud::AWS.listAZs(region: @region)
            MU.log "Using zones from #{@region}", MU::DEBUG, details: @config['zones']
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
              lb = MU::Cloud::AWS.elb(region: @region, credentials: @credentials).create_load_balancer(lb_options)
            else
              MU.log "Creating Application Load Balancer #{@mu_name}", details: lb_options
              lb = MU::Cloud::AWS.elb2(region: @region, credentials: @credentials).create_load_balancer(lb_options).load_balancers.first
              begin
                if lb.state.code != "active"
                  MU.log "Waiting for ALB #{@mu_name} to enter 'active' state", MU::NOTICE
                  sleep 20
                  lb = MU::Cloud::AWS.elb2(region: @region, credentials: @credentials).describe_load_balancers(
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
          MU.log "LoadBalancer #{@config['name']} is at #{lb.dns_name}"
          MU.log "LoadBalancer #{@config['name']} is at #{lb.dns_name}", MU::SUMMARY

          parent_thread_id = Thread.current.object_id
          generic_mu_dns = nil
          dnsthread = Thread.new {
            if MU::Cloud::AWS.hosted? and !MU::Cloud::AWS.isGovCloud?
              MU.dupGlobals(parent_thread_id)
              generic_mu_dns = MU::Cloud.resourceClass("AWS", "DNSZone").genericMuDNSEntry(name: @mu_name, target: "#{lb.dns_name}.", cloudclass: MU::Cloud::LoadBalancer, sync_wait: @config['dns_sync_wait'])
            end
          }

          if zones_to_try.size < @config["zones"].size
            zones_to_try.each { |zone|
              begin
                MU::Cloud::AWS.elb(region: @region, credentials: @credentials).enable_availability_zones_for_load_balancer(
                  load_balancer_name: @mu_name,
                  availability_zones: [zone]
                )
              rescue Aws::ElasticLoadBalancing::Errors::ValidationError => e
                MU.log "Couldn't enable Availability Zone #{zone} for Load Balancer #{@mu_name} (#{e.message})", MU::WARN
              end
            }
          end

          @targetgroups = {}
          @is_lambda = false
          if !@config['healthcheck'].nil? and @config['classic']
            MU.log "Configuring custom health check for ELB #{@mu_name}", details: @config['healthcheck']
            MU::Cloud::AWS.elb(region: @region, credentials: @credentials).configure_health_check(
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
                tg_name = @deploy.getResourceName(tg["name"], max_length: 32, disallowed_chars: /[^A-Za-z0-9-]/)
                tg_descriptor = {
                  :name => tg_name,
                  :protocol => tg['proto'],
                  :vpc_id => @vpc.cloud_id,
                  :port => tg['port'],
                  :target_type  => tg['target_type'] || "instance"
                }
                if tg['target_type'] == "lambda"
                  @is_lambda = true
                  tg_descriptor.delete(:protocol)
                  tg_descriptor.delete(:port)
                  tg_descriptor.delete(:vpc_id)
                end
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

                tg_resp = MU::Cloud::AWS.elb2(region: @region, credentials: @credentials).create_target_group(tg_descriptor)
                @targetgroups[tg['name']] = tg_resp.target_groups.first
                MU::Cloud::AWS.elb2(region: @region, credentials: @credentials).add_tags(
                  resource_arns: [tg_resp.target_groups.first.target_group_arn],
                  tags: lb_options[:tags]
                )
              }
            end
          end

          redirect_block = Proc.new { |r|
            {
              :protocol => r['protocol'],
              :port => r['port'].to_s,
              :host => r['host'],
              :path => r['path'],
              :query => r['query'],
              :status_code => "HTTP_"+r['status_code'].to_s
            }
          }

          if !@config['classic']
            @config["listeners"].each { |l|
              action = if l['redirect']
                {
                  :type => "redirect",
                  :redirect_config => redirect_block.call(l['redirect'])
                }
              else
                if !@targetgroups.has_key?(l['targetgroup'])
                  raise MuError, "Listener in #{@mu_name} configured for target group #{l['targetgroup']}, but I don't have data on a targetgroup by that name"
                end
                {
                  :target_group_arn => @targetgroups[l['targetgroup']].target_group_arn,
                  :type => "forward"
                }
              end
              listen_descriptor = {
                :default_actions => [ action ],
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
              listen_resp = MU::Cloud::AWS.elb2(region: @region, credentials: @credentials).create_listener(listen_descriptor).listeners.first
              if !l['rules'].nil?
                l['rules'].each { |rule|
                  rule_descriptor = {
                    :listener_arn => listen_resp.listener_arn,
                    :priority => rule['order'],
                    :conditions => rule['conditions'],
                    :actions => []
                  }
                  rule['actions'].each { |a|
                    rule_descriptor[:actions] << if a['action'] == "forward"
                      {
                        :target_group_arn => @targetgroups[a['targetgroup']].target_group_arn,
                        :type => a['action']
                      }
                    elsif a['action'] == "redirect"
                      {
                        :redirect_config => redirect_block.call(rule['redirect']),
                        :type => a['action']
                      }
                    end
                  }
                  MU::Cloud::AWS.elb2(region: @region, credentials: @credentials).create_rule(rule_descriptor)
                }
              end
            }
          else
            @config["listeners"].each { |l|
              if l['ssl_certificate_id']
                MU::Cloud::AWS.elb(region: @region, credentials: @credentials).set_load_balancer_policies_of_listener(
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
              MU::Cloud::AWS.elb(region: @region, credentials: @credentials).modify_load_balancer_attributes(
                load_balancer_name: @mu_name,
                load_balancer_attributes: {
                  cross_zone_load_balancing: {
                    enabled: true
                  }
                }
              )
            else
              @targetgroups.values.each { |tg|
                MU::Cloud::AWS.elb2(region: @region, credentials: @credentials).modify_target_group_attributes(
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
              MU::Cloud::AWS.elb(region: @region, credentials: @credentials).modify_load_balancer_attributes(
                load_balancer_name: @mu_name,
                load_balancer_attributes: {
                  connection_settings: {
                    idle_timeout: @config['idle_timeout']
                  }
                }
              )
            else
              MU::Cloud::AWS.elb2(region: @region, credentials: @credentials).modify_load_balancer_attributes(
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
                MU::Cloud::AWS.elb(region: @region, credentials: @credentials).modify_load_balancer_attributes(
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
                MU::Cloud::AWS.elb(region: @region, credentials: @credentials).modify_load_balancer_attributes(
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
              if !@is_lambda
                @targetgroups.values.each { |tg|
                  MU::Cloud::AWS.elb2(region: @region, credentials: @credentials).modify_target_group_attributes(
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
          end

          if !@config['access_log'].nil?
            MU.log "Setting access log params for #{lb.dns_name}", details: @config['access_log']
            if @config['classic']
              MU::Cloud::AWS.elb(region: @region, credentials: @credentials).modify_load_balancer_attributes(
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
              MU::Cloud::AWS.elb2(region: @region, credentials: @credentials).modify_load_balancer_attributes(
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
              MU::Cloud::AWS.elb(region: @region, credentials: @credentials).create_lb_cookie_stickiness_policy(cookie_policy)
              lb_policy_names = Array.new
              lb_policy_names << @config['lb_cookie_stickiness_policy']['name']
              listener_policy = {
                load_balancer_name: @mu_name,
                policy_names: lb_policy_names
              }
              lb_options[:listeners].each do |listener|
                if listener[:protocol].upcase == 'HTTP' or listener[:protocol].upcase == 'HTTPS'
                  listener_policy[:load_balancer_port] = listener[:load_balancer_port]
                  MU::Cloud::AWS.elb(region: @region, credentials: @credentials).set_load_balancer_policies_of_listener(listener_policy)
                end
              end
            else
              @targetgroups.values.each { |tg|
                MU::Cloud::AWS.elb2(region: @region, credentials: @credentials).modify_target_group_attributes(
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
              MU::Cloud::AWS.elb(region: @region, credentials: @credentials).create_app_cookie_stickiness_policy(cookie_policy)
              lb_policy_names = Array.new
              lb_policy_names << @config['app_cookie_stickiness_policy']['name']
              listener_policy = {
                load_balancer_name: @mu_name,
                policy_names: lb_policy_names
              }
              lb_options[:listeners].each do |listener|
                if listener[:protocol].upcase == 'HTTP' or listener[:protocol].upcase == 'HTTPS'
                  listener_policy[:load_balancer_port] = listener[:load_balancer_port]
                  MU::Cloud::AWS.elb(region: @region, credentials: @credentials).set_load_balancer_policies_of_listener(listener_policy)
                end
              end
            else
              MU.log "App cookie stickiness not supported in ALBs. Redeploy with 'classic' set to true if you need this functionality.", MU::WARN
            end
          end

          dnsthread.join # from genericMuDNS

          if !@config['dns_records'].nil?
            # XXX this should be a call to @deploy.nameKitten
            @config['dns_records'].each { |dnsrec|
              dnsrec['name'] = @mu_name.downcase if !dnsrec.has_key?('name')
              dnsrec['name'] = "#{dnsrec['name']}.#{MU.environment.downcase}" if dnsrec["append_environment_name"] && !dnsrec['name'].match(/\.#{MU.environment.downcase}$/)
            }
            if !@config['classic']
              # XXX should be R53ALIAS, but we get "the alias target name does not lie within the target zone"
              @config['dns_records'].each { |r|
                r['type'] = "CNAME"
              }
            end
            if !MU::Cloud::AWS.isGovCloud?
              MU::Cloud.resourceClass("AWS", "DNSZone").createRecordsFromConfig(@config['dns_records'], target: cloud_desc.dns_name)
            end
          end

          notify
        end

        def groom
          MU.log "LoadBalancer #{@config['name']} is at #{cloud_desc.dns_name}", MU::SUMMARY
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          if @config['classic']
            "arn:"+(MU::Cloud::AWS.isGovCloud?(@region) ? "aws-us-gov" : "aws")+":elasticloadbalancing:"+@region+":"+MU::Cloud::AWS.credToAcct(@credentials)+":loadbalancer/"+@cloud_id
          else
            cloud_desc.load_balancer_arn
          end
        end

        @cloud_desc_cache = nil
        # Wrapper for cloud_desc method that deals with elb vs. elb2 resources.
        def cloud_desc(use_cache: true)
          return @cloud_desc_cache if @cloud_desc_cache and use_cache
          return nil if !@cloud_id
          if @config['classic']
            @cloud_desc_cache = MU::Cloud::AWS.elb(region: @region, credentials: @credentials).describe_load_balancers(
              load_balancer_names: [@cloud_id]
            ).load_balancer_descriptions.first
            return @cloud_desc_cache
          else
            @cloud_desc_cache = MU::Cloud::AWS.elb2(region: @region, credentials: @credentials).describe_load_balancers(
              names: [@cloud_id]
            ).load_balancers.first
            if @targetgroups.nil? 
              @targetgroups = {}
              if !@deploy.nil? and
                 @deploy.deployment['loadbalancers'] and
                 @deploy.deployment['loadbalancers'][@config['name']] and
                 @deploy.deployment['loadbalancers'][@config['name']]["targetgroups"]
                @deploy.deployment['loadbalancers'][@config['name']]["targetgroups"].each_pair { |tg_name, tg_arn|
                  @targetgroups[tg_name] = MU::Cloud::AWS.elb2(region: @region, credentials: @credentials).describe_target_groups(target_group_arns: [tg_arn]).target_groups.first
                }
              else
                MU::Cloud::AWS.elb2(region: @region, credentials: @credentials).describe_target_groups(load_balancer_arn: @cloud_desc_cache.load_balancer_arn).target_groups.each { |tg|
                  tg_name = tg.target_group_name
                  if @config['targetgroups']
                    @config['targetgroups'].each { |tg_cfg|
                      if tg_name = @deploy.getResourceName(tg_cfg["name"], max_length: 32, disallowed_chars: /[^A-Za-z0-9-]/)
                        tg_name = tg_cfg['name']
                        break
                      end
                    }
                  end
                  @targetgroups[tg_name] = tg
                }
#                @config['targetgroups'].each { |tg|
#                  tg_name = @deploy.getResourceName(tg["name"], max_length: 32, disallowed_chars: /[^A-Za-z0-9-]/)
#                  @targetgroups[tg_name] = MU::Cloud::AWS.elb2(region: @region, credentials: @credentials).describe_target_groups(target_group_arns: [tg_arn]).target_groups.first
#                }
              end
            end

            return @cloud_desc_cache
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
        # @param id [String] A node or function to register.
        # @param targetgroups [Array<String>] The target group(s) of which this node should be made a member. Not applicable to classic LoadBalancers. If not supplied, the node will be registered to all available target groups on this LoadBalancer.
        def registerTarget(id, backends: nil, type: "instance")
          if @config['classic'] or !@config.has_key?("classic")
            MU.log "Registering #{id} to ELB #{@cloud_id}"
            MU::Cloud::AWS.elb(region: @region, credentials: @credentials).register_instances_with_load_balancer(
              load_balancer_name: @cloud_id,
              instances: [
                {instance_id: id}
              ]
            )
          else
            if backends.nil? or !backends.is_a?(Array) or backends.size == 0
              if @targetgroups.nil?
                cloud_desc
                return if @targetgroups.nil?
              end
              backends = @targetgroups.keys
            end
            backends.each { |tg|
              MU.log "Registering #{id} to Target Group #{tg}"
              MU::Cloud::AWS.elb2(region: @region, credentials: @credentials).register_targets(
                target_group_arn: @targetgroups[tg].target_group_arn,
                targets: [
                  {id: id}
                ]
              )
            }
          end
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

        # Remove all load balancers associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          if (deploy_id.nil? or deploy_id.empty?) and (!flags or !flags["vpc_id"])
            raise MuError, "Can't touch ELBs without MU-ID or vpc_id flag"
          end

          # Check for tags matching the current deploy identifier on an elb or 
          # elb2 resource.
          # @param arn [String]: The ARN of the resource to check
          # @param region [String]: The cloud provider region
          # @param ignoremaster [Boolean]: Whether to ignore the MU-MASTER-IP tag
          # @param classic [Boolean]: Whether to look for a classic ELB instead of an ALB (ELB2)
          def self.checkForTagMatch(arn, region, ignoremaster, credentials, classic = false, deploy_id: MU.deploy_id)
            tags = []
            if classic
              tags = MU::Cloud::AWS.elb(credentials: credentials, region: region).describe_tags(
                load_balancer_names: [arn]
              ).tag_descriptions.first.tags
            else
              tags = MU::Cloud::AWS.elb2(credentials: credentials, region: region).describe_tags(
                resource_arns: [arn]
              ).tag_descriptions.first.tags
            end
            muid_match = false
            mumaster_match = false
            saw_tags = []
            if !tags.nil?
              tags.each { |tag|
                saw_tags << tag.key
                muid_match = true if tag.key == "MU-ID" and tag.value == deploy_id
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


          resp = MU::Cloud::AWS.elb(credentials: credentials, region: region).describe_load_balancers
          resp2 = MU::Cloud::AWS.elb2(credentials: credentials, region: region).describe_load_balancers
          (resp.load_balancer_descriptions + resp2.load_balancers).each { |lb|
            classic = true
            if lb.class.name != "Aws::ElasticLoadBalancing::Types::LoadBalancerDescription" and !lb.type.nil? and lb.type == "application"
              classic = false
            end
            begin
              matched = false
              if flags and flags['vpc_id']
                matched = true if lb.vpc_id == flags['vpc_id']
              else
                if classic
                  matched = self.checkForTagMatch(lb.load_balancer_name, region, ignoremaster, credentials, classic, deploy_id: deploy_id)
                else
                  matched = self.checkForTagMatch(lb.load_balancer_arn, region, ignoremaster, credentials, classic, deploy_id: deploy_id)
                end
              end
              if matched
                if MU::Cloud::AWS.hosted? and !MU::Cloud::AWS.isGovCloud?
                  MU::Cloud.resourceClass("AWS", "DNSZone").genericMuDNSEntry(name: lb.load_balancer_name, target: lb.dns_name, cloudclass: MU::Cloud::LoadBalancer, delete: true) if !noop
                end
                if classic
                  MU.log "Removing Elastic Load Balancer #{lb.load_balancer_name}"
                  if !noop
                    MU::Cloud::AWS.elb(credentials: credentials, region: region).delete_load_balancer(load_balancer_name: lb.load_balancer_name)
                    stillhere = true
                    begin
                      ext_check = MU::Cloud::AWS.elb(credentials: credentials, region: region).describe_load_balancers(load_balancer_names: [lb.load_balancer_name])
                      if !ext_check or
                         !ext_check.load_balancer_descriptions or
                         !ext_check.load_balancer_descriptions[0]
                        sleep 3
                      else stillhere = false
                      end
                    end while stillhere
                  end
                else
                  MU.log "Removing Application Load Balancer #{lb.load_balancer_name}"
                  MU::Cloud::AWS.elb2(credentials: credentials, region: region).describe_listeners(
                    load_balancer_arn: lb.load_balancer_arn
                  ).listeners.each { |l|
                    MU.log "Removing ALB Listener #{l.listener_arn}"
                    MU::Cloud::AWS.elb2(credentials: credentials, region: region).delete_listener(
                      listener_arn: l.listener_arn
                    ) if !noop
                  }
                  tgs = MU::Cloud::AWS.elb2(credentials: credentials, region: region).describe_target_groups.target_groups
                  begin
                    if lb.state.code == "provisioning"
                      MU.log "Waiting for ALB #{lb.load_balancer_name} to leave 'provisioning' state", MU::NOTICE
                      sleep 45
                      lb = MU::Cloud::AWS.elb2(credentials: credentials, region: region).describe_load_balancers(
                        load_balancer_arns: [lb.load_balancer_arn]
                      ).load_balancers.first
                    end
                  end while lb.state.code == "provisioning"
                  MU::Cloud::AWS.elb2(credentials: credentials, region: region).delete_load_balancer(load_balancer_arn: lb.load_balancer_arn) if !noop


                  tgs.each { |tg|
                    if self.checkForTagMatch(tg.target_group_arn, region, ignoremaster, credentials, deploy_id: deploy_id)
                      MU.log "Removing Load Balancer Target Group #{tg.target_group_name}"
                      retries = 0
                      begin
                        MU::Cloud::AWS.elb2(credentials: credentials, region: region).delete_target_group(target_group_arn: tg.target_group_arn) if !noop
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

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {
            "targetgroups" => {
              "items" => {
                "properties" => {
                  "proto" => {
                    "type" => "string",
                    "enum" => ["HTTP", "HTTPS", "TCP", "SSL"],
                  },
                  "target_type" => {
                    "type" => "string",
                    "enum" => ["instance", "ip", "lambda"],
                  }
                }
              }
            },
            "ingress_rules" => MU::Cloud.resourceClass("AWS", "FirewallRule").ingressRuleAddtlSchema
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::loadbalancers}, bare and unvalidated.
        # @param lb [Hash]: The resource to process and validate
        # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(lb, _configurator)
          ok = true

          # XXX what about raw targetgroup ssl declarations?
          lb['listeners'].each { |listener|
            if (!listener["ssl_certificate_name"].nil? and !listener["ssl_certificate_name"].empty?) or
               (!listener["ssl_certificate_id"].nil? and !listener["ssl_certificate_id"].empty?)
              if lb['cloud'] != "CloudFormation" # XXX or maybe do this anyway?
                begin
                  listener["ssl_certificate_id"] = MU::Cloud::AWS.findSSLCertificate(name: listener["ssl_certificate_name"].to_s, id: listener["ssl_certificate_id"].to_s, region: lb['region']).first
                rescue MuError
                  ok = false
                  next
                end
                MU.log "Using SSL cert #{listener["ssl_certificate_id"]} on port #{listener['lb_port']} in ELB #{lb['name']}"
              end
            end
          }

#          if lb["alarms"] && !lb["alarms"].empty?
#            lb["alarms"].each { |alarm|
#              alarm["name"] = "lb-#{lb["name"]}-#{alarm["name"]}"
#              alarm['dimensions'] = [] if !alarm['dimensions']
#              alarm['dimensions'] << { "name" => lb["name"], "cloud_class" => "LoadBalancerName" }
#              alarm["namespace"] = "AWS/ELB" if alarm["namespace"].nil?
#              alarm['cloud'] = lb['cloud']
#              alarms << alarm.dup
#            }
#          end

          if !lb["classic"]
            if lb["vpc"].nil?
              MU.log "LoadBalancer #{lb['name']} has no VPC configured. Either set 'classic' to true or configure a VPC.", MU::ERR
              ok = false
            end
          else
            lb.delete("targetgroups")
          end

          ok
        end

        # Locate an existing LoadBalancer or LoadBalancers and return an array containing matching AWS resource descriptors for those that match.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching LoadBalancers
        def self.find(**args)
          args[:flags] ||= {}
          classic = args[:flags]['classic'] ? true : false

          matches = {}
          list = {}
          arn2name = {}
          resp = nil
          if args[:flags].has_key?('classic') 
            if args[:flags]['classic']
              resp = MU::Cloud::AWS.elb(region: args[:region], credentials: args[:credentials]).describe_load_balancers().load_balancer_descriptions
            else
              resp = MU::Cloud::AWS.elb2(region: args[:region], credentials: args[:credentials]).describe_load_balancers().load_balancers
            end
          elsif args[:cloud_id].nil? and args[:tag_value].nil?
            matches = find(region: args[:region], credentials: args[:credentials], flags: { "classic" => true } )
            matches.merge!(find(region: args[:region], credentials: args[:credentials], flags: { "classic" => false } ))
            return matches
          end

          resp.each { |lb|
            list[lb.load_balancer_name] = lb
            arn2name[lb.load_balancer_arn] = lb.load_balancer_name if !classic
            if !args[:cloud_id].nil? and lb.load_balancer_name == args[:cloud_id]
              matches[args[:cloud_id]] = lb
            end
          }

          return list if args[:tag_value].nil? and args[:cloud_id].nil?

          return matches if matches.size > 0

          if !args[:tag_key].nil? and !args[:tag_value].nil? and !args[:tag_key].empty? and list.size > 0
            tag_descriptions = nil
            if classic
              tag_descriptions = MU::Cloud::AWS.elb(region: args[:region], credentials: args[:credentials]).describe_tags(
                load_balancer_names: list.keys
              ).tag_descriptions
            else
              tag_descriptions = MU::Cloud::AWS.elb2(region: args[:region], credentials: args[:credentials]).describe_tags(
                resource_arns: list.values.map { |l| l.load_balancer_arn }
              ).tag_descriptions
            end
            if !resp.nil?
              tag_descriptions.each { |lb|
                lb_name = classic ? lb.load_balancer_name : arn2name[lb.resource_arn]
                lb.tags.each { |tag|
                  if tag.key == args[:tag_key] and tag.value == args[:tag_value]
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
