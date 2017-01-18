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
          if @config['classic']
            lb_options[:listeners] = listeners
# XXX ALBs: listeners are separate API call after creation
          end

          MU.log "Creating Load Balancer #{@mu_name}", details: lb_options
          zones_to_try = @config["zones"]
          retries = 0
          begin
            if @config['classic']
              resp = MU::Cloud::AWS.elb.create_load_balancer(lb_options)
            else
              resp = MU::Cloud::AWS.elb2.create_load_balancer(lb_options).load_balancers.first
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
          MU.log "Load Balancer is at #{resp.dns_name}"

          parent_thread_id = Thread.current.object_id
          dnsthread = Thread.new {
            MU.dupGlobals(parent_thread_id)
            MU::Cloud::AWS::DNSZone.genericMuDNSEntry(name: @mu_name, target: "#{resp.dns_name}.", cloudclass: MU::Cloud::LoadBalancer, sync_wait: @config['dns_sync_wait'])
          }

          if zones_to_try.size < @config["zones"].size
            zones_to_try.each { |zone|
              begin
                MU::Cloud::AWS.elb.enable_availability_zones_for_load_balancer(
                  load_balancer_name: @mu_name,
                  availability_zones: [zone]
                )
              rescue Aws::ElasticLoadBalancing::Errors::ValidationError => e
                MU.log "Couldn't enable Availability Zone #{zone} for Load Balancer #{@mu_name} (#{e.message})", MU::WARN
              end
            }
          end

          if !@config['healthcheck'].nil? and @config['classic']
            MU.log "Configuring custom health check for ELB #{@mu_name}", details: @config['healthcheck']
            MU::Cloud::AWS.elb.configure_health_check(
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
                  :vpc_id => @config['vpc']['vpc_id'],
                  :port => tg['port']
                }
# XXX vpc_id
# XXX matcher
                if tg['healthcheck']
                  hc_target = tg['healthcheck']['target'].match(/^([^:]+):(\d+)(.*)/)
                  tg_descriptor[:health_check_protocol] = hc_target[1]
                  tg_descriptor[:health_check_port] = hc_target[2]
                  tg_descriptor[:health_check_path] = hc_target[3]
                  tg_descriptor[:health_check_interval_seconds] = tg['healthcheck']['interval']
                  tg_descriptor[:health_check_timeout_seconds] = tg['healthcheck']['timeout']
                  tg_descriptor[:healthy_threshold_count] = tg['healthcheck']['healthy_threshold']
                  tg_descriptor[:unhealthy_threshold_count] = tg['healthcheck']['unhealthy_threshold']
                end
                tg_resp = MU::Cloud::AWS.elb2.create_target_group(tg_descriptor)
                MU::Cloud::AWS.elb2.add_tags(
                  resource_arns: [tg_resp.target_groups.first.target_group_arn],
                  tags: lb_options[:tags]
                )
              }
            end
          end

          if @config['cross_zone_unstickiness'] and @config['classic']
            MU.log "Enabling cross-zone un-stickiness on #{resp.dns_name}"
            MU::Cloud::AWS.elb.modify_load_balancer_attributes(
              load_balancer_name: @mu_name,
              load_balancer_attributes: {
                cross_zone_load_balancing: {
                  enabled: true
                }
              }
            )
          end

          if !@config['idle_timeout'].nil?
            MU.log "Setting idle timeout to #{@config['idle_timeout']} #{resp.dns_name}"
            if @config['classic']
              MU::Cloud::AWS.elb.modify_load_balancer_attributes(
                load_balancer_name: @mu_name,
                load_balancer_attributes: {
                  connection_settings: {
                    idle_timeout: @config['idle_timeout']
                  }
                }
              )
            else
              MU::Cloud::AWS.elb2.modify_load_balancer_attributes(
                load_balancer_arn: resp.load_balancer_arn,
                attributes: [
                  {
                    key: "idle_timeout.timeout_seconds",
                    value: @config['idle_timeout'].to_s
                  }
                ]
              )
            end
          end

          if !@config['connection_draining_timeout'].nil? and @config['classic']
            if @config['connection_draining_timeout'] >= 0
              MU.log "Setting connection draining timeout to #{@config['connection_draining_timeout']} on #{resp.dns_name}"
              MU::Cloud::AWS.elb.modify_load_balancer_attributes(
                  load_balancer_name: @mu_name,
                  load_balancer_attributes: {
                      connection_draining: {
                          enabled: true,
                          timeout: @config['connection_draining_timeout']
                      }
                  }
              )
            else
              MU.log "Disabling connection draining on #{resp.dns_name}"
              MU::Cloud::AWS.elb.modify_load_balancer_attributes(
                  load_balancer_name: @mu_name,
                  load_balancer_attributes: {
                      connection_draining: {
                          enabled: false
                      }
                  }
              )
            end
          end

          if !@config['access_log'].nil?
            MU.log "Setting access log params for #{resp.dns_name}", details: @config['access_log']
            if @config['classic']
              MU::Cloud::AWS.elb.modify_load_balancer_attributes(
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
              MU::Cloud::AWS.elb2.modify_load_balancer_attributes(
                load_balancer_arn: resp.load_balancer_arn,
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

          if !@config['lb_cookie_stickiness_policy'].nil? and @config['classic']
            MU.log "Setting ELB cookie stickiness policy for #{resp.dns_name}", details: @config['lb_cookie_stickiness_policy']
            cookie_policy = {
                load_balancer_name: @mu_name,
                policy_name: @config['lb_cookie_stickiness_policy']['name']
            }
            if !@config['lb_cookie_stickiness_policy']['timeout'].nil?
              cookie_policy[:cookie_expiration_period] = @config['lb_cookie_stickiness_policy']['timeout']
            end
            MU::Cloud::AWS.elb.create_lb_cookie_stickiness_policy(cookie_policy)
            lb_policy_names = Array.new
            lb_policy_names << @config['lb_cookie_stickiness_policy']['name']
            listener_policy = {
                load_balancer_name: @mu_name,
                policy_names: lb_policy_names
            }
            lb_options[:listeners].each do |listener|
              if listener[:protocol].upcase == 'HTTP' or listener[:protocol].upcase == 'HTTPS'
                listener_policy[:load_balancer_port] = listener[:load_balancer_port]
                MU::Cloud::AWS.elb.set_load_balancer_policies_of_listener(listener_policy)
              end
            end
          end

          if !@config['app_cookie_stickiness_policy'].nil? and @config['classic']
            MU.log "Setting application cookie stickiness policy for #{resp.dns_name}", details: @config['app_cookie_stickiness_policy']
            cookie_policy = {
                load_balancer_name: @mu_name,
                policy_name: @config['app_cookie_stickiness_policy']['name'],
                cookie_name: @config['app_cookie_stickiness_policy']['cookie']
            }
            MU::Cloud::AWS.elb.create_app_cookie_stickiness_policy(cookie_policy)
            lb_policy_names = Array.new
            lb_policy_names << @config['app_cookie_stickiness_policy']['name']
            listener_policy = {
                load_balancer_name: @mu_name,
                policy_names: lb_policy_names
            }
            lb_options[:listeners].each do |listener|
              if listener[:protocol].upcase == 'HTTP' or listener[:protocol].upcase == 'HTTPS'
                listener_policy[:load_balancer_port] = listener[:load_balancer_port]
                MU::Cloud::AWS.elb.set_load_balancer_policies_of_listener(listener_policy)
              end
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

        def cloud_desc
          if @config['classic']
            resp = MU::Cloud::AWS.elb(@config['region']).describe_load_balancers(
              load_balancer_names: [@mu_name]
            ).load_balancer_descriptions.first
          else
            MU::Cloud::AWS.elb2(@config['region']).describe_load_balancers(
              names: [@mu_name]
            ).load_balancers.first
          end
        end

        # Return the metadata for this LoadBalancer
        # @return [Hash]
        def notify
          deploy_struct = {
              "awsname" => @mu_name,
              "dns" => cloud_desc.dns_name
          }
          return deploy_struct
        end

        # Register a Server node with an existing LoadBalancer.
        #
        # @param instance_id [String] A node to register.
        def registerNode(instance_id)
          MU::Cloud::AWS.elb(@config['region']).register_instances_with_load_balancer(
              load_balancer_name: @cloud_id,
              instances: [
                  {instance_id: instance_id}
              ]
          )
        end

        # Remove all load balancers associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          raise MuError, "Can't touch ELBs without MU-ID" if MU.deploy_id.nil? or MU.deploy_id.empty?

          resp = MU::Cloud::AWS.elb(region).describe_load_balancers
          resp2 = MU::Cloud::AWS.elb2(region).describe_load_balancers
          (resp.load_balancer_descriptions + resp2.load_balancers).each { |lb|
            classic = true
            if lb.class.name != "Aws::ElasticLoadBalancing::Types::LoadBalancerDescription" and !lb.type.nil? and lb.type == "application"
              classic = false
            end
            begin
              tags = []
              if classic
                tags = MU::Cloud::AWS.elb(region).describe_tags(load_balancer_names: [lb.load_balancer_name]).tag_descriptions.first.tags
              else
                tags = MU::Cloud::AWS.elb2(region).describe_tags(resource_arns: [lb.load_balancer_arn]).tag_descriptions.first.tags
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
                  MU::Cloud::AWS::DNSZone.genericMuDNSEntry(name: lb.load_balancer_name, target: lb.dns_name, cloudclass: MU::Cloud::LoadBalancer, delete: true)
                  MU.log "Removing Elastic Load Balancer #{lb.load_balancer_name}"
                  if classic
                    MU::Cloud::AWS.elb(region).delete_load_balancer(load_balancer_name: lb.load_balancer_name) if !noop
                  else
                    MU::Cloud::AWS.elb2(region).delete_load_balancer(load_balancer_arn: lb.load_balancer_arn) if !noop
                  end
                end
                next
              end
            rescue Aws::ElasticLoadBalancing::Errors::LoadBalancerNotFound
              MU.log "ELB #{lb.load_balancer_name} already deleted", MU::WARN
            end
          }
          tgs = MU::Cloud::AWS.elb2(region).describe_target_groups.target_groups
          tgs.each { |tg|
            tg.target_group_arn
            tag_descs = MU::Cloud::AWS.elb2(region).describe_tags(
              resource_arns: [tg.target_group_arn]
            ).tag_descriptions.first
            muid_match = false
            mumaster_match = false
            saw_tags = []
            if !tag_descs.nil?
              tag_descs.tags.each { |tag|
                saw_tags << tag.key
                muid_match = true if tag.key == "MU-ID" and tag.value == MU.deploy_id
                mumaster_match = true if tag.key == "MU-MASTER-IP" and tag.value == MU.mu_public_ip
              }
            end
            if saw_tags.include?("MU-ID") and (saw_tags.include?("MU-MASTER-IP") or ignoremaster)
              if muid_match and (mumaster_match or ignoremaster)
                MU.log "Removing Load Balancer Target Group #{tg.target_group_name}"
                MU::Cloud::AWS.elb2(region).delete_target_group(target_group_arn: tg.target_group_arn) if !noop
              end
              next
            end
          }

          return nil
        end

        # Locate an existing LoadBalancer or LoadBalancers and return an array containing matching AWS resource descriptors for those that match.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region
        # @param tag_key [String]: A tag key to search.
        # @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching LoadBalancers
        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil)

          matches = {}
          list = {}
          resp = MU::Cloud::AWS.elb(region).describe_load_balancers
          lb_names = []
          resp.load_balancer_descriptions.each { |lb|
            list[lb.load_balancer_name] = lb
            if !cloud_id.nil? and lb.load_balancer_name == cloud_id
              matches[cloud_id] = lb
            end
          }
          return matches if matches.size > 0

          if !tag_key.nil? and !tag_value.nil?
            resp = MU::Cloud::AWS.elb(region).describe_tags(load_balancer_names: list.keys)
            if !resp.nil?
              resp.tag_descriptions.each { |lb|
                lb.tags.each { |tag|
                  if tag.key == tag_key and tag.value == tag_value
                    matches[lb.load_balancer_name] = list[lb.load_balancer_name]
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
