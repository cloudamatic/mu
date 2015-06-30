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
			attr_reader :cloud_id

			# @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
			# @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::loadbalancers}
			def initialize(mommacat: mommacat, kitten_cfg: kitten_cfg, mu_name: mu_name, vpc: vpc)
				@deploy = mommacat
				@config = kitten_cfg
				@vpc = vpc
				@mu_name = mu_name if !mu_name.nil?
			end

			# Called automatically by {MU::Deploy#createResources}
			def create
				@mu_name = MU::MommaCat.getResourceName(@config["name"], max_length: 32, need_unique_string: true)
				@mu_name.gsub!(/[^\-a-z0-9]/i, "-") # LB naming rules

				if @config["zones"] == nil
					@config["zones"] = MU::Cloud::AWS.listAZs(@config['region'])
					MU.log "Using zones from #{@config['region']}", MU::DEBUG, details: @config['zones']
				end

				lb_options = {
					load_balancer_name: @mu_name,
					tags: []
				}
				MU::MommaCat.listStandardTags.each_pair { |name, value|
					lb_options[:tags] << { key: name, value: value }
				}
				if !@config['tags'].nil?
					@config['tags'].each { |tag|
						lb_options[:tags] << { key: tag['key'], value: tag['value'] }
					}
				end


				sgs = Array.new
				if !@config["add_firewall_rules"].nil?
					@config["add_firewall_rules"].each { |acl|
						sg = @deploy.findLitterMate(type: "firewall_rule", name: acl["rule_name"])
						if sg.nil?
							MU.log "Couldn't find dependent security group #{acl["rule_name"]} for Load Balancer #{@config['name']}", MU::ERR, details: @deploy.kittens['firewall_rules']
							raise MuError, "deploy failure"
						end
						sgs << sg.cloud_id
					}
				end

				if @config["vpc"] != nil
					vpc_id, subnet_ids = MU::Cloud::AWS::VPC.parseVPC(@config["vpc"])
					lb_options[:subnets] = subnet_ids
					lb_options[:security_groups] = sgs
					@config['sgs'] = sgs
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
				lb_options[:listeners ] = listeners

				MU.log "Creating Load Balancer #{@mu_name}", details: lb_options
				zones_to_try = @config["zones"]
				retries = 0
				begin
					resp = MU::Cloud::AWS.elb.create_load_balancer(lb_options)
				rescue Aws::ElasticLoadBalancing::Errors::ValidationError, Aws::ElasticLoadBalancing::Errors::SubnetNotFound, Aws::ElasticLoadBalancing::Errors::InvalidConfigurationRequest => e
					if zones_to_try.size > 0
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
				MU.log "Load Balancer is at #{resp.dns_name}"
				@cloud_id = @mu_name

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

				if !@config['healthcheck'].nil?
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
				end

				if @config['cross_zone_unstickiness']
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
					MU::Cloud::AWS.elb.modify_load_balancer_attributes(
						load_balancer_name: @mu_name,
						load_balancer_attributes: {
							connection_settings: {
								idle_timeout: @config['idle_timeout']
							}
						}
					)
				end

				if !@config['connection_draining_timeout'].nil?
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
				end

				if !@config['lb_cookie_stickiness_policy'].nil?
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

				if !@config['app_cookie_stickiness_policy'].nil?
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

				if !@config['dns_records'].nil?
					@config['dns_records'].each { |dnsrec|
						dnsrec['name'] = @mu_name.downcase if !dnsrec.has_key?('name')
					}
					MU::Cloud::AWS::DNSZone.createRecordsFromConfig(@config['dns_records'], target: resp.dns_name)
				end

				notify
			end

			def notify
				mu_name, config, deploydata, cloud_descriptor = describe(cloud_id: @mu_name)
				deploy_struct = {
					"awsname" => @mu_name,
					"dns" => cloud_descriptor.dns_name
				}
				return deploy_struct
			end

			# Register a Server node with an existing LoadBalancer.
			#
			# @param lb_name [String] The name of a LoadBalancer with which to register.
			# @param instance_id [String] A node to register.
			# @param region [String]: The cloud provider region
			def self.registerInstance(lb_name, instance_id, region: MU.curRegion)
				raise MuError, "MU::Cloud::AWS::LoadBalancer.registerInstance requires a Load Balancer name and an instance id" if lb_name.nil? or instance_id.nil?
				MU::Cloud::AWS.elb(region).register_instances_with_load_balancer(
					load_balancer_name: lb_name,
					instances: [
						{ instance_id: instance_id }
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
				resp.load_balancer_descriptions.each { |lb|
					tags = MU::Cloud::AWS.elb(region).describe_tags(load_balancer_names: [lb.load_balancer_name]).tag_descriptions.first.tags
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
							MU::Cloud::AWS.elb(region).delete_load_balancer(load_balancer_name: lb.load_balancer_name) if !noop
						end
						next
					end
					if lb.load_balancer_name.match(/^#{MU.deploy_id}/)
						MU.log "Removing Elastic Load Balancer #{lb.load_balancer_name} by name match (tags unavailable). This behavior is DEPRECATED and will be removed in a future release.", MU::WARN
						resp = MU::Cloud::AWS.elb(region).delete_load_balancer(load_balancer_name: lb.load_balancer_name) if !noop
					end
				}

				return nil
			end

			# Find a LoadBalancer, given one or more pieces of identifying information.
			# @param name [String] The MU resource name of a LoadBalancer to find.
			# @param id [String] The cloud provider's internal identifier of a LoadBalancer to find.
			# @param dns_name [String] The DNS name of a LoadBalancer to Find.
			# @param region [String]: The cloud provider region
			# @param deploy_id [String]: The parent deploy identifier
			# @return [OpenStruct] The cloud provider's description of the LoadBalancer
			def self.find(name: nil, id: nil, dns_name: nil, region: MU.curRegion, deploy_id: nil, mu_name: nil)
				return nil if !name and !dns_name and !id
				id = mu_name if id.nil? and !mu_name.nil?
				deploydata = MU::MommaCat.getResourceMetadata(MU::Cloud::LoadBalancer.cfg_plural, name: name, deploy_id: deploy_id, mu_name: mu_name)
				if !deploydata.nil?
					if deploydata.is_a?(Array)
						if !dns_name.nil? or !id.nil?
							deploydata.each { |elb|
								if (!dns_name.nil? and dns_name == deploydata['dns']) or
									 (!id.nil? and id == deploydata['awsname'])
									id = deploydata['awsname'] if id.nil?
									dns_name = deploydata['dns'] if dns_name.nil?
									break
								end
							}
						end
						if !id.nil? or dns_name.nil?
							MU.log "Can't isolate a single ELB from: name: #{name}, deploy_id: #{deploy_id}, mu_name: #{mu_name}, region: #{region}, dns_name: #{dns_name}", MU::DEBUG
						end
					elsif deploydata.is_a?(Hash)
						id = deploydata['awsname'] if id.nil? and deploydata.has_key?("awsname")
						dns_name = deploydata['dns'] if dns_name.nil? and deploydata.has_key?("dns")
					end
				end

				return nil if id.nil? and dns_name.nil?

				resp = MU::Cloud::AWS.elb(region).describe_load_balancers
				resp.load_balancer_descriptions.each { |lb|
					return lb if !id.nil? and lb.load_balancer_name == id
					return lb if !dns_name.nil? and lb.dns_name == dns_name
				}

				return nil

			end
		end
	end
	end
end
