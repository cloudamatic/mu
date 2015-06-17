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
		# A DNS Zone as configured in {MU::Config::BasketofKittens::dnszones}
		class DNSZone

			@zone = nil

			# Whether {MU::Deploy} should hold creation of other resources which depend on this resource until the latter has been created.
			def deps_wait_on_my_creation; true.freeze end
			# Whether {MU::Deploy} should hold creation of this resource until resources on which it depends have been fully created and deployed.
			def waits_on_parent_completion; false.freeze end

			# @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
			# @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::dnszones}
			def initialize(mommacat: mommacat, kitten_cfg: kitten_cfg)
				@deploy = mommacat
				@zone = kitten_cfg
				MU.setVar("curRegion", @zone['region']) if !@zone['region'].nil?
			end

			# Called automatically by {MU::Deploy#createResources}
			def create
				MU.setVar("curRegion", @zone['region']) if !@zone['region'].nil?
				params = {
					:name => @zone['name'],
					:hosted_zone_config => {
						:comment => MU.mu_id
					},
					:caller_reference => MU::MommaCat.getResourceName(@zone['name'])
				}

				# Private zones have their lookup restricted by VPC
				add_vpcs = Hash.new
				if @zone['private']
					default_vpc = nil

					MU::Cloud::AWS.listRegions.each { |region|

						known_vpcs = MU::Cloud::AWS.ec2.describe_vpcs

						MU.log "Enumerating VPCs in #{region}", MU::DEBUG, details: known_vpcs.vpcs

						known_vpcs.vpcs.each { |vpc|
							if vpc.is_default and default_vpc.nil?
								default_vpc = vpc.vpc_id
							end
						}
					
						# If we've been told to make this domain available account-wide, do so
						if @zone['all_account_vpcs']
							known_vpcs.vpcs.each { |vpc|
								add_vpcs[vpc.vpc_id] = region
							}
						else
							break
						end

					}

					# Now add any other VPCs we specified in our config, if we haven't
					# already picked them up.
					if !@zone['vpcs'].nil? and @zone['vpcs'].size > 0
						@zone['vpcs'].each { |vpc|
							if !add_vpcs.has_key?(vpc['vpc_id'])
								add_vpcs[vpc['vpc_id']] = vpc['region']
							end
						}
					end

					if add_vpcs.size == 0
						MU.log "DNS Zone #{@zone['name']} is flagged as private, but I can't find any VPCs in which to put it", MU::ERR
						raise MuError, "DNS Zone #{@zone['name']} is flagged as private, but I can't find any VPCs in which to put it"
					end

					if !default_vpc.nil? and add_vpcs.has_key?(default_vpc)
						params[:vpc] = {
							:vpc_region => add_vpcs[default_vpc],
							:vpc_id => default_vpc
						}
					elsif !MU.myVPC.nil? and add_vpcs.include?(MU.myVPC)
						params[:vpc] = {
							:vpc_region => add_vpcs[MU.myVPC],
							:vpc_id => MU.myVPC
						}
					else
						params[:vpc] = {
							:vpc_region => add_vpcs[add_vpcs.keys.first],
							:vpc_id => add_vpcs.keys.first
						}
					end

				end

				MU.log "Creating DNS Zone '#{@zone['name']}'", details: params

				resp = MU::Cloud::AWS.route53.create_hosted_zone(params)
				id = resp.hosted_zone.id

				begin
					resp = MU::Cloud::AWS.route53.get_hosted_zone(
						id: id
					)
					sleep 10
				end while resp.nil? or resp.size == 0

				if add_vpcs.size > 0
					add_vpcs.each_pair { |vpc_id, region|
						if vpc_id != params[:vpc][:vpc_id]
							MU.log "Associating VPC #{vpc_id} in #{region} with DNS Zone #{@zone['name']}", MU::DEBUG
							begin
							MU::Cloud::AWS.route53.associate_vpc_with_hosted_zone(
								hosted_zone_id: id,
								vpc: {
									:vpc_region => region,
									:vpc_id => vpc_id
								}
							)
							rescue Aws::Route53::Errors::InvalidVPCId => e
								MU.log "Unable to associate #{vpc_id} in #{region} with DNS Zone #{@zone['name']}: #{e.inspect}", MU::WARN
							end
						end
					}
				end

				MU::Cloud::AWS::DNSZone.notify(@zone['name'], id, @zone)

				MU::Cloud::AWS::DNSZone.createRecordsFromConfig(@zone['records'])

				return resp.hosted_zone
			end

			# Wrapper for {MU::Cloud::AWS::DNSZone.manageRecord}. Spawns threads to create all
			# requested records in background and returns immediately.
			# @param cfg [Array]: An array of parsed {MU::Config::BasketofKittens::dnszones::records} objects.
			# @param target [String]: Optional target for the records to be created. Overrides targets embedded in cfg records.
			def self.createRecordsFromConfig(cfg, target: nil)
				return if cfg.nil?
				record_threads = []
				cfg.each { |record|
					zone, junk = MU::Cloud::DNSZone.find(name: record['zone']['name'], id: record['zone']['id'])
					healthcheck_id = nil
					record['target'] = target if !target.nil?
					if !record['healthcheck'].nil?
						healthcheck_id = MU::Cloud::AWS::DNSZone.createHealthCheck(record['healthcheck'], record['target'])
					end
					parent_thread_id = Thread.current.object_id
					record_threads << Thread.new {
						MU.dupGlobals(parent_thread_id)
						MU::Cloud::AWS::DNSZone.manageRecord(zone.id, record['name'], record['type'],
							targets: [record['target']], ttl: record['ttl'],
							failover: record['failover'], healthcheck: healthcheck_id,
							weight: record['weight'], overwrite: record['override_existing'],
							location: record['geo_location'], region: record['region'],
							alias_zone: record['alias_zone'], sync_wait: false)
					}
				}
# we probably don't have to wait for these
#			record_threads.each { |t|
#				t.join
#			}
			end

			# Create a Route53 health check. 
			# @param cfg [Hash]: Parsed hash of {MU::Config::BasketofKittens::dnszones::records::healthcheck}
			# @param target [String]: The IP address of FQDN of the target resource to check.
			def self.createHealthCheck(cfg, target)

				check = {
					:type => cfg['method'],
					:request_interval => cfg['check_interval'],
					:failure_threshold => cfg['failure_threshold']
				}
				check[:resource_path] = cfg['path'] if !cfg['path'].nil?
				check[:search_string] = cfg['search_string'] if !cfg['search_string'].nil?
				check[:port] = cfg['port'] if !cfg['port'].nil?

				if target.match(/^\d+\.\d+\.\d+\.\d+$/)
					check[:ip_address] = target
				else
					check[:fully_qualified_domain_name] = target
				end
				
				MU.log "Creating health check for #{target}", details: check
				id = MU::Cloud::AWS.route53.create_health_check(
					caller_reference: MU::MommaCat.getResourceName(cfg['method']+"-"+Time.now.to_i.to_s),
					health_check_config: check
				).health_check.id

				# Currently the only thing we can tag in Route 53... is health checks.
				tags = []
				MU::MommaCat.listStandardTags.each_pair { |name, value|
					tags << { key: name, value: value }
				}
				tags << { key: "Name", value: MU.mu_id+"-"+target.upcase }

				MU::Cloud::AWS.route53.change_tags_for_resource(
					resource_type: "healthcheck",
					resource_id: id,
					add_tags: tags
				)

				return id
			end


			# Add or remove access for a given (presumably) private cloud-hosted DNS
			# zone to/from the specified VPC.
			# @param id [String]: The cloud identifier of the DNS zone to update
			# @param vpc_id [String]: The cloud identifier of the VPC
			# @param region [String]: The cloud provider's region
			# @param remove [Boolean]: Whether to remove access (default: grant access)
			def self.toggleVPCAccess(id: id, vpc_id: vpc_id, region: MU.curRegion, remove: false)

				if !remove
					MU.log "Granting VPC #{vpc_id} access to zone #{id}"
					MU::Cloud::AWS.route53(region).associate_vpc_with_hosted_zone(
						hosted_zone_id: id,
						vpc: {
							:vpc_id => vpc_id,
							:vpc_region => region
						},
						comment: MU.mu_id
					)
				else
					MU.log "Revoking VPC #{vpc_id} access to zone #{id}"
					begin
						MU::Cloud::AWS.route53(region).disassociate_vpc_from_hosted_zone(
							hosted_zone_id: id,
							vpc: {
								:vpc_id => vpc_id,
								:vpc_region => region
							},
							comment: MU.mu_id
						)
					rescue Aws::Route53::Errors::LastVPCAssociation => e
						MU.log e.inspect, MU::WARN
					rescue Aws::Route53::Errors::VPCAssociationNotFound => e
						MU.log "VPC #{vpc_id} access to zone #{id} already revoked", MU::WARN
					end
				end
			end

			# Create a new DNS record in the given DNS zone
			# @param id [String]: The cloud provider's identifier for the zone.
			# @param name [String]: The DNS name we're creating
			# @param type [String]: The class of DNS record we're creating (e.g. A, CNAME, PTR, SPF...)
			# @param targets [Array<String>]: Standard DNS values for this record. Must be valid for the 'type' field, e.g. A records must point to a IP addresses.
			# @param ttl [Integer]: The DNS time-to-live value for this record.
			# @param delete [Boolean]: Whether to delete the described record, instead of creating.
			# @param overwrite [Boolean]: Whether to overwrite existing records which match this description, as opposed to creating an entirely new one.
			# @param sync_wait [Boolean]: Wait until the record change has fully propagated throughout Route53 before returning.
			# @param failover [String]: "PRIMARY" or "SECONDARY" for Route53 failover. See also {MU::Config::BasketofKittens::dnszones::records}.
			# @param healthcheck [String]: A Route53 healthcheck identifier for use with failover. Typically created by {MU::Config::BasketofKittens::dnszones::records::healthcheck}.
			# @param region [String]: An Amazon Web Services region for use with latency-based routing. See also {MU::Config::BasketofKittens::dnszones::records}.
			# @param weight [Integer]: A weight value used for weighted routing, used to determine proportion of traffic with other matching weighted records. See also {MU::Config::BasketofKittens::dnszones::records}.
			# @param location [Hash<String>]: A parsed Hash of {MU::Config::BasketofKittens::dnszones::records::geo_location}.
			# @param set_identifier [String]: A unique string to differentiate otherwise-similar records. Normally auto-generated, should not need to specify.
			# @param alias_zone [String]: Zone ID of the target's hosted zone, when creating an alias (type R53ALIAS)
			def self.manageRecord(id, name, type, targets: nil, aliases: nil,
					ttl: 7200, delete: false, sync_wait: true, failover: nil,
					healthcheck: nil, region: nil, weight: nil, overwrite: true,
					location: nil, set_identifier: nil, alias_zone: nil)

				MU.setVar("curRegion", region) if !region.nil?
				zone, mu_name = MU::Cloud::DNSZone.find(id: id)
				if zone.nil?
					raise MuError, "Hosted DNS Zone #{id} not found"
				end

				if zone.nil?
					MU.log "Attempting to add record to nonexistent DNS zone #{id}", MU::ERR
					raise MuError, "Attempting to add record to nonexistent DNS zone #{id}"
				end

				name = name + "." + zone.name if !name.match(/(^|\.)#{zone.name}$/)

				action = "CREATE"
				action = "UPSERT" if overwrite
				action = "DELETE" if delete

				if type == "R53ALIAS"
					target_zone = id
					target_name = targets[0].downcase
					target_name.chomp!(".")
					if !alias_zone.nil?
						target_zone = "/hostedzone/"+alias_zone if !alias_zone.match(/^\/hostedzone\//)
					else
						MU::Cloud::AWS.listRegions.each { |region|
							MU::Cloud::AWS.elb.describe_load_balancers().load_balancer_descriptions.each { |elb|
								elb_dns = elb.dns_name.downcase
								elb_dns.chomp!(".")
								if target_name == elb_dns
									MU.log "Resolved #{targets[0]} to an Elastic Load Balancer in zone #{elb.canonical_hosted_zone_name_id}", details: elb
									target_zone = "/hostedzone/"+elb.canonical_hosted_zone_name_id
									break
								end
							}
							break if target_zone != id
						}
					end
					base_rrset = {
						:name => name,
						:type => "A",
						:alias_target => {
							:hosted_zone_id => target_zone,
							:dns_name => targets[0],
							:evaluate_target_health => true
						}
					}
				else
					rrsets = []
					if !targets.nil?
						targets.each { |target|
							rrsets << { :value => target }
						}
					end
					base_rrset = {
						:name => name,
						:type => type,
						:ttl => ttl,
						:resource_records => rrsets
					}
					if !healthcheck.nil?
						base_rrset[:health_check_id] = healthcheck
					end
				end

				params = {
					:hosted_zone_id => id,
					:change_batch => {
						:changes => [
							{
								:action => action,
								:resource_record_set => base_rrset
							}
						]
					}
				}


				if !failover.nil?
					base_rrset[:failover] = failover
					base_rrset[:set_identifier] = MU.mu_id+"-failover-"+failover.downcase
				elsif !weight.nil?
					base_rrset[:weight] = weight
					base_rrset[:set_identifier] = MU.mu_id+"-weighted-"+weight.to_s
				elsif !location.nil?
					loc_arg = Hash.new
					location.each_pair { |key,val|
						sym = key.to_sym
						loc_arg[sym] = val
					}
					base_rrset[:geo_location] = loc_arg
					base_rrset[:set_identifier] = MU.mu_id+"-location-"+location.values.join("-")
				elsif !region.nil?
					base_rrset[:region] = region
					base_rrset[:set_identifier] = MU.mu_id+"-latency-"+region
				end

				if !set_identifier.nil?
					base_rrset[:set_identifier] = set_identifier
				end


				if !delete
					MU.log "Adding DNS record #{name} => #{targets} (#{type}) to #{id}", details: params
				else
					MU.log "Deleting DNS record #{name} (#{type}) from #{id}", details: params
				end

				begin
					change_id = MU::Cloud::AWS.route53.change_resource_record_sets(params).change_info.id
				rescue Aws::Route53::Errors::PriorRequestNotComplete => e
					sleep 10
					retry
				rescue Aws::Route53::Errors::InvalidChangeBatch, Aws::Route53::Errors::InvalidInput, Exception => e
					return if e.message.match(/ but it already exists$/) and !delete
					MU.log "Failed to change DNS records, #{e.inspect}", MU::ERR, details: params
					raise e if !delete
					MU.log "Record #{name} (#{type}) in #{id} can't be deleted. Already removed? #{e.inspect}", MU::WARN, details: params
					return
				end

				if sync_wait
					attempts = 0
					start_time = Time.now.to_i
					begin
						MU.log "Waiting for DNS record change for '#{name}' to propagate in zone '#{zone.name}'", MU::NOTICE if attempts % 3 == 0
						sleep 15
						change_info = MU::Cloud::AWS.route53.get_change(id: change_id).change_info
						if change_info.status != "INSYNC" and attempts % 3 == 0
							MU.log "DNS zone #{zone.name} still in state #{change_info.status} after #{Time.now.to_i - start_time}s", MU::DEBUG, details: change_info
						end
						attempts = attempts + 1
					end while change_info.status != "INSYNC"
				end

			end

#		@resolver = Resolv::DNS.new

			# Set a generic .platform-mu DNS entry for a resource, and return the name that
			# was set.
			# @param name [name]: The base name of the resource
			# @param target [String]: The target of the DNS entry, usually an IP.
			# @param noop [Boolean]: Don't attempt to adjust entries, just return the name we'd create/remove.
			# @param delete [Boolean]: Remove this entry instead of creating it.
			# @param cloudclass [Object]: The resource's Mu class.
			# @param sync_wait [Boolean]: Wait for DNS entry to propagate across zone.
			def self.genericDNSEntry(name, target, cloudclass, noop: false, delete: false, sync_wait: true)
				return nil if name.nil? or target.nil? or cloudclass.nil?
				mu_zone, junk = MU::Cloud::DNSZone.find(name: "platform-mu")
				MU::Cloud.artifact("AWS", :LoadBalancer)

				if !mu_zone.nil? and !MU.myVPC.nil?
					subdomain = cloudclass.cfg_name
					dns_name = name.downcase+"."+subdomain+"."+MU.myInstanceId
					record_type = "CNAME"
					record_type = "A" if target.match(/^\d+\.\d+\.\d+\.\d+/)
					ip = nil

					lookup = MU::Cloud::AWS.route53.list_resource_record_sets(
						hosted_zone_id: mu_zone.id,
						start_record_name: "#{dns_name}.platform-mu",
						start_record_type: record_type
					).resource_record_sets

					lookup.each { |record|
						if record.name.match(/^#{dns_name}\.platform-mu/i) and record.type == record_type
							record.resource_records.each { |rrset|
								if rrset.value == target
									ip = rrset.value
								end
							}

						end
					}

#					begin
#						ip = @resolver.getaddress("#{dns_name}.platform-mu")
#MU.log "@resolver.getaddress(#{dns_name}.platform-mu) => #{ip.to_s} (target is #{target})", MU::WARN, details: ip
#					rescue Resolv::ResolvError => e
#						MU.log "'#{dns_name}.platform-mu' does not resolve.", MU::DEBUG, details: e.inspect
#					end

					if ip == target
						return "#{dns_name}.platform-mu" if !delete
					elsif noop
						return nil
					end

					sync_wait = false if delete

					record_type = "R53ALIAS" if cloudclass == MU::Cloud::AWS::LoadBalancer
					attempts = 0
					begin
						MU::Cloud::AWS::DNSZone.manageRecord(mu_zone.id, dns_name, record_type, targets: [target], delete: delete, sync_wait: sync_wait)
					rescue Aws::Route53::Errors::PriorRequestNotComplete => e
						MU.log "Route53 was still processing a request, waiting", MU::WARN, details: e
						sleep 15
						retry
					rescue Aws::Route53::Errors::InvalidChangeBatch => e
						if e.inspect.match(/alias target name does not lie within the target zone/) and attempts < 5
							MU.log e.inspect, MU::WARN
							sleep 15
							attempts = attempts + 1
							retry
						elsif !e.inspect.match(/it already exists/)
							raise MuError "Problem managing entry for #{dns_name} -> #{target}: #{e.inspect}"
						else
							MU.log "#{dns_name} already exists", MU::DEBUG, details: e.inspect
						end
					end
					return dns_name
				else
					return nil
				end
			end

			# Log DNS zone metadata to the deployment struct for the current deploy.
			# @param name [String]: The Mu resource name of this zone, which is also the domain name.
			# @param id [String]: The cloud provider's identifier for the zone.
			# @param cfg [Hash]: The original {MU::Config::BasketofKittens::dnszones} structure for this zone.
			# @param region [String]: The region into which this zone was deployed.
			def self.notify(name, id, cfg, region: region)
				MU.setVar("curRegion", region) if !region.nil?
				if !MU.mommacat.deployment[MU::Cloud::DNSZone.cfg_plural].nil? and !MU.mommacat.deployment[MU::Cloud::DNSZone.cfg_plural][name].nil?
					deploydata = MU.mommacat.deployment[MU::Cloud::DNSZone.cfg_plural][name].dup
				else
					deploydata = Hash.new
				end

				resp = MU::Cloud::AWS.route53.get_hosted_zone(
					id: id
				)
				deploydata.merge!(MU.structToHash(resp.hosted_zone))
				deploydata['vpcs'] = cfg['vpcs'] if !cfg['vpcs'].nil?

				deploydata["region"] = region if !region.nil?

				MU.mommacat.notify(MU::Cloud::DNSZone.cfg_plural, name, deploydata)

				return deploydata
			end

			# Called by {MU::Cleanup}. Locates resources that were created by the
			# currently-loaded deployment, and purges them.
			def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
				checks_to_clean = []
				MU::Cloud::AWS.route53(region).list_health_checks().health_checks.each { |check|
					tags = MU::Cloud::AWS.route53(region).list_tags_for_resource(
						resource_type: "healthcheck",
						resource_id: check.id
					).resource_tag_set.tags
					muid_match = false
					mumaster_match = false
					tags.each { |tag|
						muid_match = true if tag.key == "MU-ID" and tag.value == MU.mu_id
						mumaster_match = true if tag.key == "MU-MASTER-IP" and tag.value == MU.mu_public_ip
					}
					if muid_match and mumaster_match
						MU.log "Removing health check #{check.id}"
						MU::Cloud::AWS.route53(region).delete_health_check(health_check_id: check.id) if !noop
					end
				}
				zones, name = MU::Cloud::DNSZone.find(deploy_id: MU.mu_id, allow_multi: true, region: region)
				zones.each { |zone|
					MU.log "Purging DNS Zone '#{zone.name}' (#{zone.id})"
					if !noop
						begin
							# Clean up resource records first
							rrsets = MU::Cloud::AWS.route53(region).list_resource_record_sets(hosted_zone_id: zone.id)
							rrsets.resource_record_sets.each { |rrset|
								next if zone.name == rrset.name and (rrset.type == "NS" or rrset.type == "SOA")
								records = []
								MU::Cloud::AWS.route53(region).change_resource_record_sets(
									hosted_zone_id: zone.id,
									change_batch: {
										changes: [
											{
												action: "DELETE",
												resource_record_set: MU.structToHash(rrset)
											}
										]
									}
								)
							}
							MU::Cloud::AWS.route53(region).delete_hosted_zone(id: zone.id)
						rescue Aws::Route53::Errors::NoSuchHostedZone => e
							MU.log "DNS Zone '#{zone.name}' (#{zone.id}) disappeared before I could remove it", MU::WARN, details: e.inspect
						rescue Aws::Route53::Errors::HostedZoneNotEmpty => e
							raise MuError, e.inspect
						end
					end
				}
			end

			# Locate an Mu controlled DNS zone hosted by our cloud provider. Can
			# identify zones by their cloud provider identifier, OR by their internal
			# Mu resource name, OR by a cloud provider tag name/value pair, OR by an
			# assigned IP address.
			# @param name [String]: An Mu resource name, usually the 'name' field of aa Basket of Kittens resource declaration. Will search the currently loaded deployment unless another is specified.
			# @param deploy_id [String]: The deployment to search using the 'name' parameter.
			# @param id [String]: The cloud provider's identifier for this resource.
			# @param allow_multi [Boolean]: When searching by tags or name, permit an array of resources to be returned (if applicable) instead of just one.
			# @param region [String]: The cloud provider's region
			# @return [OpenStruct,String]: The cloud provider's complete description of this DNS zone, and its MU resource name (if applicable).
			def self.find(name: nil, deploy_id: MU.mu_id, id: nil, allow_multi: false, region: MU.curRegion)
				return nil if !id and !name and !deploy_id

				MU.log "Searching for DNS Zone with name: #{name}, deploy_id: #{deploy_id}, id: #{id}, allow_multi: #{allow_multi}", MU::DEBUG

				resp = MU::Cloud::AWS.route53(region).list_hosted_zones(
					max_items: 100
				)
				dns_matches=deploy_matches=id_matches = []
				resp.hosted_zones.each { |zone|
					if !name.nil? and !name.empty? and (zone.name == name or zone.name == name+".")
						dns_matches << MU::Cloud::AWS.route53(region).get_hosted_zone(id: zone.id).hosted_zone
					end
					if !id.nil? and !id.empty? and zone.id == id
						id_matches << MU::Cloud::AWS.route53(region).get_hosted_zone(id: zone.id).hosted_zone
					end
					if !deploy_id.nil? and !deploy_id.empty? and zone.config.comment == deploy_id
						deploy_matches << MU::Cloud::AWS.route53(region).get_hosted_zone(id: zone.id).hosted_zone
					end
				}

				# If we specified both a DNS name and a deploy id, return only things
				# that match both. Since Route53 doesn't do tags, we need extra safety
				# in case of colliding MU-ID tags from different masters.
				if !name.nil? and !deploy_id.nil?
					matches = dns_matches & deploy_matches
				else
					matches = dns_matches + deploy_matches + id_matches
					matches.uniq!
				end

				if matches.size > 1 and !allow_multi
					MU.log "Found multiple DNS zones matching name: #{name}, deploy_id: #{deploy_id}", MU::ERR, details: matches
					raise MuError, "Found multiple DNS zones matching name: #{name}, deploy_id: #{deploy_id}"
				end

				if allow_multi
					return [matches, name]
				else
					return [matches.first, name]
				end
			end
		end
	end
	end
end
