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

	# Creation of Virtual Private Clouds and associated artifacts (routes, subnets, etc).
	class VPC
		# The {MU::Config::BasketofKittens} name for a single resource of this class.
		def self.cfg_name; "vpc".freeze end
		# The {MU::Config::BasketofKittens} name for a collection of resources of this class.
		def self.cfg_plural; "vpcs".freeze end
		# Whether {MU::Deploy} should hold creation of other resources which depend on this resource until the latter has been created.
		def self.deps_wait_on_my_creation; true.freeze end
		# Whether {MU::Deploy} should hold creation of this resource until resources on which it depends have been fully created and deployed.
		def self.waits_on_parent_completion; false.freeze end

		@deploy = nil
		@vpc = nil

		# @param deployer [MU::Deploy]: A {MU::Deploy} object, typically associated with an in-progress deployment.
		# @param vpc [Hash]: The full {MU::Config} resource declaration as defined in {MU::Config::BasketofKittens::vpcs}
		def initialize(deployer, vpc)
			@deploy = deployer
			@vpc = vpc
			MU.setVar("curRegion", @vpc['region']) if !@vpc['region'].nil?
		end

		# Called automatically by {MU::Deploy#createResources}
		def create
			vpc_name = MU::MommaCat.getResourceName(@vpc['name'])

			MU.log "Creating VPC #{vpc_name}", details: @vpc
			begin
				resp = MU.ec2.create_vpc(cidr_block: @vpc['ip_block']).vpc
			rescue Aws::EC2::Errors::Unavailable, Aws::EC2::Errors::InternalError => e
				MU.log "Transient AWS weirdness: #{e.inspect}. Retrying after 30s", MU::ERR
				sleep 30
				retry
			end
			vpc_id = @vpc['vpc_id'] = resp.vpc_id

			MU::MommaCat.createStandardTags(vpc_id, region: @vpc['region'])
			MU::MommaCat.createTag(vpc_id, "Name", vpc_name, region: @vpc['region'])
			if @vpc['tags']
				@vpc['tags'].each { |tag|
					MU::MommaCat.createTag(vpc_id,tag['key'],tag['value'], region: @vpc['region'])
				}
			end

			if resp.state != "available"
				begin
					MU.log "Waiting for VPC #{vpc_name} (#{vpc_id}) to be available", MU::NOTICE
					sleep 5
					resp = MU.ec2(@vpc['region']).describe_vpcs(vpc_ids: [vpc_id]).vpcs.first
				end while resp.state != "available"
				# There's a default route table that comes with. Let's tag it.
				resp = MU.ec2(@vpc['region']).describe_route_tables(
					filters: [
						{
							name: "vpc-id",
							values: [vpc_id]
						}
					]
				)
				resp.route_tables.each { |rtb|
					MU::MommaCat.createTag(rtb.route_table_id, "Name", vpc_name+"-#DEFAULTPRIV", region: @vpc['region'])
					if @vpc['tags']
						@vpc['tags'].each { |tag|
							MU::MommaCat.createTag(rtb.route_table_id,tag['key'],tag['value'], region: @vpc['region'])
						}
					end
					MU::MommaCat.createStandardTags(rtb.route_table_id, region: @vpc['region'])
				}
			end
			@vpc['vpc_id'] = vpc_id
			@deploy.notify("vpcs", @vpc['name'], @vpc)

			deploy_struct = @deploy.deployment['vpcs'][@vpc['name']].dup

			if @vpc['create_internet_gateway']
				MU.log "Creating Internet Gateway #{vpc_name}"
				resp = MU.ec2(@vpc['region']).create_internet_gateway
				internet_gateway_id = resp.internet_gateway.internet_gateway_id
				sleep 5
				MU::MommaCat.createStandardTags(internet_gateway_id, region: @vpc['region'])
				MU::MommaCat.createTag(internet_gateway_id, "Name", vpc_name, region: @vpc['region'])
				if @vpc['tags']
					@vpc['tags'].each { |tag|
						MU::MommaCat.createTag(internet_gateway_id,tag['key'],tag['value'], region: @vpc['region'])
					}
				end
				MU.ec2(@vpc['region']).attach_internet_gateway(vpc_id: vpc_id, internet_gateway_id: internet_gateway_id)
				@vpc['internet_gateway_id'] = internet_gateway_id
			end

			if !@vpc['route_tables'].nil?
				deploy_struct['route_tables'] = Hash.new
				@vpc['route_tables'].each { |rtb|
					rtb = createRouteTable(rtb)
					deploy_struct['route_tables'][rtb['name']] = rtb
				}
				@deploy.notify("vpcs", @vpc['name'], deploy_struct)
			end

			if !@vpc['subnets'].nil?
				deploy_struct['subnets'] = Hash.new
				subnet_semaphore = Mutex.new
				subnetthreads = Array.new
				parent_thread_id = Thread.current.object_id
				azs = MU::Config.listAZs
				@vpc['subnets'].each { |subnet|
					subnet_name = @vpc['name']+"-"+subnet['name']
					MU.log "Creating Subnet #{subnet_name}", details: subnet
					azs = MU::Config.listAZs if azs.size == 0
					if !subnet['availability_zone'].nil?
						az = subnet['availability_zone']
					else
						az = azs.pop
					end
					subnetthreads << Thread.new {
						MU.dupGlobals(parent_thread_id)
						resp = MU.ec2(@vpc['region']).create_subnet(
							vpc_id: vpc_id,
							cidr_block: subnet['ip_block'],
							availability_zone: az
						).subnet
						subnet_id = subnet['subnet_id'] = resp.subnet_id
						MU::MommaCat.createStandardTags(subnet_id, region: @vpc['region'])
						MU::MommaCat.createTag(subnet_id, "Name", vpc_name+"-"+subnet['name'], region: @vpc['region'])
						if @vpc['tags']
							@vpc['tags'].each { |tag|
								MU::MommaCat.createTag(subnet_id,tag['key'],tag['value'], region: @vpc['region'])
							}
						end
						if resp.state != "available"
							begin
								MU.log "Waiting for Subnet #{subnet_name} (#{subnet_id}) to be available", MU::NOTICE
								sleep 5
								resp = MU.ec2(@vpc['region']).describe_subnets(subnet_ids: [subnet_id]).subnets.first
							rescue Aws::EC2::Errors::InvalidSubnetIDNotFound => e
								retry
							end while resp.state != "available"
						end
						if !subnet['route_table'].nil?
							routes = deploy_struct['route_tables']
							if routes.nil? or routes[subnet['route_table']].nil?
								MU.log "Subnet #{subnet_name} references non-existent route #{subnet['route_table']}", MU::ERR, details: @deploy.deployment['vpcs']
								raise "deploy failure"
							end
							MU.log "Associating Route Table '#{subnet['route_table']}' (#{routes[subnet['route_table']]['route_table_id']}) with #{subnet_name}"
							retries = 0
							begin
								MU.ec2(@vpc['region']).associate_route_table(
									route_table_id: routes[subnet['route_table']]['route_table_id'],
									subnet_id: subnet_id
								)
							rescue Aws::EC2::Errors::InvalidRouteTableIDNotFound => e
								retries = retries + 1
								if retries < 10
									sleep 10
									retry
								else
									raise e
								end
							end
						end
						retries = 0
						begin
							resp = MU.ec2(@vpc['region']).describe_subnets(subnet_ids: [subnet_id]).subnets.first
						rescue Aws::EC2::Errors::InvalidSubnetIDNotFound => e
							if retries < 10
								MU.log "Got #{e.inspect}, waiting and retrying", MU::WARN
								sleep 10
								retries = retries + 1
								retry
							end
							raise e
						end
						subnet_semaphore.synchronize {
							deploy_struct['subnets'][subnet['name']] = subnet
						}
					}
				}
				subnetthreads.each { |t|
					t.join
				}
				@deploy.notify("vpcs", @vpc['name'], deploy_struct)
			end

			if @vpc['enable_dns_support']
				MU.log "Enabling DNS support in #{vpc_name}"
				MU.ec2(@vpc['region']).modify_vpc_attribute(
					vpc_id: vpc_id,
					enable_dns_support: { value: @vpc['enable_dns_support'] }
				)
			end
			if @vpc['enable_dns_hostnames']
				MU.log "Enabling DNS hostnames in #{vpc_name}"
				MU.ec2(@vpc['region']).modify_vpc_attribute(
					vpc_id: vpc_id,
					enable_dns_hostnames: { value: @vpc['enable_dns_hostnames'] }
				)
			end

			if @vpc['dhcp']
				MU.log "Setting custom DHCP options in #{vpc_name}", details: @vpc['dhcp']
				dhcpopts = []

				if @vpc['dhcp']['netbios_type']
					dhcpopts << { key: "netbios-node-type", values: [ @vpc['dhcp']['netbios_type'].to_s ] } 
				end
				if @vpc['dhcp']['domains']
					dhcpopts << { key: "domain-name", values: @vpc['dhcp']['domains'] }
				end
				if @vpc['dhcp']['dns_servers']
					dhcpopts << { key: "domain-name-servers", values: @vpc['dhcp']['dns_servers'] }
				end
				if @vpc['dhcp']['ntp_servers']
					dhcpopts << { key: "ntp-servers", values: @vpc['dhcp']['ntp_servers'] }
				end
				if @vpc['dhcp']['netbios_servers']
					dhcpopts << { key: "netbios-name-servers", values: @vpc['dhcp']['netbios_servers'] }
				end

				resp = MU.ec2(@vpc['region']).create_dhcp_options(
					dhcp_configurations: dhcpopts
				)
				dhcpopt_id = resp.dhcp_options.dhcp_options_id
				MU::MommaCat.createStandardTags(dhcpopt_id, region: @vpc['region'])
				MU::MommaCat.createTag(dhcpopt_id, "Name", vpc_name, region: @vpc['region'])
				if @vpc['tags']
					@vpc['tags'].each { |tag|
						MU::MommaCat.createTag(dhcpopt_id,tag['key'],tag['value'], region: @vpc['region'])
					}
				end
				MU.ec2(@vpc['region']).associate_dhcp_options(dhcp_options_id: dhcpopt_id, vpc_id: vpc_id)
			end
			@deploy.notify("vpcs", @vpc['name'], @vpc)

			mu_zone, junk = MU::DNSZone.find(name: "mu")
			if !mu_zone.nil?
				MU::DNSZone.toggleVPCAccess(id: mu_zone.id, vpc_id: vpc_id, region: @vpc['region'])
			end

			MU.log "VPC #{vpc_name} created", details: @vpc

		end

		# Called automatically by {MU::Deploy#createResources}
		def deploy
			vpc_name = MU::MommaCat.getResourceName(@vpc['name'])
			deploy_struct = @deploy.deployment['vpcs'][@vpc['name']]

			# Generate peering connections
			if !@vpc['peers'].nil? and @vpc['peers'].size > 0
				@vpc['peers'].each { |peer|
					if peer['account'].nil? or peer['account'] == MU.account_number
						tag_key, tag_value = peer['vpc']['tag'].split(/=/, 2) if !peer['vpc']['tag'].nil?
						peer_desc, peer_name = MU::VPC.find(
							id: peer['vpc']['vpc_id'],
							name: peer['vpc']['vpc_name'],
							deploy_id: peer['vpc']['deploy_id'],
							tag_key: tag_key,
							tag_value: tag_value,
							region: peer['vpc']['region']
						)
						if peer_desc.nil?
							MU.log "Unabled to locate peer VPC for #{@vpc['name']}", MU::ERR, details: peer
							raise "Unabled to locate peer VPC"
						end
						peer_id = peer_desc.vpc_id
						peer_deploy_struct = nil
						known_vpcs = MU::MommaCat.getResourceDeployStruct("vpcs", name: peer_name, deploy_id: nil)
						known_vpcs.each { |ext_vpc|
							if ext_vpc['vpc_id'] == peer_id
								peer_deploy_struct = ext_vpc
								break
							end
						}

						MU.log "Initiating peering connection from VPC #{@vpc['name']} (#{@vpc['vpc_id']}) to #{peer_id}", MU::INFO, details: peer
						resp = MU.ec2(@vpc['region']).create_vpc_peering_connection(
							vpc_id: @vpc['vpc_id'],
							peer_vpc_id: peer_id
						)
					else
						peer_id = peer['vpc']['vpc_id']
						MU.log "Initiating peering connection from VPC #{@vpc['name']} (#{@vpc['vpc_id']}) to #{peer_id} in account #{peer['account']}", MU::INFO, details: peer
						resp = MU.ec2(@vpc['region']).create_vpc_peering_connection(
							vpc_id: @vpc['vpc_id'],
							peer_vpc_id: peer_id,
							peer_owner_id: peer['account']
						)
					end
					peering_name = MU::MommaCat.getResourceName(@vpc['name']+"-PEER-"+peer_id)

					peering_id = resp.vpc_peering_connection.vpc_peering_connection_id
					MU::MommaCat.createStandardTags(peering_id, region: @vpc['region'])
					MU::MommaCat.createTag(peering_id, "Name", peering_name, region: @vpc['region'])

					# Create routes to our new friend.
					self.class.listAllSubnetRouteTables(@vpc['vpc_id'], region: @vpc['region']).each { |rtb_id|
						my_route_config = {
							:route_table_id => rtb_id,
							:destination_cidr_block => peer_desc.cidr_block,
							:vpc_peering_connection_id => peering_id
						}
						resp = MU.ec2(@vpc['region']).create_route(my_route_config)
					}

					begin
						cnxn = MU.ec2(@vpc['region']).describe_vpc_peering_connections(
							vpc_peering_connection_ids: [peering_id]
						).vpc_peering_connections.first
					
						if cnxn.status.code == "pending-acceptance" 
							if (!peer_deploy_struct.nil? and peer_deploy_struct['auto_accept_peers']) or (!ENV['ALLOW_INVADE_FOREIGN_VPCS'].nil? and !ENV['ALLOW_INVADE_FOREIGN_VPCS'].empty? and ENV['ALLOW_INVADE_FOREIGN_VPCS'] != "0")
								MU.log "Auto-accepting peering connection from VPC #{@vpc['name']} (#{@vpc['vpc_id']}) to #{peer_id}", MU::NOTICE
								MU.ec2(@vpc['region']).accept_vpc_peering_connection(
									vpc_peering_connection_id: peering_id
								)

								# Create routes back from our new friend to us.
								self.class.listAllSubnetRouteTables(peer_id, region: peer['vpc']['region']).each { |rtb_id|
									peer_route_config = {
										:route_table_id => rtb_id,
										:destination_cidr_block => @vpc['ip_block'],
										:vpc_peering_connection_id => peering_id
									}
									resp = MU.ec2(@vpc['region']).create_route(peer_route_config)
								}
#MU.log "Creating route for #{peer_deploy_struct['ip_block']}", details: route_config
#resp = MU.ec2(@vpc['region']).create_route(route_config)
							else
								MU.log "VPC #{peer_id} is not managed by this Mu server or is not configured to auto-accept peering requests. You must accept the peering request for '#{@vpc['name']}' (#{@vpc['vpc_id']}) by hand.", MU::NOTICE
							end
						end

						if cnxn.status.code == "failed" or cnxn.status.code == "rejected" or cnxn.status.code == "expired" or cnxn.status.code == "deleted"
							MU.log "VPC peering connection from VPC #{@vpc['name']} (#{@vpc['vpc_id']}) to #{peer_id} #{cnxn.status.code}: #{cnxn.status.message}", MU::ERR
							begin
								MU.ec2(@vpc['region']).delete_vpc_peering_connection(
									vpc_peering_connection_id: peering_id
								)
							rescue Aws::EC2::Errors::InvalidStateTransition => e
								# XXX apparently this is normal?
							end
							raise "VPC peering connection from VPC #{@vpc['name']} (#{@vpc['vpc_id']}) to #{peer_id} #{cnxn.status.code}: #{cnxn.status.message}"
						end
					end while cnxn.status.code != "active" and !(cnxn.status.code == "pending-acceptance" and (peer_deploy_struct.nil? or !peer_deploy_struct['auto_accept_peers']))

				}
			end

			# Add any routes that reference instances, which would've been created
			# in Server objects' create phases.
			if !@vpc['route_tables'].nil?
				@vpc['route_tables'].each { |rtb|
					# XXX get route_table_id
					route_table_id = rtb['route_table_id']

					rtb['routes'].each { |route|
						if !route['nat_host_id'].nil? or !route['nat_host_name'].nil?
							route_config = {
								:route_table_id => route_table_id,
								:destination_cidr_block => route['destination_network']
							}

							nat_instance, mu_name = MU::Server.find(
								id: route["nat_host_id"],
								name: route["nat_host_name"],
								region: @vpc['region']
							)
							if nat_instance.nil?
								MU.log "#{vpc_name} is configured to use #{route} but I can't find a running instance matching nat_host_id or nat_host_name", MU::ERR
								raise "deploy failure"
							end
							route_config[:instance_id] = nat_instance.instance_id

							MU.log "Creating route for #{route['destination_network']} through NAT host #{nat_instance.instance_id}", details: route_config
							resp = MU.ec2(@vpc['region']).create_route(route_config)
						end
					}

				}
				@deploy.notify("vpcs", @vpc['name'], deploy_struct)
			end

		end

		# Locate an existing VPC. Can identify VPCs by their cloud provider
		# identifier, OR by their internal Mu resource name, OR by a cloud
		# provider tag name/value pair.
		# @param name [String]: An Mu resource name, usually the 'name' field of aa Basket of Kittens resource declaration. Will search the currently loaded deployment unless another is specified.
		# @param deploy_id [String]: The deployment to search using the 'name' parameter.
		# @param id [String]: The cloud provider's identifier for this resource.
		# @param tag_key [String]: A tag key to search.
		# @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
		# @param allow_multi [Boolean]: When searching by tags, permit an array of resources to be returned (if applicable) instead of just one.
		# @param region [String]: The cloud provider region
		# @return [OpenStruct,String]: The cloud provider's complete description of this VPC, and its MU resource name (if applicable).
		def self.find(name: nil, deploy_id: MU.mu_id, id: nil, tag_key: "Name", tag_value: nil, allow_multi: false, region: MU.curRegion)

			retries = 0
			begin
				sleep 5 if retries < 0

				# Case one- we've been asked to find this resource by the name it was
				# given in its Mu stack configuration. Optionally, search a
				# deployment other than the currently loaded one. We pull out the cloud
				# resource id, so that we can then go and execute that search just as
				# we would if we'd been provided that in the first place.
				if id.nil? 
					resource = MU::MommaCat.getResourceDeployStruct("vpcs", name: name, deploy_id: deploy_id, use_cache: false)
					if !resource.nil?
						if resource.is_a?(Hash)
							id = resource['vpc_id']
						elsif resource.is_a?(Array)
							if resource.size > 1
								MU.log "Got multiple matching VPCs from MU::MommaCat.getResourceDeployStruct('vpcs', name: #{name}, deploy_id: #{deploy_id})", MU::WARN
								return [nil, nil]
							end
							vpc_res = resource.first
							id = vpc_res['vpc_id']
						end
					end
				else
					# If we didn't get a name but did get an id, we want to find the name.
					# Rummage through the deploy for something matching.
					resources = MU::MommaCat.getResourceDeployStruct("vpcs", deploy_id: deploy_id)
					if resources
						resources.each { |vpc|
							name = vpc['name'] if vpc['vpc_id'] == id
						}
					end
				end

				# Case two- we've been asked to find this by its cloud provider id. Make
				# the appropriate API call. Fail gently.
				if !id.nil?
					MU.log "Searching for VPC id '#{id}'", MU::DEBUG
					begin
						resp = MU.ec2(region).describe_vpcs(vpc_ids: [id])
						return [resp.data.vpcs.first, name]
					rescue Aws::EC2::Errors::InvalidVpcIDNotFound => e
					end
				end

				# Case three- try to find things by matching cloud provider tags.
				if tag_value
					MU.log "Searching for VPC '#{name}' by tag:#{tag_key}", MU::DEBUG
					resp = MU.ec2(region).describe_vpcs(
						filters: [
							{ name: "tag:#{tag_key}", values: [tag_value] }
						]
					)
					if resp.data.vpcs.nil? or resp.data.vpcs.size == 0
						return nil
					elsif resp.data.vpcs.size == 1
						return [resp.data.vpcs.first, name]
					elsif resp.data.vpcs.size > 1 
						if !allow_multi
							MU.log "Got multiple results in VPC.find (tag:#{tag_key}=#{tag_value})", MU::ERR, details: resp.data.vpcs
							raise "Got multiple results in VPC.find (tag:#{tag_key}=#{tag_value})"
						else
							return [resp.data.vpcs, name]
						end
					end
				end

				retries = retries + 1
			end while retries < 5

			return nil
		end

		# Locate an existing subnet. Can identify subnets by their cloud provider
		# identifier, OR by their internal Mu resource name, OR by a cloud
		# provider tag name/value pair. A parent VPC must be specified.
		# @param name [String]: An Mu resource name, usually the 'name' field of aa Basket of Kittens resource declaration. Will search the currently loaded deployment unless another is specified.
		# @param deploy_id [String]: The deployment to search using the 'name' parameter.
		# @param id [String]: The cloud provider's identifier for this resource.
		# @param tag_key [String]: A tag key to search.
		# @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
		# @param allow_multi [Boolean]: When searching by tags, permit an array of resources to be returned (if applicable) instead of just one.
		# @param vpc_id [String]: The cloud provider identifier of the VPC which should contain this subnet.
		# @param vpc_name [String]: The Mu resource name of the VPC which should contain this subnet.
		# @param region [String]: The cloud provider region
		# @return [OpenStruct]: The cloud provider's complete description of this VPC.
		def self.findSubnet(name: nil, deploy_id: MU.mu_id, id: nil, tag_key: "Name", tag_value: nil, allow_multi: false, vpc_id: nil, vpc_name: nil, region: MU.curRegion)
			# Go fish for our parent VPC, first off
			existing_vpc, vpc_name = find(id: vpc_id, name: vpc_name, deploy_id: deploy_id, tag_key: tag_key, tag_value: tag_value, region: region)
			if existing_vpc.nil?
				raise "Couldn't find an appropriate VPC in findSubnet (id: #{id}, name: #{name}, vpc_id: #{vpc_id}, vpc_name: #{vpc_name})"
			end
			vpc_id = existing_vpc.vpc_id

			# Now see if this subnet is referenced in any deployments as an Mu
			# resource. We actually use the parent VPC, since a subnet isn't a
			# first-class resource... except sometimes it is, if we yanked it out
			# of a CloudFormation template. Confused yet?
			if id.nil? and !name.nil? 
				vpc = MU::MommaCat.getResourceDeployStruct("vpcs", name: vpc_name, deploy_id: deploy_id)
				subnet = MU::MommaCat.getResourceDeployStruct("subnets", name: name, deploy_id: deploy_id)

				if !subnet.nil?
					if subnet.is_a?(Hash)
						id = subnet['subnet_id']
					elsif subnet.is_a?(Array)
						subnet_res = subnet.first
						id = subnet_res['subnet_id']
					end
				elsif !vpc.nil? and vpc.is_a?(Hash) and
						!vpc['subnets'].nil? and vpc['subnets'].is_a?(Hash) and
						!vpc['subnets'][name].nil?
					id = vpc['subnets'][name]['subnet_id']
				elsif !vpc.nil? and vpc.is_a?(Hash) and
						!vpc['subnets'].nil? and vpc['subnets'].is_a?(Array)
					vpc['subnets'].each { |this_subnet|
						if this_subnet['name'] == name
							id = this_subnet['subnet_id']
							break
						end
					}
				end
			end

			retries = 0
			begin
				if !id.nil?
					resp = MU.ec2(region).describe_subnets(subnet_ids: [id])
					return nil if resp.data.subnets.size == 0 or resp.data.subnets.nil?
					subnet = resp.data.subnets.first
					if subnet.vpc_id != vpc_id
						raise "Subnet #{id} isn't a member of VPC #{vpc_id} in findSubnet (id: #{id}, name: #{name}, vpc_id: #{vpc_id}, vpc_name: #{vpc_name})"
					end
					return subnet
				end

				if !tag_value.nil?
					resp = MU.ec2(region).describe_subnets(
						filters: [
							{ name: "tag:#{tag_key}", values: [tag_value] }
						]
					)
					resp.data.subnets.each { |subnet|
						if subnet.vpc_id == vpc_id
							MU.log "Subnet #{name} has AWS id #{subnet.subnet_id}", MU::DEBUG
							return subnet
						end
					}
				end
			rescue Aws::EC2::Errors::InvalidSubnetIDNotFound => e
				if retries < 10
					retries = retries + 1
					MU.log "Subnet that we know should exist wasn't found, waiting and retrying", MU::WARN
					sleep 10
					retry
				else
					raise e
				end
			end
			return nil
		end

		# List subnets associated with a VPC, given either a name or identifier for said VPC.
		# @param vpc_id [String]: The cloud provider's identifier for the VPC in which we're searching for subnets.
		# @param vpc_name [String]: The name of the VPC in which we're searching for subnets. This parameter will attempt first to find a MU resource with the given name string in the current deployment, and failing that will attempt to find a resource with a matching Name tag.
		# @param region [String]: The cloud provider region
		# @return [Array<String>]: A list of cloud provider identifiers of subnets associated with this VPC.
		def self.listSubnets(vpc_id: vpc_id, vpc_name: vpc_name, region: MU.curRegion)
			existing_vpc, vpc_name = find(id: vpc_id, name: vpc_name)
			if existing_vpc.nil?
				raise "Couldn't find VPC (name: '#{vpc_name}', id: #{vpc_id})"
			end
			resp = MU.ec2(region).describe_subnets(
				filters: [
					{ name: "vpc-id", values: [existing_vpc.vpc_id] }
				]
			)
			return nil if resp.data.subnets.nil? or resp.data.subnets.size == 0

			subnet_ids = Array.new
			resp.data.subnets.each { |subnet|
				subnet_ids << subnet.subnet_id
			}
			return subnet_ids
		end

		# Given a cloud platform identifier for a subnet, determine whether it is
		# publicly routable or private only.
		# @param subnet_id [String]: The cloud identifier of the subnet to check.
		# @param region [String]: The cloud provider region
		# @return [Boolean]
		def self.isSubnetPrivate?(subnet_id, region: MU.curRegion)
			return false if subnet_id.nil?
			resp = MU.ec2(region).describe_route_tables(
				filters: [{name: "association.subnet-id", values: [subnet_id]}]
			)
			resp.route_tables.each { |route_table|
				route_table.routes.each { |route|
					if route.destination_cidr_block =="0.0.0.0/0" and route.instance_id !=nil
						return true
					end
				}
			}
			return false
		end

		# Fetch a subnet's default route. Useful for getting NAT host IDs from
		# subnet identifiers.
		# @param subnet_id [String]: The cloud provider subnet id
		# @return [String]: route
		def self.getDefaultRoute(subnet_id, region: MU.curRegion)
			resp = MU.ec2(region).describe_route_tables(
				filters: [{name: "association.subnet-id", values: [subnet_id]}]
			)
			resp.route_tables.each { |route_table|
				route_table.routes.each { |route|
					if route.destination_cidr_block =="0.0.0.0/0" and route.state != "blackhole"
						return route.instance_id if !route.instance_id.nil?
						return route.gateway_id if !route.gateway_id.nil?
						return route.vpc_peering_connection_id if !route.vpc_peering_connection_id.nil?
						return route.network_interface_id if !route.network_interface_id.nil?
					end
				}
			}
			return nil
		end

		# Take in the @vpc_primitive configuration section and resolve to
		# to a VPC id, a list of Subnet ids, and optional NAT host configuration.
		# @param vpc_conf [Hash]: The {MU::Config} resource element describing a VPC association.
		# @return [Array<String>]: vpc_id, subnet_ids, nat_host_name, nat_ssh_user
		def self.parseVPC(vpc_conf)
			MU.log "Called parseVPC with #{vpc_conf}", MU::DEBUG
			retries = 0

			begin
				existing_vpc, vpc_name = find(
					id: vpc_conf["vpc_id"],
					name: vpc_conf["vpc_name"],
					region: vpc_conf['region']
				)
				if existing_vpc.nil? or existing_vpc.vpc_id.empty?
					sleep 5
					retries = retries + 1
				end
			end while retries < 5 and (existing_vpc.nil? or existing_vpc.vpc_id.empty?)
			raise "Couldn't find an active VPC from #{vpc_conf}" if existing_vpc.nil? or existing_vpc.vpc_id.empty?
			vpc_id = existing_vpc.vpc_id

# XXX sanity-check existence of requested subnet(s)
			subnet_ids = Array.new
			retries = Hash.new
			if vpc_conf["subnets"] != nil
				vpc_conf["subnets"].each { |subnet|
					retries[subnet] = 0 if retries[subnet].nil?
					subnet_struct = findSubnet(
						id: subnet["subnet_id"],
						name: subnet["subnet_name"],
						vpc_id: vpc_id,
						region: vpc_conf['region']
					)
					if subnet_struct.nil?
						if retries[subnet] < 5
							retries[subnet] = retries[subnet] + 1
							sleep 5
							redo
						end
						MU.log "Couldn't find a live subnet matching #{subnet} in #{vpc_id} (#{vpc_conf['region']})", MU::ERR, details: MU::Deploy.deployment['subnets']
						raise "Couldn't find a live subnet matching #{subnet} in #{vpc_id} (#{vpc_conf['region']})"
					end
					id = subnet_struct.subnet_id
					subnet_ids << id if !id.nil?
				}
			elsif !vpc_conf["subnet_id"].nil? or !vpc_conf["subnet_name"].nil?
				subnet_struct = findSubnet(
					id: vpc_conf["subnet_id"],
					name: vpc_conf["subnet_name"],
					region: vpc_conf['region'],
					vpc_id: vpc_id,
					region: vpc_conf['region']
				)
				if subnet_struct.nil?
					MU.log "Couldn't find a live subnet matching #{vpc_conf}", MU::ERR, details: MU::Deploy.deployment['subnets']
					raise "Couldn't find a live subnet matching #{vpc_conf}"
				end
				id = subnet_struct.subnet_id
				subnet_ids << id if id != nil
			else
				listSubnets(vpc_id: vpc_id, region: vpc_conf['region']).each { |subnet|
					subnet_ids << subnet
				}
				MU.log "No subnets specified, using all in #{vpc_id}", MU::DEBUG, details: subnet_ids
			end

			if subnet_ids == nil or subnet_ids.size < 1
				raise "Couldn't find subnets in #{vpc_id}"
			end


			nat_host_name = nil
			nat_ssh_user = nil
			if vpc_conf["nat_host_name"] != nil
				nat, mu_name = MU::Server.find(name: vpc_conf["nat_host_name"], region: vpc_conf['region'])
				raise "Can't find a bastion host with name #{vpc_conf["nat_host_name"]}" if nat == nil
				nat_host_name = nat.public_dns_name
			elsif vpc_conf["nat_host_id"] != nil
				nat, mu_name = MU::Server.find(id: vpc_conf["nat_host_id"], region: vpc_conf['region'])
				raise "Can't find a bastion host with id #{vpc_conf["nat_host_id"]}" if nat == nil
				nat_host_name = nat.public_dns_name
			end

			MU.log "Returning from parseVPC with #{vpc_id}/#{subnet_ids}/#{nat_host_name}", MU::DEBUG
			return [vpc_id, subnet_ids, nat_host_name, vpc_conf['nat_ssh_user']]
		end

		private

		# List the route tables for each subnet in the given VPC
		def self.listAllSubnetRouteTables(vpc_id, region: MU.curRegion)
			resp = MU.ec2(region).describe_subnets(
				filters: [
					{
						name: "vpc-id",
						values: [vpc_id]
					}
				]
			)

			subnets = resp.subnets.map { |subnet| subnet.subnet_id }

			tables = MU.ec2(region).describe_route_tables(
				filters: [
					{
						name: "vpc-id",
						values: [vpc_id]
					},
					{
						name: "association.subnet-id",
						values: subnets
					}
				]
			)
			table_ids = []
			tables.route_tables.each { |rtb|
				table_ids <<  rtb.route_table_id
			}
			return table_ids.uniq
		end

		# Helper method for manufacturing route tables. Expect to be called from
		# {MU::VPC#create} or {MU::VPC#deploy}.
		# @param rtb [Hash]: A route table description parsed through {MU::Config::BasketofKittens::vpcs::route_tables}.
		# @return [Hash]: The modified configuration that was originally passed in.
		def createRouteTable(rtb)
			vpc_id = @vpc['vpc_id']
			vpc_name = @vpc['name']
			MU.setVar("curRegion", @vpc['region']) if !@vpc['region'].nil?
			resp = MU.ec2.create_route_table(vpc_id: vpc_id).route_table
			route_table_id = rtb['route_table_id'] = resp.route_table_id
			sleep 5
			MU::MommaCat.createTag(route_table_id, "Name", vpc_name+"-"+rtb['name'].upcase)
			if @vpc['tags']
				@vpc['tags'].each { |tag|
					MU::MommaCat.createTag(route_table_id,tag['key'],tag['value'])
				}
			end
			MU::MommaCat.createStandardTags(route_table_id)
			rtb['routes'].each { |route|
				if route['nat_host_id'].nil? and route['nat_host_name'].nil?
					route_config = {
						:route_table_id => route_table_id,
						:destination_cidr_block => route['destination_network']
					}
					if !route['peer_id'].nil?
						route_config[:vpc_peering_connection_id] = route['peer_id']
					else
						route_config[:gateway_id] = @vpc['internet_gateway_id']
					end
					# XXX how do the network interfaces work with this?
					MU.log "Creating route for #{route['destination_network']}", details: route_config
					resp = MU.ec2.create_route(route_config)
				end
			}
			return rtb
		end

	end #class
end #module
