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

		# Creation of Virtual Private Clouds and associated artifacts (routes, subnets, etc).
		class VPC < MU::Cloud::VPC

			@deploy = nil
			@config = nil
			attr_reader :mu_name
			attr_reader :cloud_id
			attr_reader :config
			attr_reader :cloud_desc

			# @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
			# @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::vpcs}
			def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
				@deploy = mommacat
				@config = kitten_cfg
				@subnets = []
				if !mu_name.nil?
					@mu_name = mu_name
				else
					# Names for this resource are deterministic, so it's ok to just
					# generate it any time we're loaded up.
					@mu_name = MU::MommaCat.getResourceName(@config['name'])
				end
			end

			# Called automatically by {MU::Deploy#createResources}
			def create

				MU.log "Creating VPC #{@mu_name}", details: @config
				resp = MU::Cloud::AWS.ec2(@config['region']).create_vpc(cidr_block: @config['ip_block']).vpc
				vpc_id = @config['vpc_id'] = resp.vpc_id

				MU::MommaCat.createStandardTags(vpc_id, region: @config['region'])
				MU::MommaCat.createTag(vpc_id, "Name", @mu_name, region: @config['region'])
				if @config['tags']
					@config['tags'].each { |tag|
						MU::MommaCat.createTag(vpc_id,tag['key'],tag['value'], region: @config['region'])
					}
				end

				if resp.state != "available"
					begin
						MU.log "Waiting for VPC #{@mu_name} (#{vpc_id}) to be available", MU::NOTICE
						sleep 5
						resp = MU::Cloud::AWS.ec2(@config['region']).describe_vpcs(vpc_ids: [vpc_id]).vpcs.first
					end while resp.state != "available"
					# There's a default route table that comes with. Let's tag it.
					resp = MU::Cloud::AWS.ec2(@config['region']).describe_route_tables(
						filters: [
							{
								name: "vpc-id",
								values: [vpc_id]
							}
						]
					)
					resp.route_tables.each { |rtb|
						MU::MommaCat.createTag(rtb.route_table_id, "Name", @mu_name+"-#DEFAULTPRIV", region: @config['region'])
						if @config['tags']
							@config['tags'].each { |tag|
								MU::MommaCat.createTag(rtb.route_table_id,tag['key'],tag['value'], region: @config['region'])
							}
						end
						MU::MommaCat.createStandardTags(rtb.route_table_id, region: @config['region'])
					}
				end
				@config['vpc_id'] = vpc_id
				@cloud_id = vpc_id

				if @config['create_internet_gateway']
					MU.log "Creating Internet Gateway #{@mu_name}"
					resp = MU::Cloud::AWS.ec2(@config['region']).create_internet_gateway
					internet_gateway_id = resp.internet_gateway.internet_gateway_id
					sleep 5
					MU::MommaCat.createStandardTags(internet_gateway_id, region: @config['region'])
					MU::MommaCat.createTag(internet_gateway_id, "Name", @mu_name, region: @config['region'])
					if @config['tags']
						@config['tags'].each { |tag|
							MU::MommaCat.createTag(internet_gateway_id,tag['key'],tag['value'], region: @config['region'])
						}
					end
					MU::Cloud::AWS.ec2(@config['region']).attach_internet_gateway(vpc_id: vpc_id, internet_gateway_id: internet_gateway_id)
					@config['internet_gateway_id'] = internet_gateway_id
				end

				if !@config['route_tables'].nil?
					@config['route_tables'].each { |rtb|
						rtb = createRouteTable(rtb)
					}
				end

				if !@config['subnets'].nil?
					subnet_semaphore = Mutex.new
					subnetthreads = Array.new
					parent_thread_id = Thread.current.object_id
					azs = []
					@config['subnets'].each { |subnet|
						subnet_name = @config['name']+"-"+subnet['name']
						MU.log "Creating Subnet #{subnet_name} (#{subnet['ip_block']})", details: subnet
						azs = MU::Cloud::AWS.listAZs if azs.size == 0
						if !subnet['availability_zone'].nil?
							az = subnet['availability_zone']
						else
							az = azs.pop
						end
						subnetthreads << Thread.new {
							MU.dupGlobals(parent_thread_id)
							resp = MU::Cloud::AWS.ec2(@config['region']).create_subnet(
								vpc_id: vpc_id,
								cidr_block: subnet['ip_block'],
								availability_zone: az
							).subnet
							subnet_id = subnet['subnet_id'] = resp.subnet_id
							MU::MommaCat.createStandardTags(subnet_id, region: @config['region'])
							MU::MommaCat.createTag(subnet_id, "Name", @mu_name+"-"+subnet['name'], region: @config['region'])
							if @config['tags']
								@config['tags'].each { |tag|
									MU::MommaCat.createTag(subnet_id,tag['key'],tag['value'], region: @config['region'])
								}
							end
							if resp.state != "available"
								begin
									MU.log "Waiting for Subnet #{subnet_name} (#{subnet_id}) to be available", MU::NOTICE
									sleep 5
									resp = MU::Cloud::AWS.ec2(@config['region']).describe_subnets(subnet_ids: [subnet_id]).subnets.first
								rescue Aws::EC2::Errors::InvalidSubnetIDNotFound => e
									sleep 10
									retry
								end while resp.state != "available"
							end
							if !subnet['route_table'].nil?
								routes = {}
								@config['route_tables'].each { |tbl|
									routes[tbl['name']] = tbl
								}
								if routes.nil? or routes[subnet['route_table']].nil?
									MU.log "Subnet #{subnet_name} references non-existent route #{subnet['route_table']}", MU::ERR, details: @deploy.deployment['vpcs']
									raise MuError, "deploy failure"
								end
								MU.log "Associating Route Table '#{subnet['route_table']}' (#{routes[subnet['route_table']]['route_table_id']}) with #{subnet_name}"
								retries = 0
								begin
									MU::Cloud::AWS.ec2(@config['region']).associate_route_table(
										route_table_id: routes[subnet['route_table']]['route_table_id'],
										subnet_id: subnet_id
									)
								rescue Aws::EC2::Errors::InvalidRouteTableIDNotFound => e
									retries = retries + 1
									if retries < 10
										sleep 10
										retry
									else
										raise MuError, e.inspect
									end
								end
							end
							retries = 0
							begin
								resp = MU::Cloud::AWS.ec2(@config['region']).describe_subnets(subnet_ids: [subnet_id]).subnets.first
							rescue Aws::EC2::Errors::InvalidSubnetIDNotFound => e
								if retries < 10
									MU.log "Got #{e.inspect}, waiting and retrying", MU::WARN
									sleep 10
									retries = retries + 1
									retry
								end
								raise MuError, e.inspect, e.backtrace
							end
#							subnet_semaphore.synchronize {
#								deploy_struct['subnets'][subnet['name']] = subnet
#							}
						}
					}
					subnetthreads.each { |t|
						t.join
					}
					notify
				end

					if @config['enable_dns_support']
						MU.log "Enabling DNS support in #{@mu_name}"
						MU::Cloud::AWS.ec2(@config['region']).modify_vpc_attribute(
							vpc_id: vpc_id,
							enable_dns_support: { value: @config['enable_dns_support'] }
						)
					end
					if @config['enable_dns_hostnames']
						MU.log "Enabling DNS hostnames in #{@mu_name}"
						MU::Cloud::AWS.ec2(@config['region']).modify_vpc_attribute(
							vpc_id: vpc_id,
							enable_dns_hostnames: { value: @config['enable_dns_hostnames'] }
						)
					end

				if @config['dhcp']
					MU.log "Setting custom DHCP options in #{@mu_name}", details: @config['dhcp']
					dhcpopts = []

					if @config['dhcp']['netbios_type']
						dhcpopts << { key: "netbios-node-type", values: [ @config['dhcp']['netbios_type'].to_s ] } 
					end
					if @config['dhcp']['domains']
						dhcpopts << { key: "domain-name", values: @config['dhcp']['domains'] }
					end
					if @config['dhcp']['dns_servers']
						dhcpopts << { key: "domain-name-servers", values: @config['dhcp']['dns_servers'] }
					end
					if @config['dhcp']['ntp_servers']
						dhcpopts << { key: "ntp-servers", values: @config['dhcp']['ntp_servers'] }
					end
					if @config['dhcp']['netbios_servers']
						dhcpopts << { key: "netbios-name-servers", values: @config['dhcp']['netbios_servers'] }
					end

					resp = MU::Cloud::AWS.ec2(@config['region']).create_dhcp_options(
						dhcp_configurations: dhcpopts
					)
					dhcpopt_id = resp.dhcp_options.dhcp_options_id
					MU::MommaCat.createStandardTags(dhcpopt_id, region: @config['region'])
					MU::MommaCat.createTag(dhcpopt_id, "Name", @mu_name, region: @config['region'])
					if @config['tags']
						@config['tags'].each { |tag|
							MU::MommaCat.createTag(dhcpopt_id,tag['key'],tag['value'], region: @config['region'])
						}
					end
					MU::Cloud::AWS.ec2(@config['region']).associate_dhcp_options(dhcp_options_id: dhcpopt_id, vpc_id: vpc_id)
				end
				notify

				mu_zone = MU::Cloud::DNSZone.find(cloud_id: "platform-mu").values.first
				if !mu_zone.nil?
					MU::Cloud::AWS::DNSZone.toggleVPCAccess(id: mu_zone.id, vpc_id: vpc_id, region: @config['region'])
				end

				MU.log "VPC #{@mu_name} created", details: @config

			end

			def notify
				@config
			end

			# Called automatically by {MU::Deploy#createResources}
			def groom
				vpc_name = MU::MommaCat.getResourceName(@config['name'])

				# Generate peering connections
				if !@config['peers'].nil? and @config['peers'].size > 0
					@config['peers'].each { |peer|
						begin
							if peer['account'].nil? or peer['account'] == MU.account_number
								tag_key, tag_value = peer['vpc']['tag'].split(/=/, 2) if !peer['vpc']['tag'].nil?
								peer_desc, peer_name = MU::Cloud::VPC.find(
									id: peer['vpc']['vpc_id'],
									name: peer['vpc']['vpc_name'],
									deploy_id: peer['vpc']['deploy_id'],
									tag_key: tag_key,
									tag_value: tag_value,
									region: peer['vpc']['region']
								)
								if peer_desc.nil?
									MU.log "Unable to locate peer VPC for #{@config['name']}", MU::ERR, details: peer
									raise MuError, "Unable to locate peer VPC"
								end
								peer_id = peer_desc.vpc_id
								peer_deploy_struct = nil
								known_vpcs = MU::MommaCat.getResourceMetadata("vpcs", name: peer_name, deploy_id: nil)
								known_vpcs.each { |ext_vpc|
									if ext_vpc['vpc_id'] == peer_id
										peer_deploy_struct = ext_vpc
										break
									end
								}

								MU.log "Initiating peering connection from VPC #{@config['name']} (#{@config['vpc_id']}) to #{peer_id}", MU::INFO, details: peer
								resp = MU::Cloud::AWS.ec2(@config['region']).create_vpc_peering_connection(
									vpc_id: @config['vpc_id'],
									peer_vpc_id: peer_id
								)
							else
								peer_id = peer['vpc']['vpc_id']
								MU.log "Initiating peering connection from VPC #{@config['name']} (#{@config['vpc_id']}) to #{peer_id} in account #{peer['account']}", MU::INFO, details: peer
								resp = MU::Cloud::AWS.ec2(@config['region']).create_vpc_peering_connection(
									vpc_id: @config['vpc_id'],
									peer_vpc_id: peer_id,
									peer_owner_id: peer['account']
								)
							end
						rescue Aws::EC2::Errors::VpcPeeringConnectionAlreadyExists => e
							MU.log "Attempt to create duplicate peering connection to #{peer_id} from VPC #{@config['name']}", MU::WARN
						end
						peering_name = MU::MommaCat.getResourceName(@config['name']+"-PEER-"+peer_id)

						peering_id = resp.vpc_peering_connection.vpc_peering_connection_id
						MU::MommaCat.createStandardTags(peering_id, region: @config['region'])
						MU::MommaCat.createTag(peering_id, "Name", peering_name, region: @config['region'])

						# Create routes to our new friend.
						self.class.listAllSubnetRouteTables(@config['vpc_id'], region: @config['region']).each { |rtb_id|
							my_route_config = {
								:route_table_id => rtb_id,
								:destination_cidr_block => peer_desc.cidr_block,
								:vpc_peering_connection_id => peering_id
							}
							begin
								resp = MU::Cloud::AWS.ec2(@config['region']).create_route(my_route_config)
							rescue Aws::EC2::Errors::RouteAlreadyExists => e
								MU.log "Attempt to create duplicate route to #{peer_desc.cidr_block} from VPC #{@config['name']}", MU::WARN
							end
						}

						begin
							cnxn = MU::Cloud::AWS.ec2(@config['region']).describe_vpc_peering_connections(
								vpc_peering_connection_ids: [peering_id]
							).vpc_peering_connections.first
						
							if cnxn.status.code == "pending-acceptance" 
								if (!peer_deploy_struct.nil? and peer_deploy_struct['auto_accept_peers']) or (!ENV['ALLOW_INVADE_FOREIGN_VPCS'].nil? and !ENV['ALLOW_INVADE_FOREIGN_VPCS'].empty? and ENV['ALLOW_INVADE_FOREIGN_VPCS'] != "0")
									MU.log "Auto-accepting peering connection from VPC #{@config['name']} (#{@config['vpc_id']}) to #{peer_id}", MU::NOTICE
									begin
										MU::Cloud::AWS.ec2(@config['region']).accept_vpc_peering_connection(
											vpc_peering_connection_id: peering_id
										)
									rescue Aws::EC2::Errors::VpcPeeringConnectionAlreadyExists => e
										MU.log "Attempt to create duplicate peering connection to #{peer_id} from VPC #{@config['name']}", MU::WARN
									end

									# Create routes back from our new friend to us.
									self.class.listAllSubnetRouteTables(peer_id, region: peer['vpc']['region']).each { |rtb_id|
										peer_route_config = {
											:route_table_id => rtb_id,
											:destination_cidr_block => @config['ip_block'],
											:vpc_peering_connection_id => peering_id
										}
										begin
											resp = MU::Cloud::AWS.ec2(@config['region']).create_route(peer_route_config)
										rescue Aws::EC2::Errors::RouteAlreadyExists => e
											MU.log "Attempt to create duplicate route to #{@config['ip_block']} from VPC #{peer_id}", MU::WARN
										end
									}
#MU.log "Creating route for #{peer_deploy_struct['ip_block']}", details: route_config
#resp = MU::Cloud::AWS.ec2(@config['region']).create_route(route_config)
								else
									MU.log "VPC #{peer_id} is not managed by this Mu server or is not configured to auto-accept peering requests. You must accept the peering request for '#{@config['name']}' (#{@config['vpc_id']}) by hand.", MU::NOTICE
								end
							end

							if cnxn.status.code == "failed" or cnxn.status.code == "rejected" or cnxn.status.code == "expired" or cnxn.status.code == "deleted"
								MU.log "VPC peering connection from VPC #{@config['name']} (#{@config['vpc_id']}) to #{peer_id} #{cnxn.status.code}: #{cnxn.status.message}", MU::ERR
								begin
									MU::Cloud::AWS.ec2(@config['region']).delete_vpc_peering_connection(
										vpc_peering_connection_id: peering_id
									)
								rescue Aws::EC2::Errors::InvalidStateTransition => e
									# XXX apparently this is normal?
								end
								raise MuError, "VPC peering connection from VPC #{@config['name']} (#{@config['vpc_id']}) to #{peer_id} #{cnxn.status.code}: #{cnxn.status.message}"
							end
						end while cnxn.status.code != "active" and !(cnxn.status.code == "pending-acceptance" and (peer_deploy_struct.nil? or !peer_deploy_struct['auto_accept_peers']))

					}
				end

				# Add any routes that reference instances, which would've been created
				# in Server objects' create phases.
				if !@config['route_tables'].nil?
					@config['route_tables'].each { |rtb|
						route_table_id = rtb['route_table_id']

						rtb['routes'].each { |route|
							if !route['nat_host_id'].nil? or !route['nat_host_name'].nil?
								route_config = {
									:route_table_id => route_table_id,
									:destination_cidr_block => route['destination_network']
								}

								nat_instance = findBastion(
									nat_name: route["nat_host_name"],
									nat_cloud_id: route["nat_host_id"]
								)
								if nat_instance.nil?
									raise MuError, "VPC #{vpc_name} is configured to use #{route} as a route, but I can't find a matching bastion host!"
								end
								route_config[:instance_id] = nat_instance.cloud_id

								MU.log "Creating route for #{route['destination_network']} through NAT host #{nat_instance.cloud_id}", details: route_config
								resp = MU::Cloud::AWS.ec2(@config['region']).create_route(route_config)
							end
						}

					}
				end

			end

			# Locate an existing VPC or VPCs and return an array containing matching AWS resource descriptors for those that match.
			# @param cloud_id [String]: The cloud provider's identifier for this resource.
			# @param region [String]: The cloud provider region
			# @param tag_key [String]: A tag key to search.
			# @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
			# @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching VPCs
			def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil)

				retries = 0
				map = {}
				begin
					sleep 5 if retries < 0

					if tag_value
						MU.log "Searching for VPC by tag:#{tag_key}=#{tag_value}", MU::DEBUG
						resp = MU::Cloud::AWS.ec2(region).describe_vpcs(
							filters: [
								{ name: "tag:#{tag_key}", values: [tag_value] }
							]
						)
						if resp.data.vpcs.nil? or resp.data.vpcs.size == 0
							return nil
						elsif resp.data.vpcs.size >= 1
							resp.data.vpcs.each { |vpc|
								map[vpc.vpc_id] = vpc
							}
							return map
						end
					end

					if !cloud_id.nil?
						MU.log "Searching for VPC id '#{cloud_id}' in #{region}", MU::DEBUG
						begin
							resp = MU::Cloud::AWS.ec2(region).describe_vpcs(vpc_ids: [cloud_id])
							resp.data.vpcs.each { |vpc|
								map[vpc.vpc_id] = vpc
							}
							return map
						rescue Aws::EC2::Errors::InvalidVpcIDNotFound => e
						end
					end

					retries = retries + 1
				end while retries < 5

				return map
			end

			# Pick out one of the subnets belonging to this VPC by name or cloud
			# identifier.
			# @param name [String]: An Mu resource name, usually the 'name' field of aa Basket of Kittens resource declaration. Will search the currently loaded deployment unless another is specified.
			# @param id [String]: The cloud provider's identifier for this resource.
			# @return [OpenStruct]: The cloud provider's complete description of this VPC.
			def findSubnet(name: nil, id: nil, allow_multi: false)
				vpc_id = @cloud_id

				# Now see if this subnet is referenced in any deployments as an Mu
				# resource. We actually use the parent VPC, since a subnet isn't a
				# first-class resource... except sometimes it is, if we yanked it out
				# of a CloudFormation template. Confused yet?
				if id.nil? and !name.nil? 
					vpc = MU::MommaCat.getResourceMetadata("vpcs", name: vpc_name, deploy_id: deploy_id)
					subnet = MU::MommaCat.getResourceMetadata("subnets", name: name, deploy_id: deploy_id)

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
						resp = MU::Cloud::AWS.ec2(region).describe_subnets(subnet_ids: [id])
						return nil if resp.data.subnets.size == 0 or resp.data.subnets.nil?
						subnet = resp.data.subnets.first
						if subnet.vpc_id != vpc_id
							raise MuError, "Subnet #{id} isn't a member of VPC #{vpc_id} in findSubnet (id: #{id}, name: #{name}, vpc_id: #{vpc_id}, vpc_name: #{vpc_name})"
						end
						return subnet
					end

					if !tag_value.nil?
						resp = MU::Cloud::AWS.ec2(region).describe_subnets(
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
						raise MuError, e.inspect
					end
				end
				return nil
			end

			# Return an array of MU::Cloud::AWS::VPC::Subnet objects describe the
			# member subnets of this VPC.
			#
			# @return [Array<MU::Cloud::AWS::VPC::Subnet>]
			def subnets
				if @subnets.nil? or @subnets.size == 0
					return loadSubnets
				end
				return @subnets
			end

			# Describe subnets associated with this VPC. We'll compose identifying
			# information similar to what MU::Cloud.describe builds for first-class
			# resources.
			# XXX this is weaksauce. Subnets should be objects with their own methods
			# that work like first-class objects. How would we enforce that?
			# @return [Array<Hash>]: A list of cloud provider identifiers of subnets associated with this VPC.
			def loadSubnets
				if @cloud_id
					resp = MU::Cloud::AWS.ec2(@config['region']).describe_subnets(
						filters: [
							{ name: "vpc-id", values: [@cloud_id] }
						]
					)
					return [] if resp.subnets.nil? or resp.subnets.size == 0
				end

				@subnets = []

				# If we're a plain old Mu resource, load our config and deployment
				# metadata. Like ya do.
				if !@config.nil? and @config.has_key?("subnets")
					@config['subnets'].each { |subnet|
						subnet['mu_name'] = @mu_name+"-"+subnet['name'] if !subnet.has_key?("mu_name")
						resp.data.subnets.each { |desc|
							if desc.cidr_block == subnet["ip_block"]
								subnet["tags"] = MU.structToHash(desc.tags)
								subnet["cloud_id"] = desc.subnet_id
								break
							end
						}
						@subnets << MU::Cloud::AWS::VPC::Subnet.new(self, subnet)
					}
				# Of course we might be loading up a dummy subnet object from a foreign
				# or non-Mu-created VPC and subnet. So make something up.
				elsif !resp.nil?
					resp.data.subnets.each { |desc|
						subnet = {}
						subnet["ip_block"] = desc.cidr_block
						subnet["name"] = subnet["ip_block"].gsub(/[\.\/]/, "_")
						subnet['mu_name'] = @mu_name+"-"+subnet['name']
						subnet["tags"] = MU.structToHash(desc.tags)
						subnet["cloud_id"] = desc.subnet_id
						@subnets << MU::Cloud::AWS::VPC::Subnet.new(self, subnet)
					}
				end

				return @subnets
			end

			# Given some search criteria for a {MU::Cloud::Server}, see if we can
			# locate a NAT host in this VPC.
			# @param nat_name [String]: The name of the resource as defined in its 'name' Basket of Kittens field, typically used in conjunction with deploy_id.
			# @param nat_cloud_id [String]: The cloud provider's identifier for this NAT.
			# @param nat_tag_key [String]: A cloud provider tag to help identify the resource, used in conjunction with tag_value.
			# @param nat_tag_value [String]: A cloud provider tag to help identify the resource, used in conjunction with tag_key.
			# @param nat_ip [String]: An IP address associated with the NAT instance.
			def findBastion(nat_name: nil, nat_cloud_id: nil, nat_tag_key: nil, nat_tag_value: nil, nat_ip: nil)
				nat = nil
				deploy_id = nil
				# If we're searching by name, assume it's part of this here deploy.
				if nat_cloud_id.nil? 
					deploy_id = @deploy.deploy_id
				end
				found = MU::MommaCat.findStray(
					@config['cloud'],
					"server",
					name: nat_name,
					region: @config['region'],
					cloud_id: nat_cloud_id,
					deploy_id: deploy_id,
					tag_key: nat_tag_key,
					tag_value: nat_tag_value,
					allow_multi: true,
					calling_deploy: @deploy
				)

				return nil if found.nil?
				if found.size > 1
					found.each { |nat| 
						# Try some AWS-specific criteria
						junk, morejunk, whocares, cloud_desc = instance.describe
						if !nat_host_ip.nil? and
							 (cloud_desc.private_ip_address == nat_host_ip or cloud_desc.public_ip_address == nat_host_ip)
							return nat
						elsif cloud_desc.vpc_id == @cloud_id
							# XXX Strictly speaking we could have different NATs in different
							# subnets, so this can be wrong in corner cases. Why you'd
							# architect something that obnoxiously, I have no idea.
							return nat
						end
					}
				elsif found.size == 1
					return found.first
				end
				return nil
			end

			# Check for a subnet in this VPC matching one or more of the specified
			# criteria, and return it if found.
			def getSubnet(cloud_id: nil, name: nil, tag_key: nil, tag_value: nil, ip_block: nil)
				if !cloud_id and !name and !tag_key and !tag_value and !ip_block
					raise MuError, "getSubnet called with no non-nil arguments"
				end
				loadSubnets
				@subnets.each { |subnet|
					if !cloud_id.nil? and subnet.cloud_id == cloud_id
						return subnet
					elsif !name.nil? and subnet.name == name
						return subnet
					end
				}
				return nil
			end

			# Get the subnets associated with an instance.
			# @param instance_id [String]: The cloud identifier of the instance
			# @param region [String]: The cloud provider region of the target instance
			# @return [Array<String>]
			def self.getInstanceSubnets(instance_id, region: MU.curRegion)
				return [] if instance_id.nil?
				my_subnets = []

				begin
					instance = MU::Cloud::AWS.ec2(region).describe_instances(instance_ids: [instance_id]).reservations.first.instances.first
				rescue Aws::EC2::Errors::InvalidInstanceIDNotFound => e
					return []
				end
				my_subnets << instance.subnet_id if !instance.subnet_id.nil?
				if !instance.network_interfaces.nil?
					instance.network_interfaces.each { |iface|
						my_subnets << iface.subnet_id if !iface.subnet_id.nil?
					}
				end
				return my_subnets.uniq
			end

			@route_cache = {}
			# Check whether we (the Mu Master) have a direct route to a particular
			# subnet. Useful for skipping hops through bastion hosts to get directly
			# at child nodes in peered VPCs and the like.
			# @param instance_id [String]: The cloud identifier of the instance to check.
			# @param region [String]: The cloud provider region of the target subnet.
			# @return [Boolean]
			def self.haveRouteToInstance?(instance_id, region: MU.curRegion)
				return false if instance_id.nil?
				return @route_cache[instance_id] if @route_cache.has_key?(instance_id)
				my_subnets = MU::Cloud::AWS::VPC.getInstanceSubnets(MU.myInstanceId)
				target_subnets = MU::Cloud::AWS::VPC.getInstanceSubnets(instance_id)

				if (my_subnets & target_subnets).size > 0
					MU.log "I share a subnet with #{instance_id}, I can route to it directly", MU::DEBUG
					@route_cache[instance_id] = true
					return true
				end

				my_routes = []
				vpc_peer_mapping = {}
				MU::Cloud::AWS.ec2(MU.myRegion).describe_route_tables(
					filters: [{name: "association.subnet-id", values: my_subnets}]
				).route_tables.each { |route_table|
					route_table.routes.each { |route|
						if route.destination_cidr_block != "0.0.0.0/0" and route.state == "active"
							my_routes << NetAddr::CIDR.create(route.destination_cidr_block)
							if !route.vpc_peering_connection_id.nil?
								vpc_peer_mapping[route.vpc_peering_connection_id] = route.destination_cidr_block
							end
						end
					}
				}
				my_routes.uniq!

				target_routes = []
				MU::Cloud::AWS.ec2(region).describe_route_tables(
					filters: [{name: "association.subnet-id", values: target_subnets}]
				).route_tables.each { |route_table|
					route_table.routes.each { |route|
						next if route.destination_cidr_block == "0.0.0.0/0" or route.state != "active"
						cidr = NetAddr::CIDR.create(route.destination_cidr_block)
						shared_ip_space = false
						my_routes.each { |my_cidr|
							if my_cidr.contains?(cidr) or my_cidr == cidr
								shared_ip_space = true
								break
							end
						}

						if shared_ip_space and !route.vpc_peering_connection_id.nil? and
								vpc_peer_mapping.has_key?(route.vpc_peering_connection_id) 
							MU.log "I share a VPC peering connection (#{route.vpc_peering_connection_id}) with #{instance_id} for #{route.destination_cidr_block}, I can route to it directly", MU::DEBUG
							@route_cache[instance_id] = true
							return true
						end
					}
				}

				@route_cache[instance_id] = false
				return false
			end

			# Remove all VPC resources associated with the currently loaded deployment.
			# @param noop [Boolean]: If true, will only print what would be done
			# @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
			# @param region [String]: The cloud provider region
			# @return [void]
			def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
				tagfilters = [
					{ name: "tag:MU-ID", values: [MU.deploy_id] }
				]
				if !ignoremaster
					tagfilters << { name: "tag:MU-MASTER-IP", values: [MU.mu_public_ip] }
				end

				purge_gateways(noop, tagfilters, region: region)
				purge_routetables(noop, tagfilters, region: region)
				purge_interfaces(noop, tagfilters, region: region)
				purge_subnets(noop, tagfilters, region: region)
				purge_vpcs(noop, tagfilters, region: region)
				purge_dhcpopts(noop, tagfilters, region: region)
			end

			private

			# List the route tables for each subnet in the given VPC
			def self.listAllSubnetRouteTables(vpc_id, region: MU.curRegion)
				resp = MU::Cloud::AWS.ec2(region).describe_subnets(
					filters: [
						{
							name: "vpc-id",
							values: [vpc_id]
						}
					]
				)

				subnets = resp.subnets.map { |subnet| subnet.subnet_id }

				tables = MU::Cloud::AWS.ec2(region).describe_route_tables(
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
			# {MU::Cloud::AWS::VPC#create} or {MU::Cloud::AWS::VPC#deploy}.
			# @param rtb [Hash]: A route table description parsed through {MU::Config::BasketofKittens::vpcs::route_tables}.
			# @return [Hash]: The modified configuration that was originally passed in.
			def createRouteTable(rtb)
				vpc_id = @config['vpc_id']
				vpc_name = @config['name']
				MU.setVar("curRegion", @config['region']) if !@config['region'].nil?
				resp = MU::Cloud::AWS.ec2.create_route_table(vpc_id: vpc_id).route_table
				route_table_id = rtb['route_table_id'] = resp.route_table_id
				sleep 5
				MU::MommaCat.createTag(route_table_id, "Name", vpc_name+"-"+rtb['name'].upcase)
				if @config['tags']
					@config['tags'].each { |tag|
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
							route_config[:gateway_id] = @config['internet_gateway_id']
						end
						# XXX how do the network interfaces work with this?
						MU.log "Creating route for #{route['destination_network']}", details: route_config
						resp = MU::Cloud::AWS.ec2.create_route(route_config)
					end
				}
				return rtb
			end


			# Remove all network gateways associated with the currently loaded deployment.
			# @param noop [Boolean]: If true, will only print what would be done
			# @param region [String]: The cloud provider region
			# @return [void]
			def self.purge_gateways(noop = false, tagfilters = [{ name: "tag:MU-ID", values: [MU.deploy_id] }], region: MU.curRegion)
				resp = MU::Cloud::AWS.ec2(region).describe_internet_gateways(
					filters: tagfilters
				)
				gateways = resp.data.internet_gateways

				gateways.each { |gateway|
					gateway.attachments.each { |attachment|
						MU.log "Detaching Internet Gateway #{gateway.internet_gateway_id} from #{attachment.vpc_id}"
						begin
							MU::Cloud::AWS.ec2(region).detach_internet_gateway(
								internet_gateway_id: gateway.internet_gateway_id,
								vpc_id: attachment.vpc_id
							) if !noop
						rescue Aws::EC2::Errors::GatewayNotAttached => e
							MU.log "Gateway #{gateway.internet_gateway_id} was already detached", MU::WARN
						end
					}
					MU.log "Deleting Internet Gateway #{gateway.internet_gateway_id}"
					begin
						MU::Cloud::AWS.ec2(region).delete_internet_gateway(internet_gateway_id: gateway.internet_gateway_id) if !noop
					rescue Aws::EC2::Errors::InvalidInternetGatewayIDNotFound
						MU.log "Gateway #{gateway.internet_gateway_id} was already destroyed by the time I got to it", MU::WARN
					end
				}
				return nil
			end

			# Remove all route tables associated with the currently loaded deployment.
			# @param noop [Boolean]: If true, will only print what would be done
			# @param tagfilters [Array<Hash>]: EC2 tags to filter against when search for resources to purge
			# @param region [String]: The cloud provider region
			# @return [void]
			def self.purge_routetables(noop = false, tagfilters = [{ name: "tag:MU-ID", values: [MU.deploy_id] }], region: MU.curRegion)
				resp = MU::Cloud::AWS.ec2(region).describe_route_tables(
					filters: tagfilters
				)
				route_tables = resp.data.route_tables

				return if route_tables.nil? or route_tables.size == 0

				route_tables.each { |table|
					table.routes.each { |route|
						if !route.network_interface_id.nil?
							MU.log "Deleting Network Interface #{route.network_interface_id}"
							begin
								MU::Cloud::AWS.ec2(region).delete_network_interface(network_interface_id: route.network_interface_id) if !noop
							rescue Aws::EC2::Errors::InvalidNetworkInterfaceIDNotFound => e
								MU.log "Network Interface #{route.network_interface_id} has already been deleted", MU::WARN
							end
						end
						if route.gateway_id != "local"
							MU.log "Deleting #{table.route_table_id}'s route for #{route.destination_cidr_block}"
							begin
								MU::Cloud::AWS.ec2(region).delete_route(
									route_table_id: table.route_table_id,
									destination_cidr_block: route.destination_cidr_block
								) if !noop
							rescue Aws::EC2::Errors::InvalidRouteNotFound
								MU.log "Route #{table.route_table_id} has already been deleted", MU::WARN
							end
						end
					}
					can_delete = true
					table.associations.each { |assoc|
						begin
							MU::Cloud::AWS.ec2(region).disassociate_route_table(association_id: assoc.route_table_association_id) if !noop
						rescue Aws::EC2::Errors::InvalidAssociationIDNotFound => e
							MU.log "Route table association #{assoc.route_table_association_id} already removed", MU::WARN
						rescue Aws::EC2::Errors::InvalidParameterValue => e
							# normal and ignorable with the default route table
							can_delete = false
							next
						end
					}
					next if !can_delete
					MU.log "Deleting Route Table #{table.route_table_id}"
					begin
						MU::Cloud::AWS.ec2(region).delete_route_table(route_table_id: table.route_table_id) if !noop
					rescue Aws::EC2::Errors::InvalidRouteTableIDNotFound
						MU.log "Route table #{table.route_table_id} already removed", MU::WARN
					end
				}
				return nil
			end


			# Remove all network interfaces associated with the currently loaded deployment.
			# @param noop [Boolean]: If true, will only print what would be done
			# @param tagfilters [Array<Hash>]: EC2 tags to filter against when search for resources to purge
			# @param region [String]: The cloud provider region
			# @return [void]
			def self.purge_interfaces(noop = false, tagfilters = [{ name: "tag:MU-ID", values: [MU.deploy_id] }], region: MU.curRegion)
				resp = MU::Cloud::AWS.ec2(region).describe_network_interfaces(
					filters: tagfilters
				)
				ifaces = resp.data.network_interfaces

				return if ifaces.nil? or ifaces.size == 0

				ifaces.each { |iface|
					MU.log "Deleting Network Interface #{iface.network_interface_id}"
					MU::Cloud::AWS.ec2(region).delete_network_interface(network_interface_id: iface.network_interface_id)
				}
			end

			# Remove all subnets associated with the currently loaded deployment.
			# @param noop [Boolean]: If true, will only print what would be done
			# @param tagfilters [Array<Hash>]: EC2 tags to filter against when search for resources to purge
			# @param region [String]: The cloud provider region
			# @return [void]
			def self.purge_subnets(noop = false, tagfilters = [{ name: "tag:MU-ID", values: [MU.deploy_id] }], region: MU.curRegion)
				resp = MU::Cloud::AWS.ec2(region).describe_subnets(
					filters: tagfilters
				)
				subnets = resp.data.subnets

				return if subnets.nil? or subnets.size == 0

				retries = 0
				subnets.each { |subnet|
					begin
						if subnet.state != "available"
							MU.log "Waiting for #{subnet.subnet_id} to be in a removable state...", MU::NOTICE
							sleep 30
						else
							MU.log "Deleting Subnet #{subnet.subnet_id}"
							MU::Cloud::AWS.ec2(region).delete_subnet(subnet_id: subnet.subnet_id) if !noop
						end
					rescue Aws::EC2::Errors::DependencyViolation => e
						if retries < 7
							MU.log "#{e.inspect}, retrying in 10s", MU::WARN
							sleep 10
							retries = retries + 1
							retry
						else
							raise e
						end
					rescue Aws::EC2::Errors::InvalidSubnetIDNotFound
						MU.log "Subnet #{subnet.subnet_id} disappeared before I could remove it", MU::WARN
						next
					end while subnet.state != "available"
				}
			end

			# Remove all DHCP options sets associated with the currently loaded
			# deployment.
			# @param noop [Boolean]: If true, will only print what would be done
			# @param tagfilters [Array<Hash>]: EC2 tags to filter against when search for resources to purge
			# @param region [String]: The cloud provider region
			# @return [void]
			def self.purge_dhcpopts(noop = false, tagfilters = [{ name: "tag:MU-ID", values: [MU.deploy_id] }], region: MU.curRegion)
				resp = MU::Cloud::AWS.ec2(region).describe_dhcp_options(
					filters: tagfilters
				)
				sets = resp.data.dhcp_options

				return if sets.nil? or sets.size == 0

				sets.each { |optset|
					begin
						MU.log "Deleting DHCP Option Set #{optset.dhcp_options_id}"
						MU::Cloud::AWS.ec2(region).delete_dhcp_options(dhcp_options_id: optset.dhcp_options_id)
					rescue Aws::EC2::Errors::DependencyViolation => e
						MU.log e.inspect, MU::ERR
#				rescue Aws::EC2::Errors::InvalidSubnetIDNotFound
#					MU.log "Subnet #{subnet.subnet_id} disappeared before I could remove it", MU::WARN
#					next
					end
				}
			end

			# Remove all VPCs associated with the currently loaded deployment.
			# @param noop [Boolean]: If true, will only print what would be done
			# @param tagfilters [Array<Hash>]: EC2 tags to filter against when search for resources to purge
			# @param region [String]: The cloud provider region
			# @return [void]
			def self.purge_vpcs(noop = false, tagfilters = [{ name: "tag:MU-ID", values: [MU.deploy_id] }], region: MU.curRegion)
				resp = MU::Cloud::AWS.ec2(region).describe_vpcs(
					filters: tagfilters
				)

				vpcs = resp.data.vpcs
				return if vpcs.nil? or vpcs.size == 0

				vpcs.each { |vpc|
					my_peer_conns = MU::Cloud::AWS.ec2(region).describe_vpc_peering_connections(
						filters: [
							{
								name: "requester-vpc-info.vpc-id",
								values: [vpc.vpc_id]
							}
						]
					).vpc_peering_connections
					my_peer_conns.concat(MU::Cloud::AWS.ec2(region).describe_vpc_peering_connections(
						filters: [
							{
								name: "accepter-vpc-info.vpc-id",
								values: [vpc.vpc_id]
							}
						]
					).vpc_peering_connections)
					my_peer_conns.each { |cnxn|
						
						[cnxn.accepter_vpc_info.vpc_id, cnxn.requester_vpc_info.vpc_id].each { |peer_vpc|
							MU::Cloud::AWS::VPC.listAllSubnetRouteTables(peer_vpc, region: region).each { |rtb_id|
								resp = MU::Cloud::AWS.ec2(region).describe_route_tables(
									route_table_ids: [rtb_id]
								)
								resp.route_tables.each { |rtb|
									rtb.routes.each { |route|
										if route.vpc_peering_connection_id == cnxn.vpc_peering_connection_id
											MU.log "Removing route #{route.destination_cidr_block} from route table #{rtb_id} in VPC #{peer_vpc}"
											MU::Cloud::AWS.ec2(region).delete_route(
												route_table_id: rtb_id,
												destination_cidr_block: route.destination_cidr_block
											) if !noop
										end
									}
								}
							}
						}
						MU.log "Deleting VPC peering connection #{cnxn.vpc_peering_connection_id}"
						begin
							MU::Cloud::AWS.ec2(region).delete_vpc_peering_connection(
								vpc_peering_connection_id: cnxn.vpc_peering_connection_id
							) if !noop
						rescue Aws::EC2::Errors::InvalidStateTransition => e
							MU.log "VPC peering connection #{cnxn.vpc_peering_connection_id} not in removable (state #{cnxn.status.code})", MU::WARN
						end
					}
					
					MU.log "Deleting VPC #{vpc.vpc_id}"
					begin
						MU::Cloud::AWS.ec2(region).delete_vpc(vpc_id: vpc.vpc_id) if !noop
					rescue Aws::EC2::Errors::InvalidVpcIDNotFound
						MU.log "VPC #{vpc.vpc_id} has already been deleted", MU::WARN
					rescue Aws::EC2::Errors::DependencyViolation => e
						MU.log "Couldn't delete VPC #{vpc.vpc_id}: #{e.inspect}", MU::ERR
					end

					mu_zone = MU::Cloud::DNSZone.find(cloud_id: "platform-mu", region: region).values.first
					if !mu_zone.nil?
						MU::Cloud::AWS::DNSZone.toggleVPCAccess(id: mu_zone.id, vpc_id: vpc.vpc_id, remove: true)
					end
				}
			end


			# Subnets are almost a first-class resource. So let's kinda sorta treat
			# them like one. This should only be invoked on objects that already
			# exists in the cloud layer.
			protected
			class Subnet < MU::Cloud::AWS::VPC

				attr_reader :cloud_id
				attr_reader :ip_block
				attr_reader :mu_name
				attr_reader :name

				# @param parent [MU::Cloud::AWS::VPC]: The parent VPC of this subnet.
				# @param config [Hash<String>]:
				def initialize(parent, config)
					@parent = parent
					@config = config
					@cloud_id = config['cloud_id']
					@mu_name = config['mu_name']
					@name = config['name']
					@deploydata = config # This is a dummy for the sake of describe()
				end

				# Return the cloud identifier for the default route of this subnet.
				def defaultRoute
					resp = MU::Cloud::AWS.ec2(@config['region']).describe_route_tables(
						filters: [{name: "association.subnet-id", values: [@cloud_id]}]
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

				# Is this subnet privately-routable only, or public?
				# @return [Boolean]
				def private?
					return false if @cloud_id.nil?
					resp = MU::Cloud::AWS.ec2(@config['region']).describe_route_tables(
						filters: [{name: "association.subnet-id", values: [@cloud_id]}]
					)
					resp.route_tables.each { |route_table|
						route_table.routes.each { |route|
							if route.destination_cidr_block =="0.0.0.0/0" and !route.instance_id.nil?
								return true
							end
						}
					}
					return false
				end
			end

		end #class
	end #class
	end
end #module
