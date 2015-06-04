# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#	  http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'json'
require 'net/http'
require 'net/smtp'
require 'trollop'
require 'fileutils'

Thread.abort_on_exception = true

module MU

	# Routines for removing cloud resources.
	class Cleanup

		home = Etc.getpwuid(Process.uid).dir

		@muid = nil
		@noop = false
		@force = false
		@onlycloud = false

		# Remove all network gateways associated with the currently loaded deployment.
		# @param region [String]: The cloud provider region
		# @return [void]
		def self.purge_gateways(region: MU.curRegion)
			resp = MU.ec2(region).describe_internet_gateways(
				filters: @stdfilters
			)
			gateways = resp.data.internet_gateways

			gateways.each { |gateway|
				gateway.attachments.each { |attachment|
					MU.log "Detaching Internet Gateway #{gateway.internet_gateway_id} from #{attachment.vpc_id}"
					begin
						MU.ec2(region).detach_internet_gateway(
							internet_gateway_id: gateway.internet_gateway_id,
							vpc_id: attachment.vpc_id
						)
					rescue Aws::EC2::Errors::GatewayNotAttached => e
						MU.log "Gateway #{gateway.internet_gateway_id} was already detached", MU::WARN
					end
				}
				MU.log "Deleting Internet Gateway #{gateway.internet_gateway_id}"
				MU.ec2(region).delete_internet_gateway(internet_gateway_id: gateway.internet_gateway_id)
			}
			return nil
		end

		# Remove all route tables associated with the currently loaded deployment.
		# @param region [String]: The cloud provider region
		# @return [void]
		def self.purge_routetables(region: MU.curRegion)
			resp = MU.ec2(region).describe_route_tables(
				filters: @stdfilters
			)
			route_tables = resp.data.route_tables

			return if route_tables.nil? or route_tables.size == 0

			route_tables.each { |table|
				table.routes.each { |route|
					if !route.network_interface_id.nil?
						MU.log "Deleting Network Interface #{route.network_interface_id}"
						begin
							MU.ec2(region).delete_network_interface(network_interface_id: route.network_interface_id)
						rescue Aws::EC2::Errors::InvalidNetworkInterfaceIDNotFound => e
							MU.log "Network Interface #{route.network_interface_id} has already been deleted", MU::WARN
						end
					end
					if route.gateway_id != "local"
						MU.log "Deleting #{table.route_table_id}'s route for #{route.destination_cidr_block}"
						MU.ec2(region).delete_route(
							route_table_id: table.route_table_id,
							destination_cidr_block: route.destination_cidr_block
						)
					end
				}
				can_delete = true
				table.associations.each { |assoc|
					begin
						MU.ec2(region).disassociate_route_table(association_id: assoc.route_table_association_id)
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
				MU.ec2(region).delete_route_table(route_table_id: table.route_table_id)
			}
			return nil
		end


		# Remove all network interfaces associated with the currently loaded deployment.
		# @param region [String]: The cloud provider region
		# @return [void]
		def self.purge_interfaces(region: MU.curRegion)
			resp = MU.ec2(region).describe_network_interfaces(
				filters: @stdfilters
			)
			ifaces = resp.data.network_interfaces

			return if ifaces.nil? or ifaces.size == 0

			ifaces.each { |iface|
				MU.log "Deleting Network Interface #{iface.network_interface_id}"
				MU.ec2(region).delete_network_interface(network_interface_id: iface.network_interface_id)
			}
		end

		# Remove all subnets associated with the currently loaded deployment.
		# @param region [String]: The cloud provider region
		# @return [void]
		def self.purge_subnets(region: MU.curRegion)
			resp = MU.ec2(region).describe_subnets(
				filters: @stdfilters
			)
			subnets = resp.data.subnets

			return if subnets.nil? or subnets.size == 0

			subnets.each { |subnet|
				begin
					if subnet.state != "available"
						MU.log "Waiting for #{subnet.subnet_id} to be in a removable state...", MU::NOTICE
						sleep 30
					else
						MU.log "Deleting Subnet #{subnet.subnet_id}"
						MU.ec2(region).delete_subnet(subnet_id: subnet.subnet_id)
					end
				rescue Aws::EC2::Errors::InvalidSubnetIDNotFound
					MU.log "Subnet #{subnet.subnet_id} disappeared before I could remove it", MU::WARN
					next
				end while subnet.state != "available"
			}
		end

		# Remove all DHCP options sets associated with the currently loaded
		# deployment.
		# @param region [String]: The cloud provider region
		# @return [void]
		def self.purge_dhcpopts(region: MU.curRegion)
			resp = MU.ec2(region).describe_dhcp_options(
				filters: @stdfilters
			)
			sets = resp.data.dhcp_options

			return if sets.nil? or sets.size == 0

			sets.each { |optset|
				begin
					MU.log "Deleting DHCP Option Set #{optset.dhcp_options_id}"
					MU.ec2(region).delete_dhcp_options(dhcp_options_id: optset.dhcp_options_id)
				rescue Aws::EC2::Errors::DependencyViolation => e
					MU.log e.inspect, MU::ERR
#				rescue Aws::EC2::Errors::InvalidSubnetIDNotFound
#					MU.log "Subnet #{subnet.subnet_id} disappeared before I could remove it", MU::WARN
#					next
				end
			}
		end

		# Remove all VPCs associated with the currently loaded deployment.
		# @param region [String]: The cloud provider region
		# @return [void]
		def self.purge_vpcs(region: MU.curRegion)
			resp = MU.ec2(region).describe_vpcs(
				filters: @stdfilters
			)

			vpcs = resp.data.vpcs
			return if vpcs.nil? or vpcs.size == 0

			vpcs.each { |vpc|
				my_peer_conns = MU.ec2(region).describe_vpc_peering_connections(
					filters: [
						{
							name: "requester-vpc-info.vpc-id",
							values: [vpc.vpc_id]
						}
					]
				).vpc_peering_connections
				my_peer_conns.concat(MU.ec2(region).describe_vpc_peering_connections(
					filters: [
						{
							name: "accepter-vpc-info.vpc-id",
							values: [vpc.vpc_id]
						}
					]
				).vpc_peering_connections)
				my_peer_conns.each { |cnxn|
					
					[cnxn.accepter_vpc_info.vpc_id, cnxn.requester_vpc_info.vpc_id].each { |peer_vpc|
						MU::VPC.listAllSubnetRouteTables(peer_vpc, region: region).each { |rtb_id|
							resp = MU.ec2(region).describe_route_tables(
								route_table_ids: [rtb_id]
							)
							resp.route_tables.each { |rtb|
								rtb.routes.each { |route|
									if route.vpc_peering_connection_id == cnxn.vpc_peering_connection_id
										MU.log "Removing route #{route.destination_cidr_block} from route table #{rtb_id} in VPC #{peer_vpc}"
										MU.ec2(region).delete_route(
											route_table_id: rtb_id,
											destination_cidr_block: route.destination_cidr_block
										) if !@noop
									end
								}
							}
						}
					}
					MU.log "Deleting VPC peering connection #{cnxn.vpc_peering_connection_id}"
					begin
						MU.ec2(region).delete_vpc_peering_connection(
							vpc_peering_connection_id: cnxn.vpc_peering_connection_id
						) if !@noop
					rescue Aws::EC2::Errors::InvalidStateTransition => e
						MU.log "VPC peering connection #{cnxn.vpc_peering_connection_id} not in removable (state #{cnxn.status.code})", MU::WARN
					end
				}
				
				MU.log "Deleting VPC #{vpc.vpc_id}"
				begin
					MU.ec2(region).delete_vpc(vpc_id: vpc.vpc_id)
				rescue Aws::EC2::Errors::DependencyViolation => e
					MU.log "Couldn't delete VPC #{vpc.vpc_id}: #{e.inspect}", MU::ERR
				end

				mu_zone, junk = MU::DNSZone.find(name: "mu", region: region)
				if !mu_zone.nil?
					MU::DNSZone.toggleVPCAccess(id: mu_zone.id, vpc_id: vpc.vpc_id, remove: true)
				end

			}
		end


		# Purge all resources associated with a deployment.
		# @param muid [String]: The identifier of the deployment to remove (typically seen in the MU-ID tag on a resource).
		# @param force [Boolean]: Force deletion of resources.
		# @param noop [Boolean]: Do not delete resources, merely list what would be deleted.
		# @param skipsnapshots [Boolean]: Refrain from saving final snapshots of volumes and databases before deletion.
		# @param onlycloud [Boolean]: Purge cloud resources, but skip purging all Mu master metadata, ssh keys, etc.
		# @param verbose [Boolean]: Generate verbose output.
		# @param web [Boolean]: Generate web-friendly output.
		# @param ignoremaster [Boolean]: Ignore the tags indicating the originating MU master server when deleting.
		# @return [void]
		def self.run(muid, force, noop=false, skipsnapshots=false, onlycloud=false, verbose=false, web=false, ignoremaster=false, mommacat: nil)
			MU.setLogging(verbose, web)
			@noop = noop
			@skipsnapshots = skipsnapshots
			@onlycloud = onlycloud
			@ignoremaster = ignoremaster

			if MU.chef_user != "mu"
				MU.setVar("dataDir", Etc.getpwnam(MU.chef_user).dir+"/.mu/var")
			else
				MU.setVar("dataDir", MU.mainDataDir)
			end

			# Load up our deployment metadata
			if !mommacat.nil?
				@mommacat = mommacat
			else
				begin
					deploy_dir = File.expand_path("#{MU.dataDir}/deployments/"+muid)
					if Dir.exist?(deploy_dir)
#						key = OpenSSL::PKey::RSA.new(File.read("#{deploy_dir}/public_key"))
#						deploy_secret = key.public_encrypt(File.read("#{deploy_dir}/deploy_secret"))
						FileUtils.touch("#{deploy_dir}/.cleanup") if !@noop
					else
						MU.log "I don't see a deploy named #{muid}.", MU::WARN
						MU.log "Known deployments:\n#{Dir.entries(deploy_dir).reject{|item| item.match(/^\./) or !File.exists?(deploy_dir+"/"+item+"/public_key") }.join("\n")}", MU::WARN
						MU.log "Searching for remnants of #{muid}, though this may be an invalid MU-ID.", MU::WARN
					end
					@mommacat = MU::MommaCat.new(muid)
				rescue Exception => e
					MU.log "Can't load a deploy record for #{muid} (#{e.inspect}), cleaning up resources by guesswork", MU::WARN
					MU.setVar("mu_id", muid)
				end
			end

			# We identify most taggable resources like this.
			@stdfilters = [
				{ name: "tag:MU-ID", values: [MU.mu_id] }
			]
			if !@ignoremaster
				@stdfilters << { name: "tag:MU-MASTER-IP", values: [MU.mu_public_ip] }
			end
			parent_thread_id = Thread.current.object_id


			regions = MU::Config.listRegions
			deleted_nodes = 0
			@regionthreads = []
			keyname = "deploy-#{MU.mu_id}"
			regions.each { |r|
				@regionthreads << Thread.new {
					MU.dupGlobals(parent_thread_id)
					MU.setVar("curRegion", r)
					MU.log "Checking for cloud resources in #{r}", MU::NOTICE
					begin
						MU::CloudFormation.cleanup(@noop, @ignoremaster, region: r)
						MU::ServerPool.cleanup(@noop, @ignoremaster, region: r)
						MU::LoadBalancer.cleanup(@noop, @ignoremaster, region: r)
						MU::Server.cleanup(@noop, @ignoremaster, skipsnapshots: @skipsnapshots, onlycloud: @onlycloud, region: r)
						MU::Database.cleanup(@noop, @ignoremaster, region: r)
						MU::FirewallRule.cleanup(@noop, @ignoremaster, region: r)
						MU::DNSZone.cleanup(@noop, region: r)
						purge_gateways(region: r)
						purge_routetables(region: r)
						purge_interfaces(region: r)
						purge_subnets(region: r)
						purge_vpcs(region: r)
						purge_dhcpopts(region: r)

						# Hit CloudFormation again- sometimes the first delete will quietly
						# fail due to dependencies.
						MU::CloudFormation.cleanup(@noop, wait: true, region: r)

						resp = MU.ec2(r).describe_key_pairs(
							filters: [ { name: "key-name", values: [keyname] } ]
						)
						resp.data.key_pairs.each { |keypair|
							MU.log "Deleting key pair #{keypair.key_name} from #{r}"
							MU.ec2(r).delete_key_pair(key_name: keypair.key_name) if !@noop
						}
					rescue Aws::EC2::Errors::RequestLimitExceeded, Aws::EC2::Errors::Unavailable, Aws::EC2::Errors::InternalError => e
						MU.log e.inspect, MU::WARN
						sleep 30
						retry
					end
				}
			}

			@regionthreads.each do |t|
				t.join
			end

			# Scrub any residual Chef records with matching tags
			if !@onlycloud
				if File.exists?(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
					Chef::Config.from_file(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
				end
				deadnodes = []
				Chef::Config[:environment] = MU.environment
				q = Chef::Search::Query.new
				q.search("node", "tags_MU-ID:#{MU.mu_id}").each { |item|
					next if item.is_a?(Fixnum)
					item.each { |node|
						deadnodes << node.name
					}
				}
				MU.log "Missed some Chef resources in node cleanup, purging now", MU::NOTICE if deadnodes.size > 0
				deadnodes.uniq.each { |node|
					MU::Server.purgeChefResources(node, [], noop)
				}
			end

			# XXX Rotate vault keys and remove any residual crufty clients. This
			# doesn't actually work right now (vault bug?) and is ungodly slow.
			if !@noop and !@onlycloud
#				MU::MommaCat.lock("vault-rotate", false, true)
#				MU.log "Rotating vault keys and purging unknown clients"
#				`#{MU::Config.knife} vault rotate all keys --clean-unknown-clients #{MU::Config.vault_opts}`
#				MU::MommaCat.unlock("vault-rotate")
			end

			if !@onlycloud and !@noop and @mommacat
				@mommacat.purge!
			end

			myhome = Etc.getpwuid(Process.uid).dir
			sshdir = "#{myhome}/.ssh"
			sshconf = "#{sshdir}/config"
			ssharchive = "#{sshdir}/archive"
			
			Dir.mkdir(sshdir, 0700) if !Dir.exists?(sshdir) and !@noop
			Dir.mkdir(ssharchive, 0700) if !Dir.exists?(ssharchive) and !@noop
			
			keyname = "deploy-#{MU.mu_id}"
			if File.exists?("#{sshdir}/#{keyname}")
				MU.log "Moving #{sshdir}/#{keyname} to #{ssharchive}/#{keyname}"
				if !@noop
					File.rename("#{sshdir}/#{keyname}", "#{ssharchive}/#{keyname}")
				end
			end
			
			if File.exists?(sshconf) and File.open(sshconf).read.match(/\/deploy\-#{MU.mu_id}$/)
				MU.log "Expunging #{MU.mu_id} from #{sshconf}"
				if !@noop 
					FileUtils.copy(sshconf, "#{ssharchive}/config-#{MU.mu_id}")
					File.open(sshconf, File::CREAT|File::RDWR, 0600) { |f|
						f.flock(File::LOCK_EX)
						newlines = Array.new
						delete_block = false
						f.readlines.each { |line|
							if line.match(/^Host #{MU.mu_id}\-/)
								delete_block = true
							elsif line.match(/^Host /)
								delete_block = false
							end
							newlines << line if !delete_block
						}
						f.rewind
						f.truncate(0)
						f.puts(newlines)
						f.flush
						f.flock(File::LOCK_UN)
					}
				end
			end
			
			# XXX refactor with above? They're similar, ish.
			hostsfile = "/etc/hosts"
			if File.open(hostsfile).read.match(/ #{MU.mu_id}\-/)
				MU.log "Expunging traces of #{MU.mu_id} from #{hostsfile}"
				if !@noop 
					FileUtils.copy(hostsfile, "#{hostsfile}.cleanup-#{muid}")
					File.open(hostsfile, File::CREAT|File::RDWR, 0644) { |f|
						f.flock(File::LOCK_EX)
						newlines = Array.new
						f.readlines.each { |line|
							newlines << line if !line.match(/ #{MU.mu_id}\-/)
						}
						f.rewind
						f.truncate(0)
						f.puts(newlines)
						f.flush
						f.flock(File::LOCK_UN)
					}
				end
			end

			if !@noop
				MU.s3(MU.myRegion).delete_object(
					bucket: MU.adminBucketName,
					key: "#{MU.mu_id}-secret"
				)
			end

			MU::MommaCat.syncMonitoringConfig if !@noop

		end
	end #class
end #module
