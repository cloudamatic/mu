# Copyright:: Copyright (c) 2017 eGlobalTech, Inc., all rights reserved
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
    class Google

      # Creation of Virtual Private Clouds and associated artifacts (routes, subnets, etc).
      class VPC < MU::Cloud::VPC

        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :cloud_id
        attr_reader :config

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::vpcs}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @subnets = []
          @subnetcachesemaphore = Mutex.new
          @cloud_id = cloud_id
          if !mu_name.nil?
            @mu_name = mu_name.downcase
            loadSubnets if !@cloud_id.nil?
          elsif @config['scrub_mu_isms']
            @mu_name = @config['name'].downcase
          else
            @mu_name = @deploy.getResourceName(@config['name']).downcase
          end

        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          networkobj = ::Google::Apis::ComputeBeta::Network.new(
            name: @mu_name,
            description: @deploy.deploy_id,
            auto_create_subnetworks: false
#            i_pv4_range: @config['ip_block']
          )
          MU.log "Creating network #{@mu_name} (#{@config['ip_block']})", details: networkobj
          resp = MU::Cloud::Google.compute.insert_network(@config['project'], networkobj)
          @cloud_id = resp.target_link # XXX needs to go in notify

          if @config['subnets']
            subnetthreads = []
            parent_thread_id = Thread.current.object_id
            @config['subnets'].each { |subnet|
              subnetthreads << Thread.new {
                MU.dupGlobals(parent_thread_id)
                subnet_name = @config['name']+"-"+subnet['name']
                subnet_mu_name = @deploy.getResourceName(subnet_name).downcase
                MU.log "Creating subnetwork #{subnet_mu_name} (#{subnet['ip_block']})", details: subnet
                subnetobj = ::Google::Apis::ComputeBeta::Subnetwork.new(
                  name: subnet_mu_name,
                  description: @deploy.deploy_id,
                  ip_cidr_range: subnet['ip_block'],
                  network: @cloud_id,
                  region: subnet['availability_zone']
                )
                resp = MU::Cloud::Google.compute.insert_subnetwork(@config['project'], subnet['availability_zone'], subnetobj)
  
              }
            }
            subnetthreads.each do |t|
              t.join
            end
          end

# TODO this will matter as soon as we do anything besides 0.0.0.0/0 => #INTERNET
#          route_table_ids = []
#          if !@config['route_tables'].nil?
#            @config['route_tables'].each { |rtb|
#              rtb = createRoute(rtb, @cloud_id)
#            }
#          end
        end

        # Configure IP traffic logging on a given VPC/Subnet. Logs are saved in cloudwatch based on the network interface ID of each instance.
        # @param log_group_name [String]: The name of the CloudWatch log group all logs will be saved in.
        # @param resource_id [String]: The cloud provider's identifier of the resource that traffic logging will be enabled on.
        # @param resource_type [String]: What resource type to enable logging on (VPC or Subnet).
        # @param traffic_type [String]: What traffic to log (ALL, ACCEPT or REJECT).
        def trafficLogging(log_group_name: nil, resource_id: nil, resource_type: "VPC", traffic_type: "ALL")
        end

        # Describe this VPC
        # @return [Hash]
        def notify
          MU::Cloud::Google.compute.get_network(@config['project'], @mu_name).to_h
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom

          if !@config['peers'].nil?
            count = 0
            @config['peers'].each { |peer|
              tag_key, tag_value = peer['vpc']['tag'].split(/=/, 2) if !peer['vpc']['tag'].nil?
              if peer['vpc']['deploy_id'].nil? and peer['vpc']['vpc_id'].nil? and tag_key.nil?
                peer['vpc']['deploy_id'] = @deploy.deploy_id
              end

              peer_obj = MU::MommaCat.findStray(
                  "Google",
                  "vpcs",
                  deploy_id: peer['vpc']['deploy_id'],
                  cloud_id: peer['vpc']['vpc_id'],
                  name: peer['vpc']['vpc_name'],
                  tag_key: tag_key,
                  tag_value: tag_value,
                  dummy_ok: true
              )

              raise MuError, "No result looking for #{@mu_name}'s peer VPCs (#{peer['vpc']})" if peer_obj.nil? or peer_obj.first.nil?
              peerreq = ::Google::Apis::ComputeBeta::NetworksAddPeeringRequest.new(
                name: @mu_name+"-peer-"+count.to_s,
                auto_create_routes: true,
                peer_network: peer_obj.first.cloud_id
              )
              MU.log "Peering #{@mu_name} with #{peer_obj.first.cloud_id}", details: peerreq
              MU::Cloud::Google.compute.add_network_peering(
                @config['project'],
                @mu_name,
                peerreq
              )
            }
          end
        end

        # Locate an existing VPC or VPCs and return an array containing matching Google cloud resource descriptors for those that match.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region
        # @param tag_key [String]: A tag key to search.
        # @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching VPCs
        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil, flags: {})
          flags["project"] ||= MU::Cloud::Google.defaultProject
# XXX this is a placeholder, and quite wrong
          resp = MU::Cloud::Google.compute.list_networks(
            flags["project"],
            filter: "description eq #{MU.deploy_id}"
          )
          resp
        end

        # Return an array of MU::Cloud::Google::VPC::Subnet objects describe the
        # member subnets of this VPC.
        #
        # @return [Array<MU::Cloud::Google::VPC::Subnet>]
        def subnets
          if @subnets.nil? or @subnets.size == 0
            return loadSubnets
          end
          return @subnets
        end

        # Describe subnets associated with this VPC. We'll compose identifying
        # information similar to what MU::Cloud.describe builds for first-class
        # resources.
        # @return [Array<Hash>]: A list of cloud provider identifiers of subnets associated with this VPC.
        def loadSubnets
          network = notify

          @subnets = []
          MU::Cloud::Google.listRegions.each { |r|
            resp = MU::Cloud::Google.compute.list_subnetworks(
              @config['project'],
              r,
              filter: "network eq #{network[:self_link]}"
            )
            resp.items.each { |subnet|
              @subnets << subnet
            }
            next if resp.nil? or resp.items.nil?
          }
          @subnets
        end

        # Given some search criteria try locating a NAT Gaateway in this VPC.
        # @param nat_cloud_id [String]: The cloud provider's identifier for this NAT.
        # @param nat_filter_key [String]: A cloud provider filter to help identify the resource, used in conjunction with nat_filter_value.
        # @param nat_filter_value [String]: A cloud provider filter to help identify the resource, used in conjunction with nat_filter_key.
        # @param region [String]: The cloud provider region of the target instance.
        def findNat(nat_cloud_id: nil, nat_filter_key: nil, nat_filter_value: nil, region: MU.curRegion)
        end

        # Given some search criteria for a {MU::Cloud::Server}, see if we can
        # locate a NAT host in this VPC.
        # @param nat_name [String]: The name of the resource as defined in its 'name' Basket of Kittens field, typically used in conjunction with deploy_id.
        # @param nat_cloud_id [String]: The cloud provider's identifier for this NAT.
        # @param nat_tag_key [String]: A cloud provider tag to help identify the resource, used in conjunction with tag_value.
        # @param nat_tag_value [String]: A cloud provider tag to help identify the resource, used in conjunction with tag_key.
        # @param nat_ip [String]: An IP address associated with the NAT instance.
        def findBastion(nat_name: nil, nat_cloud_id: nil, nat_tag_key: nil, nat_tag_value: nil, nat_ip: nil)
        end

        # Check for a subnet in this VPC matching one or more of the specified
        # criteria, and return it if found.
        def getSubnet(cloud_id: nil, name: nil, tag_key: nil, tag_value: nil, ip_block: nil)
        end

        # Get the subnets associated with an instance.
        # @param instance_id [String]: The cloud identifier of the instance
        # @param instance [String]: A cloud descriptor for the instance, to save us an API call if we already have it
        # @param region [String]: The cloud provider region of the target instance
        # @return [Array<String>]
        def self.getInstanceSubnets(instance_id: nil, instance: nil, region: MU.curRegion)
        end

        @route_cache = {}
        @rtb_cache = {}
        @rtb_cache_semaphore = Mutex.new
        # Check whether we (the Mu Master) have a direct route to a particular
        # subnet. Useful for skipping hops through bastion hosts to get directly
        # at child nodes in peered VPCs and the like.
        # @param target_instance [OpenStruct]: The cloud descriptor of the instance to check.
        # @param region [String]: The cloud provider region of the target subnet.
        # @return [Boolean]
        def self.haveRouteToInstance?(target_instance, region: MU.curRegion)
        end

        # updates the route table cache (@rtb_cache).
        # @param subnet_key [String]: The subnet/subnets route tables will be extracted from.
        # @param use_cache [Boolean]: If to use the existing cache and add records to cache only if missing, or to also replace exising records in cache.
        # @param region [String]: The cloud provider region of the target subnet.
        def self.update_route_tables_cache(subnet_key, use_cache: true, region: MU.curRegion)
        end

        # Checks if the MU master has a route to a subnet in a peered VPC. Can be used on any subnets
        # @param source_subnets_key [String]: The subnet/subnets on one side of the peered VPC.
        # @param target_subnets_key [String]: The subnet/subnets on the other side of the peered VPC.
        # @param instance_id [String]: The instance ID in the target subnet/subnets.
        # @return [Boolean]
        def self.have_route_peered_vpc?(source_subnets_key, target_subnets_key, instance_id)
        end

        # Retrieves the route tables of used by subnets
        # @param subnet_ids [Array]: The cloud identifier of the subnets to retrieve the route tables for.
        # @param vpc_ids [Array]: The cloud identifier of the VPCs to retrieve route tables for.
        # @param region [String]: The cloud provider region of the target subnet.
        # @return [Array<OpenStruct>]: The cloud provider's complete descriptions of the route tables
        def self.get_route_tables(subnet_ids: [], vpc_ids: [], region: MU.curRegion)
        end

        # Remove all VPC resources associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          flags["project"] ||= MU::Cloud::Google.defaultProject
# XXX project flag has to get passed from somewheres

          purge_subnets(noop, project: flags['project'])

          resp = MU::Cloud::Google.compute.list_networks(
            flags["project"],
            filter: "description eq #{MU.deploy_id}"
          )
          return if resp.nil? or resp.items.nil?

          resp.items.each { |network|
            MU.log "Removing network #{network.name}", details: network
            if !noop
              retries = 0
              max = 10
              complete = false
              begin
                deletia = MU::Cloud::Google.compute.delete_network(flags["project"], network.name)
                if deletia.error and deletia.error.errors and deletia.error.errors.size > 0
                  retries = retries + 1
                  if retries % 3 == 0
                    MU.log "Got #{deletia.error.errors.first.code} deleting #{network.name}, may be waiting on other resources to delete (attempt #{retries}/#{max})", MU::WARN, details: deletia.error.errors
                  end
                  sleep 5
                else
                  complete = true
                end
              rescue ::Google::Apis::ClientError => e
                if e.message.match(/^notFound:/)
                  MU.log "#{network.name} has already been deleted", MU::NOTICE
                elsif e.message.match(/^resourceNotReady:/)
                  MU.log "Got #{e.message} deleting #{network.name}, may already be deleting", MU::NOTICE
                  retries = retries + 1
                  sleep 5
                  retry
                end
              end while !complete and retries < max
            end
          }
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::vpcs}, bare and unvalidated.
        # @param vpc [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(vpc, configurator)
          ok = true

          if vpc['create_standard_subnets']
            # Manufacture some generic routes, if applicable.
            if !vpc['route_tables'] or vpc['route_tables'].empty?
              vpc['route_tables'] = [
                {
                  "name" => "internet",
                  "routes" => [ { "destination_network" => "0.0.0.0/0", "gateway" => "#INTERNET" } ]
                },
                {
                  "name" => "private",
                  "routes" => [ { "destination_network" => "0.0.0.0/0", "gateway" => "#NAT" } ]
                }
              ]
            end

            # Generate a set of subnets per route, if none are declared
            if !vpc['subnets'] or vpc['subnets'].empty?
              if vpc['regions'].nil? or vpc['regions'].empty?
                vpc['regions'] = MU::Cloud::Google.listRegions(vpc['us_only'])
              end
              blocks = configurator.divideNetwork(vpc['ip_block'], vpc['regions'].size*vpc['route_tables'].size)
              ok = false if blocks.nil?

              vpc["subnets"] = []
              vpc['regions'].each { |r|
                count = 0
                vpc['route_tables'].each { |t|
                  block = blocks.shift
                  vpc["subnets"] << {
                    "availability_zone" => r,
                    "route_table" => t["name"],
                    "ip_block" => block.to_s,
                    "name" => "Subnet"+count.to_s+t["name"].capitalize,
                    "map_public_ips" => true
                  }
                  count = count + 1
                }
              }
            end
          end

          # Google VPCs can't have routes that are anything other than global
          # (or tied to individual instances by tags, but w/e). So we decompose
          # our VPCs into littler VPCs, one for each declared route table, so
          # that the routes therein will only apply to the portion of our
          # network we want them to.
          if vpc['route_tables'].size > 1
            blocks = configurator.divideNetwork(vpc['ip_block'], vpc['route_tables'].size*2)
            peernames = []
            vpc['route_tables'].each { |tbl|
              peernames << vpc['name']+"-"+tbl['name']
            }
            vpc['route_tables'].each { |tbl|
              newvpc = {
                "name" => vpc['name']+"-"+tbl['name'],
                "ip_block" => blocks.shift,
                "route_tables" => [tbl],
                "parent_block" => vpc['ip_block'],
                "subnets" => []
              }
              MU.log "Splitting VPC #{newvpc['name']} off from #{vpc['name']}", MU::NOTICE

              vpc.each_pair { |key, val|
                next if ["name", "route_tables", "subnets", "ip_block"].include?(key)
                newvpc[key] = val
              }
              newvpc['peers'] ||= []
              peernames.each { |peer|
                if peer != vpc['name']+"-"+tbl['name']
                  newvpc['peers'] << { "vpc" => { "vpc_name" => peer } }
                end
              }
              vpc["subnets"].each { |subnet|
                newvpc["subnets"] << subnet if subnet["route_table"] == tbl["name"]
              }
              ok = false if !configurator.insertKitten(newvpc, "vpcs")
            }
            configurator.removeKitten(vpc['name'], "vpcs")
          else
            if vpc['route_tables'].first["routes"].include?({"gateway"=>"#DENY", "destination_network"=>"0.0.0.0/0"})
              ok = false if !genStandardSubnetACLs(vpc['parent_block'] || vpc['ip_block'], vpc['name'], configurator, false)
            else
              ok = false if !genStandardSubnetACLs(vpc['parent_block'] || vpc['ip_block'], vpc['name'], configurator)
            end
          end

#          MU.log "GOOGLE VPC", MU::WARN, details: vpc
          ok
        end

        private

        def self.genStandardSubnetACLs(vpc_cidr, vpc_name, configurator, publicroute = true)
          private_acl = {
            "name" => vpc_name+"-routables",
            "cloud" => "Google",
            "vpc" => { "vpc_name" => vpc_name },
            "dependencies" => [ { "type" => "vpc", "name" => vpc_name } ],
            "rules" => [
              { "ingress" => true, "proto" => "all", "hosts" => [vpc_cidr] }
            ]
          }
          if publicroute
            private_acl["rules"] << {
              "egress" => true, "proto" => "all", "hosts" => ["0.0.0.0/0"]
            }
          else
            private_acl["rules"] << {
              "egress" => true, "proto" => "all", "hosts" => [vpc_cidr], "weight" => 999
            }
            private_acl["rules"] << {
              "egress" => true, "proto" => "all", "hosts" => ["0.0.0.0/0"], "deny" => true
            }
          end
          configurator.insertKitten(private_acl, "firewall_rules")
        end

        # List the routes for each subnet in the given VPC
        def self.listAllSubnetRoutes(vpc_id, region: MU.curRegion)
        end

        # Helper method for manufacturing routes. Expect to be called from
        # {MU::Cloud::Google::VPC#create} or {MU::Cloud::Google::VPC#deploy}.
        # @param rtb [Hash]: A route table description parsed through {MU::Config::BasketofKittens::vpcs::route_tables}.
        # @return [Hash]: The modified configuration that was originally passed in.
        def createRoute(rtb, network)
MU.log "ROUTEDERP", MU::WARN, details: rtb
extroutes = MU::Cloud::Google.compute.list_routes(MU::Cloud::Google.defaultProject, filter: "network eq "+network)
MU.log "ROUTEHURP", MU::WARN, details: extroutes
          rtb['routes'].each { |route|
            routename = @mu_name+"-route-"+route['destination_network'].gsub(/[\/\.]/, "-")
            if route["#INTERNET"]
            else
#              routeobj = ::Google::Apis::ComputeBeta::Route.new(
#                name: routename,
#                dest_range: route['destination_network'],
#                network: network,
#                next_hop_network: network
#              )
            end
#            resp = MU::Cloud::Google.compute.insert_route(@config['project'], routeobj)
          }
        end


        # Remove all network gateways associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.purge_gateways(noop = false, tagfilters = [{name: "tag:MU-ID", values: [MU.deploy_id]}], region: MU.curRegion)
        end

        # Remove all NAT gateways associated with the VPC of the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param vpc_id [String]: The cloud provider's unique VPC identifier
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.purge_nat_gateways(noop = false, vpc_id: nil, region: MU.curRegion)
        end

        # Remove all VPC endpoints associated with the VPC of the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param vpc_id [String]: The cloud provider's unique VPC identifier
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.purge_endpoints(noop = false, vpc_id: nil, region: MU.curRegion)
        end

        # Remove all route tables associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param tagfilters [Array<Hash>]: EC2 tags to filter against when search for resources to purge
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.purge_routetables(noop = false, tagfilters = [{name: "tag:MU-ID", values: [MU.deploy_id]}], region: MU.curRegion)
        end


        # Remove all network interfaces associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param tagfilters [Array<Hash>]: EC2 tags to filter against when search for resources to purge
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.purge_interfaces(noop = false, tagfilters = [{name: "tag:MU-ID", values: [MU.deploy_id]}], region: MU.curRegion)
        end

        # Remove all subnets associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param tagfilters [Array<Hash>]: EC2 tags to filter against when search for resources to purge
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.purge_subnets(noop = false, tagfilters = [{name: "tag:MU-ID", values: [MU.deploy_id]}], regions: nil, project: MU::Cloud::Google.defaultProject)
          regions = MU::Cloud::Google.listRegions if regions.nil?
          parent_thread_id = Thread.current.object_id
          regionthreads = []
          regions.each { |r|
            regionthreads << Thread.new {
              MU.dupGlobals(parent_thread_id)
              resp = MU::Cloud::Google.compute.list_subnetworks(
                project,
                r,
                filter: "description eq #{MU.deploy_id}"
              )
              next if resp.nil? or resp.items.nil?
  
              resp.items.each { |subnet|
                MU.log "Removing subnet #{subnet.name}", details: subnet
                if !noop
                  begin
                    MU::Cloud::Google.compute.delete_subnetwork(project, r, subnet.name)
                  rescue ::Google::Apis::ClientError => e
                    if e.message.match(/^notFound:/)
                      MU.log "#{network.name} has already been deleted", MU::NOTICE
                    elsif e.message.match(/^resourceNotReady:/)
                      MU.log "Got #{e.message} deleting #{network.name}, may already be deleting", MU::NOTICE
                      sleep 5
                      retry
                    end
                  end
                end
              }
            }
          }
          regionthreads.each do |t|
            t.join
          end
        end

        # Remove all DHCP options sets associated with the currently loaded
        # deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param tagfilters [Array<Hash>]: EC2 tags to filter against when search for resources to purge
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.purge_dhcpopts(noop = false, tagfilters = [{name: "tag:MU-ID", values: [MU.deploy_id]}], region: MU.curRegion)
        end

        # Remove all VPCs associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param tagfilters [Array<Hash>]: EC2 tags to filter against when search for resources to purge
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.purge_vpcs(noop = false, tagfilters = [{name: "tag:MU-ID", values: [MU.deploy_id]}], region: MU.curRegion)
        end

        protected

        # Subnets are almost a first-class resource. So let's kinda sorta treat
        # them like one. This should only be invoked on objects that already
        # exists in the cloud layer.
        class Subnet < MU::Cloud::Google::VPC

          attr_reader :cloud_id
          attr_reader :ip_block
          attr_reader :mu_name
          attr_reader :name
          attr_reader :az


          # @param parent [MU::Cloud::Google::VPC]: The parent VPC of this subnet.
          # @param config [Hash<String>]:
          def initialize(parent, config)
            @parent = parent
            @config = MU::Config.manxify(config)
            @cloud_id = config['cloud_id']
            @mu_name = config['mu_name'].downcase
            @name = config['name']
            @deploydata = config # This is a dummy for the sake of describe()

          end

          # Return the cloud identifier for the default route of this subnet.
          def defaultRoute
          end

          # Is this subnet privately-routable only, or public?
          # @return [Boolean]
          def private?
          end
        end

      end #class
    end #class
  end
end #module
