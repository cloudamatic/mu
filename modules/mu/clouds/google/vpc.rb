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
          networkobj = ::Google::Apis::ComputeV1::Network.new(
            name: @mu_name,
            description: @deploy.deploy_id,
            auto_create_subnetworks: false
#            i_pv4_range: @config['ip_block']
          )
          MU.log "Creating network #{@mu_name} (#{@config['ip_block']})", details: networkobj
          resp = MU::Cloud::Google.compute.insert_network(@config['project'], networkobj)
          network_url = resp.target_link # XXX needs to go in notify

          if @config['subnets']
            subnetthreads = []
            parent_thread_id = Thread.current.object_id
            @config['subnets'].each { |subnet|
              subnetthreads << Thread.new {
                MU.dupGlobals(parent_thread_id)
                subnet_name = @config['name']+"-"+subnet['name']
                subnet_mu_name = @deploy.getResourceName(subnet_name).downcase
                MU.log "Creating subnetwork #{subnet_mu_name} (#{subnet['ip_block']})", details: subnet
                subnetobj = ::Google::Apis::ComputeV1::Subnetwork.new(
                  name: subnet_mu_name,
                  description: @deploy.deploy_id,
                  ip_cidr_range: subnet['ip_block'],
                  network: network_url,
                  region: subnet['availability_zone']
                )
                resp = MU::Cloud::Google.compute.insert_subnetwork(@config['project'], subnet['availability_zone'], subnetobj)
  
              }
            }
            subnetthreads.each do |t|
              t.join
            end
          end
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
        end

        # Locate an existing VPC or VPCs and return an array containing matching Google cloud resource descriptors for those that match.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region
        # @param tag_key [String]: A tag key to search.
        # @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching VPCs
        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil, opts: {})
#          cloud_desc = MU::Cloud::Google.compute.get_network(@config['project'], cloud_id)
          {}
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
                    MU.log "Got #{deletia.error.errors.first.code} deleting #{network.name}, may be waiting on other resources to delete (attempt #{retries}/#{max})", MU::warn, details: deletia.error.errors
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

        private

        # List the route tables for each subnet in the given VPC
        def self.listAllSubnetRouteTables(vpc_id, region: MU.curRegion)
        end

        # Helper method for manufacturing route tables. Expect to be called from
        # {MU::Cloud::Google::VPC#create} or {MU::Cloud::Google::VPC#deploy}.
        # @param rtb [Hash]: A route table description parsed through {MU::Config::BasketofKittens::vpcs::route_tables}.
        # @return [Hash]: The modified configuration that was originally passed in.
        def createRouteTable(rtb)
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
