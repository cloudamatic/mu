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
        attr_reader :url
        attr_reader :config

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::vpcs}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @subnets = []
          @subnetcachesemaphore = Mutex.new
          if cloud_id and cloud_id.match(/^https:\/\//)
            @url = cloud_id.clone
            @cloud_id = cloud_id.to_s.gsub(/.*?\//, "")
          elsif cloud_id and !cloud_id.empty?
            @cloud_id = cloud_id.to_s
          end

          if !mu_name.nil?
            @mu_name = mu_name
            if @cloud_id.nil? or @cloud_id.empty?
              @cloud_id = MU::Cloud::Google.nameStr(@mu_name)
            end
            loadSubnets
          elsif @config['scrub_mu_isms']
            @mu_name = @config['name']
          else
            @mu_name = @deploy.getResourceName(@config['name'])
          end

        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          networkobj = MU::Cloud::Google.compute(:Network).new(
            name: MU::Cloud::Google.nameStr(@mu_name),
            description: @deploy.deploy_id,
            auto_create_subnetworks: false
#            i_pv4_range: @config['ip_block']
          )
          MU.log "Creating network #{@mu_name} (#{@config['ip_block']}) in project #{@config['project']}", details: networkobj
          resp = MU::Cloud::Google.compute(credentials: @config['credentials']).insert_network(@config['project'], networkobj)
          @url = resp.self_link # XXX needs to go in notify
          @cloud_id = resp.name

          if @config['subnets']
            subnetthreads = []
            parent_thread_id = Thread.current.object_id
            @config['subnets'].each { |subnet|
              subnetthreads << Thread.new {
                MU.dupGlobals(parent_thread_id)
                subnet_name = @config['name']+"-"+subnet['name']
                subnet_mu_name = MU::Cloud::Google.nameStr(@deploy.getResourceName(subnet_name))
                MU.log "Creating subnetwork #{subnet_mu_name} (#{subnet['ip_block']}) in project #{@config['project']}", details: subnet
                subnetobj = MU::Cloud::Google.compute(:Subnetwork).new(
                  name: subnet_mu_name,
                  description: @deploy.deploy_id,
                  ip_cidr_range: subnet['ip_block'],
                  network: @url,
                  region: subnet['availability_zone']
                )
                resp = MU::Cloud::Google.compute(credentials: @config['credentials']).insert_subnetwork(@config['project'], subnet['availability_zone'], subnetobj)
  
              }
            }
            subnetthreads.each do |t|
              t.join
            end
          end

          route_table_ids = []
          if !@config['route_tables'].nil?
            @config['route_tables'].each { |rtb|
              rtb['routes'].each { |route|
                # GCP does these for us, by default
                next if route['destination_network'] == "0.0.0.0/0" and
                        route['gateway'] == "#INTERNET"
                # sibling NAT host routes will get set up our groom phrase
                next if route['gateway'] == "#NAT" and !route['nat_host_name'].nil?
                createRoute(route, network: @url)
              }
            }
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
          base = MU.structToHash(cloud_desc)
          base["cloud_id"] = @cloud_id
          base.merge!(@config.to_h)
if @config['name'] == "gkeprivate"
  pp base.keys
  puts base['cloud_id']
end

          base
        end

        # Describe this VPC from the cloud platform's perspective
        # @return [Hash]
        def cloud_desc
          @config['project'] ||= MU::Cloud::Google.defaultProject(@config['credentials'])

          resp = MU::Cloud::Google.compute(credentials: @config['credentials']).get_network(@config['project'], @cloud_id)
          if @cloud_id.nil? or @cloud_id == ""
            MU.log "Couldn't describe #{self}, @cloud_id #{@cloud_id.nil? ? "undefined" : "empty" }", MU::ERR
            return nil
          end

          resp = resp.to_h
          @url ||= resp[:self_link]
          routes = MU::Cloud::Google.compute(credentials: @config['credentials']).list_routes(
            @config['project'],
            filter: "network eq #{@cloud_id}"
          ).items
          resp[:routes] = routes.map { |r| r.to_h } if routes
# XXX subnets too

          resp
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          rtb = @config['route_tables'].first

          rtb['routes'].each { |route|
            # If we had a sibling server being spun up as a NAT, rig up the 
            # route that the hosts behind it will need.
            if route['gateway'] == "#NAT" and !route['nat_host_name'].nil?
              createRoute(route, network: @url)
            end
          }

          if !@config['peers'].nil?
            count = 0
            @config['peers'].each { |peer|
              if peer['vpc']['vpc_name']
                peer_obj = @deploy.findLitterMate(name: peer['vpc']['vpc_name'], type: "vpcs")
                if peer_obj
                  if peer_obj.config['peers']
                    skipme = false
                    peer_obj.config['peers'].each { |peerpeer|
                      if peerpeer['vpc']['vpc_name'] == @config['name'] and
                         (peer['vpc']['vpc_name'] <=> @config['name']) == -1
                        skipme = true
                        MU.log "VPCs #{peer['vpc']['vpc_name']} and #{@config['name']} both declare mutual peering connection, ignoring #{@config['name']}'s redundant declaration", MU::DEBUG
# XXX and if deploy_id matches or is unset
                      end
                    }
                    next if skipme
                  end
                end

              else
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
                ).first
              end

              raise MuError, "No result looking for #{@mu_name}'s peer VPCs (#{peer['vpc']})" if peer_obj.nil?

              url = if peer_obj.cloudobj.url
                peer_obj.cloudobj.url
              elsif peer_obj.cloudobj.deploydata
                peer_obj.cloudobj.deploydata['self_link']
              else
                pp peer_obj.cloudobj.cloud_desc
                raise MuError, "Can't find the damn URL of my damn peer VPC #{peer['vpc']}"
              end
              cnxn_name = MU::Cloud::Google.nameStr(@mu_name+"-peer-"+count.to_s)
              peerreq = MU::Cloud::Google.compute(:NetworksAddPeeringRequest).new(
                name: cnxn_name,
                auto_create_routes: true,
                peer_network: url
              )

              MU.log "Peering #{@url} with #{url}, connection name is #{cnxn_name}", details: peerreq

              MU::Cloud::Google.compute(credentials: @config['credentials']).add_network_peering(
                @config['project'],
                @cloud_id,
                peerreq
              )
              count += 1
            }
          end
        end

        # Locate an existing VPC or VPCs and return an array containing matching Google cloud resource descriptors for those that match.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region
        # @param tag_key [String]: A tag key to search.
        # @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching VPCs
        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil, flags: {}, credentials: nil)
          flags["project"] ||= MU::Cloud::Google.defaultProject(credentials)
#MU.log "CALLED MU::Cloud::Google::VPC.find(#{cloud_id}, #{region}, #{tag_key}, #{tag_value}) with credentials #{credentials} from #{caller[0]}", MU::NOTICE, details: flags

          resp = {}
          if cloud_id
            vpc = MU::Cloud::Google.compute(credentials: credentials).get_network(
              flags['project'],
              cloud_id.to_s.sub(/^.*?\/([^\/]+)$/, '\1')
            )
            resp[cloud_id] = vpc if !vpc.nil?
          else # XXX other criteria
            MU::Cloud::Google.compute(credentials: credentials).list_networks(
              flags["project"]
            ).items.each { |vpc|
              resp[vpc.name] = vpc
            }
          end
#MU.log "THINGY", MU::WARN, details: resp
          resp.each_pair { |cloud_id, vpc|
            routes = MU::Cloud::Google.compute(credentials: credentials).list_routes(
              flags["project"],
              filter: "network eq #{vpc.self_link}"
            ).items
#            pp routes
          }
#MU.log "RETURNING RESPONSE FROM VPC FIND (#{resp.class.name})", MU::WARN, details: resp
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
          network = cloud_desc
          if network.nil?
            MU.log "Unabled to load cloud description in #{self}", MU::ERR
            return nil
          end
          found = []

          resp = nil
          MU::Cloud::Google.listRegions(@config['us_only']).each { |r|
            resp = MU::Cloud::Google.compute(credentials: @config['credentials']).list_subnetworks(
              @config['project'],
              r,
              filter: "network eq #{network[:self_link]}"
            )
            next if resp.nil? or resp.items.nil?
            resp.items.each { |subnet|
              found << subnet
            }
          }

          @subnetcachesemaphore.synchronize {
            @subnets ||= []
            ext_ids = @subnets.each.collect { |s| s.cloud_id }

            # If we're a plain old Mu resource, load our config and deployment
            # metadata. Like ya do.
            if !@config.nil? and @config.has_key?("subnets")
              @config['subnets'].each { |subnet|
                subnet['mu_name'] = @mu_name+"-"+subnet['name'] if !subnet.has_key?("mu_name")
                subnet['region'] = @config['region']
                found.each { |desc|
                  if desc.ip_cidr_range == subnet["ip_block"]
                    subnet["cloud_id"] = desc.name
                    subnet["url"] = desc.self_link
                    subnet['az'] = desc.region.gsub(/.*?\//, "")
                    break
                  end
                }


                if !ext_ids.include?(subnet["cloud_id"])
                  @subnets << MU::Cloud::Google::VPC::Subnet.new(self, subnet)
                end
              }

            # Of course we might be loading up a dummy subnet object from a
            # foreign or non-Mu-created VPC and subnet. So make something up.
            elsif !found.nil?
              found.each { |desc|
                subnet = {}
                subnet["ip_block"] = desc.ip_cidr_range
                subnet["name"] = subnet["ip_block"].gsub(/[\.\/]/, "_")
                subnet['mu_name'] = @mu_name+"-"+subnet['name']
                subnet["cloud_id"] = desc.name
                subnet['az'] = subnet['region'] = desc.region.gsub(/.*?\//, "")
                if !ext_ids.include?(desc.name)
                  @subnets << MU::Cloud::Google::VPC::Subnet.new(self, subnet)
                end
              }
            end

          }
          return @subnets

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
          nat = nil
          deploy_id = nil
          nat_name = nat_name.to_s if !nat_name.nil? and nat_name.class.to_s == "MU::Config::Tail"
          nat_ip = nat_ip.to_s if !nat_ip.nil? and nat_ip.class.to_s == "MU::Config::Tail"
          nat_cloud_id = nat_cloud_id.to_s if !nat_cloud_id.nil? and nat_cloud_id.class.to_s == "MU::Config::Tail"
          nat_tag_key = nat_tag_key.to_s if !nat_tag_key.nil? and nat_tag_key.class.to_s == "MU::Config::Tail"
          nat_tag_value = nat_tag_value.to_s if !nat_tag_value.nil? and nat_tag_value.class.to_s == "MU::Config::Tail"
          # If we're searching by name, assume it's part of this here deploy.
          if nat_cloud_id.nil? and !@deploy.nil?
            deploy_id = @deploy.deploy_id
          end
          found = MU::MommaCat.findStray(
            "Google",
            "server",
            name: nat_name,
            cloud_id: nat_cloud_id,
            deploy_id: deploy_id,
            tag_key: nat_tag_key,
            tag_value: nat_tag_value,
            allow_multi: true,
            dummy_ok: true,
            calling_deploy: @deploy
          )
# XXX wat
          return nil if found.nil? || found.empty?
          if found.size > 1
            found.each { |nat|
              # Try some cloud-specific criteria
              cloud_desc = nat.cloud_desc
              if !nat_host_ip.nil? and
# XXX this is AWS code, is wrong here
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
          loadSubnets
          if !cloud_id.nil? and cloud_id.match(/^https:\/\//)
            cloud_id.gsub!(/.*?\//, "")
          end
          MU.log "getSubnet(cloud_id: #{cloud_id}, name: #{name}, tag_key: #{tag_key}, tag_value: #{tag_value}, ip_block: #{ip_block})", MU::DEBUG, details: caller[0]

          @subnets.each { |subnet|
            if !cloud_id.nil? and !subnet.cloud_id.nil? and subnet.cloud_id.to_s == cloud_id.to_s
              return subnet
            elsif !name.nil? and !subnet.name.nil? and subnet.name.to_s == name.to_s
              return subnet
            end
          }
          return nil
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
        # instance. Useful for skipping hops through bastion hosts to get
        # directly at child nodes in peered VPCs, the public internet, and the
        # like.
        # @param target_instance [OpenStruct]: The cloud descriptor of the instance to check.
        # @param region [String]: The cloud provider region of the target subnet.
        # @return [Boolean]
        def self.haveRouteToInstance?(target_instance, region: MU.curRegion, credentials: nil)
          project ||= MU::Cloud::Google.defaultProject(credentials)
          return false if MU.myCloud != "Google"
# XXX see if we reside in the same Network and overlap subnets
# XXX see if we peer with the target's Network
          target_instance.network_interfaces.each { |iface|
            resp = MU::Cloud::Google.compute(credentials: credentials).list_routes(
              project,
              filter: "network eq #{iface.network}"
            )

            if resp and resp.items
MU.log "ROUTES TO #{target_instance.name}", MU::WARN, details: resp
            end
          }
          false
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

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          true
        end

        # Remove all VPC resources associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          flags["project"] ||= MU::Cloud::Google.defaultProject(credentials)

          purge_subnets(noop, project: flags['project'], credentials: credentials)
          ["route", "network"].each { |type|
# XXX tagged routes aren't showing up in list, and the networks that own them
# fail to delete silently
            MU::Cloud::Google.compute(credentials: credentials).delete(
              type,
              flags["project"],
              nil,
              noop
            )
          }
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "regions" => {
              "type" => "array",
              "items" => MU::Config.region_primitive
            },
            "project" => {
              "type" => "string",
              "description" => "The project into which to deploy resources"
            }
          }
          [toplevel_required, schema]
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
          else
            # If create_standard_subnets is off, and no route_tables were
            # declared at all, let's assume we want purely self-contained
            # private VPC, and create a dummy route accordingly.
            vpc['route_tables'] ||= [
              {
                "name" => "private",
                "routes" => [
                  {
                    "destination_network" => "0.0.0.0/0"
                  }
                ]
              }
            ]
          end

          # Generate a set of subnets per route, if none are declared
          if !vpc['subnets'] or vpc['subnets'].empty?
            if vpc['regions'].nil? or vpc['regions'].empty?
              vpc['regions'] = MU::Cloud::Google.listRegions(vpc['us_only'])
            end
            blocks = configurator.divideNetwork(vpc['ip_block'], vpc['regions'].size*vpc['route_tables'].size, 29)
            ok = false if blocks.nil?

            vpc["subnets"] = []
            vpc['route_tables'].each { |t|
              count = 0
              vpc['regions'].each { |r|
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

          # Google VPCs can't have routes that are anything other than global
          # (they can be tied to individual instances by tags, but w/e). So we
          # decompose our VPCs into littler VPCs, one for each declared route
          # table, so that the routes therein will only apply to the portion of
          # our network we want them to.
          if vpc['route_tables'].size > 1
            blocks = configurator.divideNetwork(vpc['ip_block'], vpc['route_tables'].size*2, 29)
            peernames = []
            vpc['route_tables'].each { |tbl|
              peernames << vpc['name']+"-"+tbl['name']
            }
            vpc['route_tables'].each { |tbl|
              newvpc = {
                "name" => vpc['name']+"-"+tbl['name'],
                "credentials" => vpc['credentials'],
                "virtual_name" => vpc['name'],
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
              ok = false if !configurator.insertKitten(newvpc, "vpcs", true)
            }
            configurator.removeKitten(vpc['name'], "vpcs")
          else
            has_nat = vpc['route_tables'].first["routes"].include?({"gateway"=>"#NAT", "destination_network"=>"0.0.0.0/0"})
            has_deny = vpc['route_tables'].first["routes"].include?({"gateway"=>"#DENY", "destination_network"=>"0.0.0.0/0"})
# XXX we need routes to peered Networks too

            if has_nat or has_deny
              ok = false if !genStandardSubnetACLs(vpc['parent_block'] || vpc['ip_block'], vpc['name'], configurator, vpc["project"], false, credentials: vpc['credentials'])
            else
              ok = false if !genStandardSubnetACLs(vpc['parent_block'] || vpc['ip_block'], vpc['name'], configurator, vpc["project"], credentials: vpc['credentials'])
            end
            if has_nat and !has_deny
              vpc['route_tables'].first["routes"] << {
                "gateway"=>"#DENY",
                "destination_network"=>"0.0.0.0/0"
              }
            end
            nat_count = 0
            # You know what, let's just guarantee that we'll have a route from
            # this master, always
            # XXX this confuses machines that don't have public IPs
            if !vpc['scrub_mu_isms']
#              vpc['route_tables'].first["routes"] << {
#                'gateway' => "#INTERNET",
#                'destination_network' => MU.mu_public_ip+"/32"
#              }
            end
            vpc['route_tables'].first["routes"].each { |route|
              # No such thing as a NAT gateway in Google... so make an instance
              # that'll do the deed.
              if route['gateway'] == "#NAT"
                nat_cfg = MU::Cloud::Google::Server.genericNAT
                nat_cfg['name'] = vpc['name']+"-natstion-"+nat_count.to_s
                nat_cfg['credentials'] = vpc['credentials']
                # XXX ingress/egress rules?
                # XXX for master too if applicable
                nat_cfg["application_attributes"] = {
                  "nat" => {
                    "private_net" => vpc["parent_block"].to_s
                  }
                }
                route['nat_host_name'] = nat_cfg['name']
                route['priority'] = 100
                vpc["dependencies"] << {
                  "type" => "server",
                  "name" => nat_cfg['name'],
                }

                nat_cfg['vpc'] = {
                  "vpc_name" => vpc["name"],
                  "subnet_pref" => "any"
                }
                nat_count = nat_count + 1
                ok = false if !configurator.insertKitten(nat_cfg, "servers", true)
              end
            }
          end

#          MU.log "GOOGLE VPC", MU::WARN, details: vpc
          ok
        end

        # @param route [Hash]: A route description, per the Basket of Kittens schema
        # @param server [MU::Cloud::Google::Server]: Instance to which this route will apply
        def createRouteForInstance(route, server)
          createRoute(route, network: @url, tags: [MU::Cloud::Google.nameStr(server.mu_name)])
        end

        private

        def self.genStandardSubnetACLs(vpc_cidr, vpc_name, configurator, project, publicroute = true, credentials: nil)
          private_acl = {
            "name" => vpc_name+"-rt",
            "cloud" => "Google",
            "credentials" => credentials,
            "project" => project,
            "vpc" => { "vpc_name" => vpc_name },
            "dependencies" => [ { "type" => "vpc", "name" => vpc_name } ],
            "rules" => [
              { "ingress" => true, "proto" => "all", "hosts" => [vpc_cidr] }
            ]
          }
#          if publicroute
#          XXX distinguish between "I have a NAT" and "I really shouldn't be
#          able to talk to the world"
            private_acl["rules"] << {
              "egress" => true, "proto" => "all", "hosts" => ["0.0.0.0/0"]
            }
#          else
#            private_acl["rules"] << {
#              "egress" => true, "proto" => "all", "hosts" => [vpc_cidr], "weight" => 999
#            }
#            private_acl["rules"] << {
#              "egress" => true, "proto" => "all", "hosts" => ["0.0.0.0/0"], "deny" => true
#            }
#          end
          configurator.insertKitten(private_acl, "firewall_rules", true)
        end

        # Helper method for manufacturing routes. Expect to be called from
        # {MU::Cloud::Google::VPC#create} or {MU::Cloud::Google::VPC#groom}.
        # @param route [Hash]: A route description, per the Basket of Kittens schema
        # @param network [String]: Cloud identifier of the VPC to which we're adding this route
        # @param tags [Array<String>]: Instance tags to which this route applies. If empty, applies to entire VPC.
        # @return [Hash]: The modified configuration that was originally passed in.
        def createRoute(route, network: @url, tags: [])
          routename = MU::Cloud::Google.nameStr(@mu_name+"-route-"+route['destination_network'])
          if !tags.nil? and tags.size > 0
            routename = MU::Cloud::Google.nameStr(routename+"-"+tags.first).slice(0,63)
          end
          route["priority"] ||= 999
          if route['gateway'] == "#NAT"
            if !route['nat_host_name'].nil? or !route['nat_host_id'].nil?
                sleep 5
              nat_instance = findBastion(
                nat_name: route["nat_host_name"],
                nat_cloud_id: route["nat_host_id"]
              )
              if nat_instance.nil? or nat_instance.cloud_desc.nil?
                raise MuError, "Failed to find NAT host for #NAT route in #{@mu_name} (#{route})"
              end

              routeobj = ::Google::Apis::ComputeBeta::Route.new(
                name: routename,
                next_hop_instance: nat_instance.cloud_desc.self_link,
                dest_range: route['destination_network'],
                priority: route["priority"],
                description: @deploy.deploy_id,
                tags: tags,
                network: network
              )
            end
# several other cases missing for various types of routers (raw IPs, instance ids, etc) XXX
          elsif route['gateway'] == "#DENY"
            resp = MU::Cloud::Google.compute(credentials: @config['credentials']).list_routes(
              @config['project'],
              filter: "network eq #{network}"
            )

            if !resp.nil? and !resp.items.nil?
              resp.items.each { |r|
                next if r.next_hop_gateway.nil? or !r.next_hop_gateway.match(/\/global\/gateways\/default-internet-gateway$/)
                MU.log "Removing standard route #{r.name} per our #DENY entry"
                MU::Cloud::Google.compute(credentials: @config['credentials']).delete_route(@config['project'], r.name)
              }
            end
          elsif route['gateway'] == "#INTERNET"
            routeobj = ::Google::Apis::ComputeBeta::Route.new(
              name: routename,
              next_hop_gateway: "global/gateways/default-internet-gateway",
              dest_range: route['destination_network'],
              priority: route["priority"],
              description: @deploy.deploy_id,
              tags: tags,
              network: network
            )
          end

          if route['gateway'] != "#DENY" and routeobj
            begin
              MU::Cloud::Google.compute(credentials: @config['credentials']).get_route(@config['project'], routename)
            rescue ::Google::Apis::ClientError, MU::MuError => e
              if e.message.match(/notFound/)
                MU.log "Creating route #{routename} in project #{@config['project']}", details: routeobj
                resp = MU::Cloud::Google.compute(credentials: @config['credentials']).insert_route(@config['project'], routeobj)
              else
                # TODO can't update GCP routes, would have to delete and re-create
              end
            end
          end
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

        # Remove all network interfaces associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param tagfilters [Array<Hash>]: Labels to filter against when search for resources to purge
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.purge_interfaces(noop = false, tagfilters = [{name: "tag:MU-ID", values: [MU.deploy_id]}], region: MU.curRegion)
        end

        # Remove all subnets associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param tagfilters [Array<Hash>]: Labels to filter against when search for resources to purge
        # @param regions [Array<String>]: The cloud provider regions to check
        # @return [void]
        def self.purge_subnets(noop = false, tagfilters = [{name: "tag:MU-ID", values: [MU.deploy_id]}], regions: MU::Cloud::Google.listRegions, project: nil, credentials: nil)
          project ||= MU::Cloud::Google.defaultProject(credentials)
          parent_thread_id = Thread.current.object_id
          regionthreads = []
          regions.each { |r|
            regionthreads << Thread.new {
              MU.dupGlobals(parent_thread_id)
              MU::Cloud::Google.compute(credentials: credentials).delete(
                "subnetwork",
                project,
                r,
                noop
              )
            }
          }
          regionthreads.each do |t|
            t.join
          end
        end

        protected

        # Subnets are almost a first-class resource. So let's kinda sorta treat
        # them like one. This should only be invoked on objects that already
        # exists in the cloud layer.
        class Subnet < MU::Cloud::Google::VPC

          attr_reader :cloud_id
          attr_reader :url
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
            @url = config['url']
            @mu_name = config['mu_name']
            @name = config['name']
            @deploydata = config # This is a dummy for the sake of describe()
            @az = config['az']
            @ip_block = config['ip_block']
          end

          # Return the cloud identifier for the default route of this subnet.
          def defaultRoute
          end

          # Is this subnet privately-routable only, or public?
          # @return [Boolean]
          def private?
            routes = MU::Cloud::Google.compute(credentials: @parent.config['credentials']).list_routes(
              @parent.config['project'],
              filter: "network eq #{@parent.url}"
            ).items
            routes.map { |r|
              if r.dest_range == "0.0.0.0/0" and !r.next_hop_gateway.nil? and
                 (r.tags.nil? or r.tags.size == 0) and
                 r.next_hop_gateway.match(/\/global\/gateways\/default-internet-gateway/)
                return false
              end
            }
            return true
          end
        end

      end #class
    end #class
  end
end #module
