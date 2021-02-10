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
        attr_reader :cloud_desc_cache
        attr_reader :routes

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super

          @subnets ||= []
          @subnetcachesemaphore = Mutex.new

          loadSubnets if @cloud_id

          @mu_name ||= @config['scrub_mu_isms'] ? @config['name'] : @deploy.getResourceName(@config['name'])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          networkobj = MU::Cloud::Google.compute(:Network).new(
            name: MU::Cloud::Google.nameStr(@mu_name),
            description: @deploy.deploy_id,
            auto_create_subnetworks: false
          )
          MU.log "Creating network #{@mu_name} (#{@config['ip_block']}) in project #{@project_id}", details: networkobj

          resp = MU::Cloud::Google.compute(credentials: @config['credentials']).insert_network(@project_id, networkobj)
          @url = resp.self_link
          @cloud_id = resp.name

          if @config['subnets']
            subnetthreads = []
            parent_thread_id = Thread.current.object_id
            @config['subnets'].each { |subnet|
              subnetthreads << Thread.new {
                MU.dupGlobals(parent_thread_id)
                subnet_name = @config['name']+subnet['name']

                subnet_mu_name = @config['scrub_mu_isms'] ? @cloud_id+subnet_name.downcase : MU::Cloud::Google.nameStr(@deploy.getResourceName(subnet_name, max_length: 61))
                MU.log "Creating subnetwork #{subnet_mu_name} (#{subnet['ip_block']}) in project #{@project_id} region #{subnet['availability_zone']}", details: subnet
                subnetobj = MU::Cloud::Google.compute(:Subnetwork).new(
                  name: subnet_mu_name,
                  description: @deploy.deploy_id,
                  ip_cidr_range: subnet['ip_block'],
                  network: @url,
                  region: subnet['availability_zone']
                )
                MU::Cloud::Google.compute(credentials: @config['credentials']).insert_subnetwork(@project_id, subnet['availability_zone'], subnetobj)

                # make sure the subnet we created exists, before moving on
                subnetdesc = nil
                begin 
                  subnetdesc = MU::Cloud::Google.compute(credentials: @config['credentials']).get_subnetwork(@project_id, subnet['availability_zone'], subnet_mu_name)
                  if !subnetdesc.nil?
                    subnet_cfg = {}
                    subnet_cfg["ip_block"] = subnet['ip_block']
                    subnet_cfg["name"] = subnet_name
                    subnet_cfg['mu_name'] = subnet_mu_name
                    subnet_cfg["cloud_id"] = subnetdesc.self_link.gsub(/.*?\/([^\/]+)$/, '\1')
                    subnet_cfg['az'] = subnet['availability_zone']
                    @subnets << MU::Cloud::Google::VPC::Subnet.new(self, subnet_cfg, precache_description: false)
                  end
                  sleep 1
                end while subnetdesc.nil?
              }
            }
            subnetthreads.each do |t|
              t.join
            end
          end

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
          base = MU.structToHash(cloud_desc, stringify_keys: true)
          base["cloud_id"] = @cloud_id
          base["project_id"] = habitat_id
          base.merge!(@config.to_h)
          if @subnets
            base["subnets"] = @subnets.map { |s| s.notify }
          end
          base
        end

        # Describe this VPC from the cloud platform's perspective
        # @return [Google::Apis::Core::Hashable]
        def cloud_desc(use_cache: true)
          if @cloud_desc_cache and use_cache
            return @cloud_desc_cache
          end

          resp = MU::Cloud::Google.compute(credentials: @config['credentials']).get_network(@project_id, @cloud_id)

          if @cloud_id.nil? or @cloud_id == "" or resp.nil?
            MU.log "Couldn't describe #{self}, @cloud_id #{@cloud_id.nil? ? "undefined" : "empty" }", MU::ERR
            return nil
          end
          @cloud_desc_cache = resp

          # populate other parts and pieces of ourself
          @url ||= resp.self_link
          routes = MU::Cloud::Google.compute(credentials: @config['credentials']).list_routes(
            @project_id,
            filter: "network = \"#{@url}\""
          ).items
          @routes = routes if routes and routes.size > 0

          @cloud_desc_cache
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          rtb = @config['route_tables'].first # there's only ever one

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
              if peer['vpc']['name']
                peer_obj = @deploy.findLitterMate(name: peer['vpc']['name'], type: "vpcs", habitat: peer['vpc']['project'])
              else
                tag_key, tag_value = peer['vpc']['tag'].split(/=/, 2) if !peer['vpc']['tag'].nil?
                if peer['vpc']['deploy_id'].nil? and peer['vpc']['id'].nil? and tag_key.nil?
                  peer['vpc']['deploy_id'] = @deploy.deploy_id
                end

                peer_obj = MU::MommaCat.findStray(
                  "Google",
                  "vpcs",
                  deploy_id: peer['vpc']['deploy_id'],
                  cloud_id: peer['vpc']['id'],
                  name: peer['vpc']['name'],
# XXX project flag tho
                  tag_key: tag_key,
                  tag_value: tag_value,
                  dummy_ok: true
                ).first
              end
if peer_obj.nil?
  MU.log "Failed VPC peer lookup on behalf of #{@cloud_id}", MU::WARN, details: peer
  pr = peer['vpc']['project'] || @project_id
  MU.log "all the VPCs I can see", MU::WARN, details: MU::Cloud::Google.compute(credentials: @config['credentials']).list_networks(pr)

end
              raise MuError, "No result looking for #{@mu_name}'s peer VPCs (#{peer['vpc']})" if peer_obj.nil?

              url = if peer_obj.cloudobj.url
                peer_obj.cloudobj.url
              elsif peer_obj.cloudobj.deploydata
                peer_obj.cloudobj.deploydata['self_link']
              else
                raise MuError, "Can't find the damn URL of my damn peer VPC #{peer['vpc']}"
              end
              cnxn_name = MU::Cloud::Google.nameStr(@mu_name+"-peer-"+count.to_s)
              peerreq = MU::Cloud::Google.compute(:NetworksAddPeeringRequest).new(
                name: cnxn_name,
                auto_create_routes: true,
                peer_network: url
              )

              begin
                MU.log "Peering #{@cloud_id} with #{peer_obj.cloudobj.cloud_id}, connection name is #{cnxn_name}", details: peerreq
                MU::Cloud::Google.compute(credentials: @config['credentials']).add_network_peering(
                  @project_id,
                  @cloud_id,
                  peerreq
                )
              rescue ::Google::Apis::ClientError => e
                if e.message.match(/operation in progress on the local or peer network/)
                  MU.log e.message, MU::DEBUG, details: peerreq
                  sleep 10
                  retry
                end
              end
              count += 1
            }
          end
          loadSubnets(use_cache: false)
        end

        # Locate and return cloud provider descriptors of this resource type
        # which match the provided parameters, or all visible resources if no
        # filters are specified. At minimum, implementations of +find+ must
        # honor +credentials+ and +cloud_id+ arguments. We may optionally
        # support other search methods, such as +tag_key+ and +tag_value+, or
        # cloud-specific arguments like +project+. See also {MU::MommaCat.findStray}.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching resources
        def self.find(**args)
          args = MU::Cloud::Google.findLocationArgs(args)

          resp = {}
          if args[:cloud_id] and args[:project]
            begin
              vpc = MU::Cloud::Google.compute(credentials: args[:credentials]).get_network(
              args[:project],
              args[:cloud_id].to_s.sub(/^.*?\/([^\/]+)$/, '\1')
            )
            resp[args[:cloud_id]] = vpc if !vpc.nil?
            rescue ::Google::Apis::ClientError
              MU.log "VPC #{args[:cloud_id]} in project #{args[:project]} does not exist, or I do not have permission to view it", MU::WARN
            end
          else # XXX other criteria
            vpcs = begin
              MU::Cloud::Google.compute(credentials: args[:credentials]).list_networks(
                args[:project]
              )
            rescue ::Google::Apis::ClientError => e
              raise e if !e.message.match(/^(?:notFound|forbidden): /)
            end

            if vpcs and vpcs.items
              vpcs.items.each { |v|
                resp[v.name] = v
              }
            end
          end

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
        # @param use_cache [Boolean]: If available, use saved deployment metadata to describe subnets, instead of querying the cloud API
        # @return [Array<Hash>]: A list of cloud provider identifiers of subnets associated with this VPC.
        def loadSubnets(use_cache: true)
          @subnetcachesemaphore.synchronize {
            return @subnets if use_cache and @subnets and @subnets.size > 0
          }
          network = cloud_desc

          if network.nil?
            MU.log "Unabled to load cloud description in #{self}", MU::ERR
            return nil
          end
          found = []

          if @deploy and @deploy.deployment and
             @deploy.deployment["vpcs"] and
             @deploy.deployment["vpcs"][@config['name']] and
             @deploy.deployment["vpcs"][@config['name']]["subnets"] and
             @deploy.deployment["vpcs"][@config['name']]["subnets"].size > 0
            @deploy.deployment["vpcs"][@config['name']]["subnets"].each { |desc|
              subnet = desc.clone
              subnet['mu_name'] = @config['scrub_mu_isms'] ? @cloud_id+subnet['name'].downcase : MU::Cloud::Google.nameStr(@deploy.getResourceName(subnet['name'], max_length: 61))
              subnet["cloud_id"] ||= desc['self_link'].gsub(/.*?\/([^\/]+)$/, '\1')
              subnet["cloud_id"] ||= subnet['mu_name']
              subnet['az'] ||= desc["region"].gsub(/.*?\/([^\/]+)$/, '\1')
              @subnets << MU::Cloud::Google::VPC::Subnet.new(self, subnet, precache_description: false)
            }
          else
            resp = MU::Cloud::Google.compute(credentials: @config['credentials']).list_subnetwork_usable(
              @project_id,
              filter: "network eq #{network.self_link}"
            )
            resp.items.each { |subnet|
              found << subnet
            }

            @subnetcachesemaphore.synchronize {
              @subnets ||= []
              ext_ids = @subnets.each.collect { |s| s.cloud_id }
              # If we're a plain old Mu resource, load our config and deployment
              # metadata. Like ya do.
              if !@config.nil? and @config.has_key?("subnets")
                @config['subnets'].each { |subnet|
#                  subnet['mu_name'] = @mu_name+"-"+subnet['name'] if !subnet.has_key?("mu_name")
                  subnet_name = @config['name']+subnet['name']
                  subnet['mu_name'] ||= @config['scrub_mu_isms'] ? @cloud_id+subnet_name.downcase : MU::Cloud::Google.nameStr(@deploy.getResourceName(subnet_name, max_length: 61))
                  subnet['region'] = @config['region']
                  found.each { |desc|
                    if desc.ip_cidr_range == subnet["ip_block"]
                      desc.subnetwork.match(/\/projects\/[^\/]+\/regions\/([^\/]+)\/subnetworks\/(.+)$/)
                      subnet['az'] = Regexp.last_match[1]
                      subnet['name'] ||= Regexp.last_match[2]
                      subnet["cloud_id"] = subnet['mu_name']
                      subnet["url"] = desc.subnetwork
                      break
                    end
                  }

                  if !ext_ids.include?(subnet["cloud_id"])
                    @subnets << MU::Cloud::Google::VPC::Subnet.new(self, subnet, precache_description: false)
                  end
                }

              # Of course we might be loading up a dummy subnet object from a
              # foreign or non-Mu-created VPC and subnet. So make something up.
              elsif !found.nil?
                found.each { |desc|
                  subnet = {}
                  desc.subnetwork.match(/\/projects\/[^\/]+\/regions\/([^\/]+)\/subnetworks\/(.+)$/)
                  subnet['az'] = Regexp.last_match[1]
                  subnet['name'] = Regexp.last_match[2]
                  subnet["cloud_id"] = subnet['name']
                  subnet["ip_block"] = desc.ip_cidr_range
                  subnet["url"] = desc.subnetwork
                  subnet['mu_name'] = @mu_name+"-"+subnet['name']
                  if !ext_ids.include?(subnet["cloud_id"])
                    @subnets << MU::Cloud::Google::VPC::Subnet.new(self, subnet, precache_description: false)
                  end
                }
              end
            }
          end

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
          if nat_name
            svr_obj = @deploy.findLitterMate(name: nat_name, type: "servers")
            return svr_obj if svr_obj
          end

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

          return nil if found.nil? || found.empty?

          if found.size == 1
            return found.first
          elsif found.size > 1
            found.each { |nat|
              next if !nat.cloud_desc
              # Try some cloud-specific criteria
              nat.cloud_desc.network_interfaces.each { |iface|
                if !nat_ip.nil?
                  return nat if iface.network_ip == nat_ip
                  if iface.access_configs
                    iface.access_configs.each { |public_iface|
                      return if public_iface.nat_ip == nat_ip
                    }
                  end
                end
                if iface.network == @url
                  # XXX Strictly speaking we could have different NATs in
                  # different subnets, so this can be wrong in corner cases.
                  return nat
                end
              }
            }
          end

          return nil
        end

        # Check for a subnet in this VPC matching one or more of the specified
        # criteria, and return it if found.
        def getSubnet(cloud_id: nil, name: nil, tag_key: nil, tag_value: nil, ip_block: nil, region: nil, subnet_mu_name: nil)
          if !cloud_id.nil? and cloud_id.match(/^https:\/\//)
            cloud_id.match(/\/regions\/([^\/]+)\/subnetworks\/([^\/]+)$/)
            region = Regexp.last_match[1]
            cloud_id = Regexp.last_match[2]
            cloud_id.gsub!(/.*?\//, "")
          end
          
          if name
            subnet_mu_name ||= @config['scrub_mu_isms'] ? @cloud_id+name.downcase : MU::Cloud::Google.nameStr(@deploy.getResourceName(name, max_length: 61))
          end

          MU.log "getSubnet(cloud_id: #{cloud_id}, name: #{name}, tag_key: #{tag_key}, tag_value: #{tag_value}, ip_block: #{ip_block}, region: #{region}, subnet_mu_name: #{subnet_mu_name})", MU::DEBUG, details: caller[0]
          subnets.each { |subnet|
            next if region and subnet.az != region
            if !cloud_id.nil? and !subnet.cloud_id.nil? and subnet.cloud_id.to_s == cloud_id.to_s
              return subnet
            elsif !name.nil? and !subnet.name.nil? and
                  subnet.name.downcase.to_s == name.downcase.to_s
              return subnet
            elsif !subnet_mu_name.nil? and !subnet.name.nil? and
                  subnet.name.downcase.to_s == subnet_mu_name.downcase.to_s
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
        # @return [Boolean]
        def self.haveRouteToInstance?(target_instance, credentials: nil)
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
        def self.can_route_to_master_peer?(source_subnets_key, target_subnets_key, instance_id)
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

        # Denote whether this resource implementation is experiment, ready for
        # testing, or ready for production use.
        def self.quality
          MU::Cloud::RELEASE
        end

        # Remove all VPC resources associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, credentials: nil, flags: {})
          flags["habitat"] ||= MU::Cloud::Google.defaultProject(credentials)
          return if !MU::Cloud.resourceClass("Google", "Habitat").isLive?(flags["habitat"], credentials)
          filter = %Q{(labels.mu-id = "#{MU.deploy_id.downcase}")}
          if !ignoremaster and MU.mu_public_ip
            filter += %Q{ AND (labels.mu-master-ip = "#{MU.mu_public_ip.gsub(/\./, "_")}")}
          end
          MU.log "Placeholder: Google VPC artifacts do not support labels, so ignoremaster cleanup flag has no effect", MU::DEBUG, details: filter

          purge_subnets(noop, project: flags['habitat'], credentials: credentials)
          ["route", "network"].each { |type|
# XXX tagged routes aren't showing up in list, and the networks that own them
# fail to delete silently
            retries = 0

            begin
              MU::Cloud::Google.compute(credentials: credentials).delete(
                type,
                flags["habitat"],
                nil,
                noop
              )
            rescue MU::MuError, ::Google::Apis::ClientError => e
              if retries < 5
                if type == "network"
                  MU.log e.message, MU::WARN
                  if e.message.match(/Failed to delete network (.+)/)
                    network_name = Regexp.last_match[1]
                    fwrules = MU::Cloud.resourceClass("Google", "FirewallRule").find(project: flags['habitat'], credentials: credentials)
                    fwrules.reject! { |_name, desc|
                      !desc.network.match(/.*?\/#{Regexp.quote(network_name)}$/)
                    }
                    fwrules.keys.each { |name|
                      MU.log "Attempting to delete firewall rule #{name} so that VPC #{network_name} can be removed", MU::NOTICE
                      MU::Cloud::Google.compute(credentials: credentials).delete_firewall(flags['habitat'], name)
                    }
                  end
                end
                sleep retries*3
                retries += 1
                retry
              else
                raise e
              end
            end
          }

        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        # XXX add flag to return the diff between @config and live cloud
        def toKitten(**_args)
          return nil if cloud_desc.name == "default" # parent project builds these
          bok = {
            "cloud" => "Google",
            "project" => @config['project'],
            "credentials" => @config['credentials']
          }
          MU::Cloud::Google.listRegions.size

          _schema, valid = MU::Config.loadResourceSchema("VPC", cloud: "Google")
          return [nil, nil] if !valid
#          pp schema
#          MU.log "++++++++++++++++++++++++++++++++"

          bok['name'] = cloud_desc.name.dup
          bok['cloud_id'] = cloud_desc.name.dup
          bok['create_standard_subnets'] = false

          if @subnets and @subnets.size > 0
            bok['subnets'] = []
            regions_seen = []
            names_seen = []
            @subnets.reject! { |x| x.cloud_desc.nil? }
            @subnets.map { |x| x.cloud_desc }.each { |s|
              subnet_name = s.name.dup
              names_seen << s.name.dup
              regions_seen << s.region
              bok['subnets'] << {
                "name" => subnet_name,
                "ip_block" => s.ip_cidr_range
              }
            }
            
            # If all of the subnets are named 'default' and there's one per
            # region, we're using GCP-generated subnets instead of explicitly
            # declared ones.
            if names_seen.uniq.size == 1 and names_seen.first == "default" and
               regions_seen.uniq.size == regions_seen.size and
               regions_seen.size >= (MU::Cloud::Google.listRegions.size * 0.8)
              bok.delete("subnets")
              bok['auto_create_subnetworks'] = true
            end
          end

          if cloud_desc.peerings and cloud_desc.peerings.size > 0
            bok['peers'] = []
            cloud_desc.peerings.each { |peer|
              peer.network.match(/projects\/([^\/]+?)\/[^\/]+?\/networks\/([^\/]+)$/)
              vpc_project = Regexp.last_match[1]
              vpc_name = Regexp.last_match[2]
              vpc_id = vpc_name.dup
              # Make sure the peer is something we have permission to look at
              peer_descs = MU::Cloud::Google::VPC.find(cloud_id: vpc_id, project: vpc_project)
              if peer_descs.nil? or peer_descs.empty?
                MU.log "VPC #{@cloud_id} peer #{vpc_id} #{vpc_project} is not accessible, will remove from peer list", MU::WARN
                next
              end
# XXX need to decide which of these parameters to use based on whether the peer is also in the mix of things being harvested, which is above this method's pay grade
              bok['peers'] << { "vpc" => MU::Config::Ref.get(
                id: vpc_id,
                name: vpc_name,
                cloud: "Google",
                habitat: MU::Config::Ref.get(
                  id: vpc_project,
                  cloud: "Google",
                  credentials: @credentials,
                  type: "habitats"
                ),
                credentials: @config['credentials'],
                type: "vpcs"
              ) }
            }
          end

# XXX need to grok VPN tunnels, priorities, and maybe preserve descriptions; make sure we know where next_hop_gateway  and next_hop_ip come from
          if @routes
            routes = []
            @routes.each { |r|
              next if r.next_hop_peering # these are auto-created
              route = {
                "destination_network" => r.dest_range
              }
              if r.next_hop_instance
                route["nat_host_id"] = r.next_hop_instance
              end
            }
            if routes.size > 0
              bok['route_tables'] = [
                {
                  "name" => "default",
                  "routes" => routes
                }
              ]
            end
          end

# XXX validate that we've at least touched every required attribute (maybe upstream?)
          bok
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config = nil)
          toplevel_required = []
          schema = {
            "regions" => {
              "type" => "array",
              "items" => MU::Config.region_primitive
            },
            "project" => {
              "type" => "string",
              "description" => "The project into which to deploy resources. This is shorthand for a +habitat+ key with a +name+ or +id+ set. The config parser will attempt to correctly resolve this."
            },
            "auto_create_subnetworks" => {
              "type" => "boolean",
              "default" => false,
              "description" => "Sets the +auto_create_subnetworks+ flag, which causes Google to generate a set of generic subnets, one per region. This effectively overrides Mu's +create_standard_subnets+ and any explicitly defined +subnets+."
            }
          }
          [toplevel_required, schema]
        end

        # If the VPC a config block was set to one that's been "split," try to
        # figure out which of the new VPCs we really want to be in. For use by
        # resource types that don't go in subnets, but do tie to VPCs.
        # @param vpc_block [Hash]
        # @param configurator [MU::Config]
        # @return [Hash]
        def self.pickVPC(vpc_block, my_config, my_type, configurator)
          _shortclass, cfg_name, cfg_plural, _classname = MU::Cloud.getResourceNames(my_type)
          return if vpc_block.nil?
          vpc_block['name'] ||= vpc_block['vpc_name']
          return if !vpc_block['name']

          vpcs = configurator.haveLitterMate?(
            nil,
            "vpcs",
            has_multiple: true
          )
          # drop all virtual vpcs that aren't real anymore
          vpcs.reject! { |v| v['virtual_name'] == v['name'] }
          # drop the ones that have nothing to do with us
          vpcs.reject! { |v| v['virtual_name'] != vpc_block['name'] }

          return vpc_block if vpcs.size == 0

          # see if one of this thing's siblings declared a subnet_pref we can
          # use to guess which one we should marry ourselves to
          configurator.kittens.values.each { |siblings|
            siblings.each { |sibling|
              next if !sibling['dependencies']
              sibling['dependencies'].each { |dep|
                if [cfg_name, cfg_plural].include?(dep['type']) and
                   dep['name'] == my_config['name']
                  vpcs.each { |v|
                    if sibling['vpc']['name'] == v['name']
                      vpc_block['name'] = v['name']
                      return vpc_block
                    end
                  }
                  if sibling['vpc']['subnet_pref']
                    vpcs.each { |v|
                      gateways = v['route_tables'].map { |rtb|
                        rtb['routes'].map { |r| r["gateway"] }
                      }.flatten.uniq
                      if ["public", "all_public"].include?(sibling['vpc']['subnet_pref']) and
                         gateways.include?("#INTERNET")
                        vpc_block['name'] = v['name']
                        return vpc_block
                      elsif ["private", "all_private"].include?(sibling['vpc']['subnet_pref']) and
                         !gateways.include?("#INTERNET")
                        vpc_block['name'] = v['name']
                        return vpc_block
                      end
                    }

                  end
                end
              }
            }
          }

          vpc_block
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::vpcs}, bare and unvalidated.
        # @param vpc [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(vpc, configurator)
          ok = true

          vpc['project'] ||= MU::Cloud::Google.defaultProject(vpc['credentials'])

          if vpc["project"] and !vpc["habitat"]
            vpc["habitat"] = MU::Cloud::Google.projectToRef(vpc["project"], config: configurator, credentials: vpc["credentials"])
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
              is_public = false
              t['routes'].each { |r|
                if !vpc["virtual_name"] and
                   !vpc["create_nat_gateway"] and
                   !vpc['bastion'] and
                   r["gateway"] == "#NAT"
                  r["gateway"] = "#DENY"
                end
                is_public = true if r["gateway"] == "#INTERNET"
              }
              count = 0
              vpc['regions'].each { |r|
                block = blocks.shift
                subnet = {
                  "availability_zone" => r,
                  "route_table" => t["name"],
                  "ip_block" => block.to_s,
                  "name" => "Subnet"+count.to_s+t["name"].capitalize
                }
                if is_public
                  subnet["map_public_ips"] = true
                  subnet["is_public"] = true
                end
                vpc["subnets"] << subnet
                count = count + 1
              }
            }
          end

          vpc['subnets'].each { |s|
            if !s['availability_zone']
              s['availability_zone'] = vpc['region']
              s['availability_zone'] ||= MU::Cloud::Google.myRegion(vpc['credentials'])
            end
          }

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
                "cloud" => "Google",
                "credentials" => vpc['credentials'],
                "virtual_name" => vpc['name'],
                "ip_block" => blocks.shift,
                "route_tables" => [tbl],
                "parent_block" => vpc['ip_block'],
                "subnets" => [],
                "peers" => vpc['peers']
              }
              MU.log "Splitting VPC #{newvpc['name']} off from #{vpc['name']}", MU::NOTICE

              vpc.each_pair { |key, val|
                next if ["name", "route_tables", "subnets", "ip_block"].include?(key)
                newvpc[key] = val
              }
              if vpc["bastion"] and
                 !tbl["routes"].map { |r| r["gateway"] }.include?("#INTERNET")
                newvpc["bastion"] = vpc["bastion"]
                vpc.delete("bastion")
              end
              newvpc['peers'] ||= []
# Add the peer connections we're generating, in addition 
              peernames.each { |peer|
                if peer != newvpc['name']
                  newvpc['peers'] << { "vpc" => { "vpc_name" => peer } }
                end
              }
              newvpc['peers'].reject! { |p|
                p.values.first['vpc_name'] == newvpc['name'] or p.values.first['vpc_name'] == vpc['name']
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
            if has_nat and !has_deny and !vpc['bastion']
              vpc['route_tables'].first["routes"] << {
                "gateway"=>"#DENY",
                "destination_network"=>"0.0.0.0/0"
              }
            end

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
                # theoretically our upstream validation should have inserted
                # a NAT/bastion host we can use
                nat = if vpc['virtual_name']
                  configurator.haveLitterMate?(vpc['virtual_name']+"-natstion", "servers")
                else
                  configurator.haveLitterMate?(vpc['name']+"-natstion", "servers")
                end

                if !nat
                  MU.log "Google VPC #{vpc['name']} declared a #NAT route, but I don't see an upstream NAT host I can use. Do I even have public subnets?", MU::ERR
                  ok = false
                else
                  route['nat_host_name'] = nat['name']
                  route['priority'] = 100
                  MU::Config.addDependency(vpc, nat['name'], "server", their_phase: "groom", my_phase: "groom")
                  vpc["bastion"] = MU::Config::Ref.get(
                    name: nat['name'],
                    cloud: vpc['cloud'],
                    credentials: vpc['credentials'],
                    type: "servers"
                  )

                end
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

        # Looks at existing subnets, and attempts to find the next available
        # IP block that's roughly similar to the ones we already have. This
        # checks against secondary IP ranges, as well as each subnet's primary
        # CIDR block.
        # @param exclude [Array<String>]: One or more CIDRs to treat as unavailable, in addition to those allocated to existing subnets
        # @return [String]
        def getUnusedAddressBlock(exclude: [], max_bits: 28)
          used_ranges = exclude.map { |cidr| NetAddr::IPv4Net.parse(cidr) }
          subnets.each { |s|
            used_ranges << NetAddr::IPv4Net.parse(s.cloud_desc.ip_cidr_range)
            if s.cloud_desc.secondary_ip_ranges
              used_ranges.concat(s.cloud_desc.secondary_ip_ranges.map { |r| NetAddr::IPv4Net.parse(r.ip_cidr_range) })
            end
          }
# XXX sort used_ranges
          candidate = used_ranges.first.next_sib

          begin
            if candidate.netmask.prefix_len > max_bits
              candidate = candidate.resize(max_bits)
            end
            try_again = false
            used_ranges.each { |cidr|
              if !cidr.rel(candidate).nil?
                candidate = candidate.next_sib
                try_again = true
                break
              end
            }
            try_again = false if candidate.nil?
          end while try_again

          candidate.to_s
        end

        private

        def self.genStandardSubnetACLs(vpc_cidr, vpc_name, configurator, project, _publicroute = true, credentials: nil)
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
        private_class_method :genStandardSubnetACLs

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

              routeobj = ::Google::Apis::ComputeV1::Route.new(
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
              @project_id,
              filter: "network eq #{network}"
            )

            if !resp.nil? and !resp.items.nil?
              resp.items.each { |r|
                next if r.next_hop_gateway.nil? or !r.next_hop_gateway.match(/\/global\/gateways\/default-internet-gateway$/)
                MU.log "Removing standard route #{r.name} per our #DENY entry"
                MU::Cloud::Google.compute(credentials: @config['credentials']).delete_route(@project_id, r.name)
              }
            end
          elsif route['gateway'] == "#INTERNET"
            routeobj = ::Google::Apis::ComputeV1::Route.new(
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
              MU::Cloud::Google.compute(credentials: @config['credentials']).get_route(@project_id, routename)
            rescue ::Google::Apis::ClientError, MU::MuError => e
              if e.message.match(/notFound/)
                MU.log "Creating route #{routename} in project #{@project_id}", details: routeobj
                MU::Cloud::Google.compute(credentials: @config['credentials']).insert_route(@project_id, routeobj)
              else
                # TODO can't update GCP routes, would have to delete and re-create
              end
            end
          end
        end

        # Remove all subnets associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param _tagfilters [Array<Hash>]: Labels to filter against when search for resources to purge
        # @param regions [Array<String>]: The cloud provider regions to check
        # @return [void]
        def self.purge_subnets(noop = false, _tagfilters = [{name: "tag:MU-ID", values: [MU.deploy_id]}], regions: MU::Cloud::Google.listRegions, project: nil, credentials: nil)
          project ||= MU::Cloud::Google.defaultProject(credentials)
          parent_thread_id = Thread.current.object_id
          regionthreads = []
          regions.each { |r|
            regionthreads << Thread.new {
              MU.dupGlobals(parent_thread_id)
              begin
                MU::Cloud::Google.compute(credentials: credentials).delete(
                  "subnetwork",
                  project,
                  r,
                  noop
                )
              rescue MU::Cloud::MuDefunctHabitat
                Thread.exit
              end
            }
          }
          regionthreads.each do |t|
            t.join
          end
        end
        private_class_method :purge_subnets

        # Subnets are almost a first-class resource. So let's kinda sorta treat
        # them like one. This should only be invoked on objects that already
        # exists in the cloud layer.
        class Subnet < MU::Cloud::Google::VPC

          attr_reader :cloud_id
          attr_reader :ip_block
          attr_reader :mu_name
          attr_reader :name
          attr_reader :cloud_desc_cache
          attr_reader :az

          # @param parent [MU::Cloud::Google::VPC]: The parent VPC of this subnet.
          # @param config [Hash<String>]:
          def initialize(parent, config, precache_description: true)
            @parent = parent
            @config = MU::Config.manxify(config)
            @cloud_id = config['cloud_id']
            @url = config['url']
            @mu_name = config['mu_name']
            @name = config['name']
            @deploydata = config # This is a dummy for the sake of describe()
            @az = config['az']
            @ip_block = config['ip_block']
            @cloud_desc_cache = nil
            cloud_desc if precache_description
          end

          # Return the cloud identifier for the default route of this subnet.
          def defaultRoute
          end

          # Describe this VPC Subnet
          # @return [Hash]
          def notify
            MU.structToHash(cloud_desc, stringify_keys: true)
          end

          # Return the +self_link+ to this subnet
          def url
            cloud_desc if !@url
            @url
          end

          @cloud_desc_cache = nil
          # Describe this VPC Subnet from the cloud platform's perspective
          # @return [Google::Apis::Core::Hashable]
          def cloud_desc(use_cache: true)
            return @cloud_desc_cache if @cloud_desc_cache and use_cache

            begin
              @cloud_desc_cache = MU::Cloud::Google.compute(credentials: @parent.config['credentials']).get_subnetwork(@parent.habitat_id, @az, @cloud_id)
            rescue ::Google::Apis::ClientError => e
              if e.message.match(/notFound: /)
                MU.log "Failed to fetch cloud description for Google subnet #{@cloud_id}", MU::WARN, details: { "project" => @parent.habitat_id, "region" => @az, "name" => @cloud_id }
                return nil
              else
                raise e
              end
            end
            @url ||= @cloud_desc_cache.self_link
            @cloud_desc_cache
          end

          # Is this subnet privately-routable only, or public?
          # @return [Boolean]
          def private?
            @parent.cloud_desc 
            @parent.routes.map { |r|
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
