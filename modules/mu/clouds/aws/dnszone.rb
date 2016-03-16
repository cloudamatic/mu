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
      class DNSZone < MU::Cloud::DNSZone

        @config = nil
        attr_reader :mu_name
        attr_reader :cloud_id
        attr_reader :config

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::dnszones}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          unless @mu_name
            @mu_name = mu_name ? mu_name : @deploy.getResourceName(@config["name"])
          end

          MU.setVar("curRegion", @config['region']) if !@config['region'].nil?
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          ext_zone = MU::Cloud::DNSZone.find(cloud_id: @config['name']).values.first
          @config["create_zone"] =
            if ext_zone
              false
            else
              true
            end

          if @config["create_zone"]
            params = {
                :name => @config['name'],
                :hosted_zone_config => {
                    :comment => MU.deploy_id
                },
                :caller_reference => @deploy.getResourceName(@config['name'])
            }

            # Private zones have their lookup restricted by VPC
            add_vpcs = []
            if @config['private']
              if @config['all_account_vpcs']
                # If we've been told to make this domain available account-wide, do so
                MU::Cloud::AWS.listRegions.each { |region|
                  known_vpcs = MU::Cloud::AWS.ec2(region).describe_vpcs.vpcs

                  MU.log "Enumerating VPCs in #{region}", MU::DEBUG, details: known_vpcs

                  known_vpcs.each { |vpc|
                    add_vpcs << { :vpc_id => vpc.vpc_id, :region => region }
                  }
                }
              else
                # Or if we were given a list of VPCs add them
                raise MuError, "DNS Zone #{@config['name']} is flagged as private, you must either provide a VPC, or set 'all_account_vpcs' to true" if @config['vpcs'].nil? || @config['vpcs'].empty?
                @config['vpcs'].each { |vpc|
                  add_vpcs << { :vpc_id => vpc['vpc_id'], :region => vpc['region'] }
                }
              end

              raise MuError, "DNS Zone #{@config['name']} is flagged as private, but I can't find any VPCs in which to put it" if add_vpcs.empty?

              # We can only specify one VPC when creating a private zone. We'll add the rest later
              params[:vpc] = {
                :vpc_region => add_vpcs.first[:region],
                :vpc_id => add_vpcs.first[:vpc_id]
              }
            end

            MU.log "Creating DNS Zone '#{@config['name']}'", details: params

            resp = MU::Cloud::AWS.route53.create_hosted_zone(params)
            id = resp.hosted_zone.id
            @config['zone_id'] = id

            begin
              resp = MU::Cloud::AWS.route53.get_hosted_zone(id: id)
              sleep 10
            end while resp.nil? or resp.size == 0

            if !add_vpcs.empty?
              add_vpcs.each { |vpc|
                if vpc[:vpc_id] != params[:vpc][:vpc_id]
                  MU.log "Associating VPC #{vpc[:vpc_id]} in #{vpc[:region]} with DNS Zone #{@config['name']}", MU::DEBUG
                  begin
                    MU::Cloud::AWS.route53.associate_vpc_with_hosted_zone(
                      hosted_zone_id: id,
                      vpc: {
                        :vpc_region => vpc[:region],
                        :vpc_id => vpc[:vpc_id]
                      }
                    )
                  rescue Aws::Route53::Errors::InvalidVPCId => e
                    MU.log "Unable to associate #{vpc[:vpc_id]} in #{vpc[:region]} with DNS Zone #{@config['name']}: #{e.inspect}", MU::WARN
                  end
                end
              }
            end
          end

          @config['records'].each { |dnsrec|
            dnsrec['name'] = "#{dnsrec['name']}.#{MU.environment.downcase}" if dnsrec["append_environment_name"] && !dnsrec['name'].match(/\.#{MU.environment.downcase}$/)

            if dnsrec.has_key?('mu_type')
              dnsrec['target'] =
                if dnsrec['mu_type'] == "loadbalancer"
                  if @dependencies.has_key?(dnsrec['mu_type']) && dnsrec['deploy_id'].nil?
                    @dependencies['loadbalancer'][dnsrec['target']].deploydata['dns']
                  elsif dnsrec['deploy_id']
                    found = MU::MommaCat.findStray("AWS", "loadbalancer", deploy_id: dnsrec["deploy_id"], mu_name: dnsrec["target"], region: @config["region"])
                    raise MuError, "Couldn't find #{dnsrec['mu_type']} #{dnsrec["target"]}" if found.nil? || found.empty?
                    found.first.deploydata['dns']
                  end
                elsif dnsrec['mu_type'] == "server"
                  if @dependencies.has_key?(dnsrec['mu_type']) && dnsrec['deploy_id'].nil?
                    MU.log "dnsrec['target'] #{dnsrec['target']}"
                    deploydata = @dependencies['server'][dnsrec['target']].deploydata
                  elsif dnsrec['deploy_id']
                    found = MU::MommaCat.findStray("AWS", "server", deploy_id: dnsrec["deploy_id"], mu_name: dnsrec["target"], region: @config["region"])
                    raise MuError, "Couldn't find #{dnsrec['mu_type']} #{dnsrec["target"]}" if found.nil? || found.empty?
                    deploydata = found.first.deploydata
                  end

                  public = true
                  if dnsrec.has_key?("target_type")
                    public = dnsrec["target_type"] == "private" ? false : true
                  end

                  if dnsrec["type"] == "CNAME"
                    if public
                      # Make sure we have a public canonical name to register. Use the private one if we don't
                      deploydata['public_dns_name'].empty? ? deploydata['private_dns_name'] : deploydata['public_dns_name']
                    else
                      # If we specifically requested to register the private canonical name lets use that
                      deploydata['private_dns_name']
                    end
                  elsif dnsrec["type"] == "A"
                    if public
                      # Make sure we have a public IP address to register. Use the private one if we don't
                      deploydata['public_ip_address'] ? deploydata['public_ip_address'] : deploydata['private_ip_address']
                    else
                      # If we specifically requested to register the private IP lets use that
                      deploydata['private_ip_address']
                    end
                  end
                elsif dnsrec['mu_type'] == "database"
                  if @dependencies.has_key?(dnsrec['mu_type']) && dnsrec['deploy_id'].nil?
                    @dependencies[dnsrec['mu_type']][dnsrec['target']].deploydata['endpoint']
                  elsif dnsrec['deploy_id']
                    found = MU::MommaCat.findStray("AWS", "database", deploy_id: dnsrec["deploy_id"], mu_name: dnsrec["target"], region: @config["region"])
                    raise MuError, "Couldn't find #{dnsrec['mu_type']} #{dnsrec["target"]}" if found.nil? || found.empty?
                    found.first.deploydata['endpoint']
                  end
                end
              end

            dnsrec["zone"] = {"name" => @config['name']}
          }

          MU::Cloud::AWS::DNSZone.createRecordsFromConfig(@config['records'])
          return resp.hosted_zone if @config["create_zone"]
        end

        # Wrapper for {MU::Cloud::AWS::DNSZone.manageRecord}. Spawns threads to create all
        # requested records in background and returns immediately.
        # @param cfg [Array]: An array of parsed {MU::Config::BasketofKittens::dnszones::records} objects.
        # @param target [String]: Optional target for the records to be created. Overrides targets embedded in cfg records.
        def self.createRecordsFromConfig(cfg, target: nil)
          return if cfg.nil?
          record_threads = []

          cfg.each { |record|
            zone = nil
            if record['zone'].has_key?("id")
              zone = MU::Cloud::DNSZone.find(cloud_id: record['zone']['id']).values.first
            else
              zone = MU::Cloud::DNSZone.find(cloud_id: record['zone']['name']).values.first
            end

            raise MuError, "Failed to locate Route53 DNS Zone for domain #{record['zone']['name']}" if zone.nil?

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
              caller_reference: @deploy.getResourceName(cfg['method']+"-"+Time.now.to_i.to_s),
              health_check_config: check
          ).health_check.id

          # Currently the only thing we can tag in Route 53... is health checks.
          tags = []
          MU::MommaCat.listStandardTags.each_pair { |name, value|
            tags << {key: name, value: value}
          }
          tags << {key: "Name", value: MU.deploy_id+"-"+target.upcase}

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
                comment: MU.deploy_id
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
                  comment: MU.deploy_id
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
          zone = MU::Cloud::DNSZone.find(cloud_id: id).values.first
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
                rrsets << {:value => target}
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
            base_rrset[:set_identifier] = MU.deploy_id+"-failover-"+failover.downcase
          elsif !weight.nil?
            base_rrset[:weight] = weight
            base_rrset[:set_identifier] = MU.deploy_id+"-weighted-"+weight.to_s
          elsif !location.nil?
            loc_arg = Hash.new
            location.each_pair { |key, val|
              sym = key.to_sym
              loc_arg[sym] = val
            }
            base_rrset[:geo_location] = loc_arg
            base_rrset[:set_identifier] = MU.deploy_id+"-location-"+location.values.join("-")
          elsif !region.nil?
            base_rrset[:region] = region
            base_rrset[:set_identifier] = MU.deploy_id+"-latency-"+region
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
        def self.genericMuDNSEntry(name: name, target: target, cloudclass: cloudclass, noop: false, delete: false, sync_wait: true)
          return nil if name.nil? or target.nil? or cloudclass.nil?
          mu_zone = MU::Cloud::DNSZone.find(cloud_id: "platform-mu").values.first
          raise MuError, "Couldn't isolate platform-mu DNS zone" if mu_zone.nil?

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
              elsif !e.inspect.match(/(it|name) already exists/)
                raise MuError, "Problem managing entry for #{dns_name} -> #{target}: #{e.inspect}"
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
        def notify
          if @config["create_zone"]
# # XXX this wants generalization
            # if !@deploy.deployment[MU::Cloud::DNSZone.cfg_plural].nil? and !@deploy.deployment[MU::Cloud::DNSZone.cfg_plural][name].nil?
              # deploydata = @deploy.deployment[MU::Cloud::DNSZone.cfg_plural][name].dup
            # else
              # deploydata = Hash.new
            # end

            # resp = MU::Cloud::AWS.route53.get_hosted_zone(
                # id: @config['zone_id']
            # )
            # deploydata.merge!(MU.structToHash(resp.hosted_zone))
            # deploydata['vpcs'] = @config['vpcs'] if !@config['vpcs'].nil?
            # deploydata["region"] = @config['region'] if !@config['region'].nil?
            # @deploy.notify(MU::Cloud::DNSZone.cfg_plural, mu_name, deploydata)
            # return deploydata

            resp = MU::Cloud::AWS.route53.get_hosted_zone(id: @config['zone_id'])
            vpcs = []
            hosted_zone_vpcs = resp.vp_cs
            if !hosted_zone_vpcs.empty?
              hosted_zone_vpcs.each{ |vpc|
                vpcs << vpc.to_h
              }
            end

            {
              "name" => resp.hosted_zone.name,
              "id" => resp.hosted_zone.id,
              "private" => resp.hosted_zone.config.private_zone,
              "vpcs" => vpcs,
            }

          else
            # We should probably return the records we created
            {}
          end
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
              muid_match = true if tag.key == "MU-ID" and tag.value == MU.deploy_id
              mumaster_match = true if tag.key == "MU-MASTER-IP" and tag.value == MU.mu_public_ip
            }
            if muid_match and mumaster_match
              MU.log "Removing health check #{check.id}"
              MU::Cloud::AWS.route53(region).delete_health_check(health_check_id: check.id) if !noop
            end
          }
          zones = MU::Cloud::DNSZone.find(deploy_id: MU.deploy_id, region: region)
          zones.each_pair { |id, zone|
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
              rescue Aws::Route53::Errors::PriorRequestNotComplete
                MU.log "Still waiting for all records in DNS Zone '#{zone.name}' (#{zone.id}) to delete", MU::WARN
                sleep 20
                retry
              rescue Aws::Route53::Errors::InvalidChangeBatch
                # Just skip this
              rescue Aws::Route53::Errors::NoSuchHostedZone => e
                MU.log "DNS Zone '#{zone.name}' (#{zone.id}) disappeared before I could remove it", MU::WARN, details: e.inspect
              rescue Aws::Route53::Errors::HostedZoneNotEmpty => e
                raise MuError, e.inspect
              end
            end
          }

          # Lets try cleaning MU DNS records in all zones.
          begin 
            MU::Cloud::AWS.route53(region).list_hosted_zones.hosted_zones.each { |zone|
              zone_rrsets = []
              rrsets = MU::Cloud::AWS.route53(region).list_resource_record_sets(hosted_zone_id: zone.id)
              rrsets.resource_record_sets.each { |record|
                zone_rrsets << record
              }

              # AWS API returns a maximum of 100 results. DNS zones are likely to have more than 100 records, lets page and make sure we grab all records in a given zone
              while rrsets.next_record_name && rrsets.next_record_type
                rrsets = MU::Cloud::AWS.route53(region).list_resource_record_sets(hosted_zone_id: zone.id, start_record_name: rrsets.next_record_name, start_record_type: rrsets.next_record_type)
                rrsets.resource_record_sets.each { |record|
                  zone_rrsets << record
                }
              end

              # TO DO: if we have more than one record it will retry the deletion multiple times and will throw Aws::Route53::Errors::InvalidChangeBatch / record not found even though the record was deleted
              zone_rrsets.each { |record|
                if record.name.match(MU.deploy_id.downcase)
                  resource_records = []
                  record.resource_records.each { |rrecord|
                    resource_records << rrecord.value
                  }

                  MU::Cloud::AWS::DNSZone.manageRecord(zone.id, record.name, record.type, targets: resource_records, ttl: record.ttl, sync_wait: false, delete: true) if !noop
                end
              }
            }
          rescue Aws::Route53::Errors::NoSuchHostedZone
            MU.log "DNS Zone '#{zone.name}' #{zone.id} disappeared while was looking at", MU::WARN
          end
        end

        # Locate an existing DNSZone or DNSZones and return an array containing matching AWS resource descriptors for those that match.
        # @param cloud_id [String]: The cloud provider's identifier for this resource. Can also use the domain name, we'll check for both.
        # @param region [String]: The cloud provider region
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching DNSZones
        def self.find(cloud_id: nil, deploy_id: MU.deploy_id, region: MU.curRegion)
          matches = {}

          resp = MU::Cloud::AWS.route53(region).list_hosted_zones(
              max_items: 100
          )

          resp.hosted_zones.each { |zone|
            if !cloud_id.nil? and !cloud_id.empty?
              if zone.id == cloud_id
                begin 
                  matches[zone.id] = MU::Cloud::AWS.route53(region).get_hosted_zone(id: zone.id).hosted_zone
                rescue Aws::Route53::Errors::NoSuchHostedZone
                  MU.log "Hosted zone #{zone.id} doesn't exist"
                end
              elsif zone.name == cloud_id or zone.name == cloud_id+"."
                begin 
                  matches[zone.id] = MU::Cloud::AWS.route53(region).get_hosted_zone(id: zone.id).hosted_zone
                rescue Aws::Route53::Errors::NoSuchHostedZone
                  MU.log "Hosted zone #{zone.id} doesn't exist"
                end
              end
            end
            if !deploy_id.nil? and !deploy_id.empty? and zone.config.comment == deploy_id
              begin 
                matches[zone.id] = MU::Cloud::AWS.route53(region).get_hosted_zone(id: zone.id).hosted_zone
              rescue Aws::Route53::Errors::NoSuchHostedZone
                MU.log "Hosted zone #{zone.id} doesn't exist"
              end
            end
          }

          return matches
        end
      end
    end
  end
end
