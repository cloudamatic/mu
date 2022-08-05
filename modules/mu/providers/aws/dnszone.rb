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

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config["name"])

          MU.setVar("curRegion", @region) if !@region.nil?
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
                :comment => @deploy.deploy_id
              },
              :caller_reference => @deploy.getResourceName(@config['name'])
            }

            # Private zones have their lookup restricted by VPC
            add_vpcs = []
            if @config['private']
              if @config['all_account_vpcs']
                # If we've been told to make this domain available account-wide, do so
                MU::Cloud::AWS.listRegions(@config['us_only']).each { |region|
                  known_vpcs = MU::Cloud::AWS.ec2(region: region).describe_vpcs.vpcs

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

          @config['records'] = [] if !@config['records']
          @config['records'].each { |dnsrec|
            dnsrec['name'] = "#{dnsrec['name']}.#{MU.environment.downcase}" if dnsrec["append_environment_name"] && !dnsrec['name'].match(/\.#{MU.environment.downcase}$/)

            if dnsrec.has_key?('mu_type')
              dnsrec['target'] =
                if dnsrec['mu_type'] == "loadbalancer"
                  if @dependencies.has_key?('loadbalancer') and @dependencies['loadbalancer'].has_key?(dnsrec['target']) and !@dependencies['loadbalancer'][dnsrec['target']].cloudobj.nil? and dnsrec['deploy_id'].nil?
                    @dependencies['loadbalancer'][dnsrec['target']].cloudobj.notify['dns']
                  elsif dnsrec['deploy_id']
                    found = MU::MommaCat.findStray("AWS", "loadbalancer", deploy_id: dnsrec["deploy_id"], mu_name: dnsrec["target"], region: @region)
                    raise MuError, "Couldn't find #{dnsrec['mu_type']} #{dnsrec["target"]}" if found.nil? || found.empty?
                    found.first.deploydata['dns']
                  end
                elsif dnsrec['mu_type'] == "server"
                  if @dependencies.has_key?(dnsrec['mu_type']) && dnsrec['deploy_id'].nil?
                    MU.log "dnsrec['target'] #{dnsrec['target']}"
                    deploydata = @dependencies['server'][dnsrec['target']].deploydata
                  elsif dnsrec['deploy_id']
                    found = MU::MommaCat.findStray("AWS", "server", deploy_id: dnsrec["deploy_id"], mu_name: dnsrec["target"], region: @region)
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
                    found = MU::MommaCat.findStray("AWS", "database", deploy_id: dnsrec["deploy_id"], mu_name: dnsrec["target"], region: @region)
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

        # Resolve a record entry (as in {MU::Config::BasketofKittens::dnszones::records} to the full DNS name we would assign it
        def self.recordToName(record)
          shortname = record['name']
          shortname += ".#{MU.environment.downcase}" if record["append_environment_name"]

          zone = if record['zone'].has_key?("id")
            MU::Cloud::DNSZone.find(cloud_id: record['zone']['id']).values.first
          else
            MU::Cloud::DNSZone.find(cloud_id: record['zone']['name']).values.first
          end

          if zone.nil?
            raise MuError.new "Failed to locate Route53 DNS Zone", details: record['zone']
          end

          shortname+"."+zone.name.sub(/\.$/, '')
        end

        # Wrapper for {MU::Cloud::AWS::DNSZone.manageRecord}. Spawns threads to create all
        # requested records in background and returns immediately.
        # @param cfg [Array]: An array of parsed {MU::Config::BasketofKittens::dnszones::records} objects.
        # @param target [String]: Optional target for the records to be created. Overrides targets embedded in cfg records.
        def self.createRecordsFromConfig(cfg, target: nil, name_only: false)
          return if cfg.nil?
          record_threads = []

          cfg.each { |record|
            record['name'] = "#{record['name']}.#{MU.environment.downcase}" if record["append_environment_name"] && !record['name'].match(/\.#{MU.environment.downcase}$/)
            zone = nil
            if record['zone'].has_key?("id")
              zone = MU::Cloud::DNSZone.find(cloud_id: record['zone']['id']).values.first
            else
              zone = MU::Cloud::DNSZone.find(cloud_id: record['zone']['name']).values.first
            end


            healthcheck_id = nil
            record['target'] = target if !target.nil?
            child_check_ids = []
            if record.has_key?('healthchecks')
              record['healthchecks'].each { |check|
                child_check_ids << MU::Cloud::AWS::DNSZone.createHealthCheck(check, record['target']) if check['type'] == "secondary"
              }

              record['healthchecks'].each { |check|
                if check['type'] == "primary"
                  check["health_check_ids"] = child_check_ids if !check.has_key?("health_check_ids") || check['health_check_ids'].empty?
                  healthcheck_id = MU::Cloud::AWS::DNSZone.createHealthCheck(check, record['target'])
                  break
                end
              }
            end

            # parent_thread_id seems to be nil sometimes, try to make sure we don't fail
            # There has got to be a better way to deal with this than this
            parent_thread_id = Thread.current.object_id
            while parent_thread_id.nil?
              parent_thread_id = Thread.current.object_id
              sleep 3
            end

            record_threads << Thread.new {
              MU.dupGlobals(parent_thread_id)
              MU::Cloud::AWS::DNSZone.manageRecord(
                zone.id,
                record['name'],
                record['type'],
                targets: [record['target']],
                ttl: record['ttl'],
                failover: record['failover'],
                healthcheck: healthcheck_id,
                weight: record['weight'],
                overwrite: record['override_existing'],
                location: record['geo_location'],
                region: record['region'],
                alias_zone: record['alias_zone'],
                sync_wait: false
              )
            }
          }

          record_threads.each { |t|
            t.join
          }
        end

        # Create a Route53 health check.
        # @param cfg [Hash]: Parsed hash of {MU::Config::BasketofKittens::dnszones::records::healthchecks}
        # @param target [String]: The IP address of FQDN of the target resource to check.
        def self.createHealthCheck(cfg, target)
          check = {
            type: cfg['method'],
            inverted: cfg['inverted']
          }
          
          if cfg['method'] == "CALCULATED"
            check[:health_threshold] = cfg['health_threshold'] if cfg.has_key?('health_threshold')
            check[:child_health_checks] = cfg['health_check_ids'] if cfg.has_key?('health_check_ids')
          elsif cfg['method'] == "CLOUDWATCH_METRIC"
            check[:insufficient_data] = cfg['insufficient_data'] if cfg.has_key?('insufficient_data')
            check[:alarm_identifier] = {
              region: cfg['alarm_region'],
              name: cfg['alarm_name']
            }
          else
            check[:resource_path] = cfg['path'] if cfg.has_key?('path')
            check[:search_string] = cfg['search_string'] if cfg.has_key?('search_string')
            check[:port] = cfg['port'] if cfg.has_key?('port')
            check[:enable_sni] = cfg['enable_sni'] if cfg.has_key?('enable_sni')
            check[:regions] = cfg['regions'] if cfg.has_key?('regions')
            check[:measure_latency] = cfg['latency'] if cfg.has_key?('latency')
            check[:check_interval] = cfg['check_interval']
            check[:failure_threshold] = cfg['failure_threshold']

            if target.match(/^\d+\.\d+\.\d+\.\d+$/)
              check[:ip_address] = target
            else
              check[:fully_qualified_domain_name] = target
            end
          end

          MU.log "Creating health check for #{cfg['name']}", details: check
          id = MU::Cloud::AWS.route53.create_health_check(
              caller_reference: "#{MU.deploy_id}-#{cfg['method']}-#{cfg['name']}-#{Time.now.to_i.to_s}",
              health_check_config: check
          ).health_check.id

          # Currently the only thing we can tag in Route 53... is health checks.
          tags = []
          MU::MommaCat.listStandardTags.each_pair { |name, value|
            tags << {key: name, value: value}
          }

          tags << {key: "Name", value: "#{MU.deploy_id}-#{cfg['name']}".upcase}

          if cfg['optional_tags']
            MU::MommaCat.listOptionalTags.each_pair { |name, value|
              tags << {key: name, value: value}
            }
          end

          if cfg['tags']
            cfg['tags'].each { |tag|
              tags << {key: tag['key'], value: tag['value']}
            }
          end

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
        def self.toggleVPCAccess(id: nil, vpc_id: nil, region: MU.curRegion, remove: false, credentials: nil)

          if !remove
            MU.log "Granting VPC #{vpc_id} access to zone #{id}"
            MU::Cloud::AWS.route53(credentials: credentials).associate_vpc_with_hosted_zone(
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
              MU::Cloud::AWS.route53(credentials: credentials).disassociate_vpc_from_hosted_zone(
                  hosted_zone_id: id,
                  vpc: {
                      :vpc_id => vpc_id,
                      :vpc_region => region
                  },
                  comment: MU.deploy_id
              )
            rescue Aws::Route53::Errors::LastVPCAssociation => e
              MU.log e.inspect, MU::WARN
            rescue Aws::Route53::Errors::VPCAssociationNotFound
              MU.log "VPC #{vpc_id} access to zone #{id} already revoked", MU::NOTICE
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
        # @param healthcheck [String]: A Route53 healthcheck identifier for use with failover. Typically created by {MU::Config::BasketofKittens::dnszones::records::healthchecks}.
        # @param region [String]: An Amazon Web Services region for use with latency-based routing. See also {MU::Config::BasketofKittens::dnszones::records}.
        # @param weight [Integer]: A weight value used for weighted routing, used to determine proportion of traffic with other matching weighted records. See also {MU::Config::BasketofKittens::dnszones::records}.
        # @param location [Hash<String>]: A parsed Hash of {MU::Config::BasketofKittens::dnszones::records::geo_location}.
        # @param set_identifier [String]: A unique string to differentiate otherwise-similar records. Normally auto-generated, should not need to specify.
        # @param alias_zone [String]: Zone ID of the target's hosted zone, when creating an alias (type R53ALIAS)
        def self.manageRecord(id, name, type, targets: nil,
            ttl: 7200, delete: false, sync_wait: true, failover: nil,
            healthcheck: nil, region: nil, weight: nil, overwrite: true,
            location: nil, set_identifier: nil, alias_zone: nil, noop: false)

          MU.setVar("curRegion", region) if !region.nil?
          zone = MU::Cloud::DNSZone.find(cloud_id: id).values.first
          raise MuError, "Attempting to add record to nonexistent DNS zone #{id}" if zone.nil?
          name = name + "." + zone.name if !name.match(/(^|\.)#{zone.name}$/)

          action = "CREATE"
          action = "UPSERT" if overwrite
          action = "DELETE" if delete

          record_sets = MU::Cloud::AWS.route53.list_resource_record_sets(
            hosted_zone_id: id,
            start_record_name: name
          ).resource_record_sets if delete

          if type == "R53ALIAS"
            target_zone = id
            target_name = targets[0].downcase
            target_name.chomp!(".")

            if !alias_zone.nil?
              target_zone = "/hostedzone/"+alias_zone if !alias_zone.match(/^\/hostedzone\//)
            else
              MU::Cloud::AWS.listRegions.each { |r|
                MU::Cloud::AWS.elb(region: r).describe_load_balancers.load_balancer_descriptions.each { |elb|
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
              name: name,
              type: "A",
              alias_target: {
                hosted_zone_id: target_zone,
                dns_name: targets[0],
                evaluate_target_health: true
              }
            }
          else
            rrsets = []
            if delete
              record_sets.each { |r|
                if r.name == name and r.type == type
                  rrsets = MU.structToHash(r.resource_records)
                end
              }
            end

            if !targets.nil? and (!delete or rrsets.empty?)
              targets.each { |target|
                rrsets << {value: target}
              }
            end

            base_rrset = {
              name: name,
              type: type,
              ttl: ttl,
              resource_records: rrsets
            }


            if !healthcheck.nil?
              base_rrset[:health_check_id] = healthcheck
            end
          end

          params = {
            hosted_zone_id: id,
            change_batch: {
              changes: [
                {
                  action: action,
                  resource_record_set: base_rrset
                }
              ]
            }
          }

          # Doing an UPSERT with a new set_identifier will fail with a record already exist error, so lets try and get it from an existing record. 
          # This can be an issue with multiple secondary failover records
          if (location || failover || region || weight) and set_identifier.nil?
            record_sets ||= MU::Cloud::AWS.route53.list_resource_record_sets(
              hosted_zone_id: id,
              start_record_name: name
            ).resource_record_sets

          
            record_sets.each { |r|
              if r.name == name
                if location && location == r.location
                  set_identifier = r.set_identifier
                  break
                elsif failover && failover == r.failover
                  set_identifier = r.set_identifier
                  break
                elsif region && region == r.region
                  set_identifier = r.set_identifier
                  break
                elsif weight && weight == r.weight
                  set_identifier = r.set_identifier
                  break
                end
              end
            }
          end

          if !failover.nil?
            base_rrset[:failover] = failover
            set_identifier ||= "#{MU.deploy_id}-failover-#{failover}".upcase
          elsif !weight.nil?
            base_rrset[:weight] = weight
            set_identifier ||= "#{MU.deploy_id}-weighted-#{weight.to_s}".upcase
          elsif !location.nil?
            loc_arg = Hash.new
            location.each_pair { |key, val|
              sym = key.to_sym
              loc_arg[sym] = val
            }
            base_rrset[:geo_location] = loc_arg
            set_identifier ||= "#{MU.deploy_id}-location-#{location.values.join("-")}".upcase
          elsif !region.nil?
            base_rrset[:region] = region
            set_identifier ||= "#{MU.deploy_id}-latency-#{region}".upcase
          end

          base_rrset[:set_identifier] = set_identifier if set_identifier

          if delete
            MU.log "Deleting DNS record #{name} (#{type}) from #{id}", details: params
          else
            MU.log "Adding DNS record #{name} => #{targets} (#{type}) to #{id}", details: params
          end

          return if noop

          on_retry = Proc.new { |e|
            if (delete and e.message.match(/but it was not found/)) or
               (!delete and e.message.match(/(it|name) already exists/))
              MU.log e.message, MU::DEBUG, details: params
              return
            elsif e.class == Aws::Route53::Errors::InvalidChangeBatch
              MU.log "Problem managing entry for #{name}", MU::ERR, details: params
              raise MuError, e.inspect
            end
          }

          change_id = nil
          MU.retrier([Aws::Route53::Errors::PriorRequestNotComplete, Aws::Route53::Errors::InvalidChangeBatch], wait: 15, max: 10, on_retry: on_retry) {
            change_id = MU::Cloud::AWS.route53.change_resource_record_sets(params).change_info.id
          }

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
        def self.genericMuDNSEntry(name: nil, target: nil, cloudclass: nil, noop: false, delete: false, sync_wait: true, credentials: nil)
          return nil if name.nil? or cloudclass.nil?
          return nil if target.nil? and !delete
          mu_zone = MU::Cloud::DNSZone.find(cloud_id: "platform-mu", credentials: credentials).values.first
          raise MuError, "Couldn't isolate platform-mu DNS zone" if mu_zone.nil?

          if !mu_zone.nil? and !MU.myVPC.nil?
            subdomain = cloudclass.cfg_name
            dns_name = name.downcase+"."+subdomain
            dns_name += "."+MU.myInstanceId if MU.myInstanceId

            record_type = "CNAME"
            record_type = "A" if target.match(/^\d+\.\d+\.\d+\.\d+/)
            ip = nil

            records = []
            begin
              lookup = MU::Cloud::AWS.route53(credentials: credentials).list_resource_record_sets(
                hosted_zone_id: mu_zone.id,
                start_record_name: "#{dns_name}.platform-mu",
                start_record_type: record_type,
                max_items: 1
              ).resource_record_sets
            rescue Aws::Route53::Errors::InvalidInput => e
              MU.log "Failed to look up record during #{delete ? "delete" : "add"}: "+e.message, MU::ERR, details: { "hosted_zone_id" => mu_zone.id, "start_record_name" => "#{dns_name}.platform-mu", "start_record_type" => record_type }
              return nil
            end

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

            if ip == target and !delete
              return "#{dns_name}.platform-mu"
            end

            sync_wait = false if delete

            record_type = "R53ALIAS" if cloudclass == MU::Cloud::AWS::LoadBalancer
            MU::Cloud::AWS::DNSZone.manageRecord(mu_zone.id, dns_name, record_type, targets: [target], delete: delete, sync_wait: sync_wait, noop: noop)
            return "#{dns_name}.platform-mu"
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
            # deploydata["region"] = @region if !@region.nil?
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

        # Called by {MU::Cleanup}. Locates resources that were created by the
        # currently-loaded deployment, and purges them.
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          MU.log "AWS::DNSZone.cleanup: need to support flags['known']", MU::DEBUG, details: flags

          threads = []
          MU::Cloud::AWS.route53(credentials: credentials).list_health_checks.health_checks.each { |check|
            begin
              tags = MU::Cloud::AWS.route53(credentials: credentials).list_tags_for_resource(
                  resource_type: "healthcheck",
                  resource_id: check.id
              ).resource_tag_set.tags
              muid_match = false
              mumaster_match = false
              tags.each { |tag|
                muid_match = true if tag.key == "MU-ID" and tag.value == deploy_id
                mumaster_match = true if tag.key == "MU-MASTER-IP" and tag.value == MU.mu_public_ip
              }

              delete = false
              if muid_match
                if ignoremaster
                  delete = true
                else
                  delete = true if mumaster_match
                end
              end

              if delete
                parent_thread_id = Thread.current.object_id
                threads << Thread.new(check) { |mycheck|
                  MU.dupGlobals(parent_thread_id)
                  Thread.abort_on_exception = true
                  MU.log "Removing health check #{mycheck.id}"
                  retries = 5
                  begin 
                    MU::Cloud::AWS.route53(credentials: credentials).delete_health_check(health_mycheck_id: mycheck.id) if !noop
                  rescue Aws::Route53::Errors::NoSuchHealthCheck => e
                    MU.log "Health Check '#{mycheck.id}' disappeared before I could remove it", MU::WARN, details: e.inspect
                  rescue Aws::Route53::Errors::InvalidInput => e
                    if e.message.match(/is still referenced from parent health check/) && retries <= 5
                      sleep 5
                      retries += 1
                      retry
                    else
                      MU.log "Health Check #{mycheck.id} still has a parent health check associated with it, skipping", MU::WARN, details: e.inspect
                    end
                  end
                }
              end
            rescue Aws::Route53::Errors::NoSuchHealthCheck => e
              MU.log "Health Check '#{check.id}' disappeared before I could remove it", MU::WARN, details: e.inspect
            end
          }

          threads.each { |t|
            t.join
          }

          zones = MU::Cloud::DNSZone.find(deploy_id: deploy_id, region: region)
          zones.values.each { |zone|
            MU.log "Purging DNS Zone '#{zone.name}' (#{zone.id})"
            if !noop
              begin
                # Clean up resource records first
                rrsets = MU::Cloud::AWS.route53(credentials: credentials).list_resource_record_sets(hosted_zone_id: zone.id)
                rrsets.resource_record_sets.each { |rrset|
                  next if zone.name == rrset.name and (rrset.type == "NS" or rrset.type == "SOA")
                  MU::Cloud::AWS.route53(credentials: credentials).change_resource_record_sets(
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

                MU::Cloud::AWS.route53(credentials: credentials).delete_hosted_zone(id: zone.id)
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
          MU::Cloud::AWS.route53(credentials: credentials).list_hosted_zones.hosted_zones.each { |zone|
            begin 
              zone_rrsets = []
              rrsets = MU::Cloud::AWS.route53(credentials: credentials).list_resource_record_sets(hosted_zone_id: zone.id)
              rrsets.resource_record_sets.each { |record|
                zone_rrsets << record
              }

              # AWS API returns a maximum of 100 results. DNS zones are likely to have more than 100 records, lets page and make sure we grab all records in a given zone
              while rrsets.next_record_name && rrsets.next_record_type
                rrsets = MU::Cloud::AWS.route53(credentials: credentials).list_resource_record_sets(hosted_zone_id: zone.id, start_record_name: rrsets.next_record_name, start_record_type: rrsets.next_record_type)
                rrsets.resource_record_sets.each { |record|
                  zone_rrsets << record
                }
              end

              # TO DO: if we have more than one record it will retry the deletion multiple times and will throw Aws::Route53::Errors::InvalidChangeBatch / record not found even though the record was deleted
              zone_rrsets.each { |record|
                if record.name.match(deploy_id.downcase)
                  resource_records = []
                  record.resource_records.each { |rrecord|
                    resource_records << rrecord.value
                  }

                  MU::Cloud::AWS::DNSZone.manageRecord(zone.id, record.name, record.type, targets: resource_records, ttl: record.ttl, sync_wait: false, delete: true) if !noop
                end
              }
            rescue Aws::Route53::Errors::NoSuchHostedZone
              MU.log "DNS Zone '#{zone.name}' #{zone.id} disappeared while was looking at", MU::WARN
            end
          }
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {}
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::dnszones}, bare and unvalidated.
        # @param zone [Hash]: The resource to process and validate
        # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(zone, _configurator)
          ok = true

          if !zone["records"].nil?
            zone["records"].each { |record|
              record['scrub_mu_isms'] = zone['scrub_mu_isms'] if zone.has_key?('scrub_mu_isms')
              route_types = 0
              route_types = route_types + 1 if !record['weight'].nil?
              route_types = route_types + 1 if !record['geo_location'].nil?
              route_types = route_types + 1 if !record['region'].nil?
              route_types = route_types + 1 if !record['failover'].nil?
  
              if route_types > 1
                MU.log "At most one of weight, location, region, and failover can be specified in a record.", MU::ERR, details: record
                ok = false
              end
  
              if !record['mu_type'].nil?
                MU::Config.addDependency(zone, record['target'], record['mu_type'])
              end
  
              if record.has_key?('healthchecks') && !record['healthchecks'].empty?
                primary_alarms_set = []
                record['healthchecks'].each { |check|
                  check['alarm_region'] ||= zone['region'] if check['method'] == "CLOUDWATCH_METRIC"
                  primary_alarms_set << true if check['type'] == 'primary'
                }
  
                if primary_alarms_set.size != 1
                  MU.log "Must have only one primary health check, but #{primary_alarms_set.size} are set.", MU::ERR, details: record
                  ok = false
                end
  
                # record['healthcheck']['alarm_region'] ||= zone['region'] if record['healthcheck']['method'] == "CLOUDWATCH_METRIC"
  
                if route_types == 0
                  MU.log "Health check in a DNS zone only valid with Weighted, Location-based, Latency-based, or Failover routing.", MU::ERR, details: record
                  ok = false
                end
              end
  
              if !record['geo_location'].nil?
                if !record['geo_location']['continent_code'].nil? and (!record['geo_location']['country_code'].nil? or !record['geo_location']['subdivision_code'].nil?)
                  MU.log "Location routing cannot mix continent_code with other location specifiers.", MU::ERR, details: record
                  ok = false
                end
                if record['geo_location']['country_code'].nil? and !record['geo_location']['subdivision_code'].nil?
                  MU.log "Cannot specify subdivision_code without country_code.", MU::ERR, details: record
                  ok = false
                end
              end
            }
          end

          ok
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          nil # no such animal in Route53
        end

        # Locate an existing DNSZone or DNSZones and return an array containing matching AWS resource descriptors for those that match.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching DNSZones
        def self.find(**args)
          matches = {}

          resp = MU::Cloud::AWS.route53(credentials: args[:credentials]).list_hosted_zones(
              max_items: 100
          )

          resp.hosted_zones.each { |zone|
            if !args[:cloud_id].nil? and !args[:cloud_id].empty?
              if zone.id == args[:cloud_id]
                begin 
                  matches[zone.id] = MU::Cloud::AWS.route53(credentials: args[:credentials]).get_hosted_zone(id: zone.id).hosted_zone
                rescue Aws::Route53::Errors::NoSuchHostedZone
                  MU.log "Hosted zone #{zone.id} doesn't exist"
                end
              elsif zone.name == args[:cloud_id] or zone.name == args[:cloud_id]+"."
                begin 
                  matches[zone.id] = MU::Cloud::AWS.route53(credentials: args[:credentials]).get_hosted_zone(id: zone.id).hosted_zone
                rescue Aws::Route53::Errors::NoSuchHostedZone
                  MU.log "Hosted zone #{zone.id} doesn't exist"
                end
              end
            end
            if !args[:deploy_id].nil? and !args[:deploy_id].empty? and zone.config.comment == args[:deploy_id]
              begin 
                matches[zone.id] = MU::Cloud::AWS.route53(credentials: args[:credentials]).get_hosted_zone(id: zone.id).hosted_zone
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
