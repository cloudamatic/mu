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
      # A firewall ruleset as configured in {MU::Config::BasketofKittens::firewall_rules}
      class FirewallRule < MU::Cloud::FirewallRule
        require "mu/clouds/aws/vpc"

        @admin_sgs = Hash.new
        @admin_sg_semaphore = Mutex.new

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          if !@vpc.nil?
            @mu_name ||= @deploy.getResourceName(@config['name'], need_unique_string: true)
          else
            @mu_name ||= @deploy.getResourceName(@config['name'])
          end

        end

        # Called by {MU::Deploy#createResources}
        def create
          vpc_id = @vpc.cloud_id if !@vpc.nil?
          groupname = @mu_name
          description = groupname

          sg_struct = {
            :group_name => groupname,
            :description => description
          }
          if !vpc_id.nil?
            sg_struct[:vpc_id] = vpc_id
          end

          begin
            MU.log "Creating EC2 Security Group #{groupname}", details: sg_struct

            secgroup = MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).create_security_group(sg_struct)
            @cloud_id = secgroup.group_id
          rescue Aws::EC2::Errors::InvalidGroupDuplicate => e
            MU.log "EC2 Security Group #{groupname} already exists, using it", MU::NOTICE
            filters = [{name: "group-name", values: [groupname]}]
            filters << {name: "vpc-id", values: [vpc_id]} if !vpc_id.nil?

            secgroup = MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).describe_security_groups(filters: filters).security_groups.first
            deploy_id = @deploy.deploy_id if !@deploy_id.nil?
            if secgroup.nil?
              raise MuError, "Failed to locate security group named #{groupname}, even though EC2 says it already exists", caller
            end
            @cloud_id = secgroup.group_id
          end

          begin
            MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).describe_security_groups(group_ids: [secgroup.group_id])
          rescue Aws::EC2::Errors::InvalidGroupNotFound => e
            MU.log "#{secgroup.group_id} not yet ready, waiting...", MU::NOTICE
            sleep 10
            retry
          end

          MU::Cloud::AWS.createStandardTags(secgroup.group_id, region: @config['region'], credentials: @config['credentials'])
          MU::MommaCat.createTag(secgroup.group_id, "Name", groupname, region: @config['region'], credentials: @config['credentials'])

          if @config['optional_tags']
            MU::MommaCat.listOptionalTags.each { |key, value|
              MU::MommaCat.createTag(secgroup.group_id, key, value, region: @config['region'], credentials: @config['credentials'])
            }
          end

          if @config['tags']
            @config['tags'].each { |tag|
              MU::MommaCat.createTag(secgroup.group_id, tag['key'], tag['value'], region: @config['region'], credentials: @config['credentials'])
            }
          end

          egress = false
          egress = true if !vpc_id.nil?
          # XXX the egress logic here is a crude hack, this really needs to be
          # done at config level
          setRules(
            [],
            add_to_self: @config['self_referencing'],
            ingress: true,
            egress: egress
          )

          MU.log "EC2 Security Group #{groupname} is #{secgroup.group_id}", MU::DEBUG
          return secgroup.group_id
        end

        # Called by {MU::Deploy#createResources}
        def groom
          if !@config['rules'].nil? and @config['rules'].size > 0
            egress = false
            egress = true if !@vpc.nil?
            # XXX the egress logic here is a crude hack, this really needs to be
            # done at config level
            setRules(
              @config['rules'],
              add_to_self: @config['self_referencing'],
              ingress: true,
              egress: egress
            )
          end
        end

        # Log metadata about this ruleset to the currently running deployment
        def notify
          sg_data = MU.structToHash(
              MU::Cloud::FirewallRule.find(cloud_id: @cloud_id, region: @config['region'])
          )
          sg_data["group_id"] = @cloud_id
          sg_data["cloud_id"] = @cloud_id
          return sg_data
        end

        # Insert a rule into an existing security group.
        #
        # @param hosts [Array<String>]: An array of CIDR network addresses to which this rule will apply.
        # @param proto [String]: One of "tcp," "udp," or "icmp"
        # @param port [Integer]: A port number. Only valid with udp or tcp.
        # @param egress [Boolean]: Whether this is an egress ruleset, instead of ingress.
        # @param port_range [String]: A port range descriptor (e.g. 0-65535). Only valid with udp or tcp.
        # @return [void]
        def addRule(hosts, proto: "tcp", port: nil, egress: false, port_range: "0-65535", comment: nil)
          rule = Hash.new
          rule["proto"] = proto
          sgs = []
          hosts = [hosts] if hosts.is_a?(String)
          hosts.each { |h|
            if h.match(/^sg-/)
              sgs << h
            end
          }
          rule["sgs"] = sgs if sgs.size > 0
          hosts = hosts - sgs
          rule["hosts"] = hosts if hosts.size > 0

          if port != nil
            port = port.to_s if !port.is_a?(String)
            rule["port"] = port
          else
            rule["port_range"] = port_range
          end
          rule["description"] = comment if comment
          ec2_rule = convertToEc2([rule])

          begin
            if egress
              MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).authorize_security_group_egress(
                group_id: @cloud_id,
                ip_permissions: ec2_rule
              )
            else
              MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).authorize_security_group_ingress(
                group_id: @cloud_id,
                ip_permissions: ec2_rule
              )
            end
          rescue Aws::EC2::Errors::InvalidPermissionDuplicate => e
            MU.log "Attempt to add duplicate rule to #{@cloud_id}", MU::DEBUG, details: ec2_rule
            # Ensure that, at least, the description field gets updated on
            # existing rules
            if comment
              if egress
                MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).update_security_group_rule_descriptions_egress(
                  group_id: @cloud_id,
                  ip_permissions: ec2_rule
                )
              else
                MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).update_security_group_rule_descriptions_ingress(
                  group_id: @cloud_id,
                  ip_permissions: ec2_rule
                )
              end
            end
          end
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          "arn:"+(MU::Cloud::AWS.isGovCloud?(@config["region"]) ? "aws-us-gov" : "aws")+":ec2:"+@config['region']+":"+MU::Cloud::AWS.credToAcct(@config['credentials'])+":security-group/"+@cloud_id
        end

        # Locate an existing security group or groups and return an array containing matching AWS resource descriptors for those that match.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region
        # @param tag_key [String]: A tag key to search.
        # @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
        # @param flags [Hash]: Optional flags
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching FirewallRules
        def self.find(**args)

          if !args[:cloud_id].nil? and !args[:cloud_id].empty?
            begin
              resp = MU::Cloud::AWS.ec2(region: args[:region], credentials: args[:credentials]).describe_security_groups(group_ids: [args[:cloud_id]])
              return {args[:cloud_id] => resp.data.security_groups.first}
            rescue ArgumentError => e
              MU.log "Attempting to load #{args[:cloud_id]}: #{e.inspect}", MU::WARN, details: caller
              return {}
            rescue Aws::EC2::Errors::InvalidGroupNotFound => e
              MU.log "Attempting to load #{args[:cloud_id]}: #{e.inspect}", MU::DEBUG, details: caller
              return {}
            end
          end

          map = {}
          if !args[:tag_key].nil? and !args[:tag_value].nil?
            resp = MU::Cloud::AWS.ec2(region: args[:region], credentials: args[:credentials]).describe_security_groups(
                filters: [
                    {name: "tag:#{args[:tag_key]}", values: [args[:tag_value]]}
                ]
            )
            if !resp.nil?
              resp.data.security_groups.each { |sg|
                map[sg.group_id] = sg
              }
            end
          end

          map
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          false
        end

        # Denote whether this resource implementation is experiment, ready for
        # testing, or ready for production use.
        def self.quality
          MU::Cloud::RELEASE
        end

        # Remove all security groups (firewall rulesets) associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          filters = nil
          if flags and flags["vpc_id"]
            filters = [
              {name: "vpc-id", values: [flags["vpc_id"]]}
            ]
          else
            filters = [
              {name: "tag:MU-ID", values: [MU.deploy_id]}
            ]
            if !ignoremaster
              filters << {name: "tag:MU-MASTER-IP", values: [MU.mu_public_ip]}
            end
          end

          # Some services create sneaky rogue ENIs which then block removal of
          # associated security groups. Find them and fry them.
          MU::Cloud::AWS::VPC.purge_interfaces(noop, filters, region: region, credentials: credentials)

          resp = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_security_groups(
            filters: filters
          )

          resp.data.security_groups.each { |sg|
            MU.log "Revoking rules in EC2 Security Group #{sg.group_name} (#{sg.group_id})"

            if !noop
              ingress_to_revoke = Array.new
              egress_to_revoke = Array.new
              sg.ip_permissions.each { |hole|
                ingress_to_revoke << MU.structToHash(hole)
                ingress_to_revoke.each { |rule|
                  if !rule[:user_id_group_pairs].nil? and rule[:user_id_group_pairs] .size == 0
                    rule.delete(:user_id_group_pairs)
                  elsif !rule[:user_id_group_pairs].nil?
                    rule[:user_id_group_pairs].each { |group_ref|
                      group_ref = MU.structToHash(group_ref)
                      group_ref.delete(:group_name) if group_ref[:group_id]
                    }
                  end

                  if !rule[:ip_ranges].nil? and rule[:ip_ranges].size == 0
                    rule.delete(:ip_ranges)
                  end

                  if !rule[:prefix_list_ids].nil? and rule[:prefix_list_ids].size == 0
                    rule.delete(:prefix_list_ids)
                  end
                  
                  if !rule[:ipv_6_ranges].nil? and rule[:ipv_6_ranges].size == 0
                    rule.delete(:ipv_6_ranges)
                  end
                }
              }
              sg.ip_permissions_egress.each { |hole|
                egress_to_revoke << MU.structToHash(hole)
                egress_to_revoke.each { |rule|
                  if !rule[:user_id_group_pairs].nil? and rule[:user_id_group_pairs].size == 0
                    rule.delete(:user_id_group_pairs)
                  elsif !rule[:user_id_group_pairs].nil?
                    rule[:user_id_group_pairs].each { |group_ref|
                      group_ref = MU.structToHash(group_ref)
                      group_ref.delete(:group_name) if group_ref[:group_id]
                    }
                  end

                  if !rule[:ip_ranges].nil? and rule[:ip_ranges].size == 0
                    rule.delete(:ip_ranges)
                  end

                  if !rule[:prefix_list_ids].nil? and rule[:prefix_list_ids].size == 0
                    rule.delete(:prefix_list_ids)
                  end

                  if !rule[:ipv_6_ranges].nil? and rule[:ipv_6_ranges].size == 0
                    rule.delete(:ipv_6_ranges)
                  end
                }
              }
              begin

                if ingress_to_revoke.size > 0
                  MU::Cloud::AWS.ec2(credentials: credentials, region: region).revoke_security_group_ingress(
                      group_id: sg.group_id,
                      ip_permissions: ingress_to_revoke
                  )
                end
                if egress_to_revoke.size > 0
                  MU::Cloud::AWS.ec2(credentials: credentials, region: region).revoke_security_group_egress(
                      group_id: sg.group_id,
                      ip_permissions: egress_to_revoke
                  )
                end
              rescue Aws::EC2::Errors::InvalidPermissionNotFound
                MU.log "Rule in #{sg.group_id} disappeared before I could remove it", MU::WARN
              end
            end
          }

          resp.data.security_groups.each { |sg|
            next if sg.group_name == "default"
            MU.log "Removing EC2 Security Group #{sg.group_name}"

            retries = 0
            begin
              MU::Cloud::AWS.ec2(credentials: credentials, region: region).delete_security_group(group_id: sg.group_id) if !noop
            rescue Aws::EC2::Errors::CannotDelete => e
              MU.log e.message, MU::WARN
            rescue Aws::EC2::Errors::InvalidGroupNotFound
              MU.log "EC2 Security Group #{sg.group_name} disappeared before I could delete it!", MU::WARN
            rescue Aws::EC2::Errors::DependencyViolation, Aws::EC2::Errors::InvalidGroupInUse
              if retries < 10
                MU.log "EC2 Security Group #{sg.group_name} is still in use, waiting...", MU::NOTICE
                sleep 10
                retries = retries + 1
                retry
              else
                MU.log "Failed to delete #{sg.group_name}", MU::ERR
              end
            end
          }
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "rules" => {
              "items" => {
                "properties" => {
                  "sgs" => {
                    "type" => "array",
                    "items" => {
                      "description" => "Other AWS Security Groups; resources that are associated with this group will have this rule applied to their traffic",
                      "type" => "string"
                    }
                  },
                  "lbs" => {
                    "type" => "array",
                    "items" => {
                      "description" => "AWS Load Balancers which will have this rule applied to their traffic",
                      "type" => "string"
                    }
                  }
                }
              }
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::firewall_rules}, bare and unvalidated.
        # @param acl [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment config of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(acl, configurator)
          ok = true
          if !acl["vpc_name"].nil? or !acl["vpc_id"].nil?
            acl['vpc'] = Hash.new
            if acl["vpc_id"].nil?
              acl['vpc']["vpc_id"] = config.getTail("vpc_id", value: acl["vpc_id"], prettyname: "Firewall Ruleset #{acl['name']} Target VPC",  cloudtype: "AWS::EC2::VPC::Id") if acl["vpc_id"].is_a?(String)
            elsif !acl["vpc_name"].nil?
              acl['vpc']['vpc_name'] = acl["vpc_name"]
            end
          end
          if !acl["vpc"].nil?
            # Drop meaningless subnet references
            acl['vpc'].delete("subnets")
            acl['vpc'].delete("subnet_id")
            acl['vpc'].delete("subnet_name")
            acl['vpc'].delete("subnet_pref")
          end
          acl['rules'] ||= {}
          acl['rules'].each { |rule|
            if !rule['sgs'].nil?
              rule['sgs'].each { |sg_name|
	              if configurator.haveLitterMate?(sg_name, "firewall_rules") and sg_name != acl['name']
  	              acl["dependencies"] << {
    	              "type" => "firewall_rule",
      	            "name" => sg_name,
                    "no_create_wait" => true
	                }
                elsif sg_name == acl['name']
                  acl['self_referencing'] = true
                  next
                end
              }
            end
            if !rule['lbs'].nil?
              rule['lbs'].each { |lb_name|
                acl["dependencies"] << {
                  "type" => "loadbalancer",
                  "name" => lb_name,
                  "phase" => "groom"
                }
              }
            end
          }
          acl['dependencies'].uniq!
          ok
        end

        private

        #########################################################################
        # Manufacture an EC2 security group. The second parameter, rules, is an
        # "ingress_rules" structure parsed and validated by MU::Config.
        #########################################################################
        def setRules(rules, add_to_self: false, ingress: true, egress: false)
          describe
          # XXX warn about attempt to set rules before we exist
          return if rules.nil? or rules.size == 0 or !@cloud_id

          # add_to_self means that this security is a "member" of its own rules
          # (which is to say, objects that have this SG are allowed in my these
          # rules)
          if add_to_self
            rules.each { |rule|
              if rule['sgs'].nil? or !rule['sgs'].include?(@cloud_id)
                new_rule = rule.clone
                new_rule.delete('hosts')
                rule['sgs'] = Array.new if rule['sgs'].nil?
                rule['sgs'] << @cloud_id
              end
            }
          end

          ec2_rules = convertToEc2(rules)

          ext_permissions = MU.structToHash(cloud_desc.ip_permissions)

          # Creating an empty security group is ok, so don't freak out if we get
          # a null rule list.
          if !ec2_rules.nil?
            ec2_rules.uniq!
            retries = 0
            ec2_rules.each { |rule|
              haverule = false
              ext_permissions.each { |ext_rule|
                different = false
                ext_rule.keys.each { |k|
                  next if ext_rule[k].nil? or ext_rule[k] == []
                  different = true if rule[k] != ext_rule[k]
                }
                if !different
                  haverule = true
                  break
                end
              }
              if haverule
                MU.log "Security Group rule already exists in #{@mu_name}", MU::DEBUG, details: rule
                next
              end
              MU.log "Setting rule in Security Group #{@mu_name} (#{@cloud_id})", MU::NOTICE, details: rule
              begin
                if ingress
                  MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).authorize_security_group_ingress(
                      group_id: @cloud_id,
                      ip_permissions: [rule]
                  )
                end
                if egress
                  MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).authorize_security_group_egress(
                      group_id: @cloud_id,
                      ip_permissions: [rule]
                  )
                end
              rescue Aws::EC2::Errors::InvalidGroupNotFound => e
                MU.log "#{@mu_name} (#{@cloud_id}) does not yet exist", MU::WARN
                retries = retries + 1
                if retries < 10
                  sleep 10
                  retry
                else
                  raise MuError, "#{@mu_name} does not exist", e.backtrace
                end
              rescue Aws::EC2::Errors::InvalidPermissionDuplicate => e
                MU.log "Attempt to add duplicate rule to #{@mu_name}", MU::DEBUG, details: rule
              end
            }
          end

        end

        #########################################################################
        # Convert our config languages description of firewall rules into Amazon's.
        # This rule structure is as defined in MU::Config.
        #########################################################################
        def convertToEc2(rules)
          ec2_rules = []
          if rules != nil
            rules.uniq!

            rules.each { |rule|
              ec2_rule = {}

              rule['proto'] ||= "tcp"
              ec2_rule[:ip_protocol] = rule['proto']

              p_start = nil
              p_end = nil
              if rule['port_range']
                p_start, p_end = rule['port_range'].to_s.split(/\s*-\s*/)
              elsif rule['port']
                p_start = rule['port'].to_i
                p_end = rule['port'].to_i
              elsif rule['proto'] != "icmp"
                raise MuError, "Can't create a TCP or UDP security group rule without specifying ports: #{rule}"
              end
              if rule['proto'] != "icmp"
                if p_start.nil? or p_end.nil?
                  raise MuError, "Got nil ports out of rule #{rule}"
                end
                ec2_rule[:from_port] = p_start.to_i
                ec2_rule[:to_port] = p_end.to_i
              else
                ec2_rule[:from_port] = -1
                ec2_rule[:to_port] = -1
              end

              if (!defined? rule['hosts'] or !rule['hosts'].is_a?(Array)) and
                 (!defined? rule['sgs'] or !rule['sgs'].is_a?(Array)) and
                 (!defined? rule['lbs'] or !rule['lbs'].is_a?(Array))
                rule['hosts'] = ["0.0.0.0/0"]
              end
              ec2_rule[:ip_ranges] = []
              ec2_rule[:user_id_group_pairs] = []

              if !rule['hosts'].nil?
                rule['hosts'].uniq!
                rule['hosts'].each { |cidr|
                  next if cidr.nil? # XXX where is that coming from?
                  cidr = cidr + "/32" if cidr.match(/^\d+\.\d+\.\d+\.\d+$/)
                  if rule['description']
                    ec2_rule[:ip_ranges] << {cidr_ip: cidr, description: rule['description']}
                  else
                    ec2_rule[:ip_ranges] << {cidr_ip: cidr}
                  end
                }
              end

              if !rule['lbs'].nil?
# XXX This is a dopey place for this, dependencies() should be doing our legwork
                rule['lbs'].uniq!
                rule['lbs'].each { |lb_name|
# XXX The language for addressing ELBs should be as flexible as VPCs. This sauce
# is weak.
# Try to find one by name in this deploy

                  found = MU::MommaCat.findStray(
                    "AWS",
                    "loadbalancers",
                    name: lb_name,
                    deploy_id: @deploy.deploy_id
                  )
                  # Ok, let's try it with the name being an AWS identifier
                  if found.nil? or found.size < 1
                    found = MU::MommaCat.findStray(
                      "AWS",
                      "loadbalancers",
                      cloud_id: lb_name,
                      dummy_ok: true
                    )
                    if found.nil? or found.size < 1
                      raise MuError, "Couldn't find a LoadBalancer with #{lb_name} for #{@mu_name}"
                    end
                  end
                  lb = found.first

                  if !lb.nil? and !lb.cloud_desc.nil?
                    lb.cloud_desc.security_groups.each { |lb_sg|
                      ec2_rule[:user_id_group_pairs] << {
                        user_id: MU::Cloud::AWS.credToAcct(@config['credentials']),
                        group_id: lb_sg
                      }
                    }
                  end
                }
              end

              if !rule['sgs'].nil?
                rule['sgs'].uniq!
                rule['sgs'].each { |sg_name|
                  dependencies # Make sure our cache is fresh
                  sg = @deploy.findLitterMate(type: "firewall_rule", name: sg_name)
                  sg ||= if sg_name == @config['name']
                    self
                  elsif @dependencies.has_key?("firewall_rule") and
                      @dependencies["firewall_rule"].has_key?(sg_name)
                    @dependencies["firewall_rule"][sg_name]
                  elsif sg_name.match(/^sg-/)
                    found_sgs = MU::MommaCat.findStray("AWS", "firewall_rule", cloud_id: sg_name, region: @config['region'], calling_deploy: @deploy, dummy_ok: true)
                    found_sgs.first if found_sgs
                  end

                  if sg.nil?
                    raise MuError, "FirewallRule #{@config['name']} referenced security group '#{sg_name}' in a rule, but I can't find it anywhere!"
                  end

                  ec2_rule[:user_id_group_pairs] << {
                    user_id: MU.account_number,
                    group_id: sg.cloud_id
                  }
                }
              end

              ec2_rule[:user_id_group_pairs].uniq!
              ec2_rule[:ip_ranges].uniq!
              ec2_rule.delete(:ip_ranges) if ec2_rule[:ip_ranges].empty?
              ec2_rule.delete(:user_id_group_pairs) if ec2_rule[:user_id_group_pairs].empty?

              # if !ec2_rule[:user_id_group_pairs].nil? and
                # ec2_rule[:user_id_group_pairs].size > 0 and
                  # !ec2_rule[:ip_ranges].nil? and
                  # ec2_rule[:ip_ranges].size > 0
                # MU.log "Cannot specify ip_ranges and user_id_group_pairs", MU::ERR
                # raise MuError, "Cannot specify ip_ranges and user_id_group_pairs"
              # end

              # if !ec2_rule[:user_id_group_pairs].nil? and
                  # ec2_rule[:user_id_group_pairs].size > 0
                # ec2_rule.delete(:ip_ranges)
                # ec2_rule[:user_id_group_pairs].uniq!
              # elsif !ec2_rule[:ip_ranges].nil? and
                  # ec2_rule[:ip_ranges].size > 0
                # ec2_rule.delete(:user_id_group_pairs)
                # ec2_rule[:ip_ranges].uniq!
              # end
              ec2_rules << ec2_rule
            }
          end
          ec2_rules.uniq!
          return ec2_rules
        end

      end #class
    end #class
  end
end #module
