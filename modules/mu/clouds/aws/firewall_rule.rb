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

        @deploy = nil
        @config = nil
        @admin_sgs = Hash.new
        @admin_sg_semaphore = Mutex.new

        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id
        attr_reader :cfm_template

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::firewall_rules}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          @cloud_id ||= cloud_id
          if !mu_name.nil?
            @mu_name = mu_name
          else
            if !@vpc.nil?
              @mu_name = @deploy.getResourceName(@config['name'], need_unique_string: true)
            else
              @mu_name = @deploy.getResourceName(@config['name'])
            end
            @cfm_name, @cfm_template = MU::Cloud::AWS.cloudFormationBase(self.class.cfg_name, self)
          end

        end

        # Called by {MU::Deploy#createResources}
        def create
          vpc_id = @vpc.cloud_id if !@vpc.nil?
          groupname = @mu_name
          description = groupname

          if !MU::Cloud::AWS.emitCloudformation
            MU.log "Creating EC2 Security Group #{groupname}"

            sg_struct = {
              :group_name => groupname,
              :description => description
            }
            if !vpc_id.nil?
              sg_struct[:vpc_id] = vpc_id
            end
            begin
              secgroup = MU::Cloud::AWS.ec2(@config['region']).create_security_group(sg_struct)
              @cloud_id = secgroup.group_id
            rescue Aws::EC2::Errors::InvalidGroupDuplicate => e
              MU.log "EC2 Security Group #{groupname} already exists, using it", MU::NOTICE
              filters = [{name: "group-name", values: [groupname]}]
              filters << {name: "vpc-id", values: [vpc_id]} if !vpc_id.nil?
  
              secgroup = MU::Cloud::AWS.ec2(@config['region']).describe_security_groups(filters: filters).security_groups.first
              deploy_id = @deploy.deploy_id if !@deploy_id.nil?
              if secgroup.nil?
                raise MuError, "Failed to locate security group named #{groupname}, even though EC2 says it already exists", caller
              end
              @cloud_id = secgroup.group_id
            end

            begin
              MU::Cloud::AWS.ec2(@config['region']).describe_security_groups(group_ids: [secgroup.group_id])
            rescue Aws::EC2::Errors::InvalidGroupNotFound => e
              MU.log "#{secgroup.group_id} not yet ready, waiting...", MU::NOTICE
              sleep 10
              retry
            end
          else
            if !@config['vpc'].nil? and !@config['vpc']['vpc_id'].nil?
              MU::Cloud::AWS.setCloudFormationProp(
                @cfm_template[@cfm_name],
                "VpcId",
                @config['vpc']['vpc_id']
              )
            end
          end

          if !MU::Cloud::AWS.emitCloudformation
            MU::MommaCat.createStandardTags secgroup.group_id, region: @config['region']
            MU::MommaCat.createTag secgroup.group_id, "Name", groupname, region: @config['region']
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
          if MU::Cloud::AWS.emitCloudformation
            return nil
          end

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
          return {} if MU::Cloud::AWS.emitCloudformation
          sg_data = MU.structToHash(
              MU::Cloud::FirewallRule.find(cloud_id: @cloud_id, region: @config['region'])
          )
          sg_data["group_id"] = @cloud_id
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
        def addRule(hosts,
                    proto: proto = "tcp",
                    port: port = nil,
                    egress: egress = false,
                    port_range: port_range = "0-65535"
        )
          rule = Hash.new
          rule["proto"] = proto
          if hosts.is_a?(String)
            rule["hosts"] = [hosts]
          else
            rule["hosts"] = hosts
          end
          if port != nil
            port = port.to_s if !port.is_a?(String)
            rule["port"] = port
          else
            rule["port_range"] = port_range
          end
          ec2_rule = convertToEc2([rule])

          begin
            if egress
              MU::Cloud::AWS.ec2(@config['region']).authorize_security_group_egress(
                  group_id: @cloud_id,
                  ip_permissions: ec2_rule
              )
            else
              MU::Cloud::AWS.ec2(@config['region']).authorize_security_group_ingress(
                  group_id: @cloud_id,
                  ip_permissions: ec2_rule
              )
            end
          rescue Aws::EC2::Errors::InvalidPermissionDuplicate => e
            MU.log "Attempt to add duplicate rule to #{@cloud_id}", MU::DEBUG, details: ec2_rule
          end
        end

        # Locate an existing security group or groups and return an array containing matching AWS resource descriptors for those that match.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region
        # @param tag_key [String]: A tag key to search.
        # @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching FirewallRules
        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil)

          if !cloud_id.nil? and !cloud_id.empty?
            begin
              resp = MU::Cloud::AWS.ec2(region).describe_security_groups(group_ids: [cloud_id])
              return {cloud_id => resp.data.security_groups.first}
            rescue ArgumentError => e
              MU.log "Attempting to load #{cloud_id}: #{e.inspect}", MU::WARN, details: caller
              return {}
            rescue Aws::EC2::Errors::InvalidGroupNotFound => e
              MU.log "Attempting to load #{cloud_id}: #{e.inspect}", MU::DEBUG, details: caller
              return {}
            end
          end

          map = {}
          if !tag_key.nil? and !tag_value.nil?
            resp = MU::Cloud::AWS.ec2(region).describe_security_groups(
                filters: [
                    {name: "tag:#{tag_key}", values: [tag_value]}
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

        # Remove all security groups (firewall rulesets) associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          tagfilters = [
              {name: "tag:MU-ID", values: [MU.deploy_id]}
          ]
          if !ignoremaster
            tagfilters << {name: "tag:MU-MASTER-IP", values: [MU.mu_public_ip]}
          end

          resp = MU::Cloud::AWS.ec2(region).describe_security_groups(
              filters: tagfilters
          )

          resp.data.security_groups.each { |sg|
            MU.log "Revoking rules in EC2 Security Group #{sg.group_name} (#{sg.group_id})"

            if !noop
              ingress_to_revoke = Array.new
              egress_to_revoke = Array.new
              sg.ip_permissions.each { |hole|

                hole_hash = MU.structToHash(hole)
                if !hole_hash[:user_id_group_pairs].nil?
                  hole[:user_id_group_pairs].each { |group_ref|
                    group_ref.delete(:group_name) if group_ref.is_a?(Hash)
                  }
                end
                ingress_to_revoke << MU.structToHash(hole)
                ingress_to_revoke.each { |rule|
                  if !rule[:user_id_group_pairs].nil? and rule[:user_id_group_pairs].size == 0
                    rule.delete(:user_id_group_pairs)
                  end
                  if !rule[:ip_ranges].nil? and rule[:ip_ranges].size == 0
                    rule.delete(:ip_ranges)
                  end
                  if !rule[:prefix_list_ids].nil? and rule[:prefix_list_ids].size == 0
                    rule.delete(:prefix_list_ids)
                  end
                }
              }
              sg.ip_permissions_egress.each { |hole|
                hole_hash = MU.structToHash(hole)
                if !hole_hash[:user_id_group_pairs].nil? and hole_hash[:user_id_group_pairs].is_a?(Hash)
                  hole[:user_id_group_pairs].each { |group_ref|
                    group_ref.delete(:group_name)
                  }
                end
                egress_to_revoke << MU.structToHash(hole)
                egress_to_revoke.each { |rule|
                  if !rule[:user_id_group_pairs].nil? and rule[:user_id_group_pairs].size == 0
                    rule.delete(:user_id_group_pairs)
                  end
                  if !rule[:ip_ranges].nil? and rule[:ip_ranges].size == 0
                    rule.delete(:ip_ranges)
                  end
                  if !rule[:prefix_list_ids].nil? and rule[:prefix_list_ids].size == 0
                    rule.delete(:prefix_list_ids)
                  end
                }
              }
              begin
                if ingress_to_revoke.size > 0
                  MU::Cloud::AWS.ec2(region).revoke_security_group_ingress(
                      group_id: sg.group_id,
                      ip_permissions: ingress_to_revoke
                  )
                end
                if egress_to_revoke.size > 0
                  MU::Cloud::AWS.ec2(region).revoke_security_group_egress(
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
            MU.log "Removing EC2 Security Group #{sg.group_name}"

            retries = 0
            begin
              MU::Cloud::AWS.ec2(region).delete_security_group(group_id: sg.group_id) if !noop
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

        private

        #########################################################################
        # Manufacture an EC2 security group. The second parameter, rules, is an
        # "ingress_rules" structure parsed and validated by MU::Config.
        #########################################################################
        def setRules(rules, add_to_self: add_to_self = false, ingress: ingress = true, egress: egress = false)
          return if rules.nil? or rules.size == 0


          # add_to_self means that this security is a "member" of its own rules
          # (which is to say, objects that have this SG are allowed in my these
          # rules)
          if add_to_self and !MU::Cloud::AWS.emitCloudformation
            rules.each { |rule|
              if rule['sgs'].nil? or !rule['sgs'].include?(secgroup.group_id)
                new_rule = rule.clone
                new_rule.delete('hosts')
                rule['sgs'] = Array.new if rule['sgs'].nil?
                rule['sgs'] << @cloud_id
              end
            }
          end

          ec2_rules = convertToEc2(rules)

          # Creating an empty security group is ok, so don't freak out if we get
          # a null rule list.
          if MU::Cloud::AWS.emitCloudformation
            ec2_rules.each { |rule|
              rule[:ip_ranges].each { |cidr|
                MU::Cloud::AWS.setCloudFormationProp(
                  @cfm_template[@cfm_name],
                  "SecurityGroupIngress",
                  {
                    "IpProtocol" => rule[:ip_protocol],
                    "FromPort" => rule[:from_port],
                    "ToPort" => rule[:to_port],
                    "CidrIP" => cidr[:cidr_ip]
                  }
                )
              }
            }
          else
            MU.log "Setting rules in Security Group #{@mu_name} (#{@cloud_id})", details: ec2_rules
            retries = 0
            if rules != nil
              MU.log "Rules for EC2 Security Group #{@mu_name} (#{@cloud_id}): #{ec2_rules}", MU::DEBUG
              begin
                if ingress
                  MU::Cloud::AWS.ec2(@config['region']).authorize_security_group_ingress(
                      group_id: @cloud_id,
                      ip_permissions: ec2_rules
                  )
                end
                if egress
                  MU::Cloud::AWS.ec2(@config['region']).authorize_security_group_egress(
                      group_id: @cloud_id,
                      ip_permissions: ec2_rules
                  )
                end
              rescue Aws::EC2::Errors::InvalidGroupNotFound => e
                MU.log "#{@mu_name} does not yet exist", MU::WARN
                retries = retries + 1
                if retries < 10
                  sleep 10
                  retry
                else
                  raise MuError, "#{@mu_name} does not exist", e.backtrace
                end
              rescue Aws::EC2::Errors::InvalidPermissionDuplicate => e
                MU.log "Attempt to add duplicate rule to #{@mu_name}", MU::DEBUG, details: ec2_rules
              end
            end
          end

        end

        #########################################################################
        # Convert our config languages description of firewall rules into Amazon's.
        # This rule structure is as defined in MU::Config.
        #########################################################################
        def convertToEc2(rules)
          ec2_rules = []
          if rules != nil
            rules.each { |rule|
              ec2_rule = Hash.new
              rule['proto'] = "tcp" if rule['proto'].nil? or rule['proto'].empty?
              ec2_rule[:ip_protocol] = rule['proto']

              p_start = nil
              p_end = nil
              if rule['port_range']
                p_start, p_end = rule['port_range'].split(/\s*-\s*/)
              elsif rule['port']
                p_start = rule['port']
                p_end = rule['port']
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
                raise MuError, "One of 'hosts', 'sgs', or 'lbs' in rules provided to createEc2SG must be an array."
              end
              ec2_rule[:ip_ranges] = []
              ec2_rule[:user_id_group_pairs] = []

              if !rule['hosts'].nil?
                rule['hosts'].each { |cidr|
                  next if cidr.nil? # XXX where is that coming from?
                  cidr = cidr + "/32" if cidr.match(/^\d+\.\d+\.\d+\.\d+$/)
                  ec2_rule[:ip_ranges] << {cidr_ip: cidr}
                }
              end

              if !rule['lbs'].nil?
# XXX This is a dopey place for this, dependencies() should be doing our legwork
                rule['lbs'].each { |lb_name|
# XXX The language for addressing ELBs should be as flexible as VPCs. This sauce
# is weak.
# Try to find one by name in this deploy
                  found = MU::MommaCat.findStray("AWS", "loadbalancers",
                                                 name: lb_name,
                                                 deploy_id: @deploy.deploy_id
                  )
                  # Ok, let's try it with the name being an AWS identifier
                  if found.nil? or found.size < 1
                    found = MU::MommaCat.findStray("AWS", "loadbalancers",
                                                   cloud_id: lb_name,
                                                   dummy_ok: true
                    )
                    if found.nil? or found.size < 1
                      raise MuError, "Couldn't find a LoadBalancer with #{lb_name} for #{@mu_name}"
                    end
                  end
                  lb = found.first
                  lb.cloud_desc.security_groups.each { |lb_sg|
                    ec2_rule[:user_id_group_pairs] << {
                        user_id: MU.account_number,
                        group_id: lb_sg
                    }
                  }
                }
              end

              if !rule['sgs'].nil?
                rule['sgs'].each { |sg_name|
                  dependencies # Make sure our cache is fresh
                  if @dependencies.has_key?("firewall_rule") and
                      @dependencies["firewall_rule"].has_key?(sg_name)
                    sg = @dependencies["firewall_rule"][sg_name]
                  else
                    if sg_name.match(/^sg-/)
                      found_sgs = MU::MommaCat.findStray("AWS", "firewall_rule", cloud_id: sg_name, region: @config['region'], calling_deploy: @deploy, dummy_ok: true)
                    else
                      found_sgs = MU::MommaCat.findStray("AWS", "firewall_rule", name: sg_name, region: @config['region'], calling_deploy: @deploy)
                    end
                    if found_sgs.nil? or found_sgs.size == 0
                      raise MuError, "Attempted to reference non-existing Security Group #{sg_name} while building #{@mu_name}"
                    end
                    sg = found_sgs.first
                  end
                  ec2_rule[:user_id_group_pairs] << {
                      user_id: MU.account_number,
                      group_id: sg.cloud_id
                  }
                }
              end

              if !ec2_rule[:user_id_group_pairs].nil? and
                  ec2_rule[:user_id_group_pairs].size > 0 and
                  !ec2_rule[:ip_ranges].nil? and
                  ec2_rule[:ip_ranges].size > 0
                MU.log "Cannot specify ip_ranges and user_id_group_pairs", MU::ERR
                raise MuError, "Cannot specify ip_ranges and user_id_group_pairs"
              end

              ec2_rule.delete(:ip_ranges) if ec2_rule[:ip_ranges].size == 0
              ec2_rule.delete(:user_id_group_pairs) if ec2_rule[:user_id_group_pairs].size == 0

              if !ec2_rule[:user_id_group_pairs].nil? and
                  ec2_rule[:user_id_group_pairs].size > 0
                ec2_rule.delete(:ip_ranges)
              elsif !ec2_rule[:ip_ranges].nil? and
                  ec2_rule[:ip_ranges].size > 0
                ec2_rule.delete(:user_id_group_pairs)
              end
              ec2_rules << ec2_rule
            }
          end
          return ec2_rules
        end

      end #class
    end #class
  end
end #module
