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
        require "mu/providers/aws/vpc"

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

            secgroup = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).create_security_group(sg_struct)
            @cloud_id = secgroup.group_id
          rescue Aws::EC2::Errors::InvalidGroupDuplicate
            MU.log "EC2 Security Group #{groupname} already exists, using it", MU::NOTICE
            filters = [{name: "group-name", values: [groupname]}]
            filters << {name: "vpc-id", values: [vpc_id]} if !vpc_id.nil?

            secgroup = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_security_groups(filters: filters).security_groups.first
            if secgroup.nil?
              raise MuError, "Failed to locate security group named #{groupname}, even though EC2 says it already exists", caller
            end
            @cloud_id = secgroup.group_id
          end

          begin
            MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_security_groups(group_ids: [secgroup.group_id])
          rescue Aws::EC2::Errors::InvalidGroupNotFound
            MU.log "#{secgroup.group_id} not yet ready, waiting...", MU::NOTICE
            sleep 10
            retry
          end

          MU::Cloud::AWS.createStandardTags(secgroup.group_id, region: @region, credentials: @credentials)
          MU::Cloud::AWS.createTag(secgroup.group_id, "Name", groupname, region: @region, credentials: @credentials)

          if @config['optional_tags']
            MU::MommaCat.listOptionalTags.each { |key, value|
              MU::Cloud::AWS.createTag(secgroup.group_id, key, value, region: @region, credentials: @credentials)
            }
          end

          if @config['tags']
            @config['tags'].each { |tag|
              MU::Cloud::AWS.createTag(secgroup.group_id, tag['key'], tag['value'], region: @region, credentials: @credentials)
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
              MU::Cloud::FirewallRule.find(cloud_id: @cloud_id, region: @region)
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
            sgs << h if h.match(/^sg-/)
          }
          if sgs.size > 0
            rule["firewall_rules"] ||= []
            rule["firewall_rules"].concat(sgs.map { |s|
              MU::Config::Ref.get(
                id: s,
                region: @region,
                credentials: @credentials,
                cloud: "AWS",
                type: "firewall_rule",
                dummy_ok: true
              )
            })
          end
          hosts = hosts - sgs
          rule["hosts"] = hosts if hosts.size > 0

          if port != nil
            port = port.to_s if !port.is_a?(String)
            rule["port"] = port
          else
            rule["port_range"] = port_range
          end
          ec2_rule = convertToEc2([rule])

          begin
            if egress
              MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).authorize_security_group_egress(
                group_id: @cloud_id,
                ip_permissions: ec2_rule
              )
            else
              MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).authorize_security_group_ingress(
                group_id: @cloud_id,
                ip_permissions: ec2_rule
              )
            end
          rescue Aws::EC2::Errors::InvalidPermissionDuplicate
            MU.log "Attempt to add duplicate rule to #{@cloud_id}", MU::DEBUG, details: ec2_rule
            # Ensure that, at least, the description field gets updated on
            # existing rules
            if comment
              if egress
                MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).update_security_group_rule_descriptions_egress(
                  group_id: @cloud_id,
                  ip_permissions: ec2_rule
                )
              else
                MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).update_security_group_rule_descriptions_ingress(
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
          "arn:"+(MU::Cloud::AWS.isGovCloud?(@region) ? "aws-us-gov" : "aws")+":ec2:"+@region+":"+MU::Cloud::AWS.credToAcct(@credentials)+":security-group/"+@cloud_id
        end

        # Locate an existing security group or groups and return an array containing matching AWS resource descriptors for those that match.
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching FirewallRules
        def self.find(**args)
          found = {}

          if !args[:cloud_id].nil? and !args[:cloud_id].empty?
            begin
              resp = MU::Cloud::AWS.ec2(region: args[:region], credentials: args[:credentials]).describe_security_groups(group_ids: [args[:cloud_id]])
              found[args[:cloud_id]] = resp.data.security_groups.first
            rescue ArgumentError => e
              MU.log "Attempting to load #{args[:cloud_id]}: #{e.inspect}", MU::WARN, details: caller
              return found
            rescue Aws::EC2::Errors::InvalidGroupNotFound => e
              MU.log "Attempting to load #{args[:cloud_id]}: #{e.inspect}", MU::DEBUG, details: caller
              return found
            end
          elsif !args[:tag_key].nil? and !args[:tag_value].nil?
            resp = MU::Cloud::AWS.ec2(region: args[:region], credentials: args[:credentials]).describe_security_groups(
              filters: [
                {name: "tag:#{args[:tag_key]}", values: [args[:tag_value]]}
              ]
            )
            if !resp.nil?
              resp.data.security_groups.each { |sg|
                found[sg.group_id] = sg
              }
            end
          else
            resp = MU::Cloud::AWS.ec2(region: args[:region], credentials: args[:credentials]).describe_security_groups
            resp.data.security_groups.each { |sg|
              found[sg.group_id] = sg
            }
          end

          found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(**_args)
          bok = {
            "cloud" => "AWS",
            "credentials" => @credentials,
            "cloud_id" => @cloud_id,
            "region" => @region
          }

          if !cloud_desc
            MU.log "toKitten failed to load a cloud_desc from #{@cloud_id}", MU::ERR, details: @config
            return nil
          end

          # Ignore groups created/managed by AWS
          if cloud_desc.group_name == "default" or
             cloud_desc.group_name.match(/^AWS-OpsWorks-/)
            return nil
          end

          # XXX identify if we'd be created by the ingress_rules of another
          # resource

          bok["name"] = cloud_desc.group_name

          if cloud_desc.vpc_id
            bok['vpc'] = MU::Config::Ref.get(
              id: cloud_desc.vpc_id,
              cloud: "AWS",
              credentials: @credentials,
              type: "vpcs",
            )
          end

          if cloud_desc.tags and !cloud_desc.tags.empty?
            bok['tags'] = MU.structToHash(cloud_desc.tags, stringify_keys: true)
            realname = MU::Adoption.tagsToName(bok['tags'])
            bok['name'] = realname if realname
          end

          if cloud_desc.ip_permissions
            bok["rules"] ||= []
            bok["rules"].concat(MU::Cloud::AWS::FirewallRule.rulesToBoK(cloud_desc.ip_permissions))
            bok["rules"].concat(MU::Cloud::AWS::FirewallRule.rulesToBoK(cloud_desc.ip_permissions_egress, egress: true))
          end

          bok
        end

        # Given a set of AWS Security Group rules, convert them back to our
        # language.
        def self.rulesToBoK(ip_permissions, egress: false)
          rules = []

          ip_permissions.each { |r|
            rule = {}
            if r.from_port and r.to_port
              if r.from_port == r.to_port
                rule["port"] = r.from_port
              elsif !(r.from_port == 0 and r.to_port == 65535)
                rule["port_range"] = r.from_port.to_s+"-"+ r.to_port.to_s
              end
            end

            if r.ip_ranges and r.ip_ranges.size > 0
              rule["hosts"] = r.ip_ranges.map { |c| c.cidr_ip }
              if r.ip_ranges.first.description
                rule["comment"] = r.ip_ranges.first.description
              end
            end

            if r.ip_protocol =="-1"
              rule["proto"] = "all"
            else
              rule["proto"] = r.ip_protocol
            end

            if !r.user_id_group_pairs.empty?
              rule["firewall_rules"] = []
              # XXX how do rules referencing LBs look from here? for us that
              # really means references to a loadbalancer's primary SG
              r.user_id_group_pairs.each { |g|
                if g.group_id == @cloud_id
                  bok['self_referencing'] = true
                  next
                end

                rule['firewall_rules'] << MU::Config::Ref.get(
                  cloud: "AWS",
                  type: "firewall_rules",
                  id: g.group_id,
                  habitat: MU::Config::Ref.get(
                    cloud: "AWS",
                    type: "habitats",
                    id: g.user_id,
                  )
                )
                if g.vpc_peering_connection_id
                  MU.log "Security Group #{self.to_s} has a rule referencing a peering connection (#{g.vpc_peering_connection_id}) and I don't know how to support that right now", MU::WARN
                  next
                end
              }
            end

            rule.delete("comment") if rule["comment"] == "Added by Mu"

            rule['egress'] = true if egress

            # Don't bother with the default egress rule
            if egress and rule['hosts'] == ["0.0.0.0/0"] and rule["proto"] == "all"
              next
            end

            rules << rule
          }

          rules
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
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          filters = if flags and flags["vpc_id"]
            [
              {name: "vpc-id", values: [flags["vpc_id"]]}
            ]
          else
            filters = [
              {name: "tag:MU-ID", values: [deploy_id]}
            ]
            if !ignoremaster
              filters << {name: "tag:MU-MASTER-IP", values: [MU.mu_public_ip]}
            end
            filters
          end

          # Some services create sneaky rogue ENIs which then block removal of
          # associated security groups. Find them and fry them.
          MU::Cloud.resourceClass("AWS", "VPC").purge_interfaces(noop, filters, region: region, credentials: credentials)

          resp = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_security_groups(
            filters: filters
          )

          resp.data.security_groups.each { |sg|
            MU.log "Revoking rules in EC2 Security Group #{sg.group_name} (#{sg.group_id})"

            if !noop
              revoke_rules(sg, region: region, credentials: credentials)
              revoke_rules(sg, egress: true, region: region, credentials: credentials)
            end
          }

          resp.data.security_groups.each { |sg|
            next if sg.group_name == "default"
            MU.log "Removing EC2 Security Group #{sg.group_name}"

            on_retry = Proc.new {
              # try to get out from under loose network interfaces with which
              # we're associated
              if sg.vpc_id
                default_sg = MU::Cloud.resourceClass("AWS", "VPC").getDefaultSg(sg.vpc_id, region: region, credentials: credentials)
                if default_sg
                  eni_resp = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_network_interfaces(
                    filters: [ {name: "group-id", values: [sg.group_id]} ]
                  )
                  if eni_resp and eni_resp.data and
                     eni_resp.data.network_interfaces
                    eni_resp.data.network_interfaces.each { |iface|
                      iface_groups = iface.groups.map { |if_sg| if_sg.group_id }
                      iface_groups.delete(sg.group_id)
                      iface_groups << default_sg if iface_groups.empty?
                      MU.log "Attempting to remove #{sg.group_id} (#{sg.group_name}) from ENI #{iface.network_interface_id}"
                      begin
                        MU::Cloud::AWS.ec2(credentials: credentials, region: region).modify_network_interface_attribute(
                          network_interface_id: iface.network_interface_id,
                          groups: iface_groups
                        )
                      rescue ::Aws::EC2::Errors::InvalidNetworkInterfaceIDNotFound
                        # fine by me
                      rescue ::Aws::EC2::Errors::AuthFailure
                        MU.log "Permission denied attempting to trim Security Group list for #{iface.network_interface_id}", MU::WARN, details: iface.groups.map { |g| g.group_name }.join(",")+" => default"
                      end
                    }
                  end
                end
              end
            }

            if !noop
              MU.retrier([Aws::EC2::Errors::DependencyViolation, Aws::EC2::Errors::InvalidGroupInUse], ignoreme: [Aws::EC2::Errors::InvalidGroupNotFound], max: 10, wait: 10, on_retry: on_retry) {
                begin
                  MU::Cloud::AWS.ec2(credentials: credentials, region: region).delete_security_group(group_id: sg.group_id)
                rescue Aws::EC2::Errors::CannotDelete => e
                  MU.log e.message, MU::WARN
                end
              }
            end

          }
        end

        def self.revoke_rules(sg, egress: false, region: MU.myregion, credentials: nil)
          holes = sg.send(egress ? :ip_permissions_egress : :ip_permissions)

          to_revoke = []

          holes.each { |hole|
            to_revoke << MU.structToHash(hole)
            to_revoke.each { |rule|
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

          if to_revoke.size > 0
            begin
              if egress
                MU::Cloud::AWS.ec2(credentials: credentials, region: region).revoke_security_group_egress(
                  group_id: sg.group_id,
                  ip_permissions: to_revoke
                )
              else
                MU::Cloud::AWS.ec2(credentials: credentials, region: region).revoke_security_group_ingress(
                  group_id: sg.group_id,
                  ip_permissions: to_revoke
                )
              end
            rescue Aws::EC2::Errors::InvalidPermissionNotFound
              MU.log "Rule in #{sg.group_id} disappeared before I could remove it", MU::WARN
            end
          end

        end
        private_class_method :revoke_rules

        # Return an AWS-specific chunk of schema commonly used in the +ingress_rules+ parameter of other resource types.
        # @return [Hash]
        def self.ingressRuleAddtlSchema
          {
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
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {
            "rules" => {
              "items" => {
                "properties" => {
                  "firewall_rules" => {
                    "type" => "array",
                    "items" => MU::Config::FirewallRule.reference
                  },
                  "sgs" => {
                    "type" => "array",
                    "items" => {
                      "description" => "DEPRECATED, use +firewall_rules+. Other AWS Security Groups; resources that are associated with this group will have this rule applied to their traffic",
                      "type" => "string"
                    }
                  },
                  "loadbalancers" => {
                    "type" => "array",
                    "items" => MU::Config::LoadBalancer.reference
                  },
                  "lbs" => {
                    "type" => "array",
                    "items" => {
                      "description" => "DEPRECATED, use +loadbalancers+. AWS Load Balancers which will have this rule applied to their traffic",
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
              rule['firewall_rules'] ||= []
              rule['sgs'].each { |sg_name|
	              if configurator.haveLitterMate?(sg_name, "firewall_rules") and sg_name != acl['name']
                  rule['firewall_rules'] << MU::Config::Ref.get(
                    type: "firewall_rule",
                    name: sg_name,
                    cloud: "AWS",
                    region: acl['region']
                  )
                elsif sg_name == acl['name']
                  acl['self_referencing'] = true
                else
                  rule['firewall_rules'] << MU::Config::Ref.get(
                    type: "firewall_rule",
                    id: sg_name,
                    cloud: "AWS",
                    region: acl['region']
                  )
                end
              }
            end
            rule.delete("sgs")

            if !rule['lbs'].nil?
              rule['loadbalancers'] ||= []
              rule['lbs'].each { |lb_name|
	              if configurator.haveLitterMate?(lb_name, "loadbalancers")
                  rule['loadbalancers'] << MU::Config::Ref.get(
                    type: "loadbalancer",
                    name: lb_name,
                    cloud: "AWS",
                    region: acl['region']
                  )
                else
                  rule['loadbalancers'] << MU::Config::Ref.get(
                    type: "loadbalancer",
                    id: lb_name,
                    cloud: "AWS",
                    region: acl['region']
                  )
                end
              }
              rule.delete("lbs")
            end

            if rule['firewall_rules']
              rule['firewall_rules'].each { |sg|
                if sg['name'] and !sg['deploy_id']
                  MU::Config.addDependency(acl, sg['name'], "firewall_rule", my_phase: "groom")
                end
              }
            end

            if rule['loadbalancers']
              rule['loadbalancers'].each { |lb|
                if lb['name'] and !lb['deploy_id']
                  MU::Config.addDependency(acl, lb['name'], "loadbalancer", their_phase: "groom")
                end
              }
            end
          }

          acl['dependencies'].uniq!
          ok
        end

        # Look up all the network interfaces using one or more security groups
        # @param sg_ids [Array<String>]
        # @param credentials [String]
        # @param region [String]
        # @return [Hash]
        def self.getAssociatedInterfaces(sg_ids, credentials: nil, region: MU.curRegion)
          found = {}
          resp = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_network_interfaces(
            filters: [
              {
                name: "group-id",
                values: sg_ids
              }
            ]
          )
          return found if !resp or !resp.network_interfaces

          resp.network_interfaces.each { |iface|
# It's not impossible to reverse-map to the resource that owns this, but most
# of the time it'll be something we can't manage directly, so let's leave it be
#MU.log iface.network_interface_id+": #{iface.attachment.instance_owner_id} (#{iface.attachment.attach_time})", MU::NOTICE, details: iface.description
            iface.groups.each { |sg|
              found[sg.group_id] ||= {}
              found[sg.group_id][iface.network_interface_id] = iface
            }
          }

          found
        end

        private

        def purge_extraneous_rules(ec2_rules, ext_permissions)
          # Purge any old rules that we're sure we created (check the comment)
          # but which are no longer configured.
          ext_permissions.each { |ext_rule|
            haverule = false
            ec2_rules.each { |rule|
              if rule[:from_port] == ext_rule[:from_port] and
                 rule[:to_port] == ext_rule[:to_port] and
                 rule[:ip_protocol] == ext_rule[:ip_protocol]
                haverule = true
                break
              end
            }
            next if haverule

            mu_comments = false
            (ext_rule[:user_id_group_pairs] + ext_rule[:ip_ranges]).each { |entry|
              if entry[:description] == "Added by Mu"
                mu_comments = true
              else
                mu_comments = false
                break
              end
            }

            if mu_comments
              ext_rule.keys.each { |k|
                if ext_rule[k].nil? or ext_rule[k] == []
                  ext_rule.delete(k)
                end
              }
              MU.log "Removing unconfigured rule in #{@mu_name}", MU::WARN, details: ext_rule
              MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).revoke_security_group_ingress(
                group_id: @cloud_id,
                ip_permissions: [ext_rule]
              )
            end
          }
        end

        #########################################################################
        # Manufacture an EC2 security group. The second parameter, rules, is an
        # "ingress_rules" structure parsed and validated by MU::Config.
        #########################################################################
        def setRules(rules, add_to_self: false, ingress: true, egress: false)
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
          return if ec2_rules.nil?

          ext_permissions = MU.structToHash(cloud_desc(use_cache: false).ip_permissions)

          purge_extraneous_rules(ec2_rules, ext_permissions)

          ec2_rules.uniq!
          ec2_rules.each { |rule|
            haverule = nil
            different = false
            ext_permissions.each { |ext_rule|
              if rule[:from_port] == ext_rule[:from_port] and
                 rule[:to_port] == ext_rule[:to_port] and
                 rule[:ip_protocol] == ext_rule[:ip_protocol]
                haverule = ext_rule
                ext_rule.keys.each { |k|
                  if ext_rule[k].nil? or ext_rule[k] == []
                    haverule.delete(k)
                  end
                  different = true if rule[k] != ext_rule[k]
                }
                break
              end
            }
            if haverule and !different
              MU.log "Security Group rule already up-to-date in #{@mu_name}", MU::DEBUG, details: rule
              next
            end

            MU.log "Setting #{ingress ? "ingress" : "egress"} rule in Security Group #{@mu_name} (#{@cloud_id})", MU::NOTICE, details: rule

            MU.retrier([Aws::EC2::Errors::InvalidGroupNotFound], max: 10, wait: 10, ignoreme: [Aws::EC2::Errors::InvalidPermissionDuplicate]) {
              if ingress
                if haverule
                  begin
                    MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).revoke_security_group_ingress(
                      group_id: @cloud_id,
                      ip_permissions: [haverule]
                    )
                  rescue Aws::EC2::Errors::InvalidPermissionNotFound
                  end
                end
                begin
                  MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).authorize_security_group_ingress(
                    group_id: @cloud_id,
                    ip_permissions: [rule]
                  )
                rescue Aws::EC2::Errors::InvalidParameterCombination => e
                  MU.log "FirewallRule #{@mu_name} had a bogus rule: #{e.message}", MU::ERR, details: rule
                  raise e
                end
              end

              if egress
                if haverule
                  begin
                    MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).revoke_security_group_egress(
                      group_id: @cloud_id,
                      ip_permissions: [haverule]
                    )
                  rescue Aws::EC2::Errors::InvalidPermissionNotFound
                  end
                end
                MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).authorize_security_group_egress(
                  group_id: @cloud_id,
                  ip_permissions: [rule]
                )
              end
            }
          }

        end

        #######################################################################
        # Convert our config languages description of firewall rules into
        # Amazon's. Our rule structure is as defined in MU::Config.
        #######################################################################
        def convertToEc2(rules)
          ec2_rules = []
          if rules != nil
            rules.uniq!

            rules.each { |rule|
              ec2_rule = {}
              rule["comment"] ||= "Added by Mu"


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
                MU.log "Can't create a TCP or UDP security group rule without specifying ports, assuming 'all'", MU::WARN, details: rule
                p_start = "0"
                p_end = "65535"
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
                 (!defined? rule['firewall_rules'] or !rule['firewall_rules'].is_a?(Array)) and
                 (!defined? rule['loadbalancers'] or !rule['loadbalancers'].is_a?(Array))
                rule['hosts'] = ["0.0.0.0/0"]
              end
              ec2_rule[:ip_ranges] = []
              ec2_rule[:user_id_group_pairs] = []

              if !rule['hosts'].nil?
                rule['hosts'].uniq!
                rule['hosts'].each { |cidr|
                  next if cidr.nil? # XXX where is that coming from?
                  cidr = cidr + "/32" if cidr.match(/^\d+\.\d+\.\d+\.\d+$/)
                  ec2_rule[:ip_ranges] << {cidr_ip: cidr, description: rule['comment']}
                }
              end

              if !rule['loadbalancers'].nil?
                rule['loadbalancers'].uniq!
                rule['loadbalancers'].each { |lb|
                  lb_ref = MU::Config::Ref.get(lb)

                  if !lb_ref.kitten or !lb_ref.kitten.cloud_desc
                    MU.log "Security Group #{@mu_name} failed to get cloud descriptor for referenced load balancer", MU::ERR, details: lb_ref
                    next
                  end

                  lb_ref.kitten.cloud_desc.security_groups.each { |lb_sg|
                    # XXX this probably has to infer things like region,
                    # credentials, etc from the load balancer ref
                    lb_sg_desc = MU::Cloud::AWS::FirewallRule.find(cloud_id: lb_sg)
                    owner_id = if lb_sg_desc and lb_sg_desc.size == 1
                      lb_sg_desc.values.first.owner_id
                    else
                      MU::Cloud::AWS.credToAcct(@credentials)
                    end
                    ec2_rule[:user_id_group_pairs] << {
                      user_id: owner_id,
                      group_id: lb_sg,
                      description: rule['comment']
                    }
                  }
                }
              end

              if !rule['firewall_rules'].nil?
                rule['firewall_rules'].uniq!
                rule['firewall_rules'].each { |sg|
                  sg_ref = MU::Config::Ref.get(sg)

                  if !sg_ref.kitten or !sg_ref.kitten.cloud_desc
                    MU.log "Security Group #{@mu_name} failed to get cloud descriptor for referenced Security Group", MU::ERR, details: sg_ref
                    next
                  end

                  ec2_rule[:user_id_group_pairs] << {
                    user_id: sg_ref.kitten.cloud_desc.owner_id,
                    group_id: sg_ref.cloud_id,
                    description: rule['comment']
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

          ec2_rules.uniq
        end

      end #class
    end #class
  end
end #module
