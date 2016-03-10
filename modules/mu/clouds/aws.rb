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

require "net/http"
module MU
  class Cloud
    # Support for Amazon Web Services as a provisioning layer.
    class AWS

      @@cloudformation_mode = false

      # Toggle ourselves into a mode that will emit a CloudFormation template
      # instead of actual infrastructure.
      # @param set [Boolean]: Set the mode
      # @return [Boolean]: The Availability Zones in this region.
      def self.emitCloudformation(set: @@cloudformation_mode)
        @@cloudformation_mode = set
        @@cloudformation_mode
      end

      # Generate and return a skeletal CloudFormation resource entry for the
      # caller.
      # param type [String]: The resource type, in Mu parlance
      # param cloudobj [MU::Clouds::AWS]: The resource object
      # param name [String]: An alternative name for resources which are not first-class Mu classes with their own objects
      def self.cloudFormationBase(type, cloudobj = nil, name: nil)
        desc = {}
        tags = []
        MU::MommaCat.listStandardTags.each_pair { |key, val|
          next if ["MU-OWNER", "MU-MASTER-IP", "MU-MASTER-NAME"].include?(key)
          if key == "MU-ID"
            val = { "Fn::Join" => ["", [{ "Ref" => "AWS::StackName" }, "-", { "Ref" => "Environment" }, "-", { "Ref" => "DeployID" } ] ] }
          elsif key == "MU-ENV"
            val =  { "Ref" => "Environment" }
          end
          tags << { "Key" => key, "Value" => val }
        }

        res_name = ""
        res_name = cloudobj.config["name"] if !cloudobj.nil?
        if name.nil?
          nametag = { "Fn::Join" => ["", [{ "Ref" => "AWS::StackName" }, "-", { "Ref" => "Environment" }, "-", { "Ref" => "DeployID" }, "-", res_name.gsub(/[^a-z0-9]/i, "").upcase ] ] }
          basename = ""
          basename = cloudobj.mu_name if !cloudobj.nil? and !cloudobj.mu_name.nil?
          name = (type+basename).gsub!(/[^a-z0-9]/i, "")
          tags << { "Key" => "Name", "Value" => nametag }
        else
          name = (type+name).gsub(/[^a-z0-9]/i, "")
        end

        case type
        when "vpc"
          desc = {
            "Type" => "AWS::EC2::VPC",
            "Properties" => {
              "Tags" => tags
            }
          }
        when "subnet"
          desc = {
            "Type" => "AWS::EC2::Subnet",
            "Properties" => {
              "Tags" => tags
            }
          }
        when "vpcgwattach"
          desc = {
            "Type" => "AWS::EC2::VPCGatewayAttachment",
            "Properties" => {
            }
          }
        when "loggroup"
          desc = {
            "Type" => "AWS::EC2::LogGroup",
            "Properties" => {
            }
          }
        when "igw"
          desc = {
            "Type" => "AWS::EC2::InternetGateway",
            "Properties" => {
              "Tags" => tags
            }
          }
        when "rtb"
          desc = {
            "Type" => "AWS::EC2::RouteTable",
            "Properties" => {
              "Tags" => tags
            }
          }
        when "rtbassoc"
          desc = {
            "Type" => "AWS::EC2::SubnetRouteTableAssociation",
            "Properties" => {
            }
          }
        when "route"
          desc = {
            "Type" => "AWS::EC2::Route",
            "Properties" => {
            }
          }
        when "database"
          desc = {
            "Type" => "AWS::RDS::DBInstance",
            "Properties" => {
              "Tags" => tags,
              "VPCSecurityGroups" => [],
              "DBSecurityGroups" => []
            }
          }
        when "dbsubnetgroup"
          desc = {
            "Type" => "AWS::RDS::DBSubnetGroup",
            "Properties" => {
              "Tags" => tags,
              "SubnetIds" => []
            }
          }
        when "server"
          desc = {
            "Type" => "AWS::EC2::Instance",
            "Properties" => {
              "Volumes" => [],
              "Tags" => tags,
              "SecurityGroupIds" => [],
              "BlockDeviceMappings" => []
            }
          }
        when "launch_config"
          desc = {
            "Type" => "AWS::AutoScaling::LaunchConfiguration",
            "Properties" => {
              "SecurityGroups" => [],
              "BlockDeviceMappings" => []
            }
          }
        when "server_pool"
          pool_tags = tags.dup
          pool_tags.each { |tag|
            tag["PropagateAtLaunch"] = true
          }
          desc = {
            "Type" => "AWS::AutoScaling::AutoScalingGroup",
            "Properties" => {
              "Tags" => pool_tags,
              "AvailabilityZones" => [],
              "VPCZoneIdentifier" => [],
              "LoadBalancerNames" => []
            }
          }
        when "loadbalancer"
          desc = {
            "Type" => "AWS::ElasticLoadBalancing::LoadBalancer",
            "Properties" => {
              "Tags" => tags,
              "SecurityGroups" => [],
              "LBCookieStickinessPolicy" => [],
              "Subnets" => [],
              "Listeners" => []
            }
          }
        when "firewall_rule"
          desc = {
            "Type" => "AWS::EC2::SecurityGroup",
            "Properties" => {
              "Tags" => tags,
              "SecurityGroupIngress" => []
            }
          }
        when "volume"
          desc = {
            "Type" => "AWS::EC2::Volume",
            "Properties" => {
              "Tags" => tags
            }
          }
        when "eip"
          desc = {
            "Type" => "AWS::EC2::EIP",
            "Properties" => {
            }
          }
        when "eipassoc"
          desc = {
            "Type" => "AWS::EC2::EIPAssociation",
            "Properties" => {
            }
          }
        when "iamprofile"
          desc = {
            "Type" => "AWS::IAM::InstanceProfile",
            "Properties" => {
              "Path" => "/",
              "Roles" => [],
            }
          }
        when "iamrole"
          desc = {
            "Type" => "AWS::IAM::Role",
            "Properties" => {
              "Path" => "/",
              "Policies" => [],
              "AssumeRolePolicyDocument" => JSON.parse('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":["ec2.amazonaws.com"]},"Action":["sts:AssumeRole"]}]}')
            }
          }
        else
          MU.log "Dunno how to make a CloudFormation chunk for #{type} yet", MU::WARN
          return
        end
        desc["DependsOn"] = []
        if !cloudobj.nil? and cloudobj.respond_to?(:dependencies) and type != "subnet"
          cloudobj.dependencies(use_cache: true).first.each_pair { |resource_classname, resources|
            resources.each_pair { |sibling_name, sibling_obj|
              desc["DependsOn"] << (resource_classname+sibling_obj.cloudobj.mu_name).gsub!(/[^a-z0-9]/i, "")
              # Common resource-specific references to dependencies
              if resource_classname == "firewall_rule"
                if type == "database" and cloudobj.config.has_key?("vpc")
                  desc["Properties"]["VPCSecurityGroups"] << { "Fn::GetAtt" => [(resource_classname+sibling_obj.cloudobj.mu_name).gsub!(/[^a-z0-9]/i, ""), "GroupId"] }
                else
                  ["SecurityGroupIds", "SecurityGroups"].each { |key|
                    if desc["Properties"].has_key?(key)
                      desc["Properties"][key] << { "Fn::GetAtt" => [(resource_classname+sibling_obj.cloudobj.mu_name).gsub!(/[^a-z0-9]/i, ""), "GroupId"] }
                    end
                  }
                end
              elsif resource_classname == "loadbalancer"
                if desc["Properties"].has_key?("LoadBalancerNames")
                  desc["Properties"]["LoadBalancerNames"] << { "Ref" => (resource_classname+sibling_obj.cloudobj.mu_name).gsub!(/[^a-z0-9]/i, "") }
                end
              end
            }
          }
        end
        return [name, { name => desc }]
      end

      def self.setCloudFormationProp(resource, name, value)
        realvalue = value
        if value.class.to_s == "MU::Config::Tail"
          realvalue = { "Ref" => "#{value.getPrettyName}" }
        end

        if resource.has_key?(name)
          if resource[name].is_a?(Array)
            resource[name] << realvalue
            resource[name].uniq!
          else
            resource[name] = realvalue
          end
        elsif !resource["Properties"][name].nil? and resource["Properties"][name].is_a?(Array)
          resource["Properties"][name] << realvalue
          resource["Properties"][name].uniq!
        else
          resource["Properties"][name] = realvalue
        end
      end

      # Generate a CloudFormation template that mimics what the "real" output
      # of this deployment would be.
      # @param tails [Array<MU::Config::Tail>]: Mu configuration "tails," which we turn into template parameters
      # @param config [Hash]: The fully resolved Basket of Kittens for this deployment
      # @param path [String]: An output path for the resulting template.
      def self.writeCloudFormationTemplate(tails: MU::Config.tails, config: {}, path: nil)
        cfm_template = {
          "AWSTemplateFormatVersion" => "2010-09-09",
          "Description" =>  "Automatically generated by Mu",
          "Parameters" => {
            "DeployID" => {
              "Description" => "A string to differentiate individual deployments of this stack when tagging.",
              "Type" => "String",
              "MinLength" => "1",
              "MaxLength" => "25"
            },
            "Environment" => {
              "Description" => "Typically DEV or PROD, this may be used at the application level to control certain behaviors.",
              "Type" => "String",
              "Default" => MU.environment,
              "MinLength" => "1",
              "MaxLength" => "25"
            },
# XXX only require this if we have a Server or ServerPool in this stack
            "SSHKeyName" => {
              "Description" => "Name of an existing EC2 KeyPair to enable SSH access to hosts",
              "Type" => "AWS::EC2::KeyPair::KeyName"#,
            }
          },
          "Resources" => {}
        }
        tails.each_pair { |param, data|
          cfm_template["Parameters"][data.getPrettyName] = {
            "Type" => data.getCloudType,
#            "MinLength" => "1",
#            "MaxLength" => "64",
            "Default" => data.to_s
          }
        }
        MU::Cloud.resource_types.each { |cloudclass, data|
          if !config[data[:cfg_plural]].nil? and
              config[data[:cfg_plural]].size > 0
            config[data[:cfg_plural]].each { |resource|
              if resource['#MUOBJECT'].cloudobj.respond_to?(:cfm_template) and !resource['#MUOBJECT'].cloudobj.cfm_template.nil?
                cfm_template["Resources"].merge!(resource['#MUOBJECT'].cloudobj.cfm_template)
              end
            }
          end
        }
        if path.nil? or path == "-"
          puts JSON.pretty_generate(cfm_template)
        elsif path.match(/^s3:\/\/(.+?)\/(.*)/i)
          bucket = $1
          target = $2
          MU.log "Writing CloudFormation template to S3 bucket #{bucket} path /#{target}"
          resp = MU::Cloud::AWS.s3.list_buckets
          uploaded = false
          resp.buckets.each { |b|
            if b['name'] == bucket
              MU::Cloud::AWS.s3.put_object(
                acl: "public-read",
                bucket: bucket,
                key: target,
                body: JSON.pretty_generate(cfm_template)
              )
              uploaded = true
              break
            end
          }
          if !uploaded
            MU.log "Failed to write CloudFormation template to #{path}", MU::ERR
            path = "/tmp/cloudformation-#{MU.deploy_id}.json"
            MU.log "Writing to #{path}", MU::WARN
            template = File.new(path, File::CREAT|File::TRUNC|File::RDWR, 0400)
            template.puts JSON.pretty_generate(cfm_template)
            template.close
          end
        else
          MU.log "Writing CloudFormation template to local file #{path}"
          template = File.new(path, File::CREAT|File::TRUNC|File::RDWR, 0400)
          template.puts JSON.pretty_generate(cfm_template)
          template.close
        end
      end

      # List the Availability Zones associated with a given Amazon Web Services
      # region. If no region is given, search the one in which this MU master
      # server resides.
      # @param region [String]: The region to search.
      # @return [Array<String>]: The Availability Zones in this region.
      def self.listAZs(region = MU.curRegion)
        if region
          azs = MU::Cloud::AWS.ec2(region).describe_availability_zones(
              filters: [name: "region-name", values: [region]]
          )
        else
          azs = MU::Cloud::AWS.ec2(region).describe_availability_zones
        end
        zones = Array.new
        azs.data.availability_zones.each { |az|
          zones << az.zone_name if az.state == "available"
        }
        return zones
      end


      # List the Amazon Web Services region names available to this account. The
      # region that is local to this Mu server will be listed first.
      # @return [Array<String>]
      def self.listRegions
        regions = MU::Cloud::AWS.ec2.describe_regions().regions.map { |region| region.region_name }

#			regions.sort! { |a, b|
#				val = a <=> b
#				if a == MU.myRegion
#					val = -1
#				elsif b == MU.myRegion
#					val = 1
#				end
#				val
#			}

        return regions
      end

      # Generate an EC2 keypair unique to this deployment, given a regular
      # OpenSSH-style public key and a name.
      # @param keyname [String]: The name of the key to create.
      # @param public_key [String]: The public key
      # @return [Array<String>]: keypairname, ssh_private_key, ssh_public_key
      def self.createEc2SSHKey(keyname, public_key)
        # We replicate this key in all regions
        if !MU::Cloud::AWS.emitCloudformation
          MU::Cloud::AWS.listRegions.each { |region|
            MU.log "Replicating #{keyname} to EC2 in #{region}", MU::DEBUG, details: @ssh_public_key
            MU::Cloud::AWS.ec2(region).import_key_pair(
                key_name: keyname,
                public_key_material: public_key
            )
          }
        end
      end

      # Amazon's IAM API
      def self.iam(region = MU.curRegion)
        region ||= MU.myRegion
        @@iam_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "IAM", region: region)
        @@iam_api[region]
      end

      # Amazon's EC2 API
      def self.ec2(region = MU.curRegion)
        region ||= MU.myRegion
        @@ec2_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "EC2", region: region)
        @@ec2_api[region]
      end

      # Amazon's Autoscaling API
      def self.autoscale(region = MU.curRegion)
        region ||= MU.myRegion
        @@autoscale_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "AutoScaling", region: region)
        @@autoscale_api[region]
      end

      # Amazon's ElasticLoadBalancing API
      def self.elb(region = MU.curRegion)
        region ||= MU.myRegion
        @@elb_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "ElasticLoadBalancing", region: region)
        @@elb_api[region]
      end

      # Amazon's Route53 API
      def self.route53(region = MU.curRegion)
        region ||= MU.myRegion
        @@route53_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "Route53", region: region)
        @@route53_api[region]
      end

      # Amazon's RDS API
      def self.rds(region = MU.curRegion)
        region ||= MU.myRegion
        @@rds_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "RDS", region: region)
        @@rds_api[region]
      end

      # Amazon's CloudFormation API
      def self.cloudformation(region = MU.curRegion)
        region ||= MU.myRegion
        @@cloudformation_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "CloudFormation", region: region)
        @@cloudformation_api[region]
      end

      # Amazon's S3 API
      def self.s3(region = MU.curRegion)
        region ||= MU.myRegion
        @@s3_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "S3", region: region)
        @@s3_api[region]
      end

      # Amazon's CloudTrail API
      def self.cloudtrail(region = MU.curRegion)
        region ||= MU.myRegion
        @@cloudtrail_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "CloudTrail", region: region)
        @@cloudtrail_api[region]
      end

      # Amazon's CloudWatch API
      def self.cloudwatch(region = MU.curRegion)
        region ||= MU.myRegion
        @@cloudwatch_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "CloudWatch", region: region)
        @@cloudwatch_api[region]
      end

      # Amazon's CloudWatchLogs API
      def self.cloudwatchlogs(region = MU.curRegion)
        region ||= MU.myRegion
        @@cloudwatchlogs_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "CloudWatchLogs", region: region)
        @@cloudwatchlogs_api[region]
      end

      # Amazon's CloudFront API
      def self.cloudfront(region = MU.curRegion)
        region ||= MU.myRegion
        @@cloudfront_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "CloudFront", region: region)
        @@cloudfront_api[region]
      end

      # Amazon's ElastiCache API
      def self.elasticache(region = MU.curRegion)
        region ||= MU.myRegion
        @@elasticache_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "ElastiCache", region: region)
        @@elasticache_api[region]
      end
      
      # Amazon's SNS API
      def self.sns(region = MU.curRegion)
        region ||= MU.myRegion
        @@sns_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "SNS", region: region)
        @@sns_api[region]
      end

      # Fetch an Amazon instance metadata parameter (example: public-ipv4).
      # @param param [String]: The parameter name to fetch
      # @return [String, nil]
      def self.getAWSMetaData(param)
        base_url = "http://169.254.169.254/latest/meta-data/"
        begin
          response = Net::HTTP.get_response(URI("#{base_url}/#{param}"))
          response.value
        rescue Net::HTTPServerException => e
          # This is fairly normal, just handle it gracefully
          logger = MU::Logger.new
          logger.log "Failed metadata request #{base_url}/#{param}: #{e.inspect}", MU::DEBUG
          return nil
        end

        return response.body
      end

      @syslog_port_semaphore = Mutex.new
      # Punch AWS security group holes for client nodes to talk back to us, the
      # Mu Master, if we're in AWS.
      # @return [void]
      def self.openFirewallForClients
        MU::Cloud.loadCloudType("AWS", :FirewallRule)
        if File.exists?(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
          ::Chef::Config.from_file(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
        end
        ::Chef::Config[:environment] = MU.environment

        # This is the set of (TCP) ports we're opening to clients. We assume that
        # we can and and remove these without impacting anything a human has
        # created.

        my_ports = [10514]

        my_instance_id = MU::Cloud::AWS.getAWSMetaData("instance-id")
        my_client_sg_name = "Mu Client Rules for #{MU.mu_public_ip}"
        my_sgs = Array.new

        MU.setVar("curRegion", MU.myRegion) if !MU.myRegion.nil?

        resp = MU::Cloud::AWS.ec2.describe_instances(instance_ids: [my_instance_id])
        instance = resp.reservations.first.instances.first

        instance.security_groups.each { |sg|
          my_sgs << sg.group_id
        }
        resp = MU::Cloud::AWS.ec2.describe_security_groups(
            group_ids: my_sgs,
            filters: [
                {name: "tag:MU-MASTER-IP", values: [MU.mu_public_ip]},
                {name: "tag:Name", values: [my_client_sg_name]}
            ]
        )

        if resp.nil? or resp.security_groups.nil? or resp.security_groups.size == 0
          if instance.vpc_id.nil?
            sg_id = my_sgs.first
            resp = MU::Cloud::AWS.ec2.describe_security_groups(group_ids: [sg_id])
            group = resp.security_groups.first
            MU.log "We don't have a security group named '#{my_client_sg_name}' available, and we are in EC2 Classic and so cannot create a new group. Defaulting to #{group.group_name}.", MU::NOTICE
          else
            group = MU::Cloud::AWS.ec2.create_security_group(
                group_name: my_client_sg_name,
                description: my_client_sg_name,
                vpc_id: instance.vpc_id
            )
            sg_id = group.group_id
            my_sgs << sg_id
            MU::MommaCat.createTag sg_id, "Name", my_client_sg_name
            MU::MommaCat.createTag sg_id, "MU-MASTER-IP", MU.mu_public_ip
            MU::Cloud::AWS.ec2.modify_instance_attribute(
                instance_id: my_instance_id,
                groups: my_sgs
            )
          end
        elsif resp.security_groups.size == 1
          sg_id = resp.security_groups.first.group_id
          resp = MU::Cloud::AWS.ec2.describe_security_groups(group_ids: [sg_id])
          group = resp.security_groups.first
        else
          MU.log "Found more than one security group named #{my_client_sg_name}, aborting", MU::ERR
          exit 1
        end

        begin
          MU.log "Using AWS Security Group '#{group.group_name}' (#{sg_id})"
        rescue NoMethodError
          MU.log "Using AWS Security Group #{sg_id}"
        end

        allow_ips = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        MU::MommaCat.listAllNodes.each_pair { |node, data|
          ["public_ip_address"].each { |key|
            if data.has_key?(key) and !data[key].nil? and !data[key].empty?
              allow_ips << data[key] + "/32"
            end
          }
        }
        allow_ips.uniq!

        @syslog_port_semaphore.synchronize {
          my_ports.each { |port|
            begin
              group.ip_permissions.each { |rule|
                if rule.ip_protocol == "tcp" and
                    rule.from_port == port and rule.to_port == port
                  MU.log "Revoking old rules for port #{port.to_s} from #{sg_id}", MU::NOTICE
                  begin
                    MU::Cloud::AWS.ec2(MU.myRegion).revoke_security_group_ingress(
                        group_id: sg_id,
                        ip_permissions: [
                            {
                                ip_protocol: "tcp",
                                from_port: port,
                                to_port: port,
                                ip_ranges: MU.structToHash(rule.ip_ranges)
                            }
                        ]
                    )
                  rescue Aws::EC2::Errors::InvalidPermissionNotFound => e
                    MU.log "Permission disappeared from #{sg_id} (port #{port.to_s}) before I could remove it", MU::WARN, details: MU.structToHash(rule.ip_ranges)
                  end
                end
              }
            rescue NoMethodError
# XXX this is ok
            end
            MU.log "Adding current IP list to allow rule for port #{port.to_s} in #{sg_id}", details: allow_ips

            allow_ips_cidr = []
            allow_ips.each { |cidr|
              allow_ips_cidr << {"cidr_ip" => cidr}
            }

            begin
              MU::Cloud::AWS.ec2(MU.myRegion).authorize_security_group_ingress(
                  group_id: sg_id,
                  ip_permissions: [
                      {
                          ip_protocol: "tcp",
                          from_port: 10514,
                          to_port: 10514,
                          ip_ranges: allow_ips_cidr
                      }
                  ]
              )
            rescue Aws::EC2::Errors::InvalidPermissionDuplicate => e
              MU.log "Got #{e.inspect} in MU::Cloud::AWS.openFirewallForClients", MU::WARN, details: allow_ips_cidr
            end
          }
        }
      end

      private

      # Wrapper class for the EC2 API, so that we can catch some common transient
      # endpoint errors without having to spray rescues all over the codebase.
      class Endpoint
        @api = nil
        @region = nil

        # Create an AWS API client
        # @param region [String]: Amazon region so we know what endpoint to use
        # @param api [String]: Which API are we wrapping?
        def initialize(region: MU.curRegion, api: "EC2")
          @region = region
          @api = Object.const_get("Aws::#{api}::Client").new(region: region)
        end

        @instance_cache = {}
        # Catch-all for AWS client methods. Essentially a pass-through with some
        # rescues for known silly endpoint behavior.
        def method_missing(method_sym, *arguments)
          retries = 0
          begin
            MU.log "Calling #{method_sym} in #{@region}", MU::DEBUG, details: arguments
            retval = nil
            if !arguments.nil? and arguments.size == 1
              retval = @api.method(method_sym).call(arguments[0])
            elsif !arguments.nil? and arguments.size > 0
              retval = @api.method(method_sym).call(*arguments)
            else
              retval = @api.method(method_sym).call
            end
            return retval
          rescue Aws::EC2::Errors::InternalError, Aws::EC2::Errors::RequestLimitExceeded, Aws::EC2::Errors::Unavailable, Aws::Route53::Errors::Throttling, Aws::ElasticLoadBalancing::Errors::HttpFailureException, Aws::EC2::Errors::IncorrectState, Aws::EC2::Errors::Http503Error, Aws::AutoScaling::Errors::Http503Error, Aws::AutoScaling::Errors::InternalFailure, Aws::AutoScaling::Errors::ServiceUnavailable, Aws::Route53::Errors::ServiceUnavailable, Aws::ElasticLoadBalancing::Errors::Throttling, Aws::RDS::Errors::ClientUnavailable, Aws::Waiters::Errors::UnexpectedError => e
            retries = retries + 1
            debuglevel = MU::DEBUG
            interval = 5 + Random.rand(4) - 2
            if retries < 10 and retries > 2
              debuglevel = MU::NOTICE
              interval = 20 + Random.rand(10) - 3
            # elsif retries >= 10 and retries <= 100
            elsif retries >= 10
              debuglevel = MU::WARN
              interval = 40 + Random.rand(15) - 5
            # elsif retries > 100
              # raise MuError, "Exhausted retries after #{retries} attempts while calling EC2's #{method_sym} in #{@region}.  Args were: #{arguments}"
            end
            MU.log "Got #{e.inspect} calling EC2's #{method_sym} in #{@region}, waiting #{interval.to_s}s and retrying. Args were: #{arguments}", debuglevel, details: caller
            sleep interval
            retry
          end
        end
      end
      @@iam_api = {}
      @@ec2_api = {}
      @@autoscale_api = {}
      @@elb_api = {}
      @@route53_api = {}
      @@rds_api = {}
      @@cloudformation_api = {}
      @@s3_api = {}
      @@cloudtrail_api = {}
      @@cloudwatch_api = {}
      @@cloudwatchlogs_api = {}
      @@cloudfront_api = {}
      @@elasticache_api = {}
      @@sns_api = {}

    end
  end
end
