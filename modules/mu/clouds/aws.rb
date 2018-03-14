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
require 'open-uri'
require 'timeout'
gem 'aws-sdk-core'
autoload :Aws, "aws-sdk-core"

if !$MU_CFG or !$MU_CFG['aws'] or !$MU_CFG['aws']['access_key'] or $MU_CFG['aws']['access_key'].empty?
  ENV.delete('AWS_ACCESS_KEY_ID')
  ENV.delete('AWS_SECRET_ACCESS_KEY')
  Aws.config = {region: ENV['EC2_REGION']}
else
  Aws.config = {access_key_id: $MU_CFG['aws']['access_key'], secret_access_key: $MU_CFG['aws']['access_secret'], region: $MU_CFG['aws']['region']}
end

module MU
  class Cloud
    # Support for Amazon Web Services as a provisioning layer.
    class AWS
      @@myRegion_var = nil

      # If we've configured AWS as a provider, or are simply hosted in AWS, 
      # decide what our default region is.
      def self.myRegion
        if $MU_CFG and $MU_CFG['aws'] and $MU_CFG['aws']['region']
          @@myRegion_var ||= MU::Cloud::AWS.ec2($MU_CFG['aws']['region']).describe_availability_zones.availability_zones.first.region_name
        elsif ENV.has_key?("EC2_REGION") and !ENV['EC2_REGION'].empty?
          @@myRegion_var ||= MU::Cloud::AWS.ec2(ENV['EC2_REGION']).describe_availability_zones.availability_zones.first.region_name
        else
          # hacky, but useful in a pinch
          az_str = MU::Cloud::AWS.getAWSMetaData("placement/availability-zone")
          @@myRegion_var = az_str.sub(/[a-z]$/i, "") if az_str
        end
      end

      # Is the region we're dealing with a GovCloud region?
      # @param region [String]: The region in question, defaults to the Mu Master's local region
      def self.isGovCloud?(region = myRegion)
        region.match(/^us-gov-/)
      end

      @@azs = {}
      # List the Availability Zones associated with a given Amazon Web Services
      # region. If no region is given, search the one in which this MU master
      # server resides.
      # @param region [String]: The region to search.
      # @return [Array<String>]: The Availability Zones in this region.
      def self.listAZs(region = MU.curRegion)
        if !region.nil? and @@azs[region]
          return @@azs[region]
        end
        if region
          azs = MU::Cloud::AWS.ec2(region).describe_availability_zones(
            filters: [name: "region-name", values: [region]]
          )
        end
        @@azs[region] ||= []
        azs.data.availability_zones.each { |az|
          @@azs[region] << az.zone_name if az.state == "available"
        }
        return @@azs[region]
      end

      # Plant a Mu deploy secret into a storage bucket somewhere for so our kittens can consume it
      # @param deploy_id [String]: The deploy for which we're writing the secret
      # @param value [String]: The contents of the secret
      def self.writeDeploySecret(deploy_id, value, name = nil)
        name ||= deploy_id+"-secret"
        begin
          MU.log "Writing #{name} to S3 bucket #{MU.adminBucketName}"
          MU::Cloud::AWS.s3(myRegion).put_object(
            acl: "private",
            bucket: MU.adminBucketName,
            key: name,
            body: value
          )
        rescue Aws::S3::Errors => e
          raise MU::MommaCat::DeployInitializeError, "Got #{e.inspect} trying to write #{name} to #{MU.adminBucketName}"
        end
      end

      # Determine whether we (the Mu master, presumably) are hosted in this
      # cloud.
      # @return [Boolean]
      def self.hosted
        require 'open-uri'
        begin
          Timeout.timeout(2) do
            instance_id = open("http://169.254.169.254/latest/meta-data/instance-id").read
            return true if !instance_id.nil? and instance_id.size > 0
          end
        rescue OpenURI::HTTPError, Timeout::Error, SocketError
        end
        false
      end

      @@regions = {}
      # List the Amazon Web Services region names available to this account. The
      # region that is local to this Mu server will be listed first.
      # @param us_only [Boolean]: Restrict results to United States only
      # @return [Array<String>]
      def self.listRegions(us_only = false)
        if @@regions.size == 0
          result = MU::Cloud::AWS.ec2(myRegion).describe_regions.regions
          regions = []
          result.each { |r|
            @@regions[r.region_name] = Proc.new { listAZs(r.region_name) }
          }
        end

#			regions.sort! { |a, b|
#				val = a <=> b
#				if a == myRegion
#					val = -1
#				elsif b == myRegion
#					val = 1
#				end
#				val
#			}
        if us_only
          @@regions.keys.delete_if { |r| !r.match(/^us\-/) }.uniq
        else
          @@regions.keys.uniq
        end
      end

      # Generate an EC2 keypair unique to this deployment, given a regular
      # OpenSSH-style public key and a name.
      # @param keyname [String]: The name of the key to create.
      # @param public_key [String]: The public key
      # @return [Array<String>]: keypairname, ssh_private_key, ssh_public_key
      def self.createEc2SSHKey(keyname, public_key)
        # We replicate this key in all regions
        if !MU::Cloud::CloudFormation.emitCloudFormation
          MU::Cloud::AWS.listRegions.each { |region|
            MU.log "Replicating #{keyname} to EC2 in #{region}", MU::DEBUG, details: @ssh_public_key
            MU::Cloud::AWS.ec2(region).import_key_pair(
                key_name: keyname,
                public_key_material: public_key
            )
          }
        end
      end

      # AWS can stash API-available certificates in Amazon Certificate Manager
      # or in IAM. Rather than make people crazy trying to get the syntax
      # correct in our Baskets of Kittens, let's have a helper that tries to do
      # the right thing, and only raise an exception if we need help to
      # disambiguate.
      # @param name [String]: The name of the cert. For IAM certs this can be any IAM name; for ACM, it's usually the domain name. If multiple matches are found, or no matches, an exception is raised.
      # @param id [String]: The ARN of a known certificate. We just validate that it exists. This is ignored if a name parameter is supplied.
      # @return [String]: The ARN of a matching certificate that is known to exist. If it is an ACM certificate, we also know that it is not expired.
      def self.findSSLCertificate(name: nil, id: nil, region: myRegion)
        if name.nil? and name.empty? and id.nil? and id.empty?
          raise MuError, "Can't call findSSLCertificate without specifying either a name or an id"
        end

        if !name.nil? and !name.empty?
          matches = []
          acmcerts = MU::Cloud::AWS.acm(region).list_certificates(
            certificate_statuses: ["ISSUED"]
          )
          acmcerts.certificate_summary_list.each { |cert|
            matches << cert.certificate_arn if cert.domain_name == name
          }
          begin
            iamcert = MU::Cloud::AWS.iam.get_server_certificate(
              server_certificate_name: name
            )
          rescue Aws::IAM::Errors::ValidationError, Aws::IAM::Errors::NoSuchEntity
            # valid names for ACM certs can break here, and that's ok to ignore
          end
          if !iamcert.nil?
            matches << iamcert.server_certificate.server_certificate_metadata.arn
          end
          if matches.size == 1
            return matches.first
          elsif matches.size == 0
            raise MuError, "No IAM or ACM certificate named #{name} was found"
          elsif matches.size > 1
            raise MuError, "Multiple certificates named #{name} were found. Remove extras or use ssl_certificate_id to supply the exact ARN of the one you want to use."            
          end
        end

        if id.match(/^arn:aws:acm/)
          resp = MU::Cloud::AWS.acm(region).get_certificate(
            certificate_arn: id
          )
          if resp.nil?
            raise MuError, "No such ACM certificate '#{id}'"
          end
        elsif id.match(/^arn:aws:iam/)
          resp = MU::Cloud::AWS.iam.list_server_certificates
          if resp.nil?
            raise MuError, "No such IAM certificate '#{id}'"
          end
          resp.server_certificate_metadata_list.each { |cert|
            if cert.arn == id
              if cert.expiration < Time.now
                MU.log "IAM SSL certificate #{cert.server_certificate_name} (#{id}) is EXPIRED", MU::WARN
              end
              return id
            end
          }
          raise MuError, "No such IAM certificate '#{id}'"
        else
          raise MuError, "The format of '#{id}' doesn't look like an ARN for either Amazon Certificate Manager or IAM"
        end

        id
      end

      # Amazon Certificate Manager API
      def self.acm(region = MU.curRegion)
        region ||= myRegion
        @@acm_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "ACM", region: region)
        @@acm_api[region]
      end

      # Amazon's IAM API
      def self.iam(region = MU.curRegion)
        region ||= myRegion
        @@iam_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "IAM", region: region)
        @@iam_api[region]
      end

      # Amazon's EC2 API
      def self.ec2(region = MU.curRegion)
        region ||= myRegion
        @@ec2_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "EC2", region: region)
        @@ec2_api[region]
      end

      # Amazon's Autoscaling API
      def self.autoscale(region = MU.curRegion)
        region ||= myRegion
        @@autoscale_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "AutoScaling", region: region)
        @@autoscale_api[region]
      end

      # Amazon's ElasticLoadBalancing API
      def self.elb(region = MU.curRegion)
        region ||= myRegion
        @@elb_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "ElasticLoadBalancing", region: region)
        @@elb_api[region]
      end

      # Amazon's ElasticLoadBalancingV2 (ALB) API
      def self.elb2(region = MU.curRegion)
        region ||= myRegion
        @@elb2_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "ElasticLoadBalancingV2", region: region)
        @@elb2_api[region]
      end

      # Amazon's Route53 API
      def self.route53(region = MU.curRegion)
        region ||= myRegion
        @@route53_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "Route53", region: region)
        @@route53_api[region]
      end

      # Amazon's RDS API
      def self.rds(region = MU.curRegion)
        region ||= myRegion
        @@rds_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "RDS", region: region)
        @@rds_api[region]
      end

      # Amazon's CloudFormation API
      def self.cloudformation(region = MU.curRegion)
        region ||= myRegion
        @@cloudformation_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "CloudFormation", region: region)
        @@cloudformation_api[region]
      end

      # Amazon's S3 API
      def self.s3(region = MU.curRegion)
        region ||= myRegion
        @@s3_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "S3", region: region)
        @@s3_api[region]
      end

      # Amazon's CloudTrail API
      def self.cloudtrail(region = MU.curRegion)
        region ||= myRegion
        @@cloudtrail_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "CloudTrail", region: region)
        @@cloudtrail_api[region]
      end

      # Amazon's CloudWatch API
      def self.cloudwatch(region = MU.curRegion)
        region ||= myRegion
        @@cloudwatch_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "CloudWatch", region: region)
        @@cloudwatch_api[region]
      end

      # Amazon's Web Application Firewall API (Global, for CloudFront et al)
      def self.wafglobal(region = MU.curRegion)
        region ||= myRegion
        @@wafglobal[region] ||= MU::Cloud::AWS::Endpoint.new(api: "WAF", region: region)
        @@wafglobal[region]
      end


      # Amazon's Web Application Firewall API (Regional, for ALBs et al)
      def self.waf(region = MU.curRegion)
        region ||= myRegion
        @@waf[region] ||= MU::Cloud::AWS::Endpoint.new(api: "WAFRegional", region: region)
        @@waf[region]
      end

      # Amazon's CloudWatchLogs API
      def self.cloudwatchlogs(region = MU.curRegion)
        region ||= myRegion
        @@cloudwatchlogs_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "CloudWatchLogs", region: region)
        @@cloudwatchlogs_api[region]
      end

      # Amazon's CloudFront API
      def self.cloudfront(region = MU.curRegion)
        region ||= myRegion
        @@cloudfront_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "CloudFront", region: region)
        @@cloudfront_api[region]
      end

      # Amazon's ElastiCache API
      def self.elasticache(region = MU.curRegion)
        region ||= myRegion
        @@elasticache_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "ElastiCache", region: region)
        @@elasticache_api[region]
      end
      
      # Amazon's SNS API
      def self.sns(region = MU.curRegion)
        region ||= myRegion
        @@sns_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "SNS", region: region)
        @@sns_api[region]
      end

      # Amazon's EFS API
      def self.efs(region = MU.curRegion)
        region ||= myRegion
        @@efs_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "EFS", region: region)
        @@efs_api[region]
      end

      def self.lambda(region = MU.curRegion)
        regiom ||= myRegion
        @@lambda_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "Lambda", region: region)
        @@lambda_api[region]
      end
      
      def self.cloudwatch_events(region = MU.cureRegion)
        region ||= myRegion
        @@cloudwatch_events_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "CloudWatchEvents", region: region)
        @@cloudwatch_events_api
      end


      # Fetch an Amazon instance metadata parameter (example: public-ipv4).
      # @param param [String]: The parameter name to fetch
      # @return [String, nil]
      def self.getAWSMetaData(param)
        base_url = "http://169.254.169.254/latest/meta-data/"
        begin
          response = nil
          Timeout.timeout(2) do
            response = open("#{base_url}/#{param}").read
          end

          response
        rescue OpenURI::HTTPError, Timeout::Error, SocketError, Errno::ENETUNREACH, Net::HTTPServerException, Errno::EHOSTUNREACH => e
          # This is fairly normal, just handle it gracefully
          logger = MU::Logger.new
          logger.log "Failed metadata request #{base_url}/#{param}: #{e.inspect}", MU::DEBUG
          return nil
        end
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

        MU.setVar("curRegion", myRegion) if !myRegion.nil?

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
					next if data.nil? or !data.is_a?(Hash)
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
                    MU::Cloud::AWS.ec2(myRegion).revoke_security_group_ingress(
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
              MU::Cloud::AWS.ec2(myRegion).authorize_security_group_ingress(
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
          if region
            @api = Object.const_get("Aws::#{api}::Client").new(region: region)
          else
            @api = Object.const_get("Aws::#{api}::Client").new
          end
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
          rescue Aws::EC2::Errors::InternalError, Aws::EC2::Errors::RequestLimitExceeded, Aws::EC2::Errors::Unavailable, Aws::Route53::Errors::Throttling, Aws::ElasticLoadBalancing::Errors::HttpFailureException, Aws::EC2::Errors::IncorrectState, Aws::EC2::Errors::Http503Error, Aws::AutoScaling::Errors::Http503Error, Aws::AutoScaling::Errors::InternalFailure, Aws::AutoScaling::Errors::ServiceUnavailable, Aws::Route53::Errors::ServiceUnavailable, Aws::ElasticLoadBalancing::Errors::Throttling, Aws::RDS::Errors::ClientUnavailable, Aws::Waiters::Errors::UnexpectedError, Aws::ElasticLoadBalancing::Errors::ServiceUnavailable, Aws::ElasticLoadBalancingV2::Errors::Throttling, Seahorse::Client::NetworkingError, Aws::EC2::Errors::IncorrectInstanceState, Aws::IAM::Errors::Throttling => e
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
      @@acm_api = {}
      @@ec2_api = {}
      @@autoscale_api = {}
      @@elb_api = {}
      @@elb2_api = {}
      @@route53_api = {}
      @@rds_api = {}
      @@cloudformation_api = {}
      @@s3_api = {}
      @@cloudtrail_api = {}
      @@cloudwatch_api = {}
      @@wafglobal = {}
      @@waf = {}
      @@cloudwatchlogs_api = {}
      @@cloudfront_api = {}
      @@elasticache_api = {}
      @@sns_api = {}
      @@efs_api ={}
      @@lambda_api ={}
      @@cloudwatch_events_api = {}
    end
  end
end
