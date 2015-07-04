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
			regions = MU::Cloud::AWS.ec2.describe_regions().regions.map{ |region| region.region_name }

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
			MU::Cloud::AWS.listRegions.each { |region|
				MU.log "Replicating #{keyname} to EC2 in #{region}", MU::DEBUG, details: @ssh_public_key
				MU::Cloud::AWS.ec2(region).import_key_pair(
					key_name: keyname,
					public_key_material: public_key
				)
			}
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
		def self.cloudtrails(region = MU.curRegion)
			region ||= MU.myRegion
			@@cloudtrails_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "CloudTrail", region: region)
			@@cloudtrails_api[region]
		end
		
		# Amazon's CloudWatch API
		def self.cloudwatch(region = MU.curRegion)
			region ||= MU.myRegion
			@@cloudwatch_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "CloudWatch", region: region)
			@@cloudwatch_api[region]
		end

		# Amazon's CloudFront API
		def self.cloudfront(region = MU.curRegion)
			region ||= MU.myRegion
			@@cloudfront_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "CloudFront", region: region)
			@@cloudfront_api[region]
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

			# Catch-all for AWS client methods. Essentially a pass-through with some
			# rescues for known silly endpoint behavior.
			def method_missing(method_sym, *arguments)
				retries = 0
				begin
					MU.log "Calling #{method_sym} in #{@region}", MU::DEBUG, details: arguments
					if !arguments.nil? and arguments.size == 1
						return @api.method(method_sym).call(arguments[0])
					elsif !arguments.nil? and arguments.size > 0
						return @api.method(method_sym).call(*arguments)
					else
						return @api.method(method_sym).call
					end
				rescue Aws::EC2::Errors::InternalError, Aws::EC2::Errors::RequestLimitExceeded, Aws::EC2::Errors::Unavailable, Aws::Route53::Errors::Throttling, Aws::ElasticLoadBalancing::Errors::HttpFailureException => e
					retries = retries + 1
					debuglevel = MU::DEBUG
					interval = 5 + Random.rand(4) - 2
					if retries < 5 and retries > 2
						debuglevel = MU::NOTICE
						interval = 10 + Random.rand(6) - 3
					else
						debuglevel = MU::WARN
						interval = 20 + Random.rand(10) - 5
					end
					MU.log "Got #{e.inspect} calling EC2's #{method_sym} in #{@region}, waiting #{interval.to_s}s and retrying", debuglevel, details: arguments
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
		@@cloudtrails_api = {}
		@@cloudwatch_api = {}
		@@cloudfront_api = {}
		@@cloudfront_api = {}

	end
	end
end
