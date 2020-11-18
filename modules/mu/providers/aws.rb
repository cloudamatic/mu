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
require 'inifile'
gem 'aws-sdk-core'
autoload :Aws, "aws-sdk-core"


module MU
  class Cloud
    # Support for Amazon Web Services as a provisioning layer.
    class AWS
      @@myRegion_var = nil

      @@creds_loaded = {}

      # Module used by {MU::Cloud} to insert additional instance methods into
      # instantiated resources in this cloud layer.
      module AdditionalResourceMethods
      end

      # Is this a "real" cloud provider, or a stub like CloudFormation?
      def self.virtual?
        false
      end

      # List all AWS projects available to our credentials
      def self.listHabitats(credentials = nil, use_cache: true)
        cfg = credConfig(credentials)
        return [] if !cfg or !cfg['account_number']
        [cfg['account_number']]
      end

      # A hook that is always called just before any of the instance method of
      # our resource implementations gets invoked, so that we can ensure that
      # repetitive setup tasks (like resolving +:resource_group+ for Azure
      # resources) have always been done.
      # @param cloudobj [MU::Cloud]
      # @param _deploy [MU::MommaCat]
      def self.resourceInitHook(cloudobj, _deploy)
        class << self
          attr_reader :cloudformation_data
        end
        cloudobj.instance_variable_set(:@cloudformation_data, {})
      end

      # Load some credentials for using the AWS API
      # @param name [String]: The name of the mu.yaml AWS credential set to use. If not specified, will use the default credentials, and set the global Aws.config credentials to those.
      # @return [Aws::Credentials]
      def self.loadCredentials(name = nil)
        @@creds_loaded ||= {}

        if name.nil?
          return @@creds_loaded["#default"] if @@creds_loaded["#default"]
        else
          return @@creds_loaded[name] if @@creds_loaded[name]
        end

        cred_cfg = credConfig(name)
        if cred_cfg.nil?
          return nil
        end

        cred_obj = nil
        if cred_cfg['access_key'] and cred_cfg['access_secret'] and
          # access key and secret just sitting in mu.yaml
           !cred_cfg['access_key'].empty? and
           !cred_cfg['access_secret'].empty?
          cred_obj = Aws::Credentials.new(
            cred_cfg['access_key'], cred_cfg['access_secret']
          )
          if name.nil?
#            Aws.config = {
#              access_key_id: cred_cfg['access_key'],
#              secret_access_key: cred_cfg['access_secret'],
#              region: cred_cfg['region']
#            }
          end
        elsif cred_cfg['credentials_file'] and
              !cred_cfg['credentials_file'].empty?

          # pull access key and secret from an awscli-style credentials file
          begin
            File.read(cred_cfg["credentials_file"]) # make sure it's there
            credfile = IniFile.load(cred_cfg["credentials_file"])

            if !credfile.sections or credfile.sections.size == 0
              raise ::IniFile::Error, "No AWS profiles found in #{cred_cfg["credentials_file"]}"
            end
            data = credfile.has_section?("default") ? credfile["default"] : credfile[credfile.sections.first]
            if data["aws_access_key_id"] and data["aws_secret_access_key"]
              cred_obj = Aws::Credentials.new(
                data['aws_access_key_id'], data['aws_secret_access_key']
              )
              if name.nil?
#                Aws.config = {
#                  access_key_id: data['aws_access_key_id'],
#                  secret_access_key: data['aws_secret_access_key'],
#                  region: cred_cfg['region']
#                }
              end
            else
              MU.log "AWS credentials in #{cred_cfg["credentials_file"]} specified, but is missing aws_access_key_id or aws_secret_access_key elements", MU::WARN
            end
          rescue IniFile::Error, Errno::ENOENT, Errno::EACCES => e
            MU.log "AWS credentials file #{cred_cfg["credentials_file"]} is missing or invalid", MU::WARN, details: e.message
          end
        elsif cred_cfg['credentials'] and
              !cred_cfg['credentials'].empty?
          # pull access key and secret from a vault
          begin
            vault, item = cred_cfg["credentials"].split(/:/)
            data = if !vault or !item
              raise MuError.new "AWS #{name} credentials field value '#{cred_cfg["credentials"]}' malformed, should be vaultname:itemname", details: cred_cfg
            else
              MU::Groomer::Chef.getSecret(vault: vault, item: item).to_h
            end
            if data and data["access_key"] and data["access_secret"]
              cred_obj = Aws::Credentials.new(
                data['access_key'], data['access_secret']
              )
              if name.nil?
#                Aws.config = {
#                  access_key_id: data['access_key'],
#                  secret_access_key: data['access_secret'],
#                  region: cred_cfg['region']
#                }
              end
            else
              raise MuError.new "AWS #{name} credentials vault:item #{cred_cfg["credentials"]} specified, but is missing access_key or access_secret elements", details: cred_cfg
            end
          rescue MU::Groomer::MuNoSuchSecret
            raise MuError.new "AWS #{name} credentials vault:item #{cred_cfg["credentials"]} specified, but does not exist", details: cred_cfg
          end
        end

        if !cred_obj and hosted?
          # assume we've got an IAM profile and hope for the best
          ENV.delete('AWS_ACCESS_KEY_ID')
          ENV.delete('AWS_SECRET_ACCESS_KEY')
          retries = 0
          begin
            cred_obj = Aws::InstanceProfileCredentials.new
            if cred_obj.nil?
              retries += 1
              MU.log "Failed to fetch AWS instance profile credentials, attempt #{retries.to_s}/10", MU::WARN
              sleep 3
            end
          end while cred_obj.nil? and retries < 10
#          if name.nil?
#            Aws.config = {region: ENV['EC2_REGION']}
#          end
        end
if cred_obj.nil?
MU.log "cred_obj is nil and hosted? says #{hosted?.to_s}", MU::WARN, details: name
end

        if name.nil?
          @@creds_loaded["#default"] = cred_obj
        else
          @@creds_loaded[name] = cred_obj
        end

        cred_obj
      end

      # Any cloud-specific instance methods we require our resource
      # implementations to have, above and beyond the ones specified by
      # {MU::Cloud}
      # @return [Array<Symbol>]
      def self.required_instance_methods
        [:arn]
      end

      # Given an AWS region, check the API to make sure it's a valid one
      # @param r [String]
      # @return [String]
      def self.validate_region(r, credentials: nil)
        require "aws-sdk-ec2"
        begin
          MU::Cloud::AWS.ec2(region: r, credentials: credentials).describe_availability_zones.availability_zones.first.region_name
        rescue ::Aws::EC2::Errors::UnauthorizedOperation => e
          MU.log "Got '#{e.message}' trying to validate region #{r} (hosted: #{hosted?.to_s})", MU::ERR, details: loadCredentials(credentials)
          raise MuError, "Got '#{e.message}' trying to validate region #{r} with credentials #{credentials ? credentials : "<default>"} (hosted: #{hosted?.to_s})"
        end
      end

      # Tag an EC2 resource
      #
      # @param resource [String]: The cloud provider identifier of the resource to tag
      # @param region [String]: The cloud provider region
      # @param credentials [String]: Credentials to authorize API requests
      # @param optional [Boolean]: Whether to apply our optional generic tags
      # @param nametag [String]: A +Name+ tag to apply
      # @param othertags [Array<Hash>]: Miscellaneous custom tags, in Basket of Kittens style
      # @return [void]
      def self.createStandardTags(resource = nil, region: MU.curRegion, credentials: nil, optional: true, nametag: nil, othertags: nil)
        tags = []
        MU::MommaCat.listStandardTags.each_pair { |name, value|
          tags << {key: name, value: value} if !value.nil?
        }
        if optional
          MU::MommaCat.listOptionalTags.each { |key, value|
            tags << {key: name, value: value} if !value.nil?
          }
        end
        if nametag
          tags << { key: "Name", value: nametag }
        end
        if othertags
          othertags.each { |tag|
            tags << { key: tag['key'], value: tag['value'] }
          }
        end

        if MU::Cloud::CloudFormation.emitCloudFormation
          return tags
        end

        attempts = 0
        begin
          MU::Cloud::AWS.ec2(region: region, credentials: credentials).create_tags(
            resources: [resource],
            tags: tags
          )
        rescue Aws::EC2::Errors::ServiceError => e
          MU.log "Got #{e.inspect} tagging #{resource} in #{region}, will retry", MU::WARN, details: caller.concat(tags) if attempts > 1
          if attempts < 5
            attempts = attempts + 1
            sleep 15
            retry
          else
            raise e
          end
        end
        MU.log "Created standard tags for resource #{resource}", MU::DEBUG, details: caller

      end

      @@myVPCObj = nil

      # If we reside in this cloud, return the VPC in which we, the Mu Master, reside.
      # @return [MU::Cloud::VPC]
      def self.myVPCObj
        return @@myVPCObj if @@myVPCObj
        return nil if !hosted?
        instance = MU.myCloudDescriptor
        return nil if !instance or !instance.vpc_id
        vpc = MU::MommaCat.findStray("AWS", "vpc", cloud_id: instance.vpc_id, dummy_ok: true, no_deploy_search: true)
        return nil if vpc.nil? or vpc.size == 0
        @@myVPCObj = vpc.first
        @@myVPCObj
      end

      # If we've configured AWS as a provider, or are simply hosted in AWS, 
      # decide what our default region is.
      def self.myRegion(credentials = nil)
        return @@myRegion_var if @@myRegion_var

        if credConfig.nil? and !hosted? and !ENV['EC2_REGION']
          return nil
        end

        if $MU_CFG and $MU_CFG['aws']
          $MU_CFG['aws'].each_pair { |credset, cfg|
            next if credentials and credset != credentials
            next if !cfg['region']
            if (cfg['default'] or !@@myRegion_var) and validate_region(cfg['region'], credentials: credset)
              @@myRegion_var = cfg['region']
              break if cfg['default'] or credentials
            end
          }
        elsif ENV.has_key?("EC2_REGION") and !ENV['EC2_REGION'].empty? and
              validate_region(ENV['EC2_REGION']) and
              (
               (ENV.has_key?("AWS_SECRET_ACCESS_KEY") and ENV.has_key?("AWS_SECRET_ACCESS_KEY") ) or
               (Aws.config['access_key'] and Aws.config['access_secret'])
              )
          # Make sure this string is valid by way of the API
          @@myRegion_var = ENV['EC2_REGION']
        end

        if hosted? and !@@myRegion_var
          # hacky, but useful in a pinch (and if we're hosted in AWS)
          az_str = MU::Cloud::AWS.getAWSMetaData("placement/availability-zone")
          @@myRegion_var = az_str.sub(/[a-z]$/i, "") if az_str
        end

        @@myRegion_var
      end


      # Is the region we're dealing with a GovCloud region?
      # @param region [String]: The region in question, defaults to the Mu Master's local region
      def self.isGovCloud?(region = myRegion)
        return false if !region
        region.match(/^us-gov-/)
      end

      # @param resources [Array<String>]: The cloud provider identifier of the resource to untag
      # @param key [String]: The name of the tag to remove
      # @param value [String]: The value of the tag to remove
      # @param region [String]: The cloud provider region
      def self.removeTag(key, value, resources = [], region: myRegion)
        MU::Cloud::AWS.ec2(region: region).delete_tags(
          resources: resources,
          tags: [
            {
              key: key,
              value: value
            }
          ]
        )
      end

      @@azs = {}
      # List the Availability Zones associated with a given Amazon Web Services
      # region. If no region is given, search the one in which this MU master
      # server resides.
      # @param region [String]: The region to search.
      # @return [Array<String>]: The Availability Zones in this region.
      def self.listAZs(region: MU.curRegion, credentials: nil)
        cfg = credConfig(credentials)
        return [] if !cfg
        if !region.nil? and @@azs[region]
          return @@azs[region]
        end
        if region
          azs = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_availability_zones(
            filters: [name: "region-name", values: [region]]
          )
        end
        @@azs[region] ||= []
        azs.data.availability_zones.each { |az|
          @@azs[region] << az.zone_name if az.state == "available"
        }
        return @@azs[region]
      end

      # Do cloud-specific deploy instantiation tasks, such as copying SSH keys
      # around, sticking secrets in buckets, creating resource groups, etc
      # @param deploy [MU::MommaCat]
      def self.initDeploy(deploy)
      end

      # Purge cloud-specific deploy meta-artifacts (SSH keys, resource groups,
      # etc)
      # @param deploy_id [MU::MommaCat]
      def self.cleanDeploy(deploy_id, credentials: nil, noop: false)

        if !noop
          MU.log "Deleting s3://#{adminBucketName(credentials)}/#{deploy_id}-secret"
          MU::Cloud::AWS.s3(credentials: credentials).delete_object(
            bucket: adminBucketName(credentials),
            key: "#{deploy_id}-secret"
          )
          listRegions(credentials: credentials).each { |r|
            resp = MU::Cloud::AWS.ec2(region: r, credentials: credentials).describe_key_pairs(
              filters: [{name: "key-name", values: ["deploy-#{MU.deploy_id}"]}]
            )
            resp.data.key_pairs.each { |keypair|
              MU.log "Deleting key pair #{keypair.key_name} from #{r}"
              MU::Cloud::AWS.ec2(region: r, credentials: credentials).delete_key_pair(key_name: keypair.key_name) if !noop
            }
          }

        end
        if hosted?
          MU::Cloud::AWS.openFirewallForClients
        end
      end

      # Plant a Mu deploy secret into a storage bucket somewhere for so our kittens can consume it
      # @param deploy_id [String]: The deploy for which we're writing the secret
      # @param value [String]: The contents of the secret
      def self.writeDeploySecret(deploy_id, value, name = nil, credentials: nil)
        name ||= deploy_id+"-secret"
        begin
          MU.log "Writing #{name} to S3 bucket #{adminBucketName(credentials)}"
          MU::Cloud::AWS.s3(region: myRegion, credentials: credentials).put_object(
            acl: "private",
            bucket: adminBucketName(credentials),
            key: name,
            body: value
          )
        rescue Aws::S3::Errors => e
          raise MU::MommaCat::DeployInitializeError, "Got #{e.inspect} trying to write #{name} to #{adminBucketName(credentials)}"
        end
      end

  # Log bucket policy for enabling CloudTrail logging to our log bucket in S3.
      def self.cloudtrailBucketPolicy(credentials = nil)
        cfg = credConfig(credentials)
        policy_json = '{
      		"Version": "2012-10-17",
      		"Statement": [
      			{
      				"Sid": "AWSCloudTrailAclCheck20131101",
      				"Effect": "Allow",
              "Principal": {
                "AWS": "arn:'+(MU::Cloud::AWS.isGovCloud?(cfg['region']) ? "aws-us-gov" : "aws")+':iam::<%= MU.account_number %>:root",
                "Service": "cloudtrail.amazonaws.com"
              },
      				"Action": "s3:GetBucketAcl",
      				"Resource": "arn:'+(MU::Cloud::AWS.isGovCloud?(cfg['region']) ? "aws-us-gov" : "aws")+':s3:::'+MU::Cloud::AWS.adminBucketName(credentials)+'"
      			},
      			{
      				"Sid": "AWSCloudTrailWrite20131101",
      				"Effect": "Allow",
              "Principal": {
                "AWS": "arn:'+(MU::Cloud::AWS.isGovCloud?(cfg['region']) ? "aws-us-gov" : "aws")+':iam::'+credToAcct(credentials)+':root",
                "Service": "cloudtrail.amazonaws.com"
              },
      				"Action": "s3:PutObject",
      				"Resource": "arn:'+(MU::Cloud::AWS.isGovCloud?(cfg['region']) ? "aws-us-gov" : "aws")+':s3:::'+MU::Cloud::AWS.adminBucketName(credentials)+'/AWSLogs/'+credToAcct(credentials)+'/*",
      				"Condition": {
      					"StringEquals": {
      						"s3:x-amz-acl": "bucket-owner-full-control"
      					}
      				}
      			}
      		]
      	}'
        ERB.new(policy_json).result
      end

      @@is_in_aws = nil

      # Alias for #{MU::Cloud::AWS.hosted?}
      def self.hosted
        MU::Cloud::AWS.hosted?
      end

      # Determine whether we (the Mu master, presumably) are hosted in this
      # cloud.
      # @return [Boolean]
      def self.hosted?
        if $MU_CFG.has_key?("aws_is_hosted")
          @@is_in_aws = $MU_CFG["aws_is_hosted"]
          return $MU_CFG["aws_is_hosted"]
        end

        require 'open-uri'

        if !@@is_in_aws.nil?
          return @@is_in_aws
        end

        begin
          Timeout.timeout(4) do
            instance_id = open("http://169.254.169.254/latest/meta-data/instance-id").read
            if !instance_id.nil? and instance_id.size > 0
              @@is_in_aws = true
              region = getAWSMetaData("placement/availability-zone").sub(/[a-z]$/i, "")
              begin
                validate_region(region)
              rescue MuError
                @@creds_loaded.delete("#default")
                @@is_in_aws = false
                false
              end
              return true
            end
          end
        rescue OpenURI::HTTPError, Timeout::Error, SocketError, Errno::EHOSTUNREACH
        end

        @@is_in_aws = false
        false
      end

      # If we're running this cloud, return the $MU_CFG blob we'd use to
      # describe this environment as our target one.
      def self.hosted_config
        return nil if !hosted?
        region = getAWSMetaData("placement/availability-zone").sub(/[a-z]$/i, "")
        mac = getAWSMetaData("network/interfaces/macs/").split(/\n/)[0]
        acct_num = getAWSMetaData("network/interfaces/macs/#{mac}owner-id")
        acct_num.chomp!
        {
          "region" => region,
          "account_number" => acct_num
        }
      end

      # A non-working example configuration
      def self.config_example
        sample = hosted_config
        sample ||= {
          "region" => "us-east-1",
          "account_number" => "123456789012",
        }
#        sample["access_key"] = "AKIAIXKNI3JY6JVVJIHA"
#        sample["access_secret"] = "oWjHT+2N3veyswy7+UA5i+H14KpvrOIZlnRlxpkw"
        sample["credentials_file"] = "#{Etc.getpwuid(Process.uid).dir}/.aws/credentials"
        sample["log_bucket_name"] = "my-mu-s3-bucket"
        sample
      end

      # Return what we think of as a cloud object's habitat. In AWS, this means
      # the +account_number+ in which it's resident. If this is not applicable,
      # such as for a {Habitat} or {Folder}, returns nil.
      # @param cloudobj [MU::Cloud::AWS]: The resource from which to extract the habitat id
      # @return [String,nil]
      def self.habitat(cloudobj, nolookup: false, deploy: nil)
        @@habmap ||= {}
# XXX whaddabout config['habitat'] HNNNGH

        if cloudobj.respond_to?(:account_number) and cloudobj.account_number and
           !cloudobj.account_number.empty?
          return cloudobj.account_number
        elsif cloudobj.config and cloudobj.config['account']
          if nolookup
            return cloudobj.config['account']
          end
          if @@habmap[cloudobj.config['account']]
            return @@habmap[cloudobj.config['account']]
          end
          deploy ||= cloudobj.deploy if cloudobj.respond_to?(:deploy)

          MU.log "Incomplete implementation: MU::Cloud::AWS.habitat", MU::DEBUG, details: deploy

#          accountobj = accountLookup(cloudobj.config['account'], deploy, raise_on_fail: false)

#          if accountobj
#            @@habmap[cloudobj.config['account']] = accountobj.cloud_id
#            return accountobj.cloud_id
#          end
        end

        nil
      end


      @@my_acct_num = nil
      @@my_hosted_cfg = nil
      @@acct_to_profile_map = {}

      # Map the name of a credential set back to an AWS account number
      # @param name [String]
      def self.credToAcct(name = nil)
        creds = credConfig(name)

        if creds['account_number'] and !creds['account_number'].empty?
          return creds['account_number']
        end

        acct_num = MU::Cloud::AWS.iam(credentials: name).list_users.users.first.arn.split(/:/)[4]
        acct_num.to_s
      end

      # Return the name strings of all known sets of credentials for this cloud
      # @return [Array<String>]
      def self.listCredentials
        if !$MU_CFG['aws']
          return hosted? ? ["#default"] : nil
        end

        $MU_CFG['aws'].keys
      end 

      # Resolve the administrative S3 bucket for a given credential set, or
      # return a default.
      # @param credentials [String]
      # @return [String]
      def self.adminBucketName(credentials = nil)
        cfg = credConfig(credentials)
        return nil if !cfg
        if !cfg['log_bucket_name']
          cfg['log_bucket_name'] = $MU_CFG['hostname'] 
          MU.log "No AWS log bucket defined for credentials #{credentials}, attempting to use default of #{cfg['log_bucket_name']}", MU::WARN
        end
        resp = MU::Cloud::AWS.s3(credentials: credentials).list_buckets
        found = false
        resp.buckets.each { |b|
          if b.name == cfg['log_bucket_name']
            found = true
            break
          end
        }
        if !found
          MU.log "Attempting to create log bucket #{cfg['log_bucket_name']} for credentials #{credentials}", MU::WARN
          begin
            MU::Cloud::AWS.s3(credentials: credentials).create_bucket(bucket: cfg['log_bucket_name'], acl: "private")
          rescue Aws::S3::Errors::BucketAlreadyExists
            raise MuError, "AWS credentials #{credentials} need a log bucket, and the name #{cfg['log_bucket_name']} is unavailable. Use mu-configure to edit credentials '#{credentials}' or 'hostname'"
          end
        end

        cfg['log_bucket_name']
      end

      # Resolve the administrative S3 bucket for a given credential set, or
      # return a default.
      # @param credentials [String]
      # @return [String]
      def self.adminBucketUrl(credentials = nil)
        return nil if !credConfig(credentials)
        "s3://"+adminBucketName(credentials)+"/"
      end

      # Return the $MU_CFG data associated with a particular profile/name/set of
      # credentials. If no account name is specified, will return one flagged as
      # default. Returns nil if AWS is not configured. Throws an exception if 
      # an account name is specified which does not exist.
      # @param name [String]: The name of the key under 'aws' in mu.yaml to return
      # @return [Hash,nil]
      def self.credConfig(name = nil, name_only: false)
        # If there's nothing in mu.yaml (which is wrong), but we're running
        # on a machine hosted in AWS, *and* that machine has an IAM profile,
        # fake it with those credentials and hope for the best.
        if !$MU_CFG['aws'] or !$MU_CFG['aws'].is_a?(Hash) or $MU_CFG['aws'].size == 0
          if @@my_hosted_cfg
            return name_only ? "#default" : @@my_hosted_cfg
          end

          if hosted?
            begin
              iam_blob = getAWSMetaData("iam/info")
              if iam_blob
                iam_data = JSON.parse(iam_blob)
                if iam_data["InstanceProfileArn"] and !iam_data["InstanceProfileArn"].empty?
                  @@my_hosted_cfg = hosted_config
                  return name_only ? "#default" : @@my_hosted_cfg
                end
              end
            rescue JSON::ParserError => e
            end
          elsif ENV['AWS_ACCESS_KEY_ID'] and ENV['AWS_SECRET_ACCESS_KEY']
            env_config = {
              "region" => ENV['EC2_REGION'] || "us-east-1",
              "access_key" => ENV['AWS_ACCESS_KEY_ID'],
              "access_secret" => ENV['AWS_SECRET_ACCESS_KEY'],
              "log_bucket_name" => "mu-placeholder-bucket-name"
            }
            return name_only ? "#default" : env_config
          end

          return nil
        end

        if name.nil?
          $MU_CFG['aws'].each_pair { |set, cfg|
            if cfg['default']
              return name_only ? set : cfg
            end
          }
        else
          if $MU_CFG['aws'][name]
            return name_only ? name : $MU_CFG['aws'][name]
          elsif @@acct_to_profile_map[name.to_s]
            return name_only ? name : @@acct_to_profile_map[name.to_s]
          elsif name.is_a?(Integer) or name.match(/^\d+$/)
            # Try to map backwards from an account id, if that's what we go
            $MU_CFG['aws'].each_pair { |acctname, cfg|
              if cfg['account_number'] and name.to_s == cfg['account_number'].to_s
                return name_only ? acctname : $MU_CFG['aws'][acctname]
              end
            }

            # Check each credential sets' resident account, then
            $MU_CFG['aws'].each_pair { |acctname, cfg|
              begin
                MU::Cloud::AWS.iam(credentials: acctname).list_users.users
#             rescue ::Aws::IAM::Errors => e # XXX why does this NameError here?
              rescue StandardError => e
                MU.log e.inspect, MU::WARN, details: cfg
                next
              end
              acct_num = MU::Cloud::AWS.iam(credentials: acctname).list_users.users.first.arn.split(/:/)[4]
              cfg['account_number'] ||= acct_num.to_s
              if acct_num.to_s == name.to_s
                @@acct_to_profile_map[name.to_s] = cfg
                return name_only ? name.to_s : cfg
              end
            }
          end

          raise MuError, "AWS credential set #{name} was requested, but I see no such working credentials in mu.yaml"
        end
      end

      # Fetch the AWS account number where this Mu master resides. If it's not
      # in AWS at all, or otherwise cannot be determined, return nil.  here.
      # XXX account for Google and non-cloud situations
      # XXX this needs to be "myAccountNumber" or somesuch
      # XXX and maybe do the IAM thing for arbitrary, non-resident accounts
      def self.account_number
        return nil if credConfig.nil?
        return @@my_acct_num if @@my_acct_num
        loadCredentials
# XXX take optional credential set argument

#       begin
#          user_list = MU::Cloud::AWS.iam(region: credConfig['region']).list_users.users
##        rescue ::Aws::IAM::Errors => e # XXX why does this NameError here?
#        rescue StandardError => e
#          MU.log "Got #{e.inspect} while trying to figure out our account number", MU::WARN, details: caller
#        end
#        if user_list.nil? or user_list.size == 0
          resp = MU::Cloud::AWS.getAWSMetaData("network/interfaces/macs/")
          return nil if !resp

          mac = resp.split(/\n/)[0]
          acct_num = MU::Cloud::AWS.getAWSMetaData("network/interfaces/macs/#{mac}owner-id")
          acct_num.chomp!
#        else
#          acct_num = MU::Cloud::AWS.iam(region: credConfig['region']).list_users.users.first.arn.split(/:/)[4]
#        end
        MU.setVar("acct_num", acct_num)
        @@my_acct_num ||= acct_num
        acct_num
      end

      @@regions = {}
      @@regions_semaphore = Mutex.new
      # List the Amazon Web Services region names available to this account. The
      # region that is local to this Mu server will be listed first.
      # @param us_only [Boolean]: Restrict results to United States only
      # @return [Array<String>]
      def self.listRegions(us_only = false, credentials: nil)

        if @@regions.size == 0
          return [] if credConfig.nil?
          result = MU::Cloud::AWS.ec2(region: myRegion, credentials: credentials).describe_regions.regions
          @@regions_semaphore.synchronize {
            begin
              result.each { |r|
                @@regions[r.region_name] = Proc.new {
                  listAZs(region: r.region_name, credentials: credentials)
                }
              }
            rescue ::Aws::EC2::Errors::AuthFailure => e
              MU.log "Region #{r.region_name} throws #{e.message}, ignoring it", MU::ERR
            end
          }
        end


        regions = if us_only
          @@regions.keys.delete_if { |r| !r.match(/^us\-/) }.uniq
        else
          @@regions.keys.uniq
        end

# XXX GovCloud doesn't show up if you query a commercial endpoint... that's 
# *probably* ok for most purposes? We can't call listAZs on it from out here
# apparently, so getting around it is nontrivial
#        if !@@regions.has_key?("us-gov-west-1")
#          @@regions["us-gov-west-1"] = Proc.new { listAZs("us-gov-west-1") }
#        end

        regions.sort! { |a, b|
          val = a <=> b
          if a == myRegion
            val = -1
          elsif b == myRegion
            val = 1
          end
          val
        }
        regions
      end

      # Generate an EC2 keypair unique to this deployment, given a regular
      # OpenSSH-style public key and a name.
      # @param keyname [String]: The name of the key to create.
      # @param public_key [String]: The public key
      # @return [Array<String>]: keypairname, ssh_private_key, ssh_public_key
      def self.createEc2SSHKey(keyname, public_key, credentials: nil)
        # We replicate this key in all regions
        if !MU::Cloud::CloudFormation.emitCloudFormation
          MU::Cloud::AWS.listRegions.each { |region|
            MU.log "Replicating #{keyname} to EC2 in #{region}", MU::DEBUG, details: @ssh_public_key
            begin
              MU::Cloud::AWS.ec2(region: region, credentials: credentials).import_key_pair(
                key_name: keyname,
                public_key_material: public_key
              )
            rescue ::Aws::EC2::Errors::AuthFailure => e
              @@regions_semaphore.synchronize {
                @@regions.delete(region)
              }
              MU.log "#{region} threw #{e.message}, skipping", MU::ERR
            end
          }
        end
      end

      @@instance_types = nil
      # Query the AWS API for the list of valid EC2 instance types and some of
      # their attributes. We can use this in config validation and to help
      # "translate" machine types across cloud providers.
      # @param region [String]: Supported machine types can vary from region to region, so we look for the set we're interested in specifically
      # @return [Hash]
      def self.listInstanceTypes(region = myRegion)
        return @@instance_types if @@instance_types and @@instance_types[region]
        return {} if credConfig.nil?

        human_region = @@regionLookup[region]

        @@instance_types ||= {}
        @@instance_types[region] ||= {}

        # Pricing API isn't widely available, so ask a region we know supports
        # it
        resp = MU::Cloud::AWS.pricing(region: "us-east-1").get_products(
          service_code: "AmazonEC2",
          filters: [
            {
              field: "productFamily",
              value: "Compute Instance",
              type: "TERM_MATCH"
            },
            {
              field: "tenancy",
              value: "Shared",
              type: "TERM_MATCH"
            },
            {
              field: "location",
              value: human_region,
              type: "TERM_MATCH"
            }
          ]
        )
        resp.price_list.each { |pricing|
          data = JSON.parse(pricing)
          type = data["product"]["attributes"]["instanceType"]
          next if @@instance_types[region].has_key?(type)
          @@instance_types[region][type] = {}
          ["ecu", "vcpu", "memory", "storage"].each { |a|
            @@instance_types[region][type][a] = data["product"]["attributes"][a]
          }
          @@instance_types[region][type]["memory"].sub!(/ GiB/, "")
          @@instance_types[region][type]["memory"] = @@instance_types[region][type]["memory"].to_f
          @@instance_types[region][type]["vcpu"] = @@instance_types[region][type]["vcpu"].to_f
        }

        @@instance_types
      end

      @@certificates = {}

      # AWS can stash API-available certificates in Amazon Certificate Manager
      # or in IAM. Rather than make people crazy trying to get the syntax
      # correct in our Baskets of Kittens, let's have a helper that tries to do
      # the right thing, and only raise an exception if we need help to
      # disambiguate.
      # @param name [String]: The name of the cert. For IAM certs this can be any IAM name; for ACM, it's usually the domain name. If multiple matches are found, or no matches, an exception is raised.
      # @param id [String]: The ARN of a known certificate. We just validate that it exists. This is ignored if a name parameter is supplied.
      # @return [String]: The ARN of a matching certificate that is known to exist. If it is an ACM certificate, we also know that it is not expired.
      def self.findSSLCertificate(name: nil, id: nil, region: myRegion, credentials: nil, raise_on_missing: true)
        if (name.nil? or name.empty?) and (id.nil? or id.empty?)
          raise MuError, "Can't call findSSLCertificate without specifying either a name or an id"
        end
        if id and @@certificates[id]
          return [id, @@certificates[id]]
        end

        if !name.nil? and !name.empty?
          matches = []
          acmcerts = MU::Cloud::AWS.acm(region: region, credentials: credentials).list_certificates(
            certificate_statuses: ["ISSUED"]
          )
          acmcerts.certificate_summary_list.each { |cert|
            matches << cert.certificate_arn if cert.domain_name == name
          }
          begin
            iamcert = MU::Cloud::AWS.iam(credentials: credentials).get_server_certificate(
              server_certificate_name: name
            )
          rescue Aws::IAM::Errors::ValidationError, Aws::IAM::Errors::NoSuchEntity
            # valid names for ACM certs can break here, and that's ok to ignore
          end
          if !iamcert.nil?
            matches << iamcert.server_certificate.server_certificate_metadata.arn
          end
          if matches.size == 1
            id = matches.first
          elsif matches.size == 0
            if raise_on_missing
              raise MuError, "No IAM or ACM certificate named #{name} was found in #{region}"
            else
              return nil
            end
          elsif matches.size > 1
            raise MuError, "Multiple certificates named #{name} were found in #{region}. Remove extras or use ssl_certificate_id to supply the exact ARN of the one you want to use."            
          end
        end

        domains = []

        if id.match(/^arn:aws(?:-us-gov)?:acm/)
          resp = MU::Cloud::AWS.acm(region: region).describe_certificate(
            certificate_arn: id
          )

          if resp.nil? or resp.certificate.nil?
            raise MuError, "No such ACM certificate '#{id}'"
          end
          domains << resp.certificate.domain_name
          if resp.certificate.subject_alternative_names
            domains.concat(resp.certificate.subject_alternative_names)
          end
        elsif id.match(/^arn:aws(?:-us-gov)?:iam/)
          resp = MU::Cloud::AWS.iam.list_server_certificates
          if resp.nil?
            raise MuError, "No such IAM certificate '#{id}'"
          end
          resp.server_certificate_metadata_list.each { |cert|

            if cert.arn == id
              if cert.expiration < Time.now
                MU.log "IAM SSL certificate #{cert.server_certificate_name} (#{id}) is EXPIRED", MU::WARN
              end
              @@certificates[id] = [cert.server_certificate_name]
              return [id, [cert.server_certificate_name]]
            end
          }
          raise MuError, "No such IAM certificate '#{id}'"
        else
          raise MuError, "The format of '#{id}' doesn't look like an ARN for either Amazon Certificate Manager or IAM"
        end

        @@certificates[id] = domains.uniq
        [id, domains.uniq]
      end

      # Given a domain name and an ACM or IAM certificate identifier, sort out
      # whether the domain name is "covered" by the certificate
      # @param name [String]
      # @param cert_id [String]
      # @return [Boolean]
      def self.nameMatchesCertificate(name, cert_id)
        _id, domains = findSSLCertificate(id: cert_id)
        return false if !domains
        domains.each { |dom|
          if dom == name or
             (dom =~ /^\*/ and name =~ /.*#{Regexp.quote(dom[1..-1])}/)
            return true
          end
        }
        false
      end

      # Given a {MU::Config::Ref} block for an IAM or ACM SSL certificate,
      # look up and validate the specified certificate. This is intended to be
      # invoked from resource implementations' +validateConfig+ methods.
      # @param certblock [Hash,MU::Config::Ref]: 
      # @param region [String]: Default region to use when looking up the certificate, if its configuration block does not specify any
      # @param credentials [String]: Default credentials to use when looking up the certificate, if its configuration block does not specify any
      # @return [Boolean]
      def self.resolveSSLCertificate(certblock, region: nil, credentials: nil)
        return false if !certblock
        ok = true

        certblock['region'] ||= region if !certblock['id']
        certblock['credentials'] ||= credentials
        cert_arn, cert_domains = MU::Cloud::AWS.findSSLCertificate(
          name: certblock["name"],
          id: certblock["id"],
          region: certblock['region'],
          credentials: certblock['credentials']
        )

        if cert_arn
          certblock['id'] ||= cert_arn
        end

        ['region', 'credentials'].each { |field|
          certblock.delete(field) if certblock[field].nil?
        }

        [cert_arn, cert_domains]
      end

      # Amazon Certificate Manager API
      def self.acm(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@acm_api[credentials] ||= {}
        @@acm_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "ACM", region: region, credentials: credentials)
        @@acm_api[credentials][region]
      end

      # Amazon's IAM API
      def self.iam(credentials: nil)
        @@iam_api[credentials] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "IAM", credentials: credentials)
        @@iam_api[credentials]
      end

      # Amazon's EC2 API
      def self.ec2(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@ec2_api[credentials] ||= {}
        @@ec2_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "EC2", region: region, credentials: credentials)
        @@ec2_api[credentials][region]
      end

      # Amazon's Autoscaling API
      def self.autoscale(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@autoscale_api[credentials] ||= {}
        @@autoscale_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "AutoScaling", region: region, credentials: credentials)
        @@autoscale_api[credentials][region]
      end

      # Amazon's ElasticLoadBalancing API
      def self.elb(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@elb_api[credentials] ||= {}
        @@elb_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "ElasticLoadBalancing", region: region, credentials: credentials)
        @@elb_api[credentials][region]
      end

      # Amazon's ElasticLoadBalancingV2 (ALB) API
      def self.elb2(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@elb2_api[credentials] ||= {}
        @@elb2_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "ElasticLoadBalancingV2", region: region, credentials: credentials)
        @@elb2_api[credentials][region]
      end

      # Amazon's Route53 API
      def self.route53(credentials: nil)
        @@route53_api[credentials] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "Route53", credentials: credentials)
        @@route53_api[credentials]
      end

      # Amazon's RDS API
      def self.rds(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@rds_api[credentials] ||= {}
        @@rds_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "RDS", region: region, credentials: credentials)
        @@rds_api[credentials][region]
      end

      # Amazon's CloudFormation API
      def self.cloudformation(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@cloudformation_api[credentials] ||= {}
        @@cloudformation_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "CloudFormation", region: region, credentials: credentials)
        @@cloudformation_api[credentials][region]
      end

      # Amazon's S3 API
      def self.s3(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@s3_api[credentials] ||= {}
        @@s3_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "S3", region: region, credentials: credentials)
        @@s3_api[credentials][region]
      end

      # Amazon's CloudTrail API
      def self.cloudtrail(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@cloudtrail_api[credentials] ||= {}
        @@cloudtrail_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "CloudTrail", region: region, credentials: credentials)
        @@cloudtrail_api[credentials][region]
      end

      # Amazon's CloudWatch API
      def self.cloudwatch(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@cloudwatch_api[credentials] ||= {}
        @@cloudwatch_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "CloudWatch", region: region, credentials: credentials)
        @@cloudwatch_api[credentials][region]
      end

      # Amazon's Web Application Firewall API (Global, for CloudFront et al)
      def self.wafglobal(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@wafglobal_api[credentials] ||= {}
        @@wafglobal[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "WAF", region: region, credentials: credentials)
        @@wafglobal[credentials][region]
      end


      # Amazon's Web Application Firewall API (Regional, for ALBs et al)
      def self.waf(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@waf[credentials] ||= {}
        @@waf[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "WAFRegional", region: region, credentials: credentials)
        @@waf[credentials][region]
      end

      # Amazon's CloudWatchLogs API
      def self.cloudwatchlogs(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@cloudwatchlogs_api[credentials] ||= {}
        @@cloudwatchlogs_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "CloudWatchLogs", region: region, credentials: credentials)
        @@cloudwatchlogs_api[credentials][region]
      end

      # Amazon's CloudWatchEvents API
      def self.cloudwatchevents(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@cloudwatchevents_api[credentials] ||= {}
        @@cloudwatchevents_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "CloudWatchEvents", region: region, credentials: credentials)
        @@cloudwatchevents_api[credentials][region]
      end

      # Amazon's CloudFront API
      def self.cloudfront(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@cloudfront_api[credentials] ||= {}
        @@cloudfront_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "CloudFront", region: region, credentials: credentials)
        @@cloudfront_api[credentials][region]
      end

      # Amazon's ElastiCache API
      def self.elasticache(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@elasticache_api[credentials] ||= {}
        @@elasticache_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "ElastiCache", region: region, credentials: credentials)
        @@elasticache_api[credentials][region]
      end
      
      # Amazon's SNS API
      def self.sns(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@sns_api[credentials] ||= {}
        @@sns_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "SNS", region: region, credentials: credentials)
        @@sns_api[credentials][region]
      end
      
      # Amazon's SQS API
      def self.sqs(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@sqs_api[credentials] ||= {}
        @@sqs_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "SQS", region: region, credentials: credentials)
        @@sqs_api[credentials][region]
      end

      # Amazon's EFS API
      def self.efs(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@efs_api[credentials] ||= {}
        @@efs_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "EFS", region: region, credentials: credentials)
        @@efs_api[credentials][region]
      end

      # Amazon's Lambda API
      def self.lambda(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@lambda_api[credentials] ||= {}
        @@lambda_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "Lambda", region: region, credentials: credentials)
        @@lambda_api[credentials][region]
      end

      # Amazon's API Gateway API
      def self.apig(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@apig_api[credentials] ||= {}
        @@apig_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "APIGateway", region: region, credentials: credentials)
        @@apig_api[credentials][region]
      end
      
      # Amazon's Cloudwatch Events API
      def self.cloudwatch_events(region = MU.cureRegion)
        region ||= myRegion
        @@cloudwatch_events_api[credentials] ||= {}
        @@cloudwatch_events_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "CloudWatchEvents", region: region, credentials: credentials)
        @@cloudwatch_events_api
      end

      # Amazon's ECS API
      def self.ecs(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@ecs_api[credentials] ||= {}
        @@ecs_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "ECS", region: region, credentials: credentials)
        @@ecs_api[credentials][region]
      end

      # Amazon's EKS API
      def self.eks(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@eks_api[credentials] ||= {}
        @@eks_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "EKS", region: region, credentials: credentials)
        @@eks_api[credentials][region]
      end

      # Amazon's DynamoDB API
      def self.dynamo(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@dynamo_api[credentials] ||= {}
        @@dynamo_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "DynamoDB", region: region, credentials: credentials)
        @@dynamo_api[credentials][region]
      end

      # Amazon's DynamoStream API
      def self.dynamostream(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@dynamostream_api[credentials] ||= {}
        @@dynamostream_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "DynamoDBStreams", region: region, credentials: credentials)
        @@dynamostream_api[credentials][region]
      end

      # Amazon's Pricing API
      def self.pricing(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@pricing_api[credentials] ||= {}
        @@pricing_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "Pricing", region: region, credentials: credentials)
        @@pricing_api[credentials][region]
      end

      # Amazon's Simple Systems Manager API
      def self.ssm(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@ssm_api[credentials] ||= {}
        @@ssm_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "SSM", region: region, credentials: credentials)
        @@ssm_api[credentials][region]
      end

      # Amazon's Elasticsearch API
      def self.elasticsearch(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@elasticsearch_api[credentials] ||= {}
        @@elasticsearch_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "ElasticsearchService", region: region, credentials: credentials)
        @@elasticsearch_api[credentials][region]
      end

      # Amazon's Cognito Identity API
      def self.cognito_ident(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@cognito_ident_api[credentials] ||= {}
        @@cognito_ident_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "CognitoIdentity", region: region, credentials: credentials)
        @@cognito_ident_api[credentials][region]
      end

      # Amazon's Cognito Identity Provider API
      def self.cognito_user(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@cognito_user_api[credentials] ||= {}
        @@cognito_user_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "CognitoIdentityProvider", region: region, credentials: credentials)
        @@cognito_user_api[credentials][region]
      end

      # Amazon's KMS API
      def self.kms(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@kms_api[credentials] ||= {}
        @@kms_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "KMS", region: region, credentials: credentials)
        @@kms_api[credentials][region]
      end

      # Amazon's CloudFront API
      def self.cloudfront(region: MU.curRegion, credentials: nil)
        region ||= myRegion
        @@cloudfront_api[credentials] ||= {}
        @@cloudfront_api[credentials][region] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "CloudFront", region: region, credentials: credentials)
        @@cloudfront_api[credentials][region]
      end

      # Amazon's Organizations API
      def self.orgs(credentials: nil)
        @@organizations_api ||= {}
# XXX org api doesn't seem to work in many regions
        @@organizations_api[credentials] ||= MU::Cloud::AWS::AmazonEndpoint.new(api: "Organizations", credentials: credentials, region: "us-east-1")
        @@organizations_api[credentials]
      end

      # Fetch an Amazon instance metadata parameter (example: public-ipv4).
      # @param param [String]: The parameter name to fetch
      # @return [String, nil]
      def self.getAWSMetaData(param)
        base_url = "http://169.254.169.254/latest/meta-data/"
        begin
          response = nil
          Timeout.timeout(1) do
            response = open("#{base_url}/#{param}").read
          end

          response
        rescue OpenURI::HTTPError, Timeout::Error, SocketError, Errno::ENETUNREACH, Net::HTTPServerException, Errno::EHOSTUNREACH => e
          # This is normal on machines checking to see if they're AWS-hosted
          logger = MU::Logger.new
          logger.log "Failed metadata request #{base_url}/#{param}: #{e.inspect}", MU::DEBUG
          return nil
        end
      end

      # Tag a resource. Defaults to applying our MU deployment identifier, if no
      # arguments other than the resource identifier are given.
      #
      # @param resource [String]: The cloud provider identifier of the resource to tag
      # @param tag_name [String]: The name of the tag to create
      # @param tag_value [String]: The value of the tag
      # @param region [String]: The cloud provider region
      # @return [void]
      def self.createTag(resource = nil,
          tag_name="MU-ID",
          tag_value=MU.deploy_id,
          region: MU.curRegion,
          credentials: nil)
        attempts = 0

        return nil if resource.nil?
        resource = [resource] if resource.is_a?(String)

        if !MU::Cloud::CloudFormation.emitCloudFormation
          begin
            MU::Cloud::AWS.ec2(credentials: credentials, region: region).create_tags(
              resources: resource,
              tags: [
                {
                  key: tag_name,
                  value: tag_value
                }
              ]
            )
          rescue Aws::EC2::Errors::ServiceError => e
            MU.log "Got #{e.inspect} tagging #{resource} with #{tag_name}=#{tag_value}", MU::WARN if attempts > 1
            if attempts < 5
              attempts = attempts + 1
              sleep 15
              retry
            else
              raise e
            end
          end
          MU.log "Created tag #{tag_name} with value #{tag_value} for resource #{resource}", MU::DEBUG
        else
          return {
            "Key" =>  tag_name,
            "Value" => tag_value
          }
        end
      end

      @syslog_port_semaphore = Mutex.new
      # Punch AWS security group holes for client nodes to talk back to us, the
      # Mu Master, if we're in AWS.
      # @return [void]
      def self.openFirewallForClients
        MU::Cloud.resourceClass("AWS", :FirewallRule)
        begin
          if File.exist?(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
            ::Chef::Config.from_file(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
          end
          ::Chef::Config[:environment] = MU.environment
        rescue LoadError
          # XXX why is Chef here
        end

        # This is the set of (TCP) ports we're opening to clients. We assume that
        # we can and and remove these without impacting anything a human has
        # created.

        my_ports = [10514]

        my_instance_id = MU::Cloud::AWS.getAWSMetaData("instance-id")
        my_client_sg_name = "Mu Client Rules for #{MU.mu_public_ip}"
        my_sgs = Array.new

        MU.setVar("curRegion", myRegion) if !myRegion.nil?

        MU.myCloudDescriptor.security_groups.each { |sg|
          my_sgs << sg.group_id
        }
        resp = MU::Cloud::AWS.ec2.describe_security_groups(
          filters: [
            {name: "tag:MU-MASTER-IP", values: [MU.mu_public_ip]},
            {name: "tag:Name", values: [my_client_sg_name]}
          ]
        )

        if resp.nil? or resp.security_groups.nil? or resp.security_groups.size == 0
          if MU.myCloudDescriptor.vpc_id.nil?
            sg_id = my_sgs.first
            resp = MU::Cloud::AWS.ec2.describe_security_groups(group_ids: [sg_id])
            group = resp.security_groups.first
            MU.log "We don't have a security group named '#{my_client_sg_name}' available, and we are in EC2 Classic and so cannot create a new group. Defaulting to #{group.group_name}.", MU::NOTICE
          else
            group = MU::Cloud::AWS.ec2.create_security_group(
              group_name: my_client_sg_name,
              description: my_client_sg_name,
              vpc_id: MU.myCloudDescriptor.vpc_id
            )
            sg_id = group.group_id
            my_sgs << sg_id
            MU::Cloud::AWS.createTag sg_id, "Name", my_client_sg_name
            MU::Cloud::AWS.createTag sg_id, "MU-MASTER-IP", MU.mu_public_ip
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

        if !my_sgs.include?(sg_id)
          my_sgs << sg_id
          MU.log "Associating #{my_client_sg_name} with #{MU.myInstanceId}", MU::NOTICE
          MU::Cloud::AWS.ec2.modify_instance_attribute(
            instance_id: MU.myInstanceId,
            groups: my_sgs
          )
        end

        begin
          MU.log "Using AWS Security Group '#{group.group_name}' (#{sg_id})"
        rescue NoMethodError
          MU.log "Using AWS Security Group #{sg_id}"
        end

        allow_ips = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        MU::MommaCat.listAllNodes.values.each { |data|
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
                    MU::Cloud::AWS.ec2(region: myRegion).revoke_security_group_ingress(
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
                  rescue Aws::EC2::Errors::InvalidPermissionNotFound
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
              MU::Cloud::AWS.ec2(region: myRegion).authorize_security_group_ingress(
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

      # XXX we shouldn't have to do this, but AWS does not provide a way to look
      # it up, and the pricing API only returns the human-readable strings.
      @@regionLookup = {
        "us-east-1" => "US East (N. Virginia)",
        "us-east-2" => "US East (Ohio)",
        "us-west-1" => "US West (N. California)",
        "us-west-2" => "US West (Oregon)",
        "us-gov-west-1" => "AWS GovCloud (US)",
        "us-gov-east-1" => "AWS GovCloud (US)",
        "ap-northeast-1" => "Asia Pacific (Tokyo)",
        "ap-northeast-2" => "Asia Pacific (Seoul)",
        "ap-south-1" => "Asia Pacific (Mumbai)",
        "ap-southeast-1" => "Asia Pacific (Singapore)",
        "ap-southeast-2" => "Asia Pacific (Sydney)",
        "ca-central-1" => "Canada (Central)",
        "eu-central-1" => "EU (Frankfurt)",
        "eu-west-1" => "EU (Ireland)",
        "eu-west-2" => "EU (London)",
        "eu-west-3" => "EU (Paris)",
        "sa-east-1" => "South America (Sao Paulo)"
      }.freeze
      @@regionNameLookup = @@regionLookup.invert.freeze

      # Wrapper class for the EC2 API, so that we can catch some common transient
      # endpoint errors without having to spray rescues all over the codebase.
      class AmazonEndpoint
        @api = nil
        @region = nil
        @cred_obj = nil
        attr_reader :credentials
        attr_reader :account

        # Create an AWS API client
        # @param region [String]: Amazon region so we know what endpoint to use
        # @param api [String]: Which API are we wrapping?
        def initialize(region: nil, api: "EC2", credentials: nil)
          @cred_obj = MU::Cloud::AWS.loadCredentials(credentials)
          @credentials = MU::Cloud::AWS.credConfig(credentials, name_only: true)
          @api_name = api

          if !@cred_obj
            raise MuError, "Unable to locate valid AWS credentials for #{api} API. #{credentials ? "Credentials requested were '#{credentials}'": ""}"
          end

          params = {}
          region ||= MU::Cloud::AWS.credConfig(credentials)['region']
          region ||= MU.myRegion

          if region
            @region = region
            params[:region] = @region
          end

          params[:credentials] = @cred_obj

          MU.log "Initializing #{api} object with credentials #{credentials}", MU::DEBUG, details: params
          require "aws-sdk-#{api.downcase}"

          @api = Object.const_get("Aws::#{api}::Client").new(params)
        end

        @instance_cache = {}
        # Catch-all for AWS client methods. Essentially a pass-through with some
        # rescues for known silly endpoint behavior.
        def method_missing(method_sym, *arguments)
          # make sure error symbols are loaded for our exception handling later
          require "aws-sdk-lambda"
          require "aws-sdk-rds"
          require "aws-sdk-ec2"
          require "aws-sdk-route53"
          require "aws-sdk-iam"
          require "aws-sdk-efs"
          require "aws-sdk-pricing"
          require "aws-sdk-apigateway"
          require "aws-sdk-ecs"
          require "aws-sdk-eks"
          require "aws-sdk-cloudwatchlogs"
          require "aws-sdk-cloudwatchevents"
          require "aws-sdk-elasticloadbalancing"
          require "aws-sdk-elasticloadbalancingv2"
          require "aws-sdk-autoscaling"

          known_concats = {
            "Pricing" => {
              :get_products => :price_list
            }
          }

          retries = 0
          begin
            MU.log "Calling #{@api_name}.#{method_sym} in #{@region}", MU::DEBUG, details: arguments

              retval = if !arguments.nil? and arguments.size == 1
                @api.method(method_sym).call(arguments[0])
              elsif !arguments.nil? and arguments.size > 0
                @api.method(method_sym).call(*arguments)
              else
                @api.method(method_sym).call
              end

            if !retval.nil?
              begin
              page_markers = {
                :marker => :marker,
                :next_token => :next_token,
                :next_marker => :marker
              }
              paginator = nil
              new_page = nil
              page_markers.each_key { |m|
                if !retval.nil? and retval.respond_to?(m)
                  paginator = m
                  new_page = retval.send(m)
                  break
                end
              }

              if paginator and new_page and !new_page.empty?
                resp = retval.respond_to?(:__getobj__) ? retval.__getobj__ : retval
                concat_to = MU.structToHash(resp).keys.reject { |m|
                  m.to_s.match(/=$/) or m == paginator or resp.send(m).nil? or !resp.send(m).is_a?(Array)
                }

                if concat_to.empty? and known_concats[@api_name] and
                   known_concats[@api_name][method_sym]
                  concat_to << known_concats[@api_name][method_sym]
                end

                if concat_to.empty? and method_sym.to_s.match(/^(?:describe|list)_(.*)/)
                  my_attr = Regexp.last_match[1].to_sym
                  concat_to << my_attr if resp.respond_to?(my_attr)
                end

                if concat_to.size != 1
                  raise MuError.new "Tried to figure out where I might append paginated results for a #{@api_name}.#{method_sym}, but failed", details: MU.structToHash(resp).keys
                else
                  concat_to = concat_to.first
                  new_args = arguments ? arguments.dup : [{}]
                  begin
                    if new_args.is_a?(Array)
                      new_args << {} if new_args.empty?
                      if new_args.size == 1 and new_args.first.is_a?(Hash)
                        new_args[0][page_markers[paginator]] = new_page
                      else
                        MU.log "I don't know how to insert a #{paginator} into these arguments for #{method_sym}", MU::WARN, details: new_args
                      end
                    elsif new_args.is_a?(Hash)
                      new_args[page_markers[paginator]] = new_page
                    end

                    MU.log "Attempting magic pagination for #{method_sym}", MU::DEBUG, details: new_args

#                    resp = if !arguments.nil? and arguments.size == 1
#                      @api.method(method_sym).call(new_args[0])
#                    elsif !arguments.nil? and arguments.size > 0
                    resp = @api.method(method_sym).call(*new_args)
#                    end
                    break if resp.nil?
                    resp = resp.__getobj__ if resp.respond_to?(:__getobj__)
                    retval.send(concat_to).concat(resp.send(concat_to))
                    new_page = resp.send(paginator) if !resp.nil?
                  end while !resp.nil? and !new_page.nil? and !new_page.empty?
                end
              end
              rescue StandardError => e
                MU.log "Made a good-faith effort to auto-paginate API call to #{method_sym} and failed with #{e.message}", MU::DEBUG, details: arguments
                raise e
              end
            end

            return retval
          rescue Aws::Lambda::Errors::TooManyRequestsException, Aws::RDS::Errors::Throttling, Aws::EC2::Errors::InternalError, Aws::EC2::Errors::RequestLimitExceeded, Aws::EC2::Errors::Unavailable, Aws::Route53::Errors::Throttling, Aws::ElasticLoadBalancing::Errors::HttpFailureException, Aws::EC2::Errors::Http503Error, Aws::AutoScaling::Errors::Http503Error, Aws::AutoScaling::Errors::InternalFailure, Aws::AutoScaling::Errors::ServiceUnavailable, Aws::Route53::Errors::ServiceUnavailable, Aws::ElasticLoadBalancing::Errors::Throttling, Aws::RDS::Errors::ClientUnavailable, Aws::Waiters::Errors::UnexpectedError, Aws::ElasticLoadBalancing::Errors::ServiceUnavailable, Aws::ElasticLoadBalancingV2::Errors::Throttling, Seahorse::Client::NetworkingError, Aws::IAM::Errors::Throttling, Aws::EFS::Errors::ThrottlingException, Aws::Pricing::Errors::ThrottlingException, Aws::APIGateway::Errors::TooManyRequestsException, Aws::ECS::Errors::ThrottlingException, Net::ReadTimeout, Faraday::TimeoutError, Aws::CloudWatchLogs::Errors::ThrottlingException => e
            if e.class.name == "Seahorse::Client::NetworkingError" and e.message.match(/Name or service not known/)
              MU.log e.inspect, MU::ERR
              raise e
            end
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
            MU.log "Got #{e.inspect} calling EC2's #{method_sym} in #{@region} with credentials #{@credentials}, waiting #{interval.to_s}s and retrying. Args were: #{arguments}", debuglevel, details: caller
            sleep interval
            retry
          rescue StandardError => e
            MU.log "Got #{e.inspect} calling EC2's #{method_sym} in #{@region} with credentials #{@credentials}", MU::DEBUG, details: arguments
            raise e
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
      @@cloudwatchevents_api = {}
      @@cloudfront_api = {}
      @@elasticache_api = {}
      @@sns_api = {}
      @@sqs_api = {}
      @@efs_api ={}
      @@lambda_api ={}
      @@cloudwatch_events_api = {}
      @@apig_api ={}
      @@ecs_api ={}
      @@eks_api ={}
      @@pricing_api ={}
      @@ssm_api ={}
      @@elasticsearch_api ={}
      @@cognito_ident_api ={}
      @@cognito_user_api ={}
      @@kms_api ={}
      @@organization_api ={}
      @@dynamo_api ={}
      @@dynamostream_api ={}
      @@cloudfront_api ={}
    end
  end
end
