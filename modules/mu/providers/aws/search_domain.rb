# Copyright:: Copyright (c) 2018 eGlobalTech, Inc., all rights reserved
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
      # A search_domain as configured in {MU::Config::BasketofKittens::search_domains}
      class SearchDomain < MU::Cloud::SearchDomain

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          describe if @mu_name and !@deploydata
          @cloud_id ||= @deploydata['domain_name'] if @deploydata

          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          @config['domain_name'] = @deploy.getResourceName(@config["name"], max_length: 28, need_unique_string: true).downcase

          params = genParams

          MU.log "Creating ElasticSearch domain #{@config['domain_name']}", details: params
          @cloud_id = @config['domain_name']
          MU::Cloud::AWS.elasticsearch(region: @region, credentials: @credentials).create_elasticsearch_domain(params).domain_status

          tagDomain

        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          tagDomain
          @config['domain_name'] ||= @cloud_id
          params = genParams(cloud_desc) # get parameters that would change only

          if params.size > 1
            waitWhileProcessing # wait until the create finishes, if still going

            MU.log "Updating ElasticSearch domain #{@config['domain_name']}", MU::NOTICE, details: params
            MU::Cloud::AWS.elasticsearch(region: @region, credentials: @credentials).update_elasticsearch_domain_config(params)
          end

          waitWhileProcessing # don't return until creation/updating is complete
          MU.log "Search Domain #{@config['name']}: #{cloud_desc.endpoint}", MU::SUMMARY
        end

        @cloud_desc_cache = nil
        # Wrapper for cloud_desc method that deals with finding the AWS
        # domain_name parameter, which isn't what we'd call ourselves if we had
        # our druthers.
        def cloud_desc(use_cache: true)
          return @cloud_desc_cache if @cloud_desc_cache and use_cache
          @cloud_id ||= @config['domain_name']
          return nil if !@cloud_id
          MU.retrier([::Aws::ElasticsearchService::Errors::ResourceNotFoundException], wait: 10, max: 12) {
            @cloud_desc_cache = MU::Cloud::AWS.elasticsearch(region: @region, credentials: @credentials).describe_elasticsearch_domain(
              domain_name: @cloud_id
            ).domain_status
          }

          @cloud_desc_cache
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          return nil if !cloud_desc
          cloud_desc.arn.dup
        end

        # Return the metadata for this SearchDomain rule
        # @return [Hash]
        def notify
          return nil if !cloud_desc(use_cache: false)
          deploy_struct = MU.structToHash(cloud_desc, stringify_keys: true)
          tags = MU::Cloud::AWS.elasticsearch(region: @region, credentials: @credentials).list_tags(arn: arn).tag_list
          deploy_struct['tags'] = tags.map { |t| { t.key => t.value } }
          if deploy_struct['endpoint']
            deploy_struct['kibana'] = deploy_struct['endpoint']+"/_plugin/kibana/"
          elsif deploy_struct['endpoints']
            deploy_struct['kibana'] = {}
            deploy_struct['endpoints'].each_pair { |k, v|
              deploy_struct['kibana'][k] = v+"/_plugin/kibana/"
            }
          end
          deploy_struct['domain_name'] ||= @config['domain_name'] if @config['domain_name']
          deploy_struct
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

        # Remove all search_domains associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          MU.log "AWS::SearchDomain.cleanup: need to support flags['known']", MU::DEBUG, details: flags

          list = MU::Cloud::AWS.elasticsearch(region: region, credentials: credentials).list_domain_names
          if list and list.domain_names and list.domain_names.size > 0
            names = list.domain_names.map { |d| d.domain_name }
            begin
              # why is this API so obnoxious?
              sample = names.slice!(0, (names.length >= 5 ? 5 : names.length))
              descs = MU::Cloud::AWS.elasticsearch(region: region, credentials: credentials).describe_elasticsearch_domains(domain_names: sample)

              descs.domain_status_list.each { |domain|
                tags = MU::Cloud::AWS.elasticsearch(region: region, credentials: credentials).list_tags(arn: domain.arn)
                deploy_match = false
                master_match = false
                tags.tag_list.each { |tag|
                  if tag.key == "MU-ID" and tag.value == deploy_id
                    deploy_match = true
                  elsif tag.key == "MU-MASTER-IP" and tag.value == MU.mu_public_ip
                    master_match = true
                  end
                }
                if deploy_match and (master_match or ignoremaster)
                  MU.log "Deleting ElasticSearch Domain #{domain.domain_name}"
                  if !noop
                    MU::Cloud::AWS.elasticsearch(region: region, credentials: credentials).delete_elasticsearch_domain(domain_name: domain.domain_name)
                  end
                end
              }
            end while names.size > 0
          end

          unless noop
            marker = nil
            begin
              resp = MU::Cloud::AWS.iam(credentials: credentials).list_roles(marker: marker)
              resp.roles.each{ |role|
                # XXX Maybe we should have a more generic way to delete IAM profiles and policies. The call itself should be moved from MU::Cloud.resourceClass("AWS", "Server").
#                MU::Cloud.resourceClass("AWS", "Server").removeIAMProfile(role.role_name) if role.role_name.match(/^#{Regexp.quote(deploy_id)}/)
              }
              marker = resp.marker
            end while resp.is_truncated
          end
        end

        # Locate an existing search_domain.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching search_domain.
        def self.find(**args)
          found = {}

          # Annoyingly, we might expect one of several possible artifacts,
          # since AWS couldn't decide what the real identifier of these
          # things should be
          list = MU::Cloud::AWS.elasticsearch(region: args[:region], credentials: args[:credentials]).list_domain_names
          if list and list.domain_names and list.domain_names.size > 0
            descs = MU::Cloud::AWS.elasticsearch(region: args[:region], credentials: args[:credentials]).describe_elasticsearch_domains(domain_names: list.domain_names.map { |d| d.domain_name } )
            descs.domain_status_list.each { |domain|
              if args[:cloud_id]
                if [domain.arn, domain.domain_name, domain.domain_id].include?(args[:cloud_id])
                  found[args[:cloud_id]] = domain
                  return found
                end
              else
                found[domain.domain_name] = domain
              end
            }
          end

          # TODO consider a search by tags
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

          bok['name'] = cloud_desc.domain_name
          bok['elasticsearch_version'] = cloud_desc.elasticsearch_version
          bok['instance_count'] = cloud_desc.elasticsearch_cluster_config.instance_count
          bok['instance_type'] = cloud_desc.elasticsearch_cluster_config.instance_type
          bok['zone_aware'] = cloud_desc.elasticsearch_cluster_config.zone_awareness_enabled

          if cloud_desc.elasticsearch_cluster_config.dedicated_master_enabled
            bok['dedicated_masters'] = cloud_desc.elasticsearch_cluster_config.dedicated_master_count
            bok['master_instance_type'] = cloud_desc.elasticsearch_cluster_config.dedicated_master_type
          end

          if cloud_desc.access_policies and !cloud_desc.access_policies.empty?
            bok['access_policies'] = JSON.parse(cloud_desc.access_policies)
          end

          if cloud_desc.advanced_options and !cloud_desc.advanced_options.empty?
            bok['advanced_options'] = cloud_desc.advanced_options
          end

          bok['ebs_size'] = cloud_desc.ebs_options.volume_size
          bok['ebs_type'] = cloud_desc.ebs_options.volume_type
          bok['ebs_iops'] = cloud_desc.ebs_options.iops if cloud_desc.ebs_options.iops

          if cloud_desc.snapshot_options and cloud_desc.snapshot_options.automated_snapshot_start_hour
            bok['snapshot_hour'] = cloud_desc.snapshot_options.automated_snapshot_start_hour
          end

          if cloud_desc.cognito_options.user_pool_id and
             cloud_desc.cognito_options.identity_pool_id
            bok['user_pool_id'] = cloud_desc.cognito_options.user_pool_id
            bok['identity_pool_id'] = cloud_desc.cognito_options.identity_pool_id
          end

          tags = MU::Cloud::AWS.elasticsearch(region: @region, credentials: @credentials).list_tags(arn: cloud_desc.arn).tag_list
          if tags and !tags.empty?
            bok['tags'] = MU.structToHash(tags)
          end

          if cloud_desc.vpc_options
            bok['vpc'] = MU::Config::Ref.get(
              id: cloud_desc.vpc_options.vpc_id,
              cloud: "AWS",
              credentials: @credentials,
              type: "vpcs",
              region: @region,
              subnets: cloud_desc.vpc_options.subnet_ids.map { |s| { "subnet_id" => s } }
            )
            if cloud_desc.vpc_options.security_group_ids and
               !cloud_desc.vpc_options.security_group_ids.empty?
              bok['add_firewall_rules'] = cloud_desc.vpc_options.security_group_ids.map { |sg|
                MU::Config::Ref.get(
                  id: sg,
                  cloud: "AWS",
                  credentials: @credentials,
                  region: @region,
                  type: "firewall_rules",
                )
              }
            end
          end

          if cloud_desc.log_publishing_options
            # XXX this is primitive... there are multiple other log types now,
            # and this should be a Ref blob, not a flat string
            cloud_desc.log_publishing_options.each_pair { |type, whither|
              if type == "SEARCH_SLOW_LOGS"
                bok['slow_logs'] = whither.cloud_watch_logs_log_group_arn
              end
            }
          end

          bok
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = ["elasticsearch_version", "instance_type"]

          versions = begin
            MU::Cloud::AWS.elasticsearch.list_elasticsearch_versions.elasticsearch_versions
          rescue MuError
            ["7.4", "7.1", "6.8", "6.7", "6.5", "6.4", "6.3", "6.2", "6.0", "5.6"]
          end
          instance_types = begin
            MU::Cloud::AWS.elasticsearch.list_elasticsearch_instance_types(
              elasticsearch_version: "6.3"
            ).elasticsearch_instance_types
          rescue MuError
            ["c5.large.elasticsearch", "c5.xlarge.elasticsearch", "c5.2xlarge.elasticsearch", "c5.4xlarge.elasticsearch", "c5.9xlarge.elasticsearch", "c5.18xlarge.elasticsearch", "i3.large.elasticsearch", "i3.xlarge.elasticsearch", "i3.2xlarge.elasticsearch", "i3.4xlarge.elasticsearch", "i3.8xlarge.elasticsearch", "i3.16xlarge.elasticsearch", "m5.large.elasticsearch", "m5.xlarge.elasticsearch", "m5.2xlarge.elasticsearch", "m5.4xlarge.elasticsearch", "m5.12xlarge.elasticsearch", "r5.large.elasticsearch", "r5.xlarge.elasticsearch", "r5.2xlarge.elasticsearch", "r5.4xlarge.elasticsearch", "r5.12xlarge.elasticsearch", "t2.small.elasticsearch", "t2.medium.elasticsearch", "c4.large.elasticsearch", "c4.xlarge.elasticsearch", "c4.2xlarge.elasticsearch", "c4.4xlarge.elasticsearch", "c4.8xlarge.elasticsearch", "i2.xlarge.elasticsearch", "i2.2xlarge.elasticsearch", "m4.large.elasticsearch", "m4.xlarge.elasticsearch", "m4.2xlarge.elasticsearch", "m4.4xlarge.elasticsearch", "m4.10xlarge.elasticsearch", "r4.large.elasticsearch", "r4.xlarge.elasticsearch", "r4.2xlarge.elasticsearch", "r4.4xlarge.elasticsearch", "r4.8xlarge.elasticsearch", "r4.16xlarge.elasticsearch", "m3.medium.elasticsearch", "m3.large.elasticsearch", "m3.xlarge.elasticsearch", "m3.2xlarge.elasticsearch", "r3.large.elasticsearch", "r3.xlarge.elasticsearch", "r3.2xlarge.elasticsearch", "r3.4xlarge.elasticsearch", "r3.8xlarge.elasticsearch"]
          rescue Aws::ElasticsearchService::Errors::ValidationException
            # Some regions (GovCloud) lag
            MU::Cloud::AWS.elasticsearch.list_elasticsearch_instance_types(
              elasticsearch_version: "6.2"
            ).elasticsearch_instance_types
          end

          polschema = MU::Config::Role.schema["properties"]["policies"]
          polschema.deep_merge!(MU::Cloud.resourceClass("AWS", "Role").condition_schema)

          schema = {
            "name" => {
              "type" => "string",
              "pattern" => '^[a-z][a-z0-9\-]+$'
            },
            "elasticsearch_version" => {
              "type" => "string",
              "default" => versions.first,
              "description" => "A supported ElasticSearch version for the region of this SearchDomain. Known versions from #{MU.myRegion}: "+versions.join(", ")
            },
            "instance_type" => {
              "type" => "string",
              "default" => instance_types.first,
              "description" => "A supported ElasticSearch instance type for the region of this SearchDomain. Known types from #{MU.myRegion}: "+instance_types.join(", ")+"."
            },
            "dedicated_masters" => {
              "type" => "integer",
              "default" => 0,
              "description" => "Separate, dedicated master node(s), over and above the search instances specified in instance_count."
            },
            "policies" => polschema,
            "access_policies" => {
              "type" => "object",
              "description" => "An IAM policy document for access to ElasticSearch (see {policies} for setting complex access policies with runtime dependencies). Our parser expects this to be defined inline like the rest of your YAML/JSON Basket of Kittens, not as raw JSON. For guidance on ElasticSearch IAM capabilities, see: https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-ac.html"
            },
            "master_instance_type" => {
              "type" => "string",
              "description" => "Instance type for dedicated master nodes, if any were requested. Will default to match instance_type."
            },
            "ebs_type" => {
              "type" => "string",
              "default" => "gp2",
              "description" => "Type of EBS storage to use for cluster nodes. If 'none' is specified, EBS storage will not be used, but this is only valid for certain instance types.",
              "enum" => ["standard", "gp2", "io1", "none"]
            },
            "ebs_iops" => {
              "type" => "integer",
              "description" => "Specifies the IOPD for a Provisioned IOPS EBS volume (SSD). Must specify ebs_type for this to take effect."
            },
            "ebs_size" => {
              "type" => "integer",
              "default" => 20,
              "description" => "Specifies the size (GB) of EBS storage. Must specify ebs_type for this to take effect."
            },
            "snapshot_hour" => {
              "type" => "integer",
              "default" => 23,
              "description" => "Clock hour (UTC) to begin daily snapshots"
            },
            "kms_encryption_key_id" => {
              "type" => "string",
              "description" => "If specified, will attempt to enable encryption at rest with this KMS Key ID"
            },
            "zone_aware" => {
              "type" => "boolean",
              "default" => false,
              "description" => "Spread search instances across Availability Zones to facilitate replica index sharding for greater resilience. Note that you also must use the native Elasticsearch API to create replica shards for your cluster. Zone awareness requires an even number of instances in the instance count."
            },
            "slow_logs" => {
              "type" => "string",
              "description" => "The ARN of a CloudWatch Log Group to which we we'll send slow index and search logs. If not specified, a log group will be generated."
            },
            "advanced_options" => {
              "type" => "object",
              "description" => "Key => Value strings pairs that pass certain configuration options to Elasticsearch. For a list of supported values, see https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomain-configure-advanced-options",
            },
            "cognito" => {
              "type" => "object",
              "description" => "Options to specify the Cognito user and identity pools for Kibana authentication. For more information, see http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-cognito-auth.html",
              "required" => ["user_pool_id", "identity_pool_id"],
              "properties" => {
                "user_pool_id" => {
                  "type" => "string",
                  "description" => "Amazon Cognito user pool. Looks like 'us-east-1:69e2223c-2c74-42ca-9b27-1037fcb60b91'. See https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html"
                },
                "identity_pool_id" => {
                  "type" => "string",
                  "description" => "Amazon Cognito identity pool. Looks like 'us-east-1_eSwWA1VGY'. See https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools.html"
                },
                "role_arn" => {
                  "type" => "string",
                  "description" => "An IAM role that has the AmazonESCognitoAccess policy attached. If not specified, one will be generated automatically."
                }
              }
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::search_domains}, bare and unvalidated.
        # @param dom [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(dom, configurator)
          ok = true
          versions = MU::Cloud::AWS.elasticsearch(region: dom['region']).list_elasticsearch_versions.elasticsearch_versions
          if !versions.include?(dom["elasticsearch_version"])
            MU.log "Invalid ElasticSearch version '#{dom["elasticsearch_version"]}' in SearchDomain '#{dom['name']}'", MU::ERR, details: versions
            ok = false
          else
            resp = MU::Cloud::AWS.elasticsearch(region: dom['region']).list_elasticsearch_instance_types(
              elasticsearch_version: dom["elasticsearch_version"]
            )
          
            if resp.nil? or resp.elasticsearch_instance_types.nil?
              MU.log "Failed to list valid ElasticSearch instance types in #{dom['region']}", MU::WARN
            end

            if !resp.elasticsearch_instance_types.include?(dom["instance_type"])
              MU.log "Invalid instance_type '#{dom["instance_type"]}' in SearchDomain '#{dom['name']}'", MU::ERR, details: resp.elasticsearch_instance_types
              ok = false
            end
          end

          if dom["dedicated_masters"] > 0 and dom["master_instance_type"].nil?
            dom["master_instance_type"] = dom["instance_type"]
            if dom["dedicated_masters"] != 3 and dom["dedicated_masters"] != 5
              MU.log "SearchDomain #{dom['name']}: You must choose either three or five dedicated master nodes", MU::ERR
              ok = false
            end
          end

          if dom["instance_count"] < 1
            MU.log "Must have at least one search node in SearchDomain '#{dom['name']}'", MU::ERR
            ok = false
          end

          if dom["ebs_iops"]
            MU.log "SearchDomain #{dom['name']} declared ebs_iops, setting volume type to io1", MU::NOTICE
            dom["ebs_type"] = "io1"
          end

          if dom["zone_aware"] and (dom["instance_count"] % 2) != 0
            MU.log "Must set an even number for instance_count when enabling Zone Awareness in SearchDomain '#{dom['name']}'", MU::ERR
            ok = false
          end

          if !dom["vpc"]
            MU.log "No VPC specified for SearchDomain '#{dom['name']},' endpoints will be public", MU::NOTICE
            if (dom['ingress_rules'] and dom['ingress_rules'].size > 0) or
               (dom['add_firewall_rules'] and dom['add_firewall_rules'].size > 0)
              MU.log "You must deploy SearchDomain '#{dom['name']}' into a VPC in order to use ingress_rules", MU::ERR
              ok = false
            end
          else
            if dom['ingress_rules']
              fwname = "searchdomain-#{dom['name']}"
              acl = {"name" => fwname, "rules" => dom['ingress_rules'], "region" => dom['region'], "optional_tags" => dom['optional_tags']}
              acl["tags"] = dom['tags'] if dom['tags'] && !dom['tags'].empty?
              acl["vpc"] = dom['vpc'].dup if dom['vpc']
              ok = false if !configurator.insertKitten(acl, "firewall_rules")
              dom["add_firewall_rules"] = [] if dom["add_firewall_rules"].nil?
              dom["add_firewall_rules"] << {"name" => fwname}
            end
          end

          if dom['snapshot_hour'] < 0 or dom['snapshot_hour'] > 23
            MU.log "Invalid snapshot_hour in SearchDomain '#{dom['name']}', must be in the range 0..23", MU::ERR
            ok = false
          end

          if dom['slow_logs']
            if configurator.haveLitterMate?(dom['slow_logs'], "log")
              MU::Config.addDependency(dom, dom['slow_logs'], "log")
            else
              log_group = MU::Cloud.resourceClass("AWS", "Log").find(cloud_id: dom['slow_logs'], region: dom['region']).values.first
              if !log_group
                MU.log "Specified slow_logs CloudWatch log group '#{dom['slow_logs']}' in SearchDomain '#{dom['name']}' doesn't appear to exist", MU::ERR
                ok = false
              else
                dom['slow_logs'] = log_group.arn
              end
            end
          else
            dom['slow_logs'] = dom['name']+"-slowlog"
            log_group = {
              "name" => dom['slow_logs'],
              "credentials" => dom['credentials']
            }
            ok = false if !configurator.insertKitten(log_group, "logs")
            MU::Config.addDependency(dom, dom['slow_logs'], "log")
          end

          if dom['advanced_options']
            dom['advanced_options'].each_pair { |key, val|
              dom['advanced_options'][key] = val.to_s
            }
          end

          if dom['cognito']
            begin
              MU::Cloud::AWS.cognito_ident(region: dom['region']).describe_identity_pool(
                identity_pool_id: dom['cognito']['identity_pool_id']
              )
            rescue ::Aws::CognitoIdentity::Errors::ValidationException, Aws::CognitoIdentity::Errors::ResourceNotFoundException
              MU.log "Cognito identity pool #{dom['cognito']['identity_pool_id']} malformed or does not exist in SearchDomain '#{dom['name']}'", MU::ERR
              ok = false
            end
            begin
              MU::Cloud::AWS.cognito_user(region: dom['region']).describe_user_pool(
                user_pool_id: dom['cognito']['user_pool_id']
              )
            rescue ::Aws::CognitoIdentityProvider::Errors::InvalidParameterException, Aws::CognitoIdentityProvider::Errors::ResourceNotFoundException
              MU.log "Cognito identity pool #{dom['cognito']['user_pool_id']} malformed or does not exist in SearchDomain '#{dom['name']}'", MU::ERR
              ok = false
            end

            if dom['cognito']['role_arn']
              rolename = dom['cognito']['role_arn'].sub(/.*?:role\/([a-z0-9-]+)$/, '\1')
              begin
                if !dom['cognito']['role_arn'].match(/^arn:/)
                  role = MU::Cloud::AWS.iam.get_role(role_name: rolename)
                  dom['cognito']['role_arn'] = role.role.arn
                end
                pols = MU::Cloud::AWS.iam.list_attached_role_policies(role_name: rolename).attached_policies
                found = false
                pols.each { |policy|
                  found = true if policy.policy_name == "AmazonESCognitoAccess"
                }
                if !found
                  MU.log "IAM role #{dom['cognito']['role_arn']} exists, but not does have the AmazonESCognitoAccess policy attached. SearchDomain '#{dom['name']}' may not have necessary Cognito permissions.", MU::WARN
                end
              rescue Aws::IAM::Errors::NoSuchEntity
                MU.log "IAM role #{dom['cognito']['role_arn']} malformed or does not exist in SearchDomain '#{dom['name']}'", MU::ERR
                ok = false
              end
            else
              roledesc = {
                "name" => dom['name']+"cognitorole",
                "credentials" => dom['credentials'],
                "can_assume" => [
                  {
                    "entity_id" => "es.amazonaws.com",
                    "entity_type" => "service"
                  }
                ],
                "import" => [
                  "AmazonESCognitoAccess"
                ]
              }
              configurator.insertKitten(roledesc, "roles")
              MU::Config.addDependency(dom, dom['name']+"cognitorole", "role")
            end

          end

          # TODO queue['access_policies'] should generate a policy blob via MU::Cloud::AWS::Role

          ok
        end

        private

        # create_elasticsearch_domain and update_elasticsearch_domain_config
        # take almost the same set of parameters, so our create and groom 
        # methods do nearly the same things. Factor it. If we're operating on
        # an existing domain, only return things that would be changed.
        def genParams(ext = nil)
          params = {
            :domain_name => @config['domain_name'] || @deploydata['domain_name']
          }

          if ext.nil?
            params[:elasticsearch_version] = @config['elasticsearch_version']
          elsif ext.elasticsearch_version != @config['elasticsearch_version']

            raise MU::MuError, "Can't change ElasticSearch version of an existing cluster"
          end

          if ext.nil? or
             ext.elasticsearch_cluster_config.instance_type != @config['instance_type'] or
             ext.elasticsearch_cluster_config.instance_count != @config['instance_count'] or
             ext.elasticsearch_cluster_config.zone_awareness_enabled != @config['zone_aware']
            params[:elasticsearch_cluster_config] = {}
            params[:elasticsearch_cluster_config][:instance_type] = @config['instance_type']
            params[:elasticsearch_cluster_config][:instance_count] = @config['instance_count']
            params[:elasticsearch_cluster_config][:zone_awareness_enabled] = @config['zone_aware']
          end

          if @config['dedicated_masters'] > 0
            if ext.nil? or !ext.elasticsearch_cluster_config.dedicated_master_enabled or
               ext.elasticsearch_cluster_config.dedicated_master_count != @config['dedicated_masters'] or
               ext.elasticsearch_cluster_config.dedicated_master_type != @config['master_instance_type']
              params[:elasticsearch_cluster_config][:dedicated_master_enabled] = true
              params[:elasticsearch_cluster_config][:dedicated_master_count] = @config['dedicated_masters']
              params[:elasticsearch_cluster_config][:dedicated_master_type] = @config['master_instance_type']
            end
          end

          if ext.nil? or ext.snapshot_options.automated_snapshot_start_hour != @config['snapshot_hour']
            params[:snapshot_options] = {}
            params[:snapshot_options][:automated_snapshot_start_hour] = @config['snapshot_hour']
          end

          if ext
            # Despite being called access_policies, this parameter actually
            # only accepts one policy. So, we'll munge everything we have
            # together into one policy with multiple Statements.
            policy = nil
            # TODO check against ext.access_policy.options

            if @config['access_policies']
              policy = @config['access_policies']
              # ensure the "Statement" key is cased in a predictable way
              statement_key = nil
              policy.each_pair { |k, v|
                if k.downcase == "statement" and k != "Statement"
                  statement_key = k
                  break
                end
              }
              if statement_key
                policy["Statement"] = policy.delete(statement_key)
              end
              if !policy["Statement"].is_a?(Array)
                policy["Statement"] = [policy["Statement"]]
              end
            end

            if @config['policies']
              @config['policies'].each { |p|
                p['targets'].each { |t|
                  if t['path']
                    t['path'].gsub!(/#SELF/, @mu_name.downcase)
                  end
                }
                parsed = MU::Cloud.resourceClass("AWS", "Role").genPolicyDocument([p], deploy_obj: @deploy, bucket_style: true).first.values.first

                if policy and policy["Statement"]
                  policy["Statement"].concat(parsed["Statement"])
                else
                  policy = parsed
                end
              }
            end

            if policy
              params[:access_policies] = JSON.generate(policy)
            end
          end

          if @config['slow_logs']
            arn = nil
            if @config['slow_logs'].match(/^arn:/i)
              arn = @config['slow_logs']
            else
              log_group = @deploy.findLitterMate(type: "log", name: @config['slow_logs'])
              log_group = MU::Cloud.resourceClass("AWS", "Log").find(cloud_id: log_group.mu_name, region: log_group.cloudobj.config['region']).values.first
              if log_group.nil? or log_group.arn.nil?
                raise MuError, "Failed to retrieve ARN of sibling LogGroup '#{@config['slow_logs']}'"
              end
              arn = log_group.arn
            end

            if arn
              @config['slow_logs'] = arn
            end

            if ext.nil? or
                ext.log_publishing_options.nil? or
                ext.log_publishing_options["INDEX_SLOW_LOGS"].nil? or
                !ext.log_publishing_options["INDEX_SLOW_LOGS"][:enabled] or
                ext.log_publishing_options["INDEX_SLOW_LOGS"][:cloud_watch_logs_log_group_arn] != arn or
                ext.log_publishing_options["SEARCH_SLOW_LOGS"].nil? or
                !ext.log_publishing_options["SEARCH_SLOW_LOGS"][:enabled] or
                ext.log_publishing_options["SEARCH_SLOW_LOGS"][:cloud_watch_logs_log_group_arn] != arn
              params[:log_publishing_options] = {}
              params[:log_publishing_options]["INDEX_SLOW_LOGS"] = {}
              params[:log_publishing_options]["INDEX_SLOW_LOGS"][:enabled] = true
              params[:log_publishing_options]["INDEX_SLOW_LOGS"][:cloud_watch_logs_log_group_arn] = arn

              params[:log_publishing_options]["SEARCH_SLOW_LOGS"] = {}
              params[:log_publishing_options]["SEARCH_SLOW_LOGS"][:enabled] = true
              params[:log_publishing_options]["SEARCH_SLOW_LOGS"][:cloud_watch_logs_log_group_arn] = arn
              MU::Cloud.resourceClass("AWS", "Log").allowService("es.amazonaws.com", arn, @region)
            end
          end

          if @config['advanced_options'] and (ext.nil? or 
             ext.advanced_options != @config['advanced_options'])
            params[:advanced_options] = {}
            @config['advanced_options'].each_pair { |key, value|
              params[:advanced_options][key] = value
            }
          end

          if @config['vpc']
            subnet_ids = []
            sgs = []
            if !@config["vpc"]["subnets"].nil? and @config["vpc"]["subnets"].size > 0
              @config["vpc"]["subnets"].each { |subnet|
                subnet_obj = @vpc.getSubnet(cloud_id: subnet["subnet_id"], name: subnet["subnet_name"])
                subnet_ids << subnet_obj.cloud_id
              }
            else
              @vpc.subnets.each { |subnet_obj|
                next if subnet_obj.private? and ["all_public", "public"].include?(@config["vpc"]["subnet_pref"])
                next if !subnet_obj.private? and ["all_private", "private"].include?(@config["vpc"]["subnet_pref"])
                subnet_ids << subnet_obj.cloud_id
              }
            end
            if subnet_ids.size == 0
              raise MuError, "No valid subnets found for #{@mu_name} from #{@config["vpc"]}"
            end

            if @dependencies.has_key?("firewall_rule")
              @dependencies['firewall_rule'].values.each { |sg|
                sgs << sg.cloud_id
              }
            end

            # XXX this will break on regroom, revisit and make deterministic
            # or remembered
            subnet_ids = subnet_ids.sample(3) if subnet_ids.size > 3

            if ext.nil? or
               ext.vpc_options.subnet_ids != subnet_ids or
               ext.vpc_options.security_group_ids != sgs
              params[:vpc_options] = {}
              params[:vpc_options][:subnet_ids] = subnet_ids
              params[:vpc_options][:security_group_ids] = sgs
            end
            if @config['zone_aware'] and params[:elasticsearch_cluster_config]
              params[:elasticsearch_cluster_config][:zone_awareness_config] = {
                :availability_zone_count => subnet_ids.size
              }
            end
          end

          if @config['ebs_type']
            if ext.nil? or ext.ebs_options.nil? or !ext.ebs_options.ebs_enabled or
               ext.ebs_options.volume_type != @config['ebs_type'] or
               ext.ebs_options.volume_size != @config['ebs_size'] or
               ext.ebs_options.iops != @config['ebs_iops']
              params[:ebs_options] = {}
              params[:ebs_options][:ebs_enabled] = true
              params[:ebs_options][:volume_type] = @config['ebs_type']
              params[:ebs_options][:volume_size] = @config['ebs_size']
              if @config['ebs_iops']
                params[:ebs_options][:iops] = @config['ebs_iops']
              end
            end
          end

          if @config['kms_encryption_key_id']
            if ext.nil? or !ext.encryption_at_rest_options.enabled or
               ext.kms_key_id != @config['kms_encryption_key_id']
              params[:encryption_at_rest_options] = {}
              params[:encryption_at_rest_options][:enabled] = true
              params[:encryption_at_rest_options][:kms_key_id] = @config['kms_encryption_key_id']
            end
          end


          # XXX API fails with "Amazon Elasticsearch must be allowed to use the
          # passed role" when we do this on creation, but it works fine if we
          # modify an existing group. AWS bug, workaround is to just apply
          # this in groom phase exclusively.
          if @config['cognito'] and !ext.nil?
            setIAMPolicies

            if ext.nil? or !ext.cognito_options.enabled or
               ext.cognito_options.user_pool_id != @config['cognito']['user_pool_id'] or
               ext.cognito_options.identity_pool_id != @config['cognito']['identity_pool_id'] or
               (@config['cognito']['role_arn'] and ext.cognito_options.role_arn != @config['cognito']['role_arn'])
              params[:cognito_options] = {}
              params[:cognito_options][:enabled] = true
              params[:cognito_options][:user_pool_id] = @config['cognito']['user_pool_id']
              params[:cognito_options][:identity_pool_id] = @config['cognito']['identity_pool_id']
              if @config['cognito']['role_arn']
                params[:cognito_options][:role_arn] = @config['cognito']['role_arn']
              else
                myrole = @deploy.findLitterMate(name: @config['name']+"cognitorole", type: "roles")
                params[:cognito_options][:role_arn] = myrole.cloudobj.arn
              end
            end
          end

          params
        end

        def tagDomain
          tags = [{ key: "Name", value: @mu_name }]

          MU::MommaCat.listStandardTags.each_pair { |name, value|
            tags << {key: name, value: value }
          }

          if @config['optional_tags']
            MU::MommaCat.listOptionalTags.each_pair { |name, value|
              tags << {key: name, value: value }
            }
          end

          if @config['tags']
            @config['tags'].each { |tag|
              tags << {key: tag['key'], value: tag['value'] }
            }
          end
          domain = cloud_desc
          if !domain or !domain.arn
            raise MU::MuError, "Can't tag ElasticSearch domain, cloud descriptor came back without an ARN"
          end

          MU::Cloud::AWS.elasticsearch(region: @region, credentials: @credentials).add_tags(
            arn: domain.arn,
            tag_list: tags
          )
        end

        def waitWhileProcessing
          retries = 0
          interval = 60

          begin
            resp = cloud_desc(use_cache: false)

            if (resp.endpoint.nil? or resp.endpoint.empty?) and
               (resp.endpoints.nil? or resp.endpoints.empty?) and
               !resp.deleted
              loglevel = (retries > 0 and retries % 3 == 0) ? MU::NOTICE : MU::DEBUG
              MU.log "Waiting for Elasticsearch domain #{@mu_name} (#{@config['domain_name']}) to finish creating", loglevel
              sleep interval
            end
            retries += 1
          end while (resp.endpoint.nil? or resp.endpoint.empty?) and (resp.endpoints.nil? or resp.endpoints.empty?) and !resp.deleted
        end

      end
    end
  end
end
