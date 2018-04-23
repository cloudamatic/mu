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
      # A search_domain as configured in {MU::Config::BasketofKittens::search_domain}
      class SearchDomain < MU::Cloud::SearchDomain
        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        @cloudformation_data = {}
        attr_reader :cloudformation_data

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::search_domains}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          @config['domain_name'] = @deploy.getResourceName(@config["name"], max_length: 28, need_unique_string: true).downcase

          params = genParams

          MU.log "Creating ElasticSearch domain #{@config['domain_name']}", details: params
          resp = MU::Cloud::AWS.elasticsearch(@config['region']).create_elasticsearch_domain(params).domain_status

          tagDomain

        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          tagDomain
          params = genParams(cloud_desc) # get parameters that would change only

          if params.size > 1
            waitWhileProcessing # wait until the create finishes, if still going

            MU.log "Updating ElasticSearch domain #{@config['domain_name']}", MU::NOTICE, details: params
            MU::Cloud::AWS.elasticsearch(@config['region']).update_elasticsearch_domain_config(params).domain_status
          end

          waitWhileProcessing # don't return until creation/updating is complete
        end

        # Wrapper for cloud_desc method that deals with finding the AWS
        # domain_name parameter, which isn't what we'd call ourselves if we had
        # our druthers.
        def cloud_desc
          if @config['domain_name']
            MU::Cloud::AWS.elasticsearch(@config['region']).describe_elasticsearch_domain(
              domain_name: @config['domain_name']
            ).domain_status
          elsif @deploydata['domain_name']
            MU::Cloud::AWS.elasticsearch(@config['region']).describe_elasticsearch_domain(
              domain_name: @deploydata['domain_name']
            ).domain_status
          else
            raise MU::MuError "#{@mu_name} can't find its official Elasticsearch domain name!"
          end
        end

        # Return the metadata for this SearchDomain rule
        # @return [Hash]
        def notify
          deploy_struct = MU.structToHash(cloud_desc)
          tags = MU::Cloud::AWS.elasticsearch(@config['region']).list_tags(arn: deploy_struct[:arn]).tag_list
          deploy_struct['tags'] = tags.map { |t| { t.key => t.value } }
          if deploy_struct['endpoint']
            deploy_struct['kibana'] = deploy_struct['endpoint']+"/_plugin/kibana/"
          end
          deploy_struct['domain_name'] ||= @config['domain_name'] if @config['domain_name']
          deploy_struct
        end

        # Remove all search_domains associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          list = MU::Cloud::AWS.elasticsearch(region).list_domain_names
          if list and list.domain_names and list.domain_names.size > 0
            descs = MU::Cloud::AWS.elasticsearch(region).describe_elasticsearch_domains(domain_names: list.domain_names.map { |d| d.domain_name } )

            descs.domain_status_list.each { |domain|
              tags = MU::Cloud::AWS.elasticsearch(region).list_tags(arn: domain.arn)
              tags.tag_list.each { |tag|
                if tag.key == "MU-ID" and tag.value == MU.deploy_id
                  MU.log "Deleting ElasticSearch Domain #{domain.domain_name}"
                  if !noop
                    MU::Cloud::AWS.elasticsearch(region).delete_elasticsearch_domain(domain_name: domain.domain_name)
                  end
                  break
                end
              }
            }
          end

          unless noop
            marker = nil
            begin
              resp = MU::Cloud::AWS.iam.list_roles(marker: marker)
              resp.roles.each{ |role|
                # XXX Maybe we should have a more generic way to delete IAM profiles and policies. The call itself should be moved from MU::Cloud::AWS::Server.
                MU::Cloud::AWS::Server.removeIAMProfile(role.role_name) if role.role_name.match(/^#{Regexp.quote(MU.deploy_id)}/)
              }
              marker = resp.marker
            end while resp.is_truncated
          end
        end

        # Locate an existing search_domain.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @param flags [Hash]: Optional flags
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching search_domain.
        def self.find(cloud_id: nil, region: MU.curRegion, flags: {})
          if cloud_id
            # Annoyingly, we might expect one of several possible artifacts,
            # since AWS couldn't decide what the real identifier of these
            # things should be
            list = MU::Cloud::AWS.elasticsearch(region).list_domain_names
            if list and list.domain_names and list.domain_names.size > 0
              descs = MU::Cloud::AWS.elasticsearch(region).describe_elasticsearch_domains(domain_names: list.domain_names.map { |d| d.domain_name } )
              descs.domain_status_list.each { |domain|
                return domain if domain.arn == cloud_id
                return domain if domain.domain_name == cloud_id
                return domain if domain.domain_id == cloud_id
              }
            end
          end
          # TODO consider a search by tags
          nil
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = ["elasticsearch_version", "instance_type"]
          versions = MU::Cloud::AWS.elasticsearch.list_elasticsearch_versions.elasticsearch_versions
          instance_types = MU::Cloud::AWS.elasticsearch.list_elasticsearch_instance_types(
            elasticsearch_version: "6.2"
          ).elasticsearch_instance_types

          schema = {
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
            "master_instance_type" => {
              "type" => "string",
              "description" => "Instance type for dedicated master nodes, if any were requested. Will default to match instance_type."
            },
            "ebs_type" => {
              "type" => "string",
              "default" => "standard",
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
            "index_slow_logs" => {
              "type" => "string",
              "description" => "The ARN of a CloudWatch Log Group to which we we'll send slow index logs. If not specified, a log group will be generated."
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
          versions = MU::Cloud::AWS.elasticsearch(dom['region']).list_elasticsearch_versions.elasticsearch_versions
          if !versions.include?(dom["elasticsearch_version"])
            MU.log "Invalid ElasticSearch version '#{dom["elasticsearch_version"]}' in SearchDomain '#{dom['name']}'", MU::ERR, details: versions
            ok = false
          else
            resp = MU::Cloud::AWS.elasticsearch(dom['region']).list_elasticsearch_instance_types(
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
          end

          if dom["instance_count"] < 1
            MU.log "Must have at least one search node in SearchDomain '#{dom['name']}'", MU::ERR
            ok = false
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
              dom["add_firewall_rules"] << {"rule_name" => fwname}
            end
          end

          if dom['snapshot_hour'] < 0 or dom['snapshot_hour'] > 23
            MU.log "Invalid snapshot_hour in SearchDomain '#{dom['name']}', must be in the range 0..23", MU::ERR
            ok = false
          end

          if dom['index_slow_logs']
            log_group = MU::Cloud::AWS::Log.find(cloud_id: dom['index_slow_logs'], region: dom['region'])
            pp log_group
            if !log_group
              MU.log "Specified index_slow_logs CloudWatch log group '#{dom['index_slow_logs']}' in SearchDomain '#{dom['name']}' doesn't appear to exist", MU::ERR
              ok = false
            end
            dom['index_slow_logs'] = log_group.arn
          else
            dom['index_slow_logs'] = dom['name']+"-slowlog"
            log_group = { "name" => dom['index_slow_logs'] }
            ok = false if !configurator.insertKitten(log_group, "logs")
            dom['dependencies'] << { "name" => dom['index_slow_logs'], "type" => "log" }
          end

          if dom['advanced_options']
            dom['advanced_options'].each_pair { |key, val|
              dom['advanced_options'][key] = val.to_s
            }
          end

          if dom['cognito']
            begin
              MU::Cloud::AWS.cognito_ident(dom['region']).describe_identity_pool(
                identity_pool_id: dom['cognito']['identity_pool_id']
              )
            rescue ::Aws::CognitoIdentity::Errors::ValidationException, Aws::CognitoIdentity::Errors::ResourceNotFoundException => e
              MU.log "Cognito identity pool #{dom['cognito']['identity_pool_id']} malformed or does not exist in SearchDomain '#{dom['name']}'", MU::ERR
              ok = false
            end
            begin
              MU::Cloud::AWS.cognito_user(dom['region']).describe_user_pool(
                user_pool_id: dom['cognito']['user_pool_id']
              )
            rescue ::Aws::CognitoIdentityProvider::Errors::InvalidParameterException, Aws::CognitoIdentityProvider::Errors::ResourceNotFoundException => e
              MU.log "Cognito identity pool #{dom['cognito']['user_pool_id']} malformed or does not exist in SearchDomain '#{dom['name']}'", MU::ERR
              ok = false
            end

            if dom['cognito']['role_arn']
              rolename = dom['cognito']['role_arn'].sub(/.*?:role\/([a-z0-9-]+)$/, '\1')
              begin
                if !dom['cognito']['role_arn'].match(/^arn:/)
                  role = MU::Cloud::AWS.iam(dom['region']).get_role(role_name: rolename)
                  dom['cognito']['role_arn'] = role.role.arn
                end
                pols = MU::Cloud::AWS.iam(dom['region']).list_attached_role_policies(role_name: rolename).attached_policies
                found = false
                pols.each { |policy|
                  found = true if policy.policy_name == "AmazonESCognitoAccess"
                }
                if !found
                  MU.log "IAM role #{dom['cognito']['role_arn']} exists, but not does have the AmazonESCognitoAccess policy attached. SearchDomain '#{dom['name']}' may not have necessary Cognito permissions.", MU::WARN
                end
              rescue Aws::IAM::Errors::NoSuchEntity => e
                MU.log "IAM role #{dom['cognito']['role_arn']} malformed or does not exist in SearchDomain '#{dom['name']}'", MU::ERR
                ok = false
              end

            end

          end

          ok
        end

        private

        def setIAMPolicies
          assume_role_policy = {
            "Version" => "2012-10-17",
            "Statement" => [
              {
                "Effect": "Allow",
                "Principal": {
                  "Service": "es.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
              }
            ]
          }

          begin
            MU::Cloud::AWS.iam(@config['region']).get_role(role_name: @mu_name)
          rescue ::Aws::IAM::Errors::NoSuchEntity => e
            MU.log "Creating IAM role #{@mu_name}", details: assume_role_policy
            MU::Cloud::AWS.iam(@config["region"]).create_role(
              role_name: @mu_name,
              assume_role_policy_document: JSON.generate(assume_role_policy)
            )
          end

#          pols = MU::Cloud::AWS.iam(@config['region']).list_attached_role_policies(role_name: @mu_name).attached_policies
#          pp pols
          MU::Cloud::AWS.iam.attach_role_policy(
            role_name: @mu_name,
            policy_arn: "arn:aws:iam::aws:policy/AmazonESCognitoAccess", 
          )

          MU::Cloud::AWS.iam(@config['region']).get_role(role_name: @mu_name).role
        end

        # create_elasticsearch_domain and update_elasticsearch_domain_config
        # take almost the same set of parameters, so our create and groom 
        # methods do nearly the same things. Factor it. If we're operating on
        # an existing domain, only return things that would be changed.
        def genParams(ext = nil)
          params = {
            :domain_name => @config['domain_name']
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

          if @config['index_slow_logs']
            arn = nil
            if @config['index_slow_logs'].match(/^arn:/i)
              arn = @config['index_slow_logs']
            else
              log_group = @deploy.findLitterMate(type: "log", name: @config['index_slow_logs'])
              log_group = MU::Cloud::AWS::Log.find(cloud_id: log_group.mu_name, region: log_group.cloudobj.config['region'])
              if log_group.nil? or log_group.arn.nil?
                raise MuError, "Failed to retrieve ARN of sibling LogGroup '#{@config['index_slow_logs']}'"
              end
              arn = log_group.arn
            end

            if arn
              @config['index_slow_logs'] = arn
            end

            if ext.nil? or
                ext.log_publishing_options.nil? or
                ext.log_publishing_options["INDEX_SLOW_LOGS"].nil? or
                !ext.log_publishing_options["INDEX_SLOW_LOGS"][:enabled] or
                ext.log_publishing_options["INDEX_SLOW_LOGS"][:cloud_watch_logs_log_group_arn] != arn
#              params[:log_publishing_options] = {}
#              params[:log_publishing_options]["INDEX_SLOW_LOGS"] = {}
#              params[:log_publishing_options]["INDEX_SLOW_LOGS"][:enabled] = true
#              params[:log_publishing_options]["INDEX_SLOW_LOGS"][:cloud_watch_logs_log_group_arn] = arn
              MU::Cloud::AWS::Log.allowService("es.amazonaws.com", arn, @config['region'])
            end
          end

          if @config['advanced_options'] and ext.nil? or 
             ext.advanced_options != @config['advanced_options']
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

            if ext.nil? or
               ext.vpc_options.subnet_ids != subnet_ids or
               ext.vpc_options.security_group_ids != sgs
              params[:vpc_options] = {}
              params[:vpc_options][:subnet_ids] = subnet_ids
              params[:vpc_options][:security_group_ids] = sgs
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


          if @config['cognito']
            myrole = setIAMPolicies
          pp myrole
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
                params[:cognito_options][:role_arn] = myrole.arn
              end
            end
          end
pp params
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

          MU::Cloud::AWS.elasticsearch(@config['region']).add_tags(
            arn: domain.arn,
            tag_list: tags
          )
        end

        def waitWhileProcessing
          retries = 0
          interval = 60

          begin
            resp = cloud_desc
            if resp.processing
              loglevel = (retries > 0 and retries % 3 == 0) ? MU::NOTICE : MU::DEBUG
              MU.log "Waiting for Elasticsearch domain #{@mu_name} (#{@config['domain_name']}) to be ready", loglevel
            end
            sleep interval
            retries += 1
          end while resp.processing
        end

      end
    end
  end
end
