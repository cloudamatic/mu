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
      # A user as configured in {MU::Config::BasketofKittens::roles}
      class Role < MU::Cloud::Role
        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::roles}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          @mu_name = mu_name
          @cloud_id ||= @mu_name # should be the same
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          if @config['iam_policies']
            @config['iam_policies'].each { |policy|
              policy_name = @mu_name+"-"+policy.keys.first.upcase
              MU.log "Creating IAM policy #{policy_name}"
              resp = MU::Cloud::AWS.iam(credentials: @config['credentials']).create_policy(
                policy_name: policy_name,
                path: "/"+@deploy.deploy_id+"/",
                policy_document: JSON.generate(policy.values.first),
                description: "Generated from inline policy document for Mu role #{@mu_name}"
              )
            }
          end

          if !@config['bare_policies']
            MU.log "Creating IAM role #{@mu_name}"
            @cloud_id = @mu_name
            resp = MU::Cloud::AWS.iam(credentials: @config['credentials']).create_role(
              path: "/"+@deploy.deploy_id+"/",
              role_name: @mu_name,
              description: "Generated by Mu",
              assume_role_policy_document: gen_role_policy_doc,
              tags: get_tag_params
            )
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          if @config['policies']
            @config['iam_policies'] ||= []
            @config['iam_policies'].concat(convert_policies_to_iam)
          end

          if !@config['bare_policies']
            resp = MU::Cloud::AWS.iam(credentials: @config['credentials']).get_role(
              role_name: @mu_name
            ).role
            ext_tags = resp.tags.map { |t| t.to_h }
            tag_param = get_tag_params(true)
            tag_param.reject! { |t| ext_tags.include?(t) }

            if tag_param.size > 0
              MU.log "Updating tags on IAM role #{@mu_name}", MU::NOTICE, details: tag_param
              MU::Cloud::AWS.iam(credentials: @config['credentials']).tag_role(role_name: @mu_name, tags: tag_param)
            end
          end


          if @config['iam_policies'] or @config['import']
            attached_policies = []
            configured_policies = []

            if @config['iam_policies']
              configured_policies = @config['iam_policies'].map { |p|
                @mu_name+"-"+p.keys.first.upcase
              }
            end

            if @config['import']
              MU.log "Attaching canned #{@config['import'].size > 1 ? "policies" : "policy"} #{@config['import'].join(", ")} to role #{@mu_name}", MU::NOTICE
              configured_policies.concat(@config['import'].map { |p| p.gsub(/.*?\/([^:\/]+)$/, '\1') })
            end

            if !@config['bare_policies']
              attached_policies = MU::Cloud::AWS.iam(credentials: @config['credentials']).list_attached_role_policies(
                role_name: @mu_name
              ).attached_policies
              attached_policies.each { |a|
                if !configured_policies.include?(a.policy_name)
                  MU.log "Removing IAM policy #{a.policy_name} from role #{@mu_name}", MU::NOTICE
                  MU::Cloud::AWS::Role.purgePolicy(a.policy_arn, @config['credentials'])
                end
              }
            end

            if @config['iam_policies']
              @config['iam_policies'].each { |policy|
                policy_name = @mu_name+"-"+policy.keys.first.upcase

                arn = "arn:"+(MU::Cloud::AWS.isGovCloud? ? "aws-us-gov" : "aws")+":iam::"+MU::Cloud::AWS.credToAcct(@config['credentials'])+":policy/#{@deploy.deploy_id}/#{policy_name}"
                resp = begin
                  desc = MU::Cloud::AWS.iam(credentials: @config['credentials']).get_policy(policy_arn: arn)

                  version = MU::Cloud::AWS.iam(credentials: @config['credentials']).get_policy_version(
                    policy_arn: arn,
                    version_id: desc.policy.default_version_id
                  )

                  if version.policy_version.document != URI.encode(JSON.generate(policy.values.first), /[^a-z0-9\-]/i)
                    MU.log "Updating IAM policy #{policy_name}", MU::NOTICE, details: policy.values.first
                    update_policy(arn, policy.values.first)
                    MU::Cloud::AWS.iam(credentials: @config['credentials']).get_policy(policy_arn: arn)
                  else
                    desc
                  end

                rescue Aws::IAM::Errors::NoSuchEntity => e
                  MU.log "Creating IAM policy #{policy_name}", details: policy.values.first
                  MU::Cloud::AWS.iam(credentials: @config['credentials']).create_policy(
                    policy_name: policy_name,
                    path: "/"+@deploy.deploy_id+"/",
                    policy_document: JSON.generate(policy.values.first),
                    description: "Generated from inline policy document for Mu role #{@mu_name}"
                  )
                end

              }
            end
          end

          if !@config['bare_policies'] and
             (@config['iam_policies'] or @config['import'])
            bindTo("role", @mu_name)
          end
        end


        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          desc = cloud_desc
          if desc["role"]
            desc["role"].arn
          else
            nil
          end
        end

        # Return a hash containing a +role+ element and a +policies+ element,
        # populated with one or both depending on what this resource has
        # defined.
        def cloud_desc
          desc = {}
          if @config['bare_policies']
            desc["policies"] = MU::Cloud::AWS.iam(credentials: @config['credentials']).list_policies(
              path_prefix: "/"+MU.deploy_id+"/"
            ).policies
            desc["policies"].reject! { |p|
              !p.policy_name.match(/^#{Regexp.quote(@mu_name)}-/)
            }
          else
            desc["role"] = MU::Cloud::AWS.iam(credentials: @config['credentials']).get_role(
              role_name: @mu_name
            ).role
            if @config['iam_policies']
              desc["policies"] = []
              MU::Cloud::AWS.iam(credentials: @config['credentials']).list_attached_role_policies(
                role_name: @mu_name
              ).attached_policies.each { |p|
                desc["policies"] << MU::Cloud::AWS.iam(credentials: @config['credentials']).get_policy(
                  policy_arn: p.policy_arn
                ).policy
              }
            end

          end
          desc['cloud_id'] ||= @cloud_id

          desc
        end

        # Return the metadata for this user cofiguration
        # @return [Hash]
        def notify
          MU.structToHash(cloud_desc)
        end

        # Insert a new target entity into an existing policy. 
        # @param policy [String]: The name of the policy to which we're appending, which must already exist as part of this role resource
        # @param targets [Array<String>]: The target resource. If +target_type+ isn't specified, this should be a fully-resolved ARN.
        # @param mu_type [String]: A valid Mu resource type
        def injectPolicyTargets(policy, targets, mu_type = nil)
          if !policy.match(/^#{@deploy.deploy_id}/)
            policy = @mu_name+"-"+policy.upcase
          end
          my_policies = cloud_desc["policies"]
          my_policies ||= []
          my_policies.each { |p|
            if p.policy_name == policy
              old = MU::Cloud::AWS.iam(credentials: @config['credentials']).get_policy_version(
                policy_arn: p.arn,
                version_id: p.default_version_id
              ).policy_version
              doc = JSON.parse(URI.decode(old.document))
              need_update = false
              doc["Statement"].each { |s|
                targets.each { |target|
                  targetstr = if target['type']
                    sibling = @deploy.findLitterMate(
                      name: target["identifier"],
                      type: target["type"]
                    )
                    sibling.cloudobj.arn
                  else
                    target['identifier']
                  end
                  if sibling and !s["Resource"].include?(targetstr)
                    s["Resource"] << targetstr
                    need_update = true
                  end
                }
              }
              if need_update
                MU.log "Updating IAM policy #{policy} to grant permissions on #{targets.to_s}", details: doc
                update_policy(p.arn, doc)
              end
            end
          }
        end

        # Delete an IAM policy, along with attendant versions and attachments.
        # @param policy_arn [String]: The ARN of the policy to purge
        def self.purgePolicy(policy_arn, credentials)
          attachments = MU::Cloud::AWS.iam(credentials: credentials).list_entities_for_policy(
            policy_arn: policy_arn
          )
          attachments.policy_users.each { |u|
            MU::Cloud::AWS.iam(credentials: credentials).detach_user_policy(
              user_name: u.user_name,
              policy_arn: policy_arn
            )
          }
          attachments.policy_groups.each { |g|
            MU::Cloud::AWS.iam(credentials: credentials).detach_group_policy(
              group_name: g.group_name,
              policy_arn: policy_arn
            )
          }
          attachments.policy_roles.each { |r|
            MU::Cloud::AWS.iam(credentials: credentials).detach_role_policy(
              role_name: r.role_name,
              policy_arn: policy_arn
            )
          }
          versions = MU::Cloud::AWS.iam(credentials: credentials).list_policy_versions(
            policy_arn: policy_arn,
          ).versions
          versions.each { |v|
            next if v.is_default_version
            MU::Cloud::AWS.iam(credentials: credentials).delete_policy_version(
              policy_arn: policy_arn,
              version_id: v.version_id
            )
          }

          # Delete the policy, unless it's one of the global canned ones owned
          # by AWS
          if !policy_arn.match(/^arn:aws:iam::aws:/)
            MU::Cloud::AWS.iam(credentials: credentials).delete_policy(
              policy_arn: policy_arn
            )
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
          MU::Cloud::BETA
        end

        # Remove all roles associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})

          resp = MU::Cloud::AWS.iam(credentials: credentials).list_policies(
            path_prefix: "/"+MU.deploy_id+"/"
          )
          if resp and resp.policies
            resp.policies.each { |policy|
              MU.log "Deleting IAM policy /#{MU.deploy_id}/#{policy.policy_name}"
              if !noop
                purgePolicy(policy.arn, credentials)
              end
            }
          end

          resp = MU::Cloud::AWS.iam(credentials: credentials).list_roles(
            path_prefix: "/"+MU.deploy_id+"/"
          )
          if resp and resp.roles
            resp.roles.each { |r|
              MU.log "Deleting IAM role #{r.role_name}"
              if !noop
                # purgePolicy won't touch roles we don't own, so gently detach
                # those first
                detachables = MU::Cloud::AWS.iam(credentials: credentials).list_attached_role_policies(
                  role_name: r.role_name
                ).attached_policies
                detachables.each { |rp|
                  MU::Cloud::AWS.iam(credentials: credentials).detach_role_policy(
                    role_name: r.role_name,
                    policy_arn: rp.policy_arn
                  )
                }

                begin
                  MU::Cloud::AWS.iam(credentials: credentials).remove_role_from_instance_profile(
                    instance_profile_name: r.role_name,
                    role_name: r.role_name
                  )
                  MU::Cloud::AWS.iam(credentials: credentials).delete_instance_profile(instance_profile_name: r.role_name)
                rescue Aws::IAM::Errors::ValidationError => e
                  MU.log "Cleaning up IAM role #{r.role_name}: #{e.inspect}", MU::WARN
                rescue Aws::IAM::Errors::NoSuchEntity => e
                end

                MU::Cloud::AWS.iam(credentials: credentials).delete_role(
                  role_name: r.role_name
                )
              end
            }
          end

        end

        # Locate an existing user group.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @param flags [Hash]: Optional flags
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching user group.
        def self.find(cloud_id: nil, region: MU.curRegion, credentials: nil, flags: {})
          found = nil

          found
        end

        # Attach this role or group of loose policies to the specified entity.
        # @param entitytype [String]: The type of entity (user, group or role for policies; instance_profile for roles)
        def bindTo(entitytype, entityname)
          if entitytype == "instance_profile"
            begin
              resp = MU::Cloud::AWS.iam(credentials: @config['credentials']).get_instance_profile(
                instance_profile_name: entityname
              ).instance_profile

              if !resp.roles.map { |r| r.role_name}.include?(@mu_name)
                MU::Cloud::AWS.iam(credentials: @config['credentials']).add_role_to_instance_profile(
                  instance_profile_name: entityname,
                  role_name: @mu_name
                )
              end
            rescue Exception => e
              MU.log "Error binding role #{@mu_name} to instance profile #{entityname}: #{e.message}", MU::ERR
              raise e
            end
          elsif ["user", "group", "role"].include?(entitytype)
            mypolicies = MU::Cloud::AWS.iam(credentials: @config['credentials']).list_policies(
              path_prefix: "/"+@deploy.deploy_id+"/"
            ).policies
            mypolicies.reject! { |p|
              !p.policy_name.match(/^#{Regexp.quote(@mu_name)}-/)
            }

            if @config['import']
              @config['import'].each { |policy|
                if !policy.match(/^arn:/i)
                  p_arn = "arn:"+(MU::Cloud::AWS.isGovCloud?(@config["region"]) ? "aws-us-gov" : "aws")+":iam::aws:policy/"+policy
                end
                retried = false
                begin
                  mypolicies << MU::Cloud::AWS.iam(credentials: @config['credentials']).get_policy(
                    policy_arn: p_arn
                  ).policy
                rescue Aws::IAM::Errors::NoSuchEntity => e
                  if !retried
                    p_arn = "arn:"+(MU::Cloud::AWS.isGovCloud?(@config["region"]) ? "aws-us-gov" : "aws")+":iam::aws:policy/service-role/"+policy
                    retried = true
                    retry
                  end
                  raise e
                end
              }
            end

            mypolicies.each { |p|
              if entitytype == "user"
                resp = MU::Cloud::AWS.iam(credentials: @config['credentials']).list_attached_user_policies(
                  path_prefix: "/"+@deploy.deploy_id+"/",
                  user_name: entityname
                )
                if !resp or !resp.attached_policies.map { |p| p.policy_name }.include?(p.policy_name)
                  MU.log "Attaching IAM policy #{p.policy_name} to user #{entityname}", MU::NOTICE
                  MU::Cloud::AWS.iam(credentials: @config['credentials']).attach_user_policy(
                    policy_arn: p.arn,
                    user_name: entityname
                  )
                end
              elsif entitytype == "group"
                resp = MU::Cloud::AWS.iam(credentials: @config['credentials']).list_attached_group_policies(
                  path_prefix: "/"+@deploy.deploy_id+"/",
                  group_name: entityname
                )
                if !resp or !resp.attached_policies.map { |p| p.policy_name }.include?(p.policy_name)
                  MU.log "Attaching policy #{p.policy_name} to group #{entityname}", MU::NOTICE
                  MU::Cloud::AWS.iam(credentials: @config['credentials']).attach_group_policy(
                    policy_arn: p.arn,
                    group_name: entityname
                  )
                end
              elsif entitytype == "role"
                resp = MU::Cloud::AWS.iam(credentials: @config['credentials']).list_attached_role_policies(
                  role_name: entityname
                )

                if !resp or !resp.attached_policies.map { |p| p.policy_name }.include?(p.policy_name)
                  MU.log "Attaching policy #{p.policy_name} to role #{entityname}", MU::NOTICE
                  MU::Cloud::AWS.iam(credentials: @config['credentials']).attach_role_policy(
                    policy_arn: p.arn,
                    role_name: entityname
                  )
                end
              end
            }
          else
            raise MuError, "Invalid entitytype '#{entitytype}' passed to MU::Cloud::AWS::Role.bindTo. Must be be one of: user, group, role, instance_profile"
          end
        end

        # Create an instance profile for EC2 instances, named identically and
        # bound to this role.
        def createInstanceProfile
          if @config['bare_policies']
            raise MuError, "#{self} has 'bare_policies' set, cannot create an instance profile without a role to bind"
          end

          resp = begin
            MU.log "Creating instance profile #{@mu_name} #{@config['credentials']}"
            MU::Cloud::AWS.iam(credentials: @config['credentials']).create_instance_profile(
              instance_profile_name: @mu_name
            )
          rescue Aws::IAM::Errors::EntityAlreadyExists => e
            MU::Cloud::AWS.iam(credentials: @config['credentials']).get_instance_profile(
              instance_profile_name: @mu_name
            )
          end

          # make sure it's really there before moving on
          begin
            MU::Cloud::AWS.iam(credentials: @config['credentials']).get_instance_profile(instance_profile_name: @mu_name)
          rescue Aws::IAM::Errors::NoSuchEntity => e
            MU.log e.inspect, MU::WARN
            sleep 10
            retry
          end

          bindTo("instance_profile", @mu_name)

          resp.instance_profile.arn
        end

        # Schema fragment for IAM policy conditions, which some other resource
        # types may need to import.
        def self.condition_schema
          {
            "items" => {
              "properties" => {
                "conditions" => {
                  "type" => "array",
                  "items" => {
                    "type" => "object",
                    "description" => "One or more conditions under which to apply this policy. See also: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html",
                    "required" => ["comparison", "variable", "values"],
                    "properties" => {
                      "comparison" => {
                        "type" => "string",
                        "description" => "A comparison to make, like +DateGreaterThan+ or +IpAddress+."
                      },
                      "variable" => {
                        "type" => "string",
                        "description" => "The variable which we will compare, like +aws:CurrentTime+ or +aws:SourceIp+."
                      },
                      "values" => {
                        "type" => "array",
                        "items" => {
                          "type" => "string",
                          "description" => "Value(s) to which we will compare our variable, like +2013-08-16T15:00:00Z+ or +192.0.2.0/24+."
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          aws_resource_types = MU::Cloud.resource_types.keys.reject { |t|
            begin
              MU::Cloud.loadCloudType("AWS", t)
              false
            rescue MuCloudResourceNotImplemented
              true
            end
          }.map { |t| MU::Cloud.resource_types[t][:cfg_name] }.sort


          schema = {
            "tags" => MU::Config.tags_primitive,
            "optional_tags" => MU::Config.optional_tags_primitive,
            "policies" => self.condition_schema,
            "import" => {
              "items" => {
                "description" => "Can be a shorthand reference to a canned IAM policy like +AdministratorAccess+, or a full ARN like +arn:aws:iam::aws:policy/AmazonESCognitoAccess+"
              }
            },
            "bare_policies" => {
              "type" => "boolean",
              "default" => false,
              "description" => "Do not create a role, but simply create the policies specified in +policies+ and/or +iam_policies+ for direct attachment to other entities."
            },
            "can_assume" => {
              "type" => "array",
              "items" => {
                "type" => "object",
                "description" => "Entities which are permitted to assume this role. Can be services, IAM objects, or other Mu resources.",
                "required" => ["entity_type", "entity_id"],
                "properties" => {
                  "entity_type" => {
                    "type" => "string",
                    "description" => "Type of entity which will be permitted to assume this role. See +entity_id+ for details.",
                    "enum" => ["service", "aws", "federated"]+aws_resource_types
                  },
                  "assume_method" => {
                    "type" => "string",
                    "description" => "https://docs.aws.amazon.com/STS/latest/APIReference/API_Operations.html",
                    "enum" => ["basic", "saml", "web"],
                    "default" => "basic"
                  },
                  "entity_id" => {
                    "type" => "string",
                    "description" => "An identifier appropriate for the +entity_type+ which is allowed to assume this role- see details for valid formats.\n
**service**: The name of a service which is allowed to assume this role, such as +ec2.amazonaws.com+. See also https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-service.html#roles-creatingrole-service-api. For an unofficial list of service names, see https://gist.github.com/shortjared/4c1e3fe52bdfa47522cfe5b41e5d6f22\n
**#{aws_resource_types.join(", ")}**: A resource of one of these Mu types, declared elsewhere in this stack with a name specified in +entity_id+, for which Mu will attempt to resolve the appropriate *aws* or *service* identifier.\n
**aws**: An ARN which should be permitted to assume this role, often another role like +arn:aws:iam::AWS-account-ID:role/role-name+ or a specific user session such as +arn:aws:sts::AWS-account-ID:assumed-role/role-name/role-session-name+. See also https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#Principal_specifying\n
**federated**: A federated identity provider, such as +accounts.google.com+ or +arn:aws:iam::AWS-account-ID:saml-provider/provider-name+. See also https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#Principal_specifying"
                  }
# XXX it's possible that 'role' is the only Mu resource type that maps to something that can assume another role in AWS IAM, so maybe that aws_resource_types.join should be something simpler
                }
              }
            },
            "iam_policies" => {
              "type" => "array",
              "items" => {
                "type" => "object",
                "description" => "A key (name) with a value that is a raw Amazon-compatible policy document. This is not the recommended method for granting permissions- we suggest listing +roles+ for the user instead. See https://docs.aws.amazon.com/IAM/latest/RoleGuide/access_policies_examples.html for example policies.",
              }
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::roles}, bare and unvalidated.
        # @param role [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(role, configurator)
          ok = true

          if role['import']
            role['import'].each { |policy|
              arn = if !policy.match(/^arn:/i)
                "arn:"+(MU::Cloud::AWS.isGovCloud?(role["region"]) ? "aws-us-gov" : "aws")+":iam::aws:policy/"+policy
              else
                policy
              end
              retried = false
              begin
                MU::Cloud::AWS.iam(credentials: role['credentials']).get_policy(policy_arn: arn)
              rescue Aws::IAM::Errors::NoSuchEntity => e
                if !retried
                  arn = "arn:"+(MU::Cloud::AWS.isGovCloud?(role["region"]) ? "aws-us-gov" : "aws")+":iam::aws:policy/service-role/"+policy
                  retried = true
                  retry
                end
                MU.log "No such canned AWS IAM policy '#{arn}'", MU::ERR
                ok = false
              end
              policy = arn
            }
          end

          if role["bare_policies"] and (!role["iam_policies"] or role["iam_policies"].empty?)
            MU.log "IAM role #{role['name']} has bare_policies set, but no iam_policies specified", MU::ERR
            ok = false
          end

          if (!role['can_assume'] or role['can_assume'].empty?) and
             !role["bare_policies"]
            MU.log "IAM role #{role['name']} must specify at least one can_assume entry", MU::ERR
            ok = false
          end

          if role['policies']
            role['policies'].each { |policy|
              policy['targets'].each { |target|
                if target['type']
                  role['dependencies'] ||= []
                  role['dependencies'] << {
                    "name" => target['identifier'],
                    "type" => target['type']
                  }
                end
              }
            }
          end

          ok
        end

        # Convert our generic internal representation of access policies into
        # structures suitable for AWS IAM policy documents.
        # @param policies [Array<Hash>]: One or more policy chunks
        # @param deploy_obj [MU::MommaCat]: Deployment object to use when looking up sibling Mu resources
        # @return [Array<Hash>]
        def self.genPolicyDocument(policies, deploy_obj: nil)
          iam_policies = []
          if policies
            policies.each { |policy|
              doc = {
                "Version" => "2012-10-17",
                "Statement" => [
                  {
                    "Sid" => policy["name"].gsub(/[^0-9A-Za-z]*/, ""),
                    "Effect" => policy['flag'].capitalize,
                    "Action" => [],
                    "Resource" => []
                  }
                ]
              }
              policy["permissions"].each { |perm|
                doc["Statement"].first["Action"] << perm
              }
              if policy["conditions"]
                doc["Statement"].first["Condition"] ||= {}
                policy["conditions"].each { |cond|
                  doc["Statement"].first["Condition"][cond['comparison']] = {
                    cond["variable"] => cond["values"]
                  }
                }
              end
              if policy["grant_to"] # XXX factor this with target, they're too similar
                doc["Statement"].first["Principal"] ||= []
                policy["grant_to"].each { |grantee|
                  if grantee["type"] and deploy_obj
                    sibling = deploy_obj.findLitterMate(
                      name: grantee["identifier"],
                      type: grantee["type"]
                    )
                    if sibling
                      id = sibling.cloudobj.arn
                      doc["Statement"].first["Principal"] << id
                    else
                      raise MuError, "Couldn't find a #{grantee["type"]} named #{grantee["identifier"]} when generating IAM policy"
                    end
                  else
                    doc["Statement"].first["Principal"] << grantee["identifier"]
                  end
                }
                if policy["grant_to"].size == 1
                  doc["Statement"].first["Principal"] = doc["Statement"].first["Principal"].first
                end
              end
              if policy["targets"]
                policy["targets"].each { |target|
                  if target["type"] and deploy_obj
                    sibling = deploy_obj.findLitterMate(
                      name: target["identifier"],
                      type: target["type"]
                    )
                    if sibling
                      id = sibling.cloudobj.arn
                      id.sub!(/:([^:]+)$/, ":"+target["path"]) if target["path"]
                      doc["Statement"].first["Resource"] << id
                      if id.match(/:log-group:/)
                        stream_id = id.sub(/:([^:]+)$/, ":log-stream:*")
#                        "arn:aws:logs:us-east-2:accountID:log-group:log_group_name:log-stream:CloudTrail_log_stream_name_prefix*"
                        doc["Statement"].first["Resource"] << stream_id
                      end
                    else
                      raise MuError, "Couldn't find a #{target["entity_type"]} named #{target["identifier"]} when generating IAM policy"
                    end
                  else
                    target["identifier"] += target["path"] if target["path"]
                    doc["Statement"].first["Resource"] << target["identifier"]
                  end
                }
              end
              iam_policies << { policy["name"] => doc }
            }
          end

          iam_policies
        end

        private

        # Convert entries from the cloud-neutral @config['policies'] list into
        # AWS syntax.
        def convert_policies_to_iam
          MU::Cloud::AWS::Role.genPolicyDocument(@config['policies'], deploy_obj: @deploy)
        end

        def get_tag_params(strip_std = false)
          @config['tags'] ||= []

          if !strip_std
            MU::MommaCat.listStandardTags.each_pair { |key, value|
              @config['tags'] << { "key" => key, "value" => value }
            }

            if @config['optional_tags']
              MU::MommaCat.listOptionalTags.each { |key, value|
                @config['tags'] << { "key" => key, "value" => value }
              }
            end
          end

          @config['tags'].map { |t|
            { :key => t["key"], :value => t["value"] }
          }
        end

        def gen_role_policy_doc
          role_policy_doc = {
            "Version" => "2012-10-17",
          }

          statements = []
          if @config['can_assume']
            act_map = {
              "basic" => "sts:AssumeRole",
              "saml" => "sts:AssumeRoleWithSAML",
              "web" => "sts:AssumeRoleWithWebIdentity"
            }
            @config['can_assume'].each { |svc|
              statement = {
                "Effect" => "Allow",
                "Action" => act_map[svc['assume_method']],
                "Principal" => {}
              }
              if ["service", "iam", "federated"].include?(svc["entity_type"])
                statement["Principal"][svc["entity_type"].capitalize] = svc["entity_id"]
              else
                sibling = @deploy.findLitterMate(
                  name: svc["entity_id"],
                  type: svc["entity_type"]
                )
                if sibling
                  statement["Principal"][svc["entity_type"].capitalize] = sibling.cloudobj.arn
                else
                  raise MuError, "Couldn't find a #{svc["entity_type"]} named #{svc["entity_id"]} when generating IAM policy in role #{@mu_name}"
                end
              end
              statements << statement
            }
          end

          role_policy_doc["Statement"] = statements

          JSON.generate(role_policy_doc)
        end

        # Update a policy, handling deletion of old versions as needed
        def update_policy(arn, doc)
          begin
            MU::Cloud::AWS.iam(credentials: @config['credentials']).create_policy_version(
              policy_arn: arn,
              set_as_default: true,
              policy_document: JSON.generate(doc)
            )
          rescue Aws::IAM::Errors::LimitExceeded => e
            delete_version = MU::Cloud::AWS.iam(credentials: @config['credentials']).list_policy_versions(
              policy_arn: arn,
            ).versions.last.version_id
            MU.log "Purging oldest version (#{delete_version}) of IAM policy #{arn}", MU::NOTICE
            MU::Cloud::AWS.iam(credentials: @config['credentials']).delete_policy_version(
              policy_arn: arn,
              version_id: delete_version
            )
            retry
          end
        end

      end
    end
  end
end
