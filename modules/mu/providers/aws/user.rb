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
      # A user as configured in {MU::Config::BasketofKittens::users}
      class User < MU::Cloud::User

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= if @config['unique_name']
            @deploy.getResourceName(@config["name"])
          else
            @config['name']
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def create

          begin
            MU::Cloud::AWS.iam(credentials: @credentials).get_user(user_name: @mu_name, path: @config['path'])
            if !@config['use_if_exists']
              raise MuError, "IAM user #{@mu_name} already exists and use_if_exists is false"
            end
          rescue Aws::IAM::Errors::NoSuchEntity
            @config['path'] ||= "/"+@deploy.deploy_id+"/"
            MU.log "Creating IAM user #{@config['path']}/#{@mu_name}"
            tags = get_tag_params
            MU::Cloud::AWS.iam(credentials: @credentials).create_user(
              user_name: @mu_name,
              path: @config['path'],
              tags: tags
            )
          end

        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          resp = MU::Cloud::AWS.iam(credentials: @credentials).list_user_tags(user_name: @mu_name)

          ext_tags = resp.tags.map { |t| t.to_h }
          tag_param = get_tag_params(true)
          tag_param.reject! { |t| ext_tags.include?(t) }

          if tag_param.size > 0
            MU.log "Updating tags on IAM user #{@mu_name}", MU::NOTICE, details: tag_param
            MU::Cloud::AWS.iam(credentials: @credentials).tag_user(user_name: @mu_name, tags: tag_param)
          end
          # Note: We don't delete tags, because we often share user accounts
          # managed outside of Mu. We have no way of know what tags might come
          # from other things, so we err on the side of caution instead of 
          # deleting stuff.

          if @config['create_console_password']
            begin
              MU::Cloud::AWS.iam(credentials: @credentials).get_login_profile(user_name: @mu_name)
            rescue Aws::IAM::Errors::NoSuchEntity
              pw = Password.pronounceable(12..14)
              retries = 0
              begin
                MU::Cloud::AWS.iam(credentials: @credentials).create_login_profile(
                  user_name: @mu_name,
                  password: pw
                )
                scratchitem = MU::Master.storeScratchPadSecret("AWS Console password for user #{@mu_name}:\n<pre>#{pw}</pre>")
                MU.log "User #{@mu_name}'s AWS Console password can be retrieved from: https://#{$MU_CFG['public_address']}/scratchpad/#{scratchitem}", MU::SUMMARY
              rescue Aws::IAM::Errors::PasswordPolicyViolation => e
                if retries < 1
                  pw = MU.generateWindowsPassword
                  retries += 1
                  sleep 1
                  retry
                else
                  MU.log "Error setting password for #{e.message}", MU::WARN
                end
              end
            end
          end

          if @config['create_api_keys']
            resp = MU::Cloud::AWS.iam(credentials: @credentials).list_access_keys(
              user_name: @mu_name
            )
            if resp.access_key_metadata.size == 0
              resp = MU::Cloud::AWS.iam(credentials: @credentials).create_access_key(
                user_name: @mu_name
              )
              scratchitem = MU::Master.storeScratchPadSecret("AWS Access Key and Secret for user #{@mu_name}:\nKEY: #{resp.access_key.access_key_id}\nSECRET: #{resp.access_key.secret_access_key}")
              MU.log "User #{@mu_name}'s AWS Key and Secret can be retrieved from: https://#{$MU_CFG['public_address']}/scratchpad/#{scratchitem}", MU::SUMMARY
            end
          end

          # Create these if necessary, then append them to the list of
          # attachable_policies
          if @config['raw_policies']
            pol_arns = MU::Cloud.resourceClass("AWS", "Role").manageRawPolicies(
              @config['raw_policies'],
              basename: @deploy.getResourceName(@config['name']),
              credentials: @credentials
            )
            @config['attachable_policies'] ||= []
            @config['attachable_policies'].concat(pol_arns.map { |a| { "id" => a } })
          end

          if @config['attachable_policies']
            configured_policies = @config['attachable_policies'].map { |p|
              if p.is_a?(MU::Config::Ref)
                p.cloud_id
              else
                p = MU::Config::Ref.get(p)
                p.kitten
                p.cloud_id
              end
            }

            attached_policies = MU::Cloud::AWS.iam(credentials: @credentials).list_attached_user_policies(
              user_name: @cloud_id
            ).attached_policies
            attached_policies.each { |a|
              if !configured_policies.include?(a.policy_arn)
                MU.log "Removing IAM policy #{a.policy_arn} from user #{@mu_name}", MU::NOTICE
                MU::Cloud.resourceClass("AWS", "Role").purgePolicy(a.policy_arn, @credentials)
              else
                configured_policies.delete(a.policy_arn)
              end
            }

            configured_policies.each { |policy_arn|
              MU.log "Attaching #{policy_arn} to user #{@cloud_id}"
              MU::Cloud::AWS.iam(credentials: @credentials).attach_user_policy(
                policy_arn: policy_arn,
                user_name: @cloud_id
              )
            }
          end

          if @config['inline_policies']
            docs = MU::Cloud.resourceClass("AWS", "Role").genPolicyDocument(@config['inline_policies'], deploy_obj: @deploy)
            docs.each { |doc|
              MU.log "Putting user policy #{doc.keys.first} to user #{@cloud_id} "
              MU::Cloud::AWS.iam(credentials: @credentials).put_user_policy(
                policy_document: JSON.generate(doc.values.first),
                policy_name: doc.keys.first,
                user_name: @cloud_id
              )
            }
          end

        end


        # Return the metadata for this user cofiguration
        # @return [Hash]
        def notify
          descriptor = MU.structToHash(MU::Cloud::AWS.iam(credentials: @credentials).get_user(user_name: @mu_name).user)
          descriptor["cloud_id"] = @mu_name
          descriptor
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

        # Remove all users associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, credentials: nil, flags: {})
          MU.log "AWS::User.cleanup: need to support flags['known']", MU::DEBUG, details: flags

          # XXX this doesn't belong here; maybe under roles, maybe as its own stupid first-class resource
          resp = MU::Cloud::AWS.iam(credentials: credentials).list_policies(
            path_prefix: "/"+deploy_id+"/"
          )
          if resp and resp.policies
            resp.policies.each { |policy|
              MU.log "Deleting policy /#{deploy_id}/#{policy.policy_name}"
              if !noop
                attachments = begin
                  MU::Cloud::AWS.iam(credentials: credentials).list_entities_for_policy(
                    policy_arn: policy.arn
                  )
                rescue ::Aws::IAM::Errors::NoSuchEntity
                end
                if attachments
                  begin
                    attachments.policy_users.each { |u|
                      MU::Cloud::AWS.iam(credentials: credentials).detach_user_policy(
                        user_name: u.user_name,
                        policy_arn: policy.arn
                      )
                    }
                  rescue ::Aws::IAM::Errors::NoSuchEntity
                  end
                  begin
                    attachments.policy_groups.each { |g|
                      MU::Cloud::AWS.iam(credentials: credentials).detach_group_policy(
                        group_name: g.group_name,
                        policy_arn: policy.arn
                      )
                    }
                  rescue ::Aws::IAM::Errors::NoSuchEntity
                  end
                  begin
                    attachments.policy_roles.each { |r|
                      MU::Cloud::AWS.iam(credentials: credentials).detach_role_policy(
                        role_name: r.role_name,
                        policy_arn: policy.arn
                      )
                    }
                  rescue ::Aws::IAM::Errors::NoSuchEntity
                  end
                end

                begin
                  MU::Cloud::AWS.iam(credentials: credentials).delete_policy(
                    policy_arn: policy.arn
                  )
                rescue ::Aws::IAM::Errors::DeleteConflict
                  versions = MU::Cloud::AWS.iam(credentials: credentials).list_policy_versions(
                    policy_arn: policy.arn,
                  ).versions
                  versions.each { |v|
                    next if v.is_default_version
                    begin
                      MU::Cloud::AWS.iam(credentials: credentials).delete_policy_version(
                        policy_arn: policy.arn,
                        version_id: v.version_id
                      )
                    rescue ::Aws::IAM::Errors::NoSuchEntity
                    end
                  }
                  retry
                rescue ::Aws::IAM::Errors::NoSuchEntity
rescue StandardError => e
MU.log e.inspect, MU::ERR, details: policy
                end
              end
            }
          end

          resp = MU::Cloud::AWS.iam(credentials: credentials).list_users

          # XXX this response includes a tags attribute, but it's always empty,
          # even when the user is tagged. So we go through the extra call for
          # each user. Inefficient. Probably Amazon's bug.
          resp.users.each { |u|
            tags = MU::Cloud::AWS.iam(credentials: credentials).list_user_tags(
              user_name: u.user_name
            ).tags
            has_nodelete = false
            has_ourdeploy = false
            has_ourmaster = false
            tags.each { |tag|
              if tag.key == "MU-ID" and tag.value == deploy_id
                has_ourdeploy = true
              elsif tag.key == "MU-MASTER-IP" and tag.value == MU.mu_public_ip
                has_ourmaster = true
              elsif tag.key == "MU-NO-DELETE" and tag.value == "true"
                has_nodelete = true
              end
            }
            if has_ourdeploy and !has_nodelete and (ignoremaster or has_ourmaster)
              MU.log "Deleting IAM user #{u.path}#{u.user_name}"
              if !@noop
                begin
                  groups = MU::Cloud::AWS.iam(credentials: credentials).list_groups_for_user(
                    user_name: u.user_name
                  ).groups

                  groups.each { |g|
                    MU::Cloud::AWS.iam(credentials: credentials).remove_user_from_group(
                      user_name: u.user_name,
                      group_name: g.group_name
                    )
                  }
                  MU::Cloud::AWS.iam(credentials: credentials).get_login_profile(
                    user_name: u.user_name
                  )
                  MU.log "Deleting IAM login profile for #{u.user_name}"
                  MU::Cloud::AWS.iam(credentials: credentials).delete_login_profile(
                    user_name: u.user_name
                  )
                rescue Aws::IAM::Errors::EntityTemporarilyUnmodifiable
                  sleep 10
                  retry
                rescue Aws::IAM::Errors::NoSuchEntity
                end
                keys = MU::Cloud::AWS.iam(credentials: credentials).list_access_keys(
                  user_name: u.user_name
                )
                if keys.access_key_metadata.size > 0
                  keys.access_key_metadata.each { |key|
                    MU.log "Deleting IAM access key #{key.access_key_id} for #{u.user_name}"
                    keys = MU::Cloud::AWS.iam(credentials: credentials).delete_access_key(
                      user_name: u.user_name,
                      access_key_id: key.access_key_id
                    )
                  }
                end

                poldesc = MU::Cloud::AWS.iam(credentials: credentials).list_user_policies(user_name: u.user_name)
                if poldesc and poldesc.policy_names and poldesc.policy_names.size > 0
                  poldesc.policy_names.each { |pol_name|
                    MU::Cloud::AWS.iam(credentials: credentials).delete_user_policy(user_name: u.user_name, policy_name: pol_name)
                  }
                end

                attached_policies = MU::Cloud::AWS.iam(credentials: credentials).list_attached_user_policies(
                  user_name: u.user_name
                ).attached_policies
                attached_policies.each { |a|
                  MU.log "Detaching IAM policy #{a.policy_arn} from user #{u.user_name}"
                  MU::Cloud::AWS.iam(credentials: credentials).detach_user_policy(user_name: u.user_name, policy_arn: a.policy_arn)
                }

                MU::Cloud::AWS.iam(credentials: credentials).delete_user(user_name: u.user_name)
              end
            end
          }

        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          cloud_desc.arn
        end

        # Locate an existing IAM user
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching user group.
        def self.find(**args)
          found = {}

          if args[:cloud_id]
            begin
              resp = MU::Cloud::AWS.iam(credentials: args[:credentials]).get_user(user_name: args[:cloud_id])
              if resp and resp.user
                found[args[:cloud_id]] = resp.user
              end
            rescue ::Aws::IAM::Errors::NoSuchEntity
            end
          else
            marker = nil
            begin
              resp = MU::Cloud::AWS.iam(credentials: args[:credentials]).list_users(marker: marker)
              break if !resp or !resp.users
              marker = resp.marker

              resp.users.each { |u|
                found[u.user_name] = u
              }
            end while marker
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
            "cloud_id" => @cloud_id
          }

          if !cloud_desc
            MU.log "toKitten failed to load a cloud_desc from #{@cloud_id}", MU::ERR, details: @config
            return nil
          end

          bok['name'] = cloud_desc.user_name

          if cloud_desc.tags and cloud_desc.tags.size > 0
            bok["tags"] = MU.structToHash(cloud_desc.tags, stringify_keys: true)
          end

          if cloud_desc.path != "/"
            bok["path"] = cloud_desc.path
          end

          begin
            resp = MU::Cloud::AWS.iam(credentials: @credentials).get_login_profile(user_name: @cloud_id)
            if resp and resp.login_profile
              bok['create_console_password'] = true
              if resp.login_profile.password_reset_required
                bok['force_password_change'] = true
              end
            end
          rescue ::Aws::IAM::Errors::NoSuchEntity
          end

          begin
            resp = MU::Cloud::AWS.iam(credentials: @credentials).list_access_keys(user_name: @cloud_id)
            if resp and resp.access_key_metadata
              bok['create_api_key'] = true
            end
          rescue ::Aws::IAM::Errors::NoSuchEntity
          end

          # Grab and assimilate any inline policies attached to this user
          resp = MU::Cloud::AWS.iam(credentials: @credentials).list_user_policies(user_name: @cloud_id)
          if resp and resp.policy_names and resp.policy_names.size > 0
            resp.policy_names.each { |pol_name|
              pol = MU::Cloud::AWS.iam(credentials: @credentials).get_user_policy(user_name: @cloud_id, policy_name: pol_name)
              doc = JSON.parse(CGI.unescape(pol.policy_document))
              bok["inline_policies"] = MU::Cloud.resourceClass("AWS", "Role").doc2MuPolicies(pol.policy_name, doc, bok["inline_policies"])
            }
          end

          # Grab and reference any managed policies attached to this user
          resp = MU::Cloud::AWS.iam(credentials: @credentials).list_attached_user_policies(user_name: @cloud_id)
          if resp and resp.attached_policies
            resp.attached_policies.each { |pol|
              bok["attachable_policies"] ||= []
              if pol.policy_arn.match(/arn:aws(?:-us-gov)?:iam::aws:policy\//)
                bok["attachable_policies"] << MU::Config::Ref.get(
                  id: pol.policy_name,
                  cloud: "AWS"
                )
              else
                bok["attachable_policies"] << MU::Config::Ref.get(
                  id: pol.policy_arn,
                  name: pol.policy_name,
                  cloud: "AWS",
                  type: "roles"
                )
              end
            }
          end

          bok
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          polschema = MU::Config::Role.schema["properties"]["policies"]
          polschema.deep_merge!(MU::Cloud.resourceClass("AWS", "Role").condition_schema)

          schema = {
            "inline_policies" => polschema,
            "attachable_policies" => {
              "type" => "array",
              "items" => MU::Config::Ref.schema(type: "roles", desc: "Reference to a managed policy, which can either refer to an existing managed policy or a sibling {MU::Config::BasketofKittens::roles} object which has +bare_policies+ set.", omit_fields: ["region", "tag"])
            },
            "raw_policies" => {
              "type" => "array",
              "items" => {
                "description" => "A key (name) with a value that is an Amazon-compatible policy document. See https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_examples.html for example policies.",
                "type" => "object"
              }
            },
            "name" => {
              "type" => "string",
              "description" => "A plain IAM user. If the user already exists, we will operate on that existing user. Otherwise, we will attempt to create a new user. AWS IAM does not distinguish between human user accounts and machine accounts."
            },
            "path" => {
              "type" => "string",
              "description" => "AWS IAM users can be namespaced with a path (ex: +/organization/unit/user+). If not specified, and if we do not see a matching existing user under +/+ with +use_if_exists+ set, we will prepend the deploy identifier to the path of users we create. Ex: +/IAMTESTS-DEV-2018112910-GR/myuser+.",
              "pattern" => '^\/(?:[^\/]+(?:\/[^\/]+)*\/$)?'
            },
            "tags" => MU::Config.tags_primitive,
            "optional_tags" => MU::Config.optional_tags_primitive,
            "unique_name" => {
              "type" => "boolean",
              "default" => false,
              "description" => "Instead of creating/updating a user account with
 the exact name specified in the 'name' field, generate a unique-per-deploy Mu-
style long name, like +IAMTESTS-DEV-2018112815-IS-USER-FOO+"
            },
            "create_console_password" => {
              "type" => "boolean",
              "default" => false,
              "description" => "Generate a password for this user, for use logging into the AWS Console. It will be shared via Scratchpad for one-time retrieval."
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::users}, bare and unvalidated.
        # @param user [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(user, configurator)
          ok = true

          # If we're attaching some managed policies, make sure all of the ones
          # that should already exist do indeed exist
          if user['attachable_policies']
            ok = false if !MU::Cloud.resourceClass("AWS", "Role").validateAttachablePolicies(
              user['attachable_policies'],
              credentials: user['credentials'],
              region: user['region']
            )
          end

          if user['groups']
            user['groups'].each { |group|
              need_dependency = false
              if configurator.haveLitterMate?(group, "groups")
                need_dependency = true
              else
                found = MU::Cloud.resourceClass("AWS", "Group").find(cloud_id: group)
                if found.nil? or found.empty? or (configurator.updating and
                   found.values.first.group.path == "/"+configurator.updating+"/")
                  groupdesc = {
                    "name" => group
                  }
                  configurator.insertKitten(groupdesc, "groups")
                  need_dependency = true
                end
              end

              if need_dependency
                MU::Config.addDependency(user, group, "group")
              end
            }
          end

          ok
        end

        private

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

          if @config['preserve_on_cleanup']
            @config['tags'] << { "key" => "MU-NO-DELETE", "value" => "true" }
          end

          @config['tags'].map { |t|
            { :key => t["key"], :value => t["value"] }
          }
        end

      end
    end
  end
end
