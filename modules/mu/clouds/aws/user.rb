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
            MU::Cloud::AWS.iam(credentials: @config['credentials']).get_user(user_name: @mu_name, path: @config['path'])
            if !@config['use_if_exists']
              raise MuError, "IAM user #{@mu_name} already exists and use_if_exists is false"
            end
          rescue Aws::IAM::Errors::NoSuchEntity => e
            @config['path'] ||= "/"+@deploy.deploy_id+"/"
            MU.log "Creating IAM user #{@config['path']}/#{@mu_name}"
            tags = get_tag_params
            MU::Cloud::AWS.iam(credentials: @config['credentials']).create_user(
              user_name: @mu_name,
              path: @config['path'],
              tags: tags
            )
          end

        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          resp = MU::Cloud::AWS.iam(credentials: @config['credentials']).list_user_tags(user_name: @mu_name)

          ext_tags = resp.tags.map { |t| t.to_h }
          tag_param = get_tag_params(true)
          tag_param.reject! { |t| ext_tags.include?(t) }

          if tag_param.size > 0
            MU.log "Updating tags on IAM user #{@mu_name}", MU::NOTICE, details: tag_param
            MU::Cloud::AWS.iam(credentials: @config['credentials']).tag_user(user_name: @mu_name, tags: tag_param)
          end
          # Note: We don't delete tags, because we often share user accounts
          # managed outside of Mu. We have no way of know what tags might come
          # from other things, so we err on the side of caution instead of 
          # deleting stuff.

          if @config['create_console_password']
            begin
              MU::Cloud::AWS.iam(credentials: @config['credentials']).get_login_profile(user_name: @mu_name)
            rescue Aws::IAM::Errors::NoSuchEntity
              pw = Password.pronounceable(12..14)
              retries = 0
              begin
                MU::Cloud::AWS.iam(credentials: @config['credentials']).create_login_profile(
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
            resp = MU::Cloud::AWS.iam(credentials: @config['credentials']).list_access_keys(
              user_name: @mu_name
            )
            if resp.access_key_metadata.size == 0
              resp = MU::Cloud::AWS.iam(credentials: @config['credentials']).create_access_key(
                user_name: @mu_name
              )
              scratchitem = MU::Master.storeScratchPadSecret("AWS Access Key and Secret for user #{@mu_name}:\nKEY: #{resp.access_key.access_key_id}\nSECRET: #{resp.access_key.secret_access_key}")
              MU.log "User #{@mu_name}'s AWS Key and Secret can be retrieved from: https://#{$MU_CFG['public_address']}/scratchpad/#{scratchitem}", MU::SUMMARY
            end
          end

          if @config['iam_policies']
             @dependencies["role"].each_pair { |rolename, roleobj|
               roleobj.cloudobj.bindTo("user", @cloud_id)
             }
          end
        end


        # Return the metadata for this user cofiguration
        # @return [Hash]
        def notify
          descriptor = MU.structToHash(MU::Cloud::AWS.iam(credentials: @config['credentials']).get_user(user_name: @mu_name).user)
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
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})

          # XXX this doesn't belong here; maybe under roles, maybe as its own stupid first-class resource
          resp = MU::Cloud::AWS.iam(credentials: credentials).list_policies(
            path_prefix: "/"+MU.deploy_id+"/"
          )
          if resp and resp.policies
            resp.policies.each { |policy|
              MU.log "Deleting policy /#{MU.deploy_id}/#{policy.policy_name}"
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
                      MU::Cloud::AWS.iam(credentials: credentials).detach_role_policy(
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
            tags.each { |tag|
              if tag.key == "MU-ID" and tag.value == MU.deploy_id
                has_ourdeploy = true
              elsif tag.key == "MU-NO-DELETE" and tag.value == "true"
                has_nodelete = true
              end
            }
            if has_ourdeploy and !has_nodelete
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
                  profile = MU::Cloud::AWS.iam(credentials: credentials).get_login_profile(
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
        def toKitten(rootparent: nil, billing: nil, habitats: nil)
          bok = {
            "cloud" => "AWS",
            "credentials" => @config['credentials'],
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

          resp = MU::Cloud::AWS.iam(credentials: @credentials).list_user_policies(user_name: @cloud_id)
          if resp and resp.policy_names and resp.policy_names.size > 0
            resp.policy_names.each { |pol_name|
              pol = MU::Cloud::AWS.iam(credentials: @credentials).get_user_policy(user_name: @cloud_id, policy_name: pol_name)
              doc = JSON.parse(URI.decode(pol.policy_document))
              bok["policies"] = MU::Cloud::AWS::Role.doc2MuPolicies(pol.policy_name, doc, bok["policies"])
            }
          end

          MU.log @cloud_id, MU::NOTICE, details: resp

          bok
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "name" => {
              "type" => "string",
              "description" => "A plain IAM user. If the user already exists, we will operate on that existing user. Otherwise, we will attempt to create a new user. AWS IAM does not distinguish between human user accounts and machine accounts."
            },
            "policies" => MU::Cloud::AWS::Role.condition_schema,
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
            },
            "iam_policies" => {
              "type" => "array",
              "items" => {
                "description" => "A key (name) with a value that is an Amazon-compatible policy document. See https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_examples.html for example policies.",
                "type" => "object"
              }
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

          if user['iam_policies'] and user['iam_policies'].size > 0
            roledesc = {
              "name" => user["name"]+"role",
              "bare_policies" => true,
              "iam_policies" => user['iam_policies'].dup
            }
            configurator.insertKitten(roledesc, "roles")
            user["dependencies"] ||= []
            user["dependencies"] << {
              "type" => "role",
              "name" => user["name"]+"role"
            }
          end

          if user['groups']
            user['groups'].each { |group|
              need_dependency = false
              if configurator.haveLitterMate?(group, "groups")
                need_dependency = true
              else
                found = MU::Cloud::AWS::Group.find(cloud_id: group)
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
                user["dependencies"] ||= []
                user["dependencies"] << {
                  "type" => "group",
                  "name" => group
                }
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
