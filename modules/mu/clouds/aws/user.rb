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
        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::users}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          @mu_name ||= if @config['unique']
            @deploy.getResourceName(@config["name"])
          else
            @config['name']
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def create

          begin
            MU::Cloud::AWS.iam.get_user(user_name: @mu_name, path: @config['path'])
            if !@config['use_if_exists']
              raise MuError, "IAM user #{@mu_name} already exists and fail_if_exists is true"
            end
          rescue Aws::IAM::Errors::NoSuchEntity => e
            @config['path'] ||= "/"+@deploy.deploy_id+"/"
            MU.log "Creating IAM user #{@config['path']}/#{@mu_name}"
            tags = get_tag_params
            MU::Cloud::AWS.iam.create_user(
              user_name: @mu_name,
              path: @config['path'],
              tags: tags
            )
          end

        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          resp = MU::Cloud::AWS.iam.list_user_tags(user_name: @mu_name)

          ext_tags = resp.tags.map { |t| t.to_h }
          tag_param = get_tag_params(true)
          tag_param.reject! { |t| ext_tags.include?(t) }

          if tag_param.size > 0
            MU.log "Updating tags on IAM user #{@mu_name}", MU::NOTICE, details: tag_param
            MU::Cloud::AWS.iam.tag_user(user_name: @mu_name, tags: tag_param)
          end
          # Note: We don't delete tags, because we often share user accounts
          # managed outside of Mu. We have no way of know what tags might come
          # from other things, so we err on the side of caution instead of 
          # deleting stuff.

          if @config['create_console_password']
            begin
              MU::Cloud::AWS.iam.get_login_profile(user_name: @mu_name)
            rescue Aws::IAM::Errors::NoSuchEntity
              pw = Password.pronounceable(12..14)
              retries = 0
              begin
                MU::Cloud::AWS.iam.create_login_profile(
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
            resp = MU::Cloud::AWS.iam.list_access_keys(
              user_name: @mu_name
            )
            if resp.access_key_metadata.size == 0
              resp = MU::Cloud::AWS.iam.create_access_key(
                user_name: @mu_name
              )
              scratchitem = MU::Master.storeScratchPadSecret("AWS Access Key and Secret for user #{@mu_name}:\nKEY: #{resp.access_key.access_key_id}\nSECRET: #{resp.access_key.secret_access_key}")
              MU.log "User #{@mu_name}'s AWS Key and Secret can be retrieved from: https://#{$MU_CFG['public_address']}/scratchpad/#{scratchitem}", MU::SUMMARY
            end
          end
        end


        # Return the metadata for this user cofiguration
        # @return [Hash]
        def notify
          MU.structToHash(MU::Cloud::AWS.iam.get_user(user_name: @mu_name).user)
        end

        # Remove all users associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          resp = MU::Cloud::AWS.iam.list_users

          # XXX this response includes a tags attribute, but it's always empty,
          # even when the user is tagged. So we go through the extra call for
          # each user. Inefficient. Probably Amazon's bug.
          resp.users.each { |u|
            tags = MU::Cloud::AWS.iam.list_user_tags(
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
                  profile = MU::Cloud::AWS.iam.get_login_profile(
                    user_name: u.user_name
                  )
                  MU.log "Deleting IAM login profile for #{u.user_name}"
                  MU::Cloud::AWS.iam.delete_login_profile(
                    user_name: u.user_name
                  )
                rescue Aws::IAM::Errors::NoSuchEntity
                end
                keys = MU::Cloud::AWS.iam.list_access_keys(
                  user_name: u.user_name
                )
                if keys.access_key_metadata.size > 0
                  keys.access_key_metadata.each { |key|
                    MU.log "Deleting IAM access key #{key.access_key_id} for #{u.user_name}"
                    keys = MU::Cloud::AWS.iam.delete_access_key(
                      user_name: u.user_name,
                      access_key_id: key.access_key_id
                    )
                  }
                end
                MU::Cloud::AWS.iam.delete_user(user_name: u.user_name)
              end
            end
          }

#          MU.log "CLEANUP CALLED ON AWS::USER", MU::WARN, details: resp
        end

        # Locate an existing user group.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @param flags [Hash]: Optional flags
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching user group.
        def self.find(cloud_id: nil, region: MU.curRegion, flags: {})
          found = nil

          resp = MU::Cloud::AWS.iam.get_user(user_name: cloud_id)
          if resp and resp.user
            found ||= {}
            found[cloud_id] = resp.user
          end

          MU.log "IN User.find cloud_id: #{cloud_id}", MU::WARN, details: flags
          found
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "name" => {
              "type" => "string",
              "description" => "A plain IAM user. If the user already exists, we will operate on that existing user. Otherwise, we will attempt to create a new user."
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
