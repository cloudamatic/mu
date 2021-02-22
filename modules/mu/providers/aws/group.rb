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
      # A group as configured in {MU::Config::BasketofKittens::groups}
      class Group < MU::Cloud::Group

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
            MU::Cloud::AWS.iam(credentials: @credentials).get_group(
              group_name: @mu_name,
              path: @config['path']
            )
            if !@config['use_if_exists']
              raise MuError, "IAM group #{@mu_name} already exists and use_if_exists is false"
            end
          rescue Aws::IAM::Errors::NoSuchEntity
            @config['path'] ||= "/"+@deploy.deploy_id+"/"
            MU.log "Creating IAM group #{@config['path']}#{@mu_name}"
            MU::Cloud::AWS.iam(credentials: @credentials).create_group(
              group_name: @mu_name,
              path: @config['path']
            )
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          if @config['members']
            ext = cloud_desc.users.map { |u| u.user_name }

            @config['members'].each { |user|
              next if ext.include?(user)

              userid = user
              userdesc = @deploy.findLitterMate(name: user, type: "users")
              userid = userdesc.cloud_id if userdesc
              found = MU::Cloud.resourceClass("AWS", "User").find(cloud_id: userid)
              if found.size == 1
                userdesc = found.values.first
                MU.log "Adding IAM user #{userdesc.path}#{userdesc.user_name} to group #{@mu_name}", MU::NOTICE
                MU::Cloud::AWS.iam(credentials: @credentials).add_user_to_group(
                  user_name: userid,
                  group_name: @mu_name
                )
              else
                MU.log "IAM user #{userid} doesn't seem to exist, can't add to group #{@mu_name}", MU::ERR
              end
            }
            
            if @config['purge_extra_members']
              extras = cloud_desc.users.map { |u| u.user_name } - @config['members']
              extras.each { |user_name|
                MU.log "Purging user #{user_name} from IAM group #{@cloud_id}", MU::NOTICE
                MU::Cloud::AWS.iam(credentials: @credentials).remove_user_from_group(
                  user_name: user_name,
                  group_name: @cloud_id
                )
              }
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

            attached_policies = MU::Cloud::AWS.iam(credentials: @credentials).list_attached_group_policies(
              group_name: @cloud_id
            ).attached_policies
            attached_policies.each { |a|
              if !configured_policies.include?(a.policy_arn)
                MU.log "Removing IAM policy #{a.policy_arn} from group #{@mu_name}", MU::NOTICE
                MU::Cloud.resourceClass("AWS", "Role").purgePolicy(a.policy_arn, @credentials)
              else
                configured_policies.delete(a.policy_arn)
              end
            }

            configured_policies.each { |policy_arn|
              MU.log "Attaching #{policy_arn} to group #{@cloud_id}"
              MU::Cloud::AWS.iam(credentials: @credentials).attach_group_policy(
                policy_arn: policy_arn,
                group_name: @cloud_id
              )
            }

          end

          if @config['inline_policies']
            docs = MU::Cloud.resourceClass("AWS", "Role").genPolicyDocument(@config['inline_policies'], deploy_obj: @deploy)
            docs.each { |doc|
              MU.log "Putting user policy #{doc.keys.first} to group #{@cloud_id} "
              MU::Cloud::AWS.iam(credentials: @credentials).put_group_policy(
                policy_document: JSON.generate(doc.values.first),
                policy_name: doc.keys.first,
                group_name: @cloud_id
              )
            }
          end

        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          cloud_desc.arn
        end

        @cloud_desc_cache = nil
        # Fetch the AWS API description of this group
        # return [Struct]
        def cloud_desc(use_cache: true)
          return @cloud_desc_cache if @cloud_desc_cache and use_cache
          return nil if !@mu_name
          @cloud_desc_cache = MU::Cloud::AWS.iam(credentials: @credentials).get_group(
            group_name: @mu_name
          )
          @cloud_desc_cache
        end

        # Return the metadata for this group configuration
        # @return [Hash]
        def notify
          descriptor = MU.structToHash(cloud_desc)
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

        # Remove all groups associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, credentials: nil, flags: {})
          MU.log "AWS::Group.cleanup: need to support flags['known']", MU::DEBUG, details: flags
          MU.log "Placeholder: AWS Group artifacts do not support tags, so ignoremaster cleanup flag has no effect", MU::DEBUG, details: ignoremaster

          resp = MU::Cloud::AWS.iam(credentials: credentials).list_groups(
            path_prefix: "/"+deploy_id+"/"
          )
          if resp and resp.groups
            resp.groups.each { |g|
              MU.log "Deleting IAM group #{g.path}#{g.group_name}"
              if !noop
                desc = MU::Cloud::AWS.iam(credentials: credentials).get_group(
                  group_name: g.group_name
                )
                desc.users.each { |u|
                  MU::Cloud::AWS.iam(credentials: credentials).remove_user_from_group(
                    user_name: u.user_name,
                    group_name: g.group_name
                  )
                }

                poldesc = MU::Cloud::AWS.iam(credentials: credentials).list_group_policies(group_name: g.group_name)
                if poldesc and poldesc.policy_names and poldesc.policy_names.size > 0
                  poldesc.policy_names.each { |pol_name|
                    MU::Cloud::AWS.iam(credentials: credentials).delete_group_policy(group_name: g.group_name, policy_name: pol_name)
                  }
                end

                attached_policies = MU::Cloud::AWS.iam(credentials: credentials).list_attached_group_policies(
                  group_name: g.group_name
                ).attached_policies
                attached_policies.each { |a|
                  MU.log "Detaching IAM policy #{a.policy_arn} from group #{g.group_name}"
                  MU::Cloud::AWS.iam(credentials: credentials).detach_group_policy(group_name: g.group_name, policy_arn: a.policy_arn)
                }

                MU::Cloud::AWS.iam(credentials: credentials).delete_group(
                  group_name: g.group_name
                )
              end
            }
          end
        end

        # Locate an existing group group.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching group group.
        def self.find(**args)
          found = {}

          if args[:cloud_id]
            begin
              resp = MU::Cloud::AWS.iam(credentials: args[:credentials]).get_group(
                group_name: args[:cloud_id]
              )
              found ||= {}
              found[args[:cloud_id]] = resp
            rescue Aws::IAM::Errors::NoSuchEntity
            end
          else
            marker = nil
            begin
              resp = MU::Cloud::AWS.iam(credentials: args[:credentials]).list_groups(marker: marker)
              break if !resp or !resp.groups
              marker = resp.marker

              resp.groups.each { |g|
                found[g.group_name] = g
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

          group_desc = cloud_desc(use_cache: false).respond_to?(:group) ? cloud_desc.group : cloud_desc
          bok["name"] = group_desc.group_name

          if group_desc.path != "/"
            bok["path"] = group_desc.path
          end

          if cloud_desc.respond_to?(:users) and cloud_desc.users and cloud_desc.users.size > 0
            bok["members"] = cloud_desc.users.map { |u| u.user_name }
          end

          # Grab and assimilate any inline policies attached to this group
          resp = MU::Cloud::AWS.iam(credentials: @credentials).list_group_policies(group_name: @cloud_id)
          if resp and resp.policy_names and resp.policy_names.size > 0
            resp.policy_names.each { |pol_name|
              pol = MU::Cloud::AWS.iam(credentials: @credentials).get_group_policy(group_name: @cloud_id, policy_name: pol_name)
              doc = JSON.parse(CGI.unescape(pol.policy_document))
              bok["inline_policies"] = MU::Cloud.resourceClass("AWS", "Role").doc2MuPolicies(pol.policy_name, doc, bok["inline_policies"])
            }
          end

          # Grab and reference any managed policies attached to this group
          resp = MU::Cloud::AWS.iam(credentials: @credentials).list_attached_group_policies(group_name: @cloud_id)
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
                  cloud: "AWS"
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
            "unique_name" => {
              "type" => "boolean",
              "description" => "Instead of creating/updating a group with
 the exact name specified in the 'name' field, generate a unique-per-deploy Mu-
style long name, like +IAMTESTS-DEV-2018112815-IS-GROUP-FOO+. This parameter will automatically be set to +true+ if it is left unspecified and +use_if_exists+ is set to +false+."
            },
            "path" => {
              "type" => "string",
              "description" => "AWS IAM groups can be namespaced with a path (ex: +/organization/unit/group+). If not specified, and if we do not see a matching existing group under +/+ with +use_if_exists+ set, we will prepend the deploy identifier to the path of groups we create. Ex: +/IAMTESTS-DEV-2018112910-GR/mygroup+.",
              "pattern" => '^\/(?:[^\/]+(?:\/[^\/]+)*\/$)?'
            },
            "raw_policies" => {
              "type" => "array",
              "items" => {
                "description" => "A key (name) with a value that is an Amazon-compatible policy document. See https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_examples.html for example policies.",
                "type" => "object"
              }
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::groups}, bare and unvalidated.
        # @param group [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(group, configurator)
          ok = true

          # If we're attaching some managed policies, make sure all of the ones
          # that should already exist do indeed exist
          if group['attachable_policies']
            ok = false if !MU::Cloud.resourceClass("AWS", "Role").validateAttachablePolicies(
              group['attachable_policies'],
              credentials: group['credentials'],
              region: group['region']
            )
          end

          if !group['use_if_exists'] and group['unique_name'].nil?
            group['unique_name'] = true
          end

          if group['members']
            group['members'].each { |user|
              if configurator.haveLitterMate?(user, "users")
                MU::Config.addDependency(group, user, "user")
              else
                found = MU::Cloud.resourceClass("AWS", "User").find(cloud_id: user)
                if found.nil? or found.empty?
                  MU.log "Error in members for group #{group['name']}: No such user #{user}", MU::ERR
                  ok = false
                end
              end
            }
          end

          ok
        end

      end
    end
  end
end
