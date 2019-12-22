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
            MU::Cloud::AWS.iam(credentials: @config['credentials']).get_group(
              group_name: @mu_name,
              path: @config['path']
            )
            if !@config['use_if_exists']
              raise MuError, "IAM group #{@mu_name} already exists and use_if_exists is false"
            end
          rescue Aws::IAM::Errors::NoSuchEntity => e
            @config['path'] ||= "/"+@deploy.deploy_id+"/"
            MU.log "Creating IAM group #{@config['path']}#{@mu_name}"
            MU::Cloud::AWS.iam(credentials: @config['credentials']).create_group(
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
              found = MU::Cloud::AWS::User.find(cloud_id: userid)
              if found.size == 1
                userdesc = found.values.first
                MU.log "Adding IAM user #{userdesc.path}#{userdesc.user_name} to group #{@mu_name}", MU::NOTICE
                MU::Cloud::AWS.iam(credentials: @config['credentials']).add_user_to_group(
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
                MU::Cloud::AWS.iam(credentials: @config['credentials']).remove_user_from_group(
                  user_name: user_name,
                  group_name: @cloud_id
                )
              }
            end
          end

          if @config['iam_policies']
             @dependencies["role"].each_pair { |rolename, roleobj|
               roleobj.cloudobj.bindTo("group", @cloud_id)
             }
          end
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          cloud_desc.arn
        end


        # Fetch the AWS API description of this group
        # return [Struct]
        def cloud_desc
          MU::Cloud::AWS.iam(credentials: @config['credentials']).get_group(
            group_name: @mu_name
          )
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
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          resp = MU::Cloud::AWS.iam(credentials: credentials).list_groups(
            path_prefix: "/"+MU.deploy_id+"/"
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
          
          bok["name"] = cloud_desc.group.group_name

          if cloud_desc.group.path != "/"
            bok["path"] = cloud_desc.group.path
          end

          if cloud_desc.users and cloud_desc.users.size > 0
            bok["members"] = cloud_desc.users.map { |u| u.user_name }
          end

          resp = MU::Cloud::AWS.iam(credentials: @credentials).list_group_policies(group_name: @cloud_id)
          if resp and resp.policy_names
            resp.policy_names.each { |pol_name|
              pol = MU::Cloud::AWS.iam(credentials: @credentials).get_group_policy(group_name: @cloud_id, policy_name: pol_name)
              pp pol
            }
          end


          resp = MU::Cloud::AWS.iam(credentials: @credentials).list_attached_group_policies(group_name: @cloud_id)
          if resp and resp.attached_policies
            resp.attached_policies.each { |pol|
            puts pol.policy_arn
            }
          end

          bok
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "policies" => MU::Config::Role.schema["properties"]["policies"],
            "import" => MU::Config::Role.schema["properties"]["import"],
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

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::groups}, bare and unvalidated.
        # @param group [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(group, configurator)
          ok = true

          if group['iam_policies'] and group['iam_policies'].size > 0
            roledesc = {
              "name" => group["name"]+"role",
              "bare_policies" => true,
              "iam_policies" => group['iam_policies'].dup
            }
            configurator.insertKitten(roledesc, "roles")
            group["dependencies"] ||= []
            group["dependencies"] << {
              "type" => "role",
              "name" => group["name"]+"role"
            }
          end

          if !group['use_if_exists'] and group['unique_name'].nil?
            group['unique_name'] = true
          end

          if group['members']
            group['members'].each { |user|
              if configurator.haveLitterMate?(user, "users")
                group["dependencies"] ||= []
                group["dependencies"] << {
                  "type" => "user",
                  "name" => user
                }
              else
                found = MU::Cloud::AWS::User.find(cloud_id: user)
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
