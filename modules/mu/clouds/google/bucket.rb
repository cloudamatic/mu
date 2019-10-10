# Copyright:: Copyright (c) 2019 eGlobalTech, Inc., all rights reserved
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
    class Google
      # Support for Google Cloud Storage
      class Bucket < MU::Cloud::Bucket

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          @project_id = MU::Cloud::Google.projectLookup(@config['project'], @deploy).cloud_id
          MU::Cloud::Google.storage(credentials: credentials).insert_bucket(@project_id, bucket_descriptor)
          @cloud_id = @mu_name.downcase
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          @project_id = MU::Cloud::Google.projectLookup(@config['project'], @deploy).cloudobj.cloud_id

          current = cloud_desc
          changed = false

          if !current.versioning.enabled and @config['versioning']
            MU.log "Enabling versioning on Cloud Storage bucket #{@cloud_id}", MU::NOTICE
            changed = true
          elsif current.versioning.enabled and !@config['versioning']
            MU.log "Disabling versioning on Cloud Storage bucket #{@cloud_id}", MU::NOTICE
            changed = true
          end

          if current.website.nil? and @config['web']
            MU.log "Enabling website service on Cloud Storage bucket #{@cloud_id}", MU::NOTICE
            changed = true
          elsif !current.website.nil? and !@config['web']
            MU.log "Disabling website service on Cloud Storage bucket #{@cloud_id}", MU::NOTICE
            changed = true
          end

          if @config['bucket_wide_acls'] and (!current.iam_configuration or
             !current.iam_configuration.bucket_policy_only or
             !current.iam_configuration.bucket_policy_only.enabled)
            MU.log "Converting Cloud Storage bucket #{@cloud_id} to use bucket-wide ACLs only", MU::NOTICE
            changed = true
          elsif !@config['bucket_wide_acls'] and current.iam_configuration and
                current.iam_configuration.bucket_policy_only and
                current.iam_configuration.bucket_policy_only.enabled
            MU.log "Converting Cloud Storage bucket #{@cloud_id} to use bucket and object ACLs", MU::NOTICE
            changed = true
          end

          if changed
            MU::Cloud::Google.storage(credentials: credentials).patch_bucket(@cloud_id, bucket_descriptor)
          end

          if @config['policies']
            @config['policies'].each { |pol|
              pol['grant_to'].each { |grantee|
                grantee['id'] ||= grantee["identifier"]
                entity = if grantee["type"]
                  sibling = deploy_obj.findLitterMate(
                    name: grantee["id"],
                    type: grantee["type"]
                  )
                  if sibling
                    sibling.cloudobj.cloud_id
                  else
                    raise MuError, "Couldn't find a #{grantee["type"]} named #{grantee["id"]} when generating Cloud Storage access policy"
                  end
                else
                  pol['grant_to'].first['id']
                end

                if entity.match(/@/) and !entity.match(/^(group|user)\-/)
                  entity = "user-"+entity if entity.match(/@/)
                end

                bucket_acl_obj = MU::Cloud::Google.storage(:BucketAccessControl).new(
                  bucket: @cloud_id,
                  role: pol['permissions'].first,
                  entity: entity
                )
                MU.log "Adding Cloud Storage policy to bucket #{@cloud_id}", MU::NOTICE, details: bucket_acl_obj
                MU::Cloud::Google.storage(credentials: credentials).insert_bucket_access_control(
                  @cloud_id,
                  bucket_acl_obj
                )

                acl_obj = MU::Cloud::Google.storage(:ObjectAccessControl).new(
                  bucket: @cloud_id,
                  role: pol['permissions'].first,
                  entity: entity
                )
                MU::Cloud::Google.storage(credentials: credentials).insert_default_object_access_control(
                  @cloud_id,
                  acl_obj
                )
              }
            }

          end
        end

        # Upload a file to a bucket.
        # @param url [String]: Target URL, of the form gs://bucket/folder/file
        # @param acl [String]: Canned ACL permission to assign to the object we upload
        # @param file [String]: Path to a local file to write to our target location. One of +file+ or +data+ must be specified.
        # @param data [String]: Data to write to our target location. One of +file+ or +data+ must be specified.
        def self.upload(url, acl: "private", file: nil, data: nil, credentials: nil)
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

        # Remove all buckets associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          flags["project"] ||= MU::Cloud::Google.defaultProject(credentials)

          resp = MU::Cloud::Google.storage(credentials: credentials).list_buckets(flags['project'])
          if resp and resp.items
            resp.items.each { |bucket|
              if bucket.labels and bucket.labels["mu-id"] == MU.deploy_id.downcase
                MU.log "Deleting Cloud Storage bucket #{bucket.name}"
                if !noop
                  MU::Cloud::Google.storage(credentials: credentials).delete_bucket(bucket.name)
                end
              end
            }
          end
        end

        # Return the metadata for this user cofiguration
        # @return [Hash]
        def notify
          desc = MU.structToHash(cloud_desc)
          desc["project_id"] = @project_id
          desc
        end

        # Locate an existing bucket.
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching bucket.
        def self.find(**args)
          args[:project] ||= args[:habitat]
          args[:project] ||= MU::Cloud::Google.defaultProject(args[:credentials])

          found = {}
          if args[:cloud_id]
            found[args[:cloud_id]] = MU::Cloud::Google.storage(credentials: args[:credentials]).get_bucket(args[:cloud_id])
          else
            resp = begin
              MU::Cloud::Google.storage(credentials: args[:credentials]).list_buckets(args[:project])
            rescue ::Google::Apis::ClientError => e
              raise e if !e.message.match(/forbidden:/)
            end

            if resp and resp.items
              resp.items.each { |bucket|
                found[bucket.id] = bucket
              }
            end
          end

          found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(rootparent: nil, billing: nil, habitats: nil)
          bok = {
            "cloud" => "Google",
            "credentials" => @config['credentials'],
            "cloud_id" => @cloud_id
          }

          bok['name'] = cloud_desc.name
          bok['project'] = @project_id
          bok['storage_class'] = cloud_desc.storage_class
          if cloud_desc.versioning and cloud_desc.versioning.enabled
            bok['versioning'] = true
          end
          if cloud_desc.website
            bok['web'] = true
            if cloud_desc.website.not_found_page
              bok['web_error_object'] = cloud_desc.website.not_found_page
            end
            if cloud_desc.website.main_page_suffix
              bok['web_index_object'] = cloud_desc.website.main_page_suffix
            end
            pp cloud_desc
          end

#          MU.log "get_bucket_iam_policy", MU::NOTICE, details: MU::Cloud::Google.storage(credentials: @credentials).get_bucket_iam_policy(@cloud_id)
          pols = MU::Cloud::Google.storage(credentials: @credentials).get_bucket_iam_policy(@cloud_id)

          if pols and pols.bindings and pols.bindings.size > 0
            bok['policies'] = []
            count = 0
            grantees = {}
            pols.bindings.each { |binding|
              grantees[binding.role] ||= []
              binding.members.each { |grantee|
                if grantee.match(/^(user|group):(.*)/)
                  grantees[binding.role] << MU::Config::Ref.get(
                    id: Regexp.last_match[2],
                    type: Regexp.last_match[1]+"s",
                    cloud: "Google",
                    credentials: @credentials
                  )
                elsif grantee == "allUsers" or
                      grantee == "allAuthenticatedUsers" or
                      grantee.match(/^project(?:Owner|Editor|Viewer):/)
                  grantees[binding.role] << { "id" => grantee }
                elsif grantee.match(/^serviceAccount:(.*)/)
                  sa_name = Regexp.last_match[1]
                  if MU::Cloud::Google::User.cannedServiceAcctName?(sa_name)
                    grantees[binding.role] << { "id" => grantee }
                  else
                    grantees[binding.role] << MU::Config::Ref.get(
                      id: sa_name,
                      type: "users",
                      cloud: "Google",
                      credentials: @credentials
                    )
                  end
                else
                  # *shrug*
                  grantees[binding.role] << { "id" => grantee }
                end
              }
            }

            # munge together roles that apply to the exact same set of
            # principals
            reverse_map = {}
            grantees.each_pair { |perm, grant_to|
              reverse_map[grant_to] ||= []
              reverse_map[grant_to] << perm
            }
            already_done = []

            grantees.each_pair { |perm, grant_to|
              if already_done.include?(perm+grant_to.to_s)
                next
              end
              bok['policies'] << {
                "name" => "policy"+count.to_s,
                "grant_to" => grant_to,
                "permissions" => reverse_map[grant_to]
              }
              reverse_map[grant_to].each { |doneperm|
                already_done << doneperm+grant_to.to_s
              }
              count = count+1
            }
          end

          if cloud_desc.iam_configuration and
             cloud_desc.iam_configuration.bucket_policy_only and
             cloud_desc.iam_configuration.bucket_policy_only.enabled
            bok['bucket_wide_acls'] = true
          else
#            MU.log "list_bucket_access_controls", MU::NOTICE, details:  MU::Cloud::Google.storage(credentials: @credentials).list_bucket_access_controls(@cloud_id)
#            MU.log "list_default_object_access_controls", MU::NOTICE, details:  MU::Cloud::Google.storage(credentials: @credentials).list_default_object_access_controls(@cloud_id)
          end

          bok
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "storage_class" => {
              "type" => "string",
              "enum" => ["MULTI_REGIONAL", "REGIONAL", "STANDARD", "NEARLINE", "COLDLINE", "DURABLE_REDUCED_AVAILABILITY"],
              "default" => "STANDARD"
            },
            "bucket_wide_acls" => {
              "type" => "boolean",
              "default" => false,
              "description" => "Disables object-level access controls in favor of bucket-wide policies"
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::bucket}, bare and unvalidated.

        # @param bucket [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(bucket, configurator)
          ok = true
          bucket['project'] ||= MU::Cloud::Google.defaultProject(bucket['credentials'])

          if bucket['policies']
            bucket['policies'].each { |pol|
              if !pol['permissions'] or pol['permissions'].empty?
                pol['permissions'] = ["READER"]
              end
            }
# XXX validate READER OWNER EDITOR w/e
          end

          ok
        end

        private

        # create and return the Google::Apis::StorageV1::Bucket object used by
        # both +insert_bucket+ and +patch_bucket+
        def bucket_descriptor
          labels = {}
          MU::MommaCat.listStandardTags.each_pair { |name, value|
            if !value.nil?
              labels[name.downcase] = value.downcase.gsub(/[^a-z0-9\-\_]/i, "_")
            end
          }
          labels["name"] = @mu_name.downcase

          params = {
            :name => @mu_name.downcase,
            :labels => labels,
            :storage_class => @config['storage_class'],
          }

          if @config['web']
            params[:website] = MU::Cloud::Google.storage(:Bucket)::Website.new(
              main_page_suffix: @config['web_index_object'],
              not_found_page: @config['web_error_object']
            )
          end

          if @config['versioning']
            params[:versioning] = MU::Cloud::Google.storage(:Bucket)::Versioning.new(enabled: true)
          else
            params[:versioning] = MU::Cloud::Google.storage(:Bucket)::Versioning.new(enabled: false)
          end

          if @config['bucket_wide_acls']
            params[:iam_configuration] =  MU::Cloud::Google.storage(:Bucket)::IamConfiguration.new(
              bucket_policy_only: MU::Cloud::Google.storage(:Bucket)::IamConfiguration::BucketPolicyOnly.new(
                enabled: @config['bucket_wide_acls']
              )
            )
          else
            params[:iam_configuration] =  MU::Cloud::Google.storage(:Bucket)::IamConfiguration.new(
              bucket_policy_only: MU::Cloud::Google.storage(:Bucket)::IamConfiguration::BucketPolicyOnly.new(
                enabled: false
              )
            )
          end

          MU::Cloud::Google.storage(:Bucket).new(params)
        end

      end
    end
  end
end
