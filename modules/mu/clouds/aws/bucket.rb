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
    class AWS
      # Support for AWS S3
      class Bucket < MU::Cloud::Bucket

        @@region_cache = {}
        @@region_cache_semaphore = Mutex.new

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          bucket_name = @deploy.getResourceName(@config["name"], max_length: 63).downcase

          MU.log "Creating S3 bucket #{bucket_name}"
          resp = MU::Cloud::AWS.s3(credentials: @config['credentials'], region: @config['region']).create_bucket(
            acl: @config['acl'],
            bucket: bucket_name
          )

          @cloud_id = bucket_name
          is_live = self.find(cloud_id: cloud_id, region: @config['region'], credentials: @credentials).values.first
          begin
            is_live = self.find(cloud_id: cloud_id, region: @config['region'], credentials: @credentials).values.first
            sleep 1
          end while !is_live

          @@region_cache_semaphore.synchronize {
            @@region_cache[@cloud_id] ||= @config['region']
          }

          tagBucket if !@config['scrub_mu_isms']
        end

        # Apply tags to this bucket object
        def tagBucket
          tagset = []

          MU::MommaCat.listStandardTags.each_pair { |key, value|
            tagset << { :key => key, :value => value }
          }

          if @config['tags']
            @config['tags'].each { |tag|
              tagset << { :key => tag['key'], :value => tag['value'] }
            }
          end

          if @config['optional_tags']
            MU::MommaCat.listOptionalTags.each { |key, value|
              tagset << { :key => key, :value => value }
            }
          end

          MU::Cloud::AWS.s3(credentials: @config['credentials'], region: @config['region']).put_bucket_tagging(
            bucket: @cloud_id,
            tagging: {
              tag_set: tagset
            }
          )

        end

        # Called automatically by {MU::Deploy#createResources}
        def groom

          @@region_cache_semaphore.synchronize {
            @@region_cache[@cloud_id] ||= @config['region']
          }
          tagBucket if !@config['scrub_mu_isms']

          current = cloud_desc

          if @config['policies']
            policy_docs = MU::Cloud::AWS::Role.genPolicyDocument(@config['policies'], deploy_obj: @deploy)
            policy_docs.each { |doc|
              MU.log "Applying S3 bucket policy #{doc.keys.first} to bucket #{@cloud_id}", MU::NOTICE, details: doc.values.first
              MU::Cloud::AWS.s3(credentials: @config['credentials'], region: @config['region']).put_bucket_policy(
                bucket: @cloud_id,
                policy: JSON.generate(doc.values.first)
              )
            }
          end

          if @config['web'] and current["website"].nil?
            MU.log "Enabling web service on S3 bucket #{@cloud_id}", MU::NOTICE
            MU::Cloud::AWS.s3(credentials: @config['credentials'], region: @config['region']).put_bucket_website(
              bucket: @cloud_id,
              website_configuration: {
                error_document: {
                  key: @config['web_error_object']
                },
                index_document: {
                  suffix: @config['web_index_object']
                }
              }
            )
          elsif !@config['web'] and !current["website"].nil?
            MU.log "Disabling web service on S3 bucket #{@cloud_id}", MU::NOTICE
            MU::Cloud::AWS.s3(credentials: @config['credentials'], region: @config['region']).delete_bucket_website(
              bucket: @cloud_id
            )
          end

          if @config['versioning'] and current["versioning"].status != "Enabled"
            MU.log "Enabling versioning on S3 bucket #{@cloud_id}", MU::NOTICE
            MU::Cloud::AWS.s3(credentials: @config['credentials'], region: @config['region']).put_bucket_versioning(
              bucket: @cloud_id,
              versioning_configuration: {
                mfa_delete: "Disabled",
                status: "Enabled"
              }
            )
          elsif !@config['versioning'] and current["versioning"].status == "Enabled"
            MU.log "Suspending versioning on S3 bucket #{@cloud_id}", MU::NOTICE
            MU::Cloud::AWS.s3(credentials: @config['credentials'], region: @config['region']).put_bucket_versioning(
              bucket: @cloud_id,
              versioning_configuration: {
                mfa_delete: "Disabled",
                status: "Suspended"
              }
            )
          end
        end

        # Upload a file to a bucket.
        # @param url [String]: Target URL, of the form s3://bucket/folder/file
        # @param acl [String]: Canned ACL permission to assign to the object we upload
        # @param file [String]: Path to a local file to write to our target location. One of +file+ or +data+ must be specified.
        # @param data [String]: Data to write to our target location. One of +file+ or +data+ must be specified.
        def self.upload(url, acl: "private", file: nil, data: nil, credentials: nil, region: nil)
          if (!file or file.empty?) and !data
            raise MuError, "Must specify a file or some data to upload to bucket #{s3_url}"
          end

          if file and !file.empty?
            if !File.exist?(file) or !File.readable?(file)
              raise MuError, "Unable to read #{file} for upload to #{url}"
            else
              data = File.read(file)
            end
          end

          url.match(/^(?:s3:\/\/)([^\/:]+?)[\/:]\/?(.+)?/)
          bucket = Regexp.last_match[1]
          path = Regexp.last_match[2]
          if !path 
            if !file
              raise MuError, "Unable to determine upload path from url #{url}"
            end
          end

          begin
puts data
puts acl
puts bucket
puts path
            MU.log "Writing #{path} to S3 bucket #{bucket}"
            MU::Cloud::AWS.s3(region: region, credentials: credentials).put_object(
              acl: acl,
              bucket: bucket,
              key: path,
              body: data
            )
          rescue Aws::S3::Errors => e
            raise MuError, "Got #{e.inspect} trying to write #{path} to #{bucket} (region: #{region}, credentials: #{credentials})"
          end

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
          MU::Cloud::BETA
        end

        # Remove all buckets associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})

          resp = MU::Cloud::AWS.s3(credentials: credentials, region: region).list_buckets
          if resp and resp.buckets
            resp.buckets.each { |bucket|
              @@region_cache_semaphore.synchronize {
                if @@region_cache[bucket.name]
                  next if @@region_cache[bucket.name] != region
                else
                  begin
                    location = MU::Cloud::AWS.s3(credentials: credentials, region: region).get_bucket_location(bucket: bucket.name).location_constraint
                    if location.nil? or location.empty?
                      @@region_cache[bucket.name] = region
                    else
                      @@region_cache[bucket.name] = location
                    end
                  rescue Aws::S3::Errors::NoSuchBucket, Aws::S3::Errors::AccessDenied
                    # this is routine- we saw a bucket that's not our business
                    next
                  end

                end
              }

              if @@region_cache[bucket.name] != region
                MU.log "#{bucket.name} is in #{@@region_cache[bucket.name]} but I'm checking from #{region}, skipping", MU::DEBUG
                next
              end

              begin
                tags = MU::Cloud::AWS.s3(credentials: credentials, region: region).get_bucket_tagging(bucket: bucket.name).tag_set
                tags.each { |tag|
                  if tag.key == "MU-ID" and tag.value == MU.deploy_id
                    MU.log "Deleting S3 Bucket #{bucket.name}"
                    if !noop
                      MU::Cloud::AWS.s3(credentials: credentials, region: region).delete_bucket(bucket: bucket.name)
                    end
                    break
                  end
                }
              rescue Aws::S3::Errors::NoSuchTagSet, Aws::S3::Errors::PermanentRedirect
                next
              end
            }
          end
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          "arn:"+(MU::Cloud::AWS.isGovCloud?(@config["region"]) ? "aws-us-gov" : "aws")+":s3:::"+@cloud_id
        end

        # Return the metadata for this user cofiguration
        # @return [Hash]
        def notify
          desc = MU::Cloud::AWS::Bucket.describe_bucket(@cloud_id, credentials: @config['credentials'], region: @config['region'])
          MU.structToHash(desc)
        end

        # Locate an existing bucket.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @param flags [Hash]: Optional flags
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching bucket.
        def self.find(**args)
          found = {}
          if args[:cloud_id]
            begin
              found[args[:cloud_id]] = describe_bucket(args[:cloud_id], minimal: true, credentials: args[:credentials], region: args[:region])
            rescue ::Aws::S3::Errors::NoSuchBucket
            end
          end
          found
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "policies" => MU::Cloud::AWS::Role.condition_schema,
            "acl" => {
              "type" => "string",
              "enum" => ["private", "public-read", "public-read-write", "authenticated-read"],
              "default" => "private"
            },
            "storage_class" => {
              "type" => "string",
              "enum" => ["STANDARD", "REDUCED_REDUNDANCY", "STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER"],
              "default" => "STANDARD"
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

          if bucket['policies']
            bucket['policies'].each { |pol|
              if !pol['permissions'] or pol['permissions'].empty?
                pol['permissions'] = ["s3:GetObject"]
              end
            }
          end

          ok
        end

        private

        # AWS doesn't really implement a useful describe_ method for S3 buckets;
        # instead we run the million little individual API calls to construct
        # an approximation for our uses
        def self.describe_bucket(bucket, minimal: false, credentials: nil, region: nil)
          @@region_cache = {}
          @@region_cache_semaphore = Mutex.new
          calls = if minimal
            %w{encryption lifecycle lifecycle_configuration location logging policy replication tagging versioning website}
          else
            %w{accelerate_configuration acl cors encryption lifecycle lifecycle_configuration location logging notification notification_configuration policy policy_status replication request_payment tagging versioning website} # XXX analytics_configuration, inventory_configuration, metrics_configuration all require an id of some sort
          end

          desc = {}

          calls.each { |method|
            method_sym = ("get_bucket_"+method).to_sym
            # "The horrors of this place claw at your mind"
            begin
              desc[method] = MU::Cloud::AWS.s3(credentials: credentials, region: region).method_missing(method_sym, {:bucket => bucket})
              if method == "location"
                @@region_cache_semaphore.synchronize {
                  if desc[method].location_constraint.nil? or desc[method].location_constraint.empty?
                    @@region_cache[bucket] = region
                  else
                    @@region_cache[bucket] = desc[method].location_constraint
                  end
                }
              end

            rescue Aws::S3::Errors::NoSuchCORSConfiguration, Aws::S3::Errors::ServerSideEncryptionConfigurationNotFoundError, Aws::S3::Errors::NoSuchLifecycleConfiguration, Aws::S3::Errors::NoSuchBucketPolicy, Aws::S3::Errors::ReplicationConfigurationNotFoundError, Aws::S3::Errors::NoSuchTagSet, Aws::S3::Errors::NoSuchWebsiteConfiguration => e
              desc[method] = nil
              next
            end
          }
          desc
        end

      end
    end
  end
end
