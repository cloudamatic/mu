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

        # Map some filename extensions to mime types. S3 does most of this on
        # its own, add to this for cases it doesn't cover.
        MIME_MAP = {
          ".svg" => "image/svg+xml"
        }

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
          MU::Cloud::AWS.s3(credentials: @credentials, region: @region).create_bucket(
            acl: @config['acl'],
            bucket: bucket_name
          )

          @cloud_id = bucket_name
          is_live = MU::Cloud::AWS::Bucket.find(cloud_id: @cloud_id, region: @region, credentials: @credentials).values.first
          begin
            is_live = MU::Cloud::AWS::Bucket.find(cloud_id: @cloud_id, region: @region, credentials: @credentials).values.first
            sleep 3
          end while !is_live

          @@region_cache_semaphore.synchronize {
            @@region_cache[@cloud_id] ||= @region
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

          MU::Cloud::AWS.s3(credentials: @credentials, region: @region).put_bucket_tagging(
            bucket: @cloud_id,
            tagging: {
              tag_set: tagset
            }
          )

        end

        # @return [String]
        def url
          "https://#{@cloud_id}.s3.amazonaws.com"
        end

        # Grant access via our bucket policy to the specified resource
        # @param principal [String]
        # @param permissions [Array<String>]
        # @param paths [Array<String>]
        def allowPrincipal(principal, permissions: ["GetObject", "ListBucket"], paths: [""], doc_id: nil, name: nil)
          @config['policies'] ||= []
          name ||= principal.sub(/.*?([0-9a-z\-_]+)$/i, '\1')
          @config['policies'] << {
            "name" => name,
            "grant_to" => [ { "identifier" => principal } ],
            "permissions" => permissions.map { |p| "s3:"+p },
            "flag" => "allow",
            "targets" => paths.map { |p|
              {
                "path" => p,
                "type" => "bucket",
                "identifier" => @config['name']
              }
            }
          }

          applyPolicies(doc_id: doc_id)
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom

          @@region_cache_semaphore.synchronize {
            @@region_cache[@cloud_id] ||= @region
          }
          tagBucket if !@config['scrub_mu_isms']

          current = cloud_desc
          applyPolicies if @config['policies']

          if @config['versioning'] and current["versioning"].status != "Enabled"
            MU.log "Enabling versioning on S3 bucket #{@cloud_id}", MU::NOTICE
            MU::Cloud::AWS.s3(credentials: @credentials, region: @region).put_bucket_versioning(
              bucket: @cloud_id,
              versioning_configuration: {
                mfa_delete: "Disabled",
                status: "Enabled"
              }
            )
          elsif !@config['versioning'] and current["versioning"].status == "Enabled"
            MU.log "Suspending versioning on S3 bucket #{@cloud_id}", MU::NOTICE
            MU::Cloud::AWS.s3(credentials: @credentials, region: @region).put_bucket_versioning(
              bucket: @cloud_id,
              versioning_configuration: {
                mfa_delete: "Disabled",
                status: "Suspended"
              }
            )
          end

          if @config['upload']
            @config['upload'].each { |batch|
              urlbase = "s3://"+@cloud_id+batch['destination']
              urlbase += "/" if urlbase !~ /\/$/
              upload_me = if File.directory?(batch['source'])
                Dir[batch['source']+'/**/*'].reject {|d|
                  File.directory?(d)
                }.map { |f|
                  [ f, urlbase+f.sub(/^#{Regexp.quote(batch['source'])}\/?/, '') ]
                }
              else
                batch['source'].match(/([^\/]+)$/)
                [ [batch['source'], urlbase+Regexp.last_match[1]] ]
              end

              Hash[upload_me].each_pair { |file, url|
                self.class.upload(url, file: file, credentials: @credentials, region: @region, acl: batch['acl'])
              }
            }
          end

          if @config['web'] and current["website"].nil?
            MU.log "Enabling web service on S3 bucket #{@cloud_id}", MU::NOTICE
            MU::Cloud::AWS.s3(credentials: @credentials, region: @region).put_bucket_website(
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
            ['web_error_object', 'web_index_object'].each { |key|
              begin
                MU::Cloud::AWS.s3(credentials: @credentials, region: @region).head_object(
                  bucket: @cloud_id,
                  key: @config[key]
                )
              rescue Aws::S3::Errors::NotFound
                MU.log "Uploading placeholder #{@config[key]} to bucket #{@cloud_id}"
                MU::Cloud::AWS.s3(credentials: @credentials, region: @region).put_object(
                  acl: "public-read",
                  bucket: @cloud_id,
                  key: @config[key],
                  body: ""
                )
              end
            }
# XXX check if error and index objs exist, and if not provide placeholders
          elsif !@config['web'] and !current["website"].nil?
            MU.log "Disabling web service on S3 bucket #{@cloud_id}", MU::NOTICE
            MU::Cloud::AWS.s3(credentials: @credentials, region: @region).delete_bucket_website(
              bucket: @cloud_id
            )
          end

          symbolify_keys = Proc.new { |parent|
            if parent.is_a?(Hash)
              newhash = {}
              parent.each_pair { |k, v|
                newhash[k.to_sym] = symbolify_keys.call(v)
              }
              newhash
            elsif parent.is_a?(Array)
              newarr = []
              parent.each { |child|
                newarr << symbolify_keys.call(child)
              }
              newarr
            else
              parent
            end
          }

          if @config['cors']
            MU.log "Setting CORS rules on #{@cloud_id}", details: @config['cors']
            MU::Cloud::AWS.s3(credentials: @credentials, region: @region).put_bucket_cors(
              bucket: @cloud_id,
              cors_configuration: {
                cors_rules: symbolify_keys.call(@config['cors'])
              }
            )
          end

          MU.log "Bucket #{@config['name']}: s3://#{@cloud_id}", MU::SUMMARY
          if @config['web']
            MU.log "Bucket #{@config['name']} web access: http://#{@cloud_id}.s3-website-#{@region}.amazonaws.com/", MU::SUMMARY
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
              raise MuError, "Unable to read #{file} for upload to #{url} (I'm at #{Dir.pwd}"
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
            MU.log "Writing #{path} to S3 bucket #{bucket}"
            params = {
              acl: acl,
              bucket: bucket,
              key: path,
              body: data
            }

            MIME_MAP.each_pair { |extension, content_type|
              if path =~ /#{Regexp.quote(extension)}$/i
                params[:content_type] = content_type
              end
            }
            MU::Cloud::AWS.s3(region: region, credentials: credentials).put_object(params)
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
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          MU.log "AWS::Bucket.cleanup: need to support flags['known']", MU::DEBUG, details: flags

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
                deploy_match = false
                master_match = false
                tags.each { |tag|
                  if tag.key == "MU-ID" and tag.value == deploy_id
                    deploy_match = true
                  elsif tag.key == "MU-MASTER-IP" and tag.value == MU.mu_public_ip
                    master_match = true
                  end
                }
                if deploy_match and (ignoremaster or master_match)
                  MU.log "Deleting S3 Bucket #{bucket.name}"
                  if !noop
                    MU::Cloud::AWS.s3(credentials: credentials, region: region).delete_bucket(bucket: bucket.name)
                  end
                end
              rescue Aws::S3::Errors::BucketNotEmpty => e
                if flags["skipsnapshots"]
                  del = MU::Cloud::AWS.s3(credentials: credentials, region: region).list_objects(bucket: bucket.name).contents.map { |o| { key: o.key } }
                  del.concat(MU::Cloud::AWS.s3(credentials: credentials, region: region).list_object_versions(bucket: bucket.name).versions.map { |o| { key: o.key, version_id: o.version_id } })

                  MU.log "Purging #{del.size.to_s} objects and versions from #{bucket.name}"
                  begin
                    batch = del.slice!(0, (del.length >= 1000 ? 1000 : del.length))
                    MU::Cloud::AWS.s3(credentials: credentials, region: region).delete_objects(bucket: bucket.name, delete: { objects: batch } ) if !noop
                  end while del.size > 0

                  retry if !noop
                else
                  MU.log "Bucket #{bucket.name} is non-empty, will preserve it and its contents. Use --skipsnapshots to forcibly remove.", MU::WARN
                end
              rescue Aws::S3::Errors::NoSuchTagSet, Aws::S3::Errors::PermanentRedirect
                next
              end
            }
          end
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          "arn:"+(MU::Cloud::AWS.isGovCloud?(@region) ? "aws-us-gov" : "aws")+":s3:::"+@cloud_id
        end

        # Return the metadata for this user cofiguration
        # @return [Hash]
        def notify
          desc = MU::Cloud::AWS::Bucket.describe_bucket(@cloud_id, credentials: @credentials, region: @region)
          MU.structToHash(desc)
        end

        # Locate an existing bucket.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching bucket.
        def self.find(**args)
          found = {}

          args[:region] ||= MU::Cloud::AWS.myRegion(args[:credentials])
          if args[:flags] and args[:flags][:allregions]
            args[:allregions] = args[:flags][:allregions]
          end
          minimal = args[:full] ? false : true

          location = Proc.new { |name|
            begin
              loc_resp = MU::Cloud::AWS.s3(credentials: args[:credentials], region: args[:region]).get_bucket_location(bucket: name)
  
              if loc_resp.location_constraint and !loc_resp.location_constraint.empty?
                loc_resp.location_constraint
              else
                nil
              end
            rescue Aws::S3::Errors::AccessDenied
              nil
            end
          }

          if args[:cloud_id]
            begin
              found[args[:cloud_id]] = describe_bucket(args[:cloud_id], minimal: minimal, credentials: args[:credentials], region: args[:region])
              found[args[:cloud_id]]['region'] ||= location.call(args[:cloud_id])
              found[args[:cloud_id]]['region'] ||= args[:region]
              found[args[:cloud_id]]['name'] ||= args[:cloud_id]
            rescue ::Aws::S3::Errors::NoSuchBucket
            end
          else
            resp = MU::Cloud::AWS.s3(credentials: args[:credentials], region: args[:region]).list_buckets
            if resp and resp.buckets
              resp.buckets.each { |b|
                begin
                  bucket_region = location.call(b.name)
                  if !args[:allregions] and bucket_region != args[:region]
                    next
                  end
                  bucket_region ||= args[:region]
                  found[b.name] = describe_bucket(b.name, minimal: minimal, credentials: args[:credentials], region: bucket_region)
                  found[b.name]["region"] ||= bucket_region
                  found[b.name]['name'] ||= b.name
                rescue Aws::S3::Errors::AccessDenied
                end
              }
            end
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

if @cloud_id =~ /espier/i
  MU.log @cloud_id, MU::WARN, details: cloud_desc
end

          if !cloud_desc
            MU.log "toKitten failed to load a cloud_desc from #{@cloud_id}", MU::ERR, details: @config
            return nil
          end

          nil
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {
            "policies" => MU::Cloud.resourceClass("AWS", "Role").condition_schema,
            "upload" => {
              "items" => {
                "properties" => {
                  "acl" => {
                    "type" => "string",
                    "enum" => ["private", "public-read", "public-read-write", "authenticated-read"],
                    "default" => "private"
                  }
                }
              }
            },
            "storage_class" => {
              "type" => "string",
              "enum" => ["STANDARD", "REDUCED_REDUNDANCY", "STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER"],
              "default" => "STANDARD"
            },
            "cors" => {
              "type" => "array",
              "items" => {
                "type" => "object",
                "description" => "AWS S3 Cross-origin resource sharing policy",
                "required" => ["allowed_origins"],
                "properties" => {
                  "allowed_headers" => {
                    "type" => "array",
                    "default" => ["*"],
                    "items" => {
                      "type" => "string",
                      "description" => "Specifies which headers are allowed in a preflight request through the +Access-Control-Request-Headers+ header."
                    }
                  },
                  "allowed_methods" => {
                    "type" => "array",
                    "default" => ["GET"],
                    "items" => {
                      "type" => "string",
                      "enum" => %w{GET PUT POST DELETE HEAD},
                      "description" => "Specifies which HTTP methods for which cross-domain request are permitted"
                    }
                  },
                  "allowed_origins" => {
                    "type" => "array",
                    "items" => {
                      "type" => "string",
                      "description" => "Origins (in URL form) for which cross-domain request are permitted"  
                    }
                  },
                  "expose_headers" => {
                    "type" => "array",
                    "items" => {
                      "type" => "string",
                      "description" => "Headers in the response which should be visible to the requesting application"
                    }
                  },
                  "max_age_seconds" => {
                    "type" => "integer",
                    "default" => 3600,
                    "description" => "Maximum cache time for preflight requests"
                  }
                }
              }
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::bucket}, bare and unvalidated.

        # @param bucket [Hash]: The resource to process and validate
        # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(bucket, _configurator)
          ok = true

          if bucket['policies']
            bucket['policies'].each { |pol|
              if !pol['permissions'] or pol['permissions'].empty?
                pol['permissions'] = ["s3:GetObject", "s3:ListBucket"]
              end
            }
          end

          ok
        end

        # AWS doesn't really implement a useful describe_ method for S3 buckets;
        # instead we run the million little individual API calls to construct
        # an approximation for our uses
        # @param bucket [String]:
        # @param minimal [Boolean]:
        # @param credentials [String]:
        # @param region [String]:
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

            rescue Aws::S3::Errors::NoSuchCORSConfiguration, Aws::S3::Errors::ServerSideEncryptionConfigurationNotFoundError, Aws::S3::Errors::NoSuchLifecycleConfiguration, Aws::S3::Errors::NoSuchBucketPolicy, Aws::S3::Errors::ReplicationConfigurationNotFoundError, Aws::S3::Errors::NoSuchTagSet, Aws::S3::Errors::NoSuchWebsiteConfiguration
              desc[method] = nil
              next
            end
          }
          desc
        end

        private

        def applyPolicies(doc_id: nil)
          return if !@config['policies']

          @config['policies'].each { |pol|
            pol['grant_to'] ||= [
              { "id" => "*" }
            ]
          }

          policy_docs = MU::Cloud.resourceClass("AWS", "Role").genPolicyDocument(@config['policies'], deploy_obj: @deploy, bucket_style: true, version: "2008-10-17", doc_id: doc_id)
          policy_docs.each { |doc|
            MU.log "Applying S3 bucket policy #{doc.keys.first} to bucket #{@cloud_id}", MU::NOTICE, details: JSON.pretty_generate(doc.values.first)
            MU::Cloud::AWS.s3(credentials: @credentials, region: @region).put_bucket_policy(
              bucket: @cloud_id,
              policy: JSON.generate(doc.values.first)
            )
          }
        end

      end
    end
  end
end
