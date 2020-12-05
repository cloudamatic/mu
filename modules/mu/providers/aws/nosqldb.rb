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
      # Support for AWS DynamoDB
      class NoSQLDB < MU::Cloud::NoSQLDB

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
          params = {
            :table_name => @mu_name,
            :attribute_definitions => [],
            :key_schema => [],
            :provisioned_throughput => {
              :read_capacity_units => @config['read_capacity'],
              :write_capacity_units => @config['write_capacity']
            }
          }

          if @config['stream']
            params[:stream_specification] = {
              :stream_enabled => true,
              :stream_view_type => @config['stream']
            }
          end

          type_map = {}

          @config['attributes'].each { |attr|
            type_map[attr['name']] = attr['type']

            params[:attribute_definitions] << {
              :attribute_name => attr['name'],
              :attribute_type => attr['type']
            }

            if attr['primary_partition']
              params[:key_schema] << {
                :attribute_name => attr['name'],
                :key_type => "HASH"
              }
            end

            if attr['primary_sort']
              params[:key_schema] << {
                :attribute_name => attr['name'],
                :key_type => "RANGE"
              }
            end
          }
          # apparently the HASH key always has to be before RANGE, so sort it
          # lexically by that field and call it a day
          params[:key_schema].sort! { |a, b|
            a[:key_type] <=> b[:key_type]
          }

          if @config['secondary_indexes']
            @config['secondary_indexes'].each { |idx|
              idx_cfg = {
                :index_name => idx['index_name'],
                :projection => {
                  :projection_type => idx['projection']['type'],
                  :non_key_attributes => idx['projection']['non_key_attributes']
                },
                :key_schema => []
              }
              idx['key_schema'].each { |attr|
                idx_cfg[:key_schema] << {
                  :attribute_name => attr['attribute'],
                  :key_type => attr['type']
                }
              }
              if idx['type'] == "global"

                idx_cfg[:provisioned_throughput] = {
                  :read_capacity_units => idx['read_capacity'],
                  :write_capacity_units => idx['write_capacity']
                }
                params[:global_secondary_indexes] ||= []
                params[:global_secondary_indexes] << idx_cfg
              else
                params[:local_secondary_indexes] ||= []
                params[:local_secondary_indexes] << idx_cfg
              end
            }
          end

          if @tags
            params[:tags] = @tags.each_key.map { |k| { :key => k, :value => @tags[k] } }
          end

          MU.log "Creating DynamoDB table #{@mu_name}", MU::NOTICE, details: params

          resp = MU::Cloud::AWS.dynamo(credentials: @credentials, region: @region).create_table(params)
          @cloud_id = @mu_name

          begin
            resp = MU::Cloud::AWS.dynamo(credentials: @credentials, region: @region).describe_table(table_name: @cloud_id)
            sleep 5 if resp.table.table_status == "CREATING"
          end while resp.table.table_status == "CREATING"

          tagTable if !@config['scrub_mu_isms']

          if @config['populate'] and !@config['populate'].empty?
            MU.log "Preloading #{@mu_name} with #{@config['populate'].size.to_s} items"
            items_to_write = @config['populate'].dup
            begin
              batch = items_to_write.slice!(0, (items_to_write.length >= 25 ? 25 : items_to_write.length))
              begin
                MU::Cloud::AWS.dynamo(credentials: @credentials, region: @region).batch_write_item(
                  request_items: {
                    @cloud_id => batch.map { |i| { put_request: { item: i } } }
                  }
                )
              rescue ::Aws::DynamoDB::Errors::ValidationException => e
                MU.log e.message, MU::ERR, details: item
              end
            end while !items_to_write.empty?
          end
        end

        # Apply tags to this DynamoDB table
        def tagTable
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

          MU::Cloud::AWS.dynamo(credentials: @credentials, region: @region).tag_resource(
            resource_arn: arn,
            tags: tagset
          )

        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          tagTable if !@config['scrub_mu_isms']
          MU.log "NoSQL Table #{@config['name']}: #{@cloud_id}", MU::SUMMARY
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
          MU.log "AWS::NoSQLDb.cleanup: need to support flags['known']", MU::DEBUG, details: flags

          resp = MU::Cloud::AWS.dynamo(credentials: credentials, region: region).list_tables
          if resp and resp.table_names
            resp.table_names.each { |table|
              desc = MU::Cloud::AWS.dynamo(credentials: credentials, region: region).describe_table(table_name: table).table
              next if desc.table_status == "DELETING"
              if desc.table_status == "CREATING"
                begin
                  desc = MU::Cloud::AWS.dynamo(credentials: credentials, region: region).describe_table(table_name: table).table
                  sleep 1
                end while desc.table_status == "CREATING"
              end
              begin
                tags = MU::Cloud::AWS.dynamo(credentials: credentials, region: region).list_tags_of_resource(resource_arn: desc.table_arn)
                if tags and tags.tags
                  deploy_match = false
                  master_match = false
                  tags.tags.each { |tag|
                    if tag.key == "MU-ID" and tag.value == deploy_id
                      deploy_match = true
                    elsif tag.key == "MU-MASTER-IP" and tag.value == MU.mu_public_ip
                      master_match = true
                    end
                  }
                  if deploy_match and (master_match or ignoremaster)
                    MU.log "Deleting DynamoDB table #{desc.table_name}"
                    if !noop
                      MU::Cloud::AWS.dynamo(credentials: credentials, region: region).delete_table(table_name: desc.table_name)
                    end
                  end
                end
              rescue Aws::DynamoDB::Errors::ResourceNotFoundException
              end

            }
          end

        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          return nil if cloud_desc.nil?
          cloud_desc.table_arn 
        end

        # Return the metadata for this user cofiguration
        # @return [Hash]
        def notify
          return nil if !@cloud_id or !cloud_desc(use_cache: false)
          MU.structToHash(cloud_desc, stringify_keys: true)
        end

        # Locate an existing DynamoDB table
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching bucket.
        def self.find(**args)
          found = {}

          if args[:cloud_id]
            begin
              resp = MU::Cloud::AWS.dynamo(credentials: args[:credentials], region: args[:region]).describe_table(table_name: args[:cloud_id])
              found[args[:cloud_id]] = resp.table if resp and resp.table
            rescue ::Aws::DynamoDB::Errors::ResourceNotFoundException
            end
          else
            resp = MU::Cloud::AWS.dynamo(credentials: args[:credentials], region: args[:region]).list_tables
            if resp and resp.table_names
              resp.table_names.each { |t|
                begin
                  resp = MU::Cloud::AWS.dynamo(credentials: args[:credentials], region: args[:region]).describe_table(table_name: t)
                  found[t] = resp.table if resp and resp.table
                rescue ::Aws::DynamoDB::Errors::ResourceNotFoundException
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
            "cloud_id" => @cloud_id,
            "region" => @region
          }

          if !cloud_desc
            MU.log "toKitten failed to load a cloud_desc from #{@cloud_id}", MU::ERR, details: @config
            return nil
          end
          bok['name'] = cloud_desc.table_name
          bok['read_capacity'] = cloud_desc.provisioned_throughput.read_capacity_units
          bok['write_capacity'] = cloud_desc.provisioned_throughput.write_capacity_units


          cloud_desc.attribute_definitions.each { |attr|
            bok['attributes'] ||= []
            newattr = {
              "name" => attr.attribute_name,
              "type" => attr.attribute_type
            }
            if cloud_desc.key_schema
              cloud_desc.key_schema.each { |key|
                next if key.attribute_name == attr.attribute_name
                if key.key_type == "RANGE"
                  newattr["primary_partition"] = true
                elsif key.key_type == "HASH"
                  newattr["primary_sort"] = true
                end
              }
            end
            bok['attributes'] << newattr
          }

          if cloud_desc.stream_specification and cloud_desc.stream_specification.stream_enabled

            bok['stream'] = cloud_desc.stream_specification.stream_view_type
#            cloud_desc.latest_stream_arn
#            MU::Cloud::AWS.dynamostream(credentials: @credentials, region: @region).list_streams
          end

          bok["populate"] = MU::Cloud::AWS.dynamo(credentials: @credentials, region: @region).scan(
            table_name: @cloud_id
          ).items

          bok
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = ["attributes"]


          schema = {
            "populate" => {
              "type" => "array",
              "items" => {
                "type" => "object",
                "description" => "Key-value pairs, compatible with the +attributes+ schema, with which to populate this +table+ during its initial creation."
              }
            },
            "attributes" => {
              "type" => "array",
              "minItems" => 1,
              "items" => {
                "type" => "object",
                "description" => "Fields for data we'll be storing in this database, somewhat akin to SQL columns. Note that all attributes declared here must be a +primary_partition+, +primary_sort+, or named in a +secondary_index+.",
                "properties" => {
                  "name" => {
                    "type" => "string",
                    "description" => "The name of this attribute"
                  },
                  "type" => {
                    "type" => "string",
                    "description" => "The type of attribute; S = String, N = Number, B = Binary",
                    "enum" => ["S", "N", "B"]
                  },
                  "primary_partition" => {
                    "type" => "boolean",
                    "default" => false
                  },
                  "primary_sort" => {
                    "type" => "boolean",
                    "default" => false
                  }
                }
              }
            },
            "read_capacity" => {
              "type" => "integer",
              "description" => "Provisioned read throughput. See also: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ProvisionedThroughput.html",
              "default" => 1
            },
            "write_capacity" => {
              "type" => "integer",
              "description" => "Provisioned write throughput. See also: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ProvisionedThroughput.html",
              "default" => 1
            },
            "stream" => {
              "type" => "string",
              "description" => "If specified, enables a streaming log of changes to this DynamoDB table. See also https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Streams.html",
              "enum" => ["NEW_IMAGE", "OLD_IMAGE", "NEW_AND_OLD_IMAGES", "KEYS_ONLY"]
            },
            "secondary_indexes" => {
              "type" => "array",
              "description" => "Define a global and/or a local secondary index.",
              "items" => {
                "type" => "object",
                "description" => "An index with a partition key and a sort key that can be different from those on the base table; queries on the index can span all of the data in the base table, across all partitions",
                "required" => ["index_name", "key_schema", "projection"],
                "properties" => {
                  "index_name" => {
                    "type" => "string",
                    "description" => "A name for this index"
                  },
                  "type" => {
                    "type" => "string",
                    "description" => "Whether to create a global or local secondary index. See also: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/SecondaryIndexes.html",
                    "enum" => ["global", "local"],
                    "default" => "global"
                  },
                  "projection" => {
                    "type" => "object",
                    "description" => "The set of attributes to return for queries against this index.",
                    "properties" => {
                      "type" => {
                        "type" => "string",
                        "enum" => ["ALL", "KEYS_ONLY", "INCLUDE"],
                        "default" => "ALL"
                      },
                      "non_key_attributes" => {
                        "type" => "array",
                        "items" => {
                          "type" => "string",
                          "description" => "The name of an extra attribute to include in results for queries against this index"
                        }
                      }
                    },
                    "default" => { "type" => "ALL" }
                  },
                  "read_capacity" => {
                    "type" => "integer",
                    "description" => "Provisioned read throughput. Only valid for global secondary indexes. Defaults to the read capacity of the whole table.",
                  },
                  "write_capacity" => {
                    "type" => "integer",
                    "description" => "Provisioned write throughput. Only valid for global secondary indexes. Defaults to the read capacity of the whole table.",
                  },
                  "key_schema" => {
                    "type" => "array",
                    "minItems" => 1,
                    "items" => {
                      "type" => "object",
                      "description" => "Define the key for this index, which most be composed of one or more declared +attributes+ for this table. See also: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/SecondaryIndexes.html",
                      "properties" => {
                        "type" => {
                          "type" => "string",
                          "enum" => ["HASH", "RANGE"]
                        },
                        "attribute" => {
                          "description" => "This must refer to a declared +attribute+ by name",
                          "type" => "string",
                        }

                      }
                    }
                  }
                }

              }
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::nosqldbs}, bare and unvalidated.

        # @param db [Hash]: The resource to process and validate
        # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(db, _configurator)
          ok = true

          partition = nil
          db['attributes'].each { |attr|
            if attr['primary_partition']
              partition = attr['name']
            end
          }
          if !partition
            if db['attributes'].size == 1
              MU.log "NoSQL database '#{db['name']}' only declares one attribute; setting '#{db['attributes'].first['name']}' as primary partition key", MU::NOTICE
              db['attributes'].first['primary_partition'] = true
            else
              MU.log "NoSQL database '#{db['name']}' must have an attribute flagged as primary_partition", MU::ERR
              ok = false
            end
          end
          db['attributes'].each { |attr|
            if attr['primary_partition'] and attr['primary_sort']
              MU.log "NoSQL database '#{db['name']}' attribute '#{attr['name']}' cannot be both primary_partition and primary_sort", MU::ERR
              ok = false
            end
          }

          if db['secondary_indexes']
             db['secondary_indexes'].each { |idx|
               if idx['type'] == "global"
                 idx['read_capacity'] ||= db['read_capacity']
                 idx['write_capacity'] ||= db['write_capacity']
               end
             }
          end

          ok
        end

      end
    end
  end
end
