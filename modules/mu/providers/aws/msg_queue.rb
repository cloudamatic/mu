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
      # A MsgQueue as configured in {MU::Config::BasketofKittens::msg_queues}
      class MsgQueue < MU::Cloud::MsgQueue

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          attrs = genQueueAttrs

          namestr = @mu_name
          namestr += ".fifo" if attrs['FifoQueue']

          MU.log "Creating SQS queue #{namestr}", details: attrs
          resp = MU::Cloud::AWS.sqs(region: @region, credentials: @credentials).create_queue(
            queue_name: namestr,
            attributes: attrs
          )
          sleep 1
					MU.log "SQS queue #{@config['name']} is at: #{resp.queue_url}", MU::SUMMARY
          @cloud_id = resp.queue_url
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          tagQueue

          cur_attrs = notify
#          if cur_attrs["Policy"]
#            MU.log "FECK", MU::WARN, details: JSON.parse(cur_attrs["Policy"]).to_yaml
#          end
          new_attrs = genQueueAttrs

          changed = false
          new_attrs.each_pair { |k, _v|
            if !cur_attrs.has_key?(k) or cur_attrs[k] != new_attrs[k]
              changed = true
            end
          }
          if changed
            MU.log "Updating SQS queue #{@mu_name}", MU::NOTICE, details: new_attrs
            MU::Cloud::AWS.sqs(region: @region, credentials: @credentials).set_queue_attributes(
              queue_url: @cloud_id,
              attributes: new_attrs
            )
          end

        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          "arn:"+(MU::Cloud::AWS.isGovCloud?(@region) ? "aws-us-gov" : "aws")+":sqs:"+@region+":"+MU::Cloud::AWS.credToAcct(@credentials)+":"+@cloud_id
        end

        @cloud_desc_cache = nil
        # Retrieve the AWS descriptor for this SQS queue. AWS doesn't exactly
        # provide one; if you want real information for SQS ask notify()
        # @return [Hash]: AWS doesn't return anything but the SQS URL, so supplement with attributes
        def cloud_desc(use_cache: true)
          return @cloud_desc_cache if @cloud_desc_cache and use_cache
          return nil if !@cloud_id

          if !@cloud_id
            resp = MU::Cloud::AWS.sqs(region: @region, credentials: @credentials).list_queues(
              queue_name_prefix: @mu_name
            )
            return nil if !resp or !resp.queue_urls
            resp.queue_urls.each { |url|
              if url.match(/\/#{Regexp.quote(@mu_name)}$/)
                @cloud_id ||= url
                break
              end
            }
          end

          return nil if !@cloud_id
          @cloud_desc_cache = MU::Cloud::AWS::MsgQueue.find(
            cloud_id: @cloud_id.dup,
            region: @region,
            credentials: @credentials
          )
          @cloud_desc_cache
        end

        # Return the metadata for this MsgQueue rule
        # @return [Hash]
        def notify
          cloud_desc
          deploy_struct = MU::Cloud::AWS::MsgQueue.find(
            cloud_id: @cloud_id,
            region: @region,
            credentials: @credentials
          )
          return deploy_struct
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
          MU::Cloud::RELEASE
        end

        # Remove all msg_queues associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          MU.log "AWS::MsgQueue.cleanup: need to support flags['known']", MU::DEBUG, details: flags
          MU.log "Placeholder: AWS MsgQueue artifacts do not support tags, so ignoremaster cleanup flag has no effect", MU::DEBUG, details: ignoremaster

          resp = MU::Cloud::AWS.sqs(credentials: credentials, region: region).list_queues(
            queue_name_prefix: deploy_id
          )
          if resp and resp.queue_urls
            threads = []
            resp.queue_urls.each { |url|
              threads << Thread.new {
                MU.log "Deleting SQS queue #{url}"
                if !noop
                  MU::Cloud::AWS.sqs(credentials: credentials, region: region).delete_queue(
                    queue_url: url
                  )
                  sleep 60 # per API docs, this is how long it takes to really delete
                end
              }
            }
            threads.each { |t|
              t.join
            }
          end
        end

        # Locate an existing msg_queue.
        # @return [Hash]: AWS doesn't return anything but the SQS URL, so supplement with attributes
        def self.find(**args)
          args[:flags] ||= {}
          args[:flags]['account'] ||= MU.account_number
          found = {}

          # If it's a URL, make sure it's good
          begin
            if args[:cloud_id]
              if args[:cloud_id].match(/^https?:/i)
                resp = MU::Cloud::AWS.sqs(region: args[:region], credentials: args[:credentials]).get_queue_attributes(
                  queue_url: args[:cloud_id],
                  attribute_names: ["All"]
                )
                if resp and resp.attributes
                  desc = resp.attributes.dup
                  desc["Url"] = args[:cloud_id]
                  found[args[:cloud_id]] = desc
                  return found
                end
              else
                # If it's a plain queue name, resolve it to a URL
                resp = MU::Cloud::AWS.sqs(region: args[:region], credentials: args[:credentials]).get_queue_url(
                  queue_name: args[:cloud_id],
                  queue_owner_aws_account_id: args[:flags]['account']
                )
                args[:cloud_id] = resp.queue_url if resp and resp.queue_url
              end
            end
          rescue ::Aws::SQS::Errors::NonExistentQueue
          end

          # Go fetch its attributes
          fetch = if args[:cloud_id]
            if args[:cloud_id] !~ /^https?:\/\//
              [begin
                MU::Cloud::AWS.sqs(region: args[:region], credentials: args[:credentials]).get_queue_url(queue_name: args[:cloud_id]).queue_url
              rescue Aws::SQS::Errors::NonExistentQueue
                return found
              end]
            else
              [args[:cloud_id]]
            end
          else
            resp = MU::Cloud::AWS.sqs(region: args[:region], credentials: args[:credentials]).list_queues
            resp.queue_urls
          end

          if fetch
            fetch.each { |url|
              resp = MU::Cloud::AWS.sqs(region: args[:region], credentials: args[:credentials]).get_queue_attributes(
                queue_url: url,
                attribute_names: ["All"]
              )
              if resp and resp.attributes
                desc = resp.attributes.dup
                desc["Url"] = url
                found[url] = desc
              end
            }
          end

          found
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {
            "max_msg_size" => {
              "type" => "integer",
              "description" => "Maximum size of messages in this queue, in kB. Must be between 1 and 256.", 
              "default" => 256
            },
            "retain" => {
              "type" => "string",
              "description" => "The length of time for which Amazon SQS retains a message. Assumed to be in seconds, unless you specify a string like '4d' or 'five hours'. Must be between 1 minute and 14 days.",
              "default" => "4 days"
            },
            "delay" => {
              "type" => "string",
              "description" => "Delay delivery by up to 15 minutes. You can specify a string like '1m' or '600 seconds'.", 
              "default" => "0 seconds"
            },
            "receive_timeout" => {
              "type" => "string",
              "description" => "The length of time, for which a ReceiveMessage action waits for a message to arrive, between 0 and 20 seconds. You can specify a string like '5s' or '20 seconds'.", 
              "default" => "0 seconds"
            },
            "visibility_timeout" => {
              "type" => "string",
              "description" => "The length of time during which Amazon SQS prevents other consumers from receiving and processing a message after another consumer has received it. Must be between 0 seconds and 12 hours. You can specify a string like '5 minutes' or '3 hours'. See also: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html",

              "default" => "30 seconds"
            },
            "fifo" => {
              "type" => "boolean",
              "description" => "Designate this queue as a FIFO queue. Messages in this queue must explicitly specify MessageGroupId. This cannot be changed once instantiated. This feature is not available in all regions. See also: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues.html#FIFO-queues-understanding-logic",
              "default" => false
            },
            "dedup" => {
              "type" => "boolean",
              "description" => "Enables content-based deduplication. When ContentBasedDeduplication is in effect, messages with identical content sent within the deduplication interval are treated as duplicates and only one copy of the message is delivered. This feature is not available in all regions. See also: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues.html#FIFO-queues-exactly-once-processing",
              "default" => false
            },
            "failqueue" => {
              "type" => "object",
              "description" => "Target queue for messages that can't be processed (consumed) successfully. See also: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html",
              "properties" => {
                "create" => {
                  "type" => "boolean",
                  "description" => "Create a separate MsgQueue on the fly."
                },
                "retries_before_fail" => {
                  "type" => "integer",
                  "description" => "Number of times a message should fail before being sent to this queue. Must be between 1 and 1000.",
                  "default" => 10
                },
                "name" => {
                  "type" => "string",
                  "description" => "The name of a sibling SQS resource in this deploy, or the cloud identifier or URL of a pre-existing one"
                }
              }
            },
# TODO this doesn't work as either an ARN, short identifier, or full JSON policy descriptor. Docs are vague. Need to ask AWS.
#            "iam_policy" => {
#              "type" => "string",
#              "description" => "An IAM policy document for access to this SQS queue. Our parser expects this to be defined inline like the rest of your YAML/JSON Basket of Kittens, not as raw JSON. For guidance on SQS IAM capabilities, see: https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazonsqs.html"
#            },
            "kms" => {
              "type" => "object",
              "description" => "Use an Amazon KMS key to encrypt and decrypt messages in the background. This feature is not available in all regions. https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html#sqs-sse-key-terms",
              "required" => ["key_id", "key_reuse_period"],
              "properties" => {
                "key_id" => {
                  "type" => "string",
                  "description" => "KMS key to use for encryption and decryption"
                },
                "key_reuse_period" => {
                  "type" => "string",
                  "description" => "The length of time, in seconds, for which Amazon SQS can reuse a data key to encrypt or decrypt messages before calling AWS KMS again. You can specify a string like '5m' or '2 hours'.",
                  "default" => "5 minutes"
                }
              }
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::msg_queues}, bare and unvalidated.
        # @param queue [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(queue, configurator)
          ok = true

          if queue['failqueue']
            if (!queue['failqueue']['create'] and !queue['failqueue'].has_key?("name")) or
               (queue['failqueue']['create'] and queue['failqueue']['name'])
              MU.log "Must set exactly one of 'create' or 'failqueue' in MsgQueue #{queue['name']}.", MU::ERR
              ok = false
            end
            if queue['failqueue']['retries_before_fail'] < 1 or 
               queue['failqueue']['retries_before_fail'] > 1000
              MU.log "'retries_before_fail' must be between 1 and 1000 in MsgQueue #{queue['name']}.", MU::ERR
              ok = false
            end
            if queue['failqueue']['create']
              failq = queue.dup
              failq['name'] += "-fail"
              failq.delete("failqueue")
              ok = false if !configurator.insertKitten(failq, "msg_queues")
              queue['failqueue']['name'] = failq['name']
              MU::Config.addDependency(queue, failq["name"], "msg_queue")
            else
              if configurator.haveLitterMate?(queue['failqueue']['name'], "msg_queue")
                MU::Config.addDependency(queue, queue['failqueue']['name'], "msg_queue")
              else
                failq = MU::Cloud::AWS::MsgQueue.find(cloud_id: queue['failqueue']['name'])
                if !failq
                  MU.log "Could not find an SQS queue named #{queue['failqueue']['name']} for failqueue in MsgQueue '#{queue['name']}'", MU::ERR
                  ok = false
                end
              end
            end
          end

          if queue['max_msg_size'] < 1 or queue['max_msg_size'] > 256
            MU.log "Must specify a 'max_msg_size' value between 1 and 256 in MsgQueue #{queue['name']}.", MU::ERR
            ok = false
          end
          queue['max_msg_size'] *= 1024 # the API takes it in bytes

          queue['retain'] = ChronicDuration.parse(queue['retain'], :keep_zero => true)
          if !queue['retain'] or queue['retain'] < 60 or queue['retain'] > 1209600
            MU.log "Must specify a 'retain' value between 1 minute and 14 days in MsgQueue #{queue['name']}.", MU::ERR
            ok = false
          end

          queue['delay'] = ChronicDuration.parse(queue['delay'], :keep_zero => true)
          if !queue['delay'] or queue['delay'] < 0 or queue['delay'] > 900
            MU.log "'delay' value must be between 0 seconds and 15 minutes in MsgQueue #{queue['name']}.", MU::ERR
            ok = false
          end

          queue['receive_timeout'] = ChronicDuration.parse(queue['receive_timeout'], :keep_zero => true)
          if !queue['receive_timeout'] or queue['receive_timeout'] < 0 or queue['receive_timeout'] > 20
            MU.log "'receive_timeout' value must be between 0 seconds and 20 seconds in MsgQueue #{queue['name']}.", MU::ERR
            ok = false
          end

          queue['visibility_timeout'] = ChronicDuration.parse(queue['visibility_timeout'], :keep_zero => true)
          if !queue['visibility_timeout'] or queue['visibility_timeout'] < 0 or queue['visibility_timeout'] > 43200
            MU.log "'visibility_timeout' value must be between 0 seconds and 12 hours in MsgQueue #{queue['name']}.", MU::ERR
            ok = false
          end

          if queue['kms']
            good_regions = ["us-east-1", "us-east-2", "us-west-2"]
            if !good_regions.include?(queue['region'])
              MU.log "KMS SQS encryption isn't supported in all regions, and #{queue['region']} wasn't on the list last we checked. Queue '#{queue['name']}' may not work.", MU::WARN, details: good_regions
            end
            queue['kms']['key_reuse_period'] = ChronicDuration.parse(queue['kms']['key_reuse_period'], :keep_zero => true)
            if !queue['kms']['key_reuse_period'] or queue['kms']['key_reuse_period'] < 60 or queue['kms']['key_reuse_period'] > 86400
              MU.log "KMS 'visibility_period' value must be between 60 seconds and 24 hours in MsgQueue #{queue['name']}.", MU::ERR
              ok = false
            end
            begin
              MU::Cloud::AWS.kms(region: queue['region']).describe_key(key_id: queue['kms']['key_id'])
            rescue Aws::KMS::Errors::NotFoundException
              MU.log "KMS key '#{queue['kms']['key_id']}' specified in Queue '#{queue['name']}' was not found.", MU::ERR, details: "Key IDs are of the form bf64a093-2c3d-46fa-0d4f-8232fa7ed53. Keys can be created at https://console.aws.amazon.com/iam/home#/encryptionKeys/#{queue['region']}"
              ok = false
            end

          end

          good_regions = ["us-east-1", "us-east-2", "us-west-2", "eu-west-1"]

          if (queue['fifo'] or queue['dedup']) and !good_regions.include?(queue['region'])
            MU.log "Fifo queues aren't supported in all regions, and #{queue['region']} wasn't on the list last we checked. MsgQueue '#{queue['name']}' may not work.", MU::WARN, details: good_regions
          end

          # TODO have IAM API validate queue['iam_policy'] if any is set

          ok
        end

        private

        def genQueueAttrs
          attrs = {
            "MaximumMessageSize" => @config['max_msg_size'].to_s,
            "MessageRetentionPeriod" => @config['retain'].to_s,
            "DelaySeconds" => @config['delay'].to_s,
            "ReceiveMessageWaitTimeSeconds" => @config['receive_timeout'].to_s
          }

          if @config['failqueue']
            sibling = @deploy.findLitterMate(type: "msg_queue", name: @config['failqueue']['name'])
            id = @config['failqueue']['name']
            if sibling # resolve sibling queues to something useful
              id = sibling.cloud_id
            end
            desc = MU::Cloud::AWS::MsgQueue.find(cloud_id: id, credentials: @credentials)
            if !desc
              raise MuError, "Failed to get cloud descriptor for SQS queue #{@config['failqueue']['name']}"
            end
            rdr_pol = {
              "deadLetterTargetArn" => desc["QueueArn"],
              "maxReceiveCount" => @config['failqueue']['retries_before_fail']
            }
            attrs["RedrivePolicy"] = JSON.generate(rdr_pol)
          end

          # These aren't supported in most regions, and will fail loudly and
          # spectacularly if you try to use them in the forbidden lands.
          if @config['fifo'] or @config['dedup']
            attrs["FifoQueue"] = "true" # dedup enables fifo implicitly
            attrs["ContentBasedDeduplication"] = @config['dedup'].to_s
          end
          if @config['kms']
            attrs["KmsMasterKeyId"] = @config['kms']['key_id'].to_s
            attrs["KmsDataKeyReusePeriodSeconds"] = @config['kms']['key_reuse_period'].to_s
          end

# TODO this doesn't work as either an ARN, short identifier, or full JSON policy descriptor. Docs are vague. Need to ask AWS.
#          if @config['iam_policy']
#            attrs["Policy"] = JSON.generate(@config['iam_policy'])
#          end

          attrs
        end

        def tagQueue(url = nil)
          tags = {}
          tags["Name"] = @mu_name

          MU::MommaCat.listStandardTags.each_pair { |name, value|
            tags[name] = value
          }

          if @config['optional_tags']
            MU::MommaCat.listOptionalTags.each_pair { |name, value|
              tags[name] = value
            }
          end

          if @config['tags']
            @config['tags'].each { |tag|
              tags[tag['key']] = tag['value']
            }
          end
          if !url
            desc = cloud_desc
            url = desc["Url"]
            if !url
              raise MU::MuError, "Can't tag SQS queue, failed to retrieve queue_url"
            end
          end

          begin
            MU::Cloud::AWS.sqs(region: @region, credentials: @credentials).tag_queue(
              queue_url: url,
              tags: tags
            )
          rescue ::Aws::SQS::Errors::UnsupportedOperation, NameError => e
            MU.log "We appear to be in a region that does not support SQS tagging. Skipping tags for #{@mu_name}", MU::NOTICE, details: e.message
          end
        end

      end
    end
  end
end
