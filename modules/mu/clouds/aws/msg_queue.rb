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
        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        @cloudformation_data = {}
        attr_reader :cloudformation_data

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::msg_queues}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          if mu_name
            @mu_name = mu_name
            cloud_desc if !@cloud_id
          else
            @mu_name ||= @deploy.getResourceName(@config["name"])
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          attrs = genQueueAttrs

          namestr = @mu_name
          namestr += ".fifo" if attrs['FifoQueue']

          MU.log "Creating SQS queue #{namestr}", details: attrs
          resp = MU::Cloud::AWS.sqs(@config['region']).create_queue(
            queue_name: namestr,
            attributes: attrs
          )
          sleep 1
          @cloud_id = resp.queue_url
          puts @cloud_id
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          tagQueue

          cur_attrs = notify
          new_attrs = genQueueAttrs

          changed = false
          new_attrs.each_pair { |k, v|
            if !cur_attrs.has_key?(k) or cur_attrs[k] != new_attrs[k]
              changed = true
            end
          }
          if changed
            MU.log "Updating SQS queue #{@mu_name}", MU::NOTICE, details: new_attrs
            resp = MU::Cloud::AWS.sqs(@config['region']).set_queue_attributes(
              queue_url: @cloud_id,
              attributes: new_attrs
            )
          end

        end

        # Retrieve the AWS descriptor for this SQS queue. AWS doesn't exactly
        # provide one; if you want real information for SQS ask notify()
        # @return [Hash]: AWS doesn't return anything but the SQS URL, so supplement with attributes
        def cloud_desc
          if !@cloud_id
            resp = MU::Cloud::AWS.sqs(@config['region']).list_queues(
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

          MU::Cloud::AWS::MsgQueue.find(
            cloud_id: @cloud_id.dup,
            region: @config['region']
          )
        end

        # Return the metadata for this MsgQueue rule
        # @return [Hash]
        def notify
          cloud_desc
          deploy_struct = MU::Cloud::AWS::MsgQueue.find(
            cloud_id: @cloud_id,
            region: @config['region']
          )
          return deploy_struct
        end

        # Remove all msg_queues associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          resp = MU::Cloud::AWS.sqs(region).list_queues(
            queue_name_prefix: MU.deploy_id
          )
          if resp and resp.queue_urls
            threads = []
            resp.queue_urls.each { |url|
              threads << Thread.new {
                MU.log "Deleting SQS queue #{url}"
                if !noop
                  MU::Cloud::AWS.sqs(region).delete_queue(
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
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @param flags [Hash]: Optional flags
        # @return [Hash]: AWS doesn't return anything but the SQS URL, so supplement with attributes
        def self.find(cloud_id: nil, region: MU.curRegion, flags: {})
          flags['account'] ||= MU.account_number
          return nil if !cloud_id


          # If it's a URL, make sure it's good
          begin
            if cloud_id.match(/^https?:/i)
              resp = MU::Cloud::AWS.sqs(region).get_queue_attributes(
                queue_url: cloud_id,
                attribute_names: ["All"]
              )
              if resp and resp.attributes
                desc = resp.attributes.dup
                desc["Url"] = cloud_id
                return desc
              end
            else
              # If it's a plain queue name, resolve it to a URL
              resp = MU::Cloud::AWS.sqs(region).get_queue_url(
                queue_name: cloud_id,
                queue_owner_aws_account_id: flags['account']
              )
              cloud_id = resp.queue_url if resp and resp.queue_url
            end
          rescue ::Aws::SQS::Errors::NonExistentQueue => e
          end

          # Go fetch its attributes
          if cloud_id
            resp = MU::Cloud::AWS.sqs(region).get_queue_attributes(
              queue_url: cloud_id,
              attribute_names: ["All"]
            )
            if resp and resp.attributes
              desc = resp.attributes.dup
              desc["Url"] = cloud_id
MU.log "RETURNING FROM FIND ON #{cloud_id}", MU::WARN, details: caller
              return desc
            end
          end

          nil
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
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
              queue['dependencies'] << {
                "name" => failq['name'],
                "type" => "msg_queue"
              }
            else
              if configurator.haveLitterMate?(queue['failqueue']['name'], "msg_queue")
                queue['dependencies'] << {
                  "name" => queue['failqueue']['name'],
                  "type" => "msg_queue"
                }
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
# XXX check for existence of queue['kms']['key_id']
          end

          good_regions = ["us-east-1", "us-east-2", "us-west-2", "eu-west-1"]

          if (queue['fifo'] or queue['dedup']) and !good_regions.include?(queue['region'])
            MU.log "Fifo queues aren't supported in all regions, and #{queue['region']} wasn't on the list last we checked. MsgQueue '#{queue['name']}' may not work.", MU::WARN, details: good_regions
          end


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
#            attrs["RedrivePolicy"] = {}
            sibling = @deploy.findLitterMate(type: "msg_queue", name: config['failqueue']['name'])
            id = config['failqueue']['name']
            if sibling # resolve sibling queues to something useful
              id = sibling.cloud_id
            end
            desc = MU::Cloud::AWS::MsgQueue.find(cloud_id: id)
            if !desc
              raise MuError, "Failed to get cloud descriptor for SQS queue #{config['failqueue']['name']}"
            end
            rdr_pol = {
              "deadLetterTargetArn" => desc["QueueArn"],
              "maxReceiveCount" => config['failqueue']['retries_before_fail']
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
            MU::Cloud::AWS.sqs(@config['region']).tag_queue(
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
