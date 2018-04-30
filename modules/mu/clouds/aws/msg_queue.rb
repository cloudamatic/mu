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

        @cloudformation_data = {}
        attr_reader :cloudformation_data

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::msg_queues}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          attrs = {
            "MaximumMessageSize" => @config['max_msg_size'].to_s,
            "MessageRetentionPeriod" => @config['retain'].to_s,
            "DelaySeconds" => @config['delay'].to_s,
            "ReceiveMessageWaitTimeSeconds" => @config['receive_timeout'].to_s
          }
          namestr = @mu_name

          # These aren't supported in most regions, and will fail loudly and
          # spectacularly if you try to use them in the forbidden lands.
          if @config['fifo'] or @config['dedup']
            attrs["FifoQueue"] = "true" # dedup enables fifo implicitly
            attrs["ContentBasedDeduplication"] = @config['dedup'].to_s
            namestr += ".fifo"
          end

          MU.log "Creating SQS queue #{namestr}", details: attrs
          resp = MU::Cloud::AWS.sqs(@config['region']).create_queue(
            queue_name: namestr,
            attributes: attrs
          )
          @cloud_id = resp.queue_url

        end

        def groom
          tagQueue
        end

        # Retrieve the AWS descriptor for this SQS queue. AWS doesn't exactly
        # provide one; if you want real information for SQS ask notify()
        def cloud_desc
          if !@cloud_id
            resp = MU::Cloud::AWS.sqs(@config['region']).list_queues(
              queue_name_prefix: @mu_name
            )
            return nil if !resp or !resp.queue_urls
            resp.queue_urls.each { |url|
              if url.match(/\/#{Regexp.quote(@mu_name)}$/)
                @cloud_id = url
                break
              end
            }
          end
          @cloud_id
        end

        # Return the metadata for this MsgQueue rule
        # @return [Hash]
        def notify
          resp = MU::Cloud::AWS.sqs(@config['region']).get_queue_attributes(
            queue_url: cloud_desc, # all there is to a cloud_desc here
            attribute_names: ["All"]
          )
          deploy_struct = {
            "Url" => @cloud_id
          }
          deploy_struct.merge!(resp.attributes)
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
            resp.queue_urls.each { |url|
              MU.log "Deleting SQS queue #{url}"
              if !noop
                MU::Cloud::AWS.sqs(region).delete_queue(
                  queue_url: url
                )
              end
            }
            sleep 60 # per API docs, this is how long it takes to really delete
          end
        end

        # Locate an existing msg_queue.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @param flags [Hash]: Optional flags
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching msg_queue.
        def self.find(cloud_id: nil, region: MU.curRegion, flags: {})
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
              "description" => "The length of time, in seconds, for which a ReceiveMessage action waits for a message to arrive, between 0 and 20 seconds. YOu can specify a string like '5s' or '20 seconds'.", 
              "default" => "0 seconds"
            },
            "fifo" => {
              "type" => "boolean",
              "description" => "Designate this queue as a FIFO queue. Messages in this queue must explicitly specify MessageGroupId. This cannot be changed once instantiated. See also: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues.html#FIFO-queues-understanding-logic",
              "default" => false
            },
            "dedup" => {
              "type" => "boolean",
              "description" => "Enables content-based deduplication. When ContentBasedDeduplication is in effect, messages with identical content sent within the deduplication interval are treated as duplicates and only one copy of the message is delivered. See also: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues.html#FIFO-queues-exactly-once-processing",
              "default" => false
            },
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::msg_queues}, bare and unvalidated.
        # @param queue [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(queue, configurator)
          ok = true
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

          good_regions = ["us-east-1", "us-east-2", "us-west-2", "eu-west-1"]

          if (queue['fifo'] or queue['dedup']) and !good_regions.include?(queue['region'])
            MU.log "Fifo queues aren't supported in all regions, and #{queue['region']} wasn't on the list last we checked. Queue '#{queue['name']}' may not work.", MU::WARN, details: good_regions
          end

          ok
        end

        private

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
            queue = cloud_desc
            if !queue or !queue.queue_url
              raise MU::MuError, "Can't tag SQS queue, failed to retrieve queue_url"
            end
            url = queue.queue_url
          end

          begin
            MU::Cloud::AWS.sqs(@config['region']).tag_queue(
              queue_url: url,
              tags: tags
            )
          rescue ::Aws::SQS::Errors::UnsupportedOperation, NameError => e
            MU.log "We appear to be in a region that does not support SQS tagging, unfortunately ('#{e.message}'). Skipping tags.", MU::WARN
          end
        end

      end
    end
  end
end
