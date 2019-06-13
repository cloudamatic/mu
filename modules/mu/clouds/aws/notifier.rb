# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
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
      # Support for AWS SNS
      class Notifier < MU::Cloud::Notifier
        @deploy = nil
        @config = nil

        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::logs}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          MU::Cloud::AWS.sns(region: @config['region'], credentials: @config['credentials']).create_topic(name: @mu_name)
          @cloud_id = @mu_name
          MU.log "Created SNS topic #{@mu_name}"
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          if @config['subscriptions']
            @config['subscriptions'].each { |sub|
              MU::Cloud::AWS::Notifier.subscribe(
                arn: arn,
                endpoint: sub['endpoint'],
                region: @config['region'],
                credentials: @config['credentials'],
                protocol: sub['type']
              )
            }
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

        # Remove all notifiers associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          MU::Cloud::AWS.sns(region: region, credentials: credentials).list_topics.topics.each { |topic|
            if topic.topic_arn.match(MU.deploy_id)
              # We don't have a way to tag our SNS topics, so we will delete any topic that has the MU-ID in its ARN. 
              # This may fail to find notifier groups in some cases (eg. cache_cluster) so we might want to delete from each API as well.
              MU::Cloud::AWS.sns(region: region, credentials: credentials).delete_topic(topic_arn: topic.topic_arn)
              MU.log "Deleted SNS topic: #{topic.topic_arn}"
            end
          }
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          @cloud_id ||= @mu_name
          "arn:"+(MU::Cloud::AWS.isGovCloud?(@config["region"]) ? "aws-us-gov" : "aws")+":sns:"+@config['region']+":"+MU::Cloud::AWS.credToAcct(@config['credentials'])+":"+@cloud_id
        end

        # Return the metadata for this user cofiguration
        # @return [Hash]
        def notify
          desc = MU::Cloud::AWS.sns(region: @config["region"], credentials: @config["credentials"]).get_topic_attributes(topic_arn: arn).attributes
          MU.structToHash(desc)
        end

        # Locate an existing notifier.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @param flags [Hash]: Optional flags
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching notifier.
        def self.find(cloud_id: nil, region: MU.curRegion, credentials: nil, flags: {})
          found = {}
          if cloud_id
            arn = "arn:"+(MU::Cloud::AWS.isGovCloud?(region) ? "aws-us-gov" : "aws")+":sns:"+region+":"+MU::Cloud::AWS.credToAcct(credentials)+":"+cloud_id
            desc = MU::Cloud::AWS.sns(region: region, credentials: credentials).get_topic_attributes(topic_arn: arn).attributes
            found[cloud_id] = desc if desc
          end
          found
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "subscriptions" => {
              "type" => "array",
              "items" => {
                "type" => "object",
                "required" => ["endpoint"],
                "properties" => {
                  "type" => {
                    "type" => "string",
                    "description" => "",
                    "enum" => ["http", "https", "email", "email-json", "sms", "sqs", "application", "lambda"]
                  }
                }
              }
            }

          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::notifier}, bare and unvalidated.

        # @param notifier [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(notifier, configurator)
          ok = true

          if notifier['subscriptions']
            notifier['subscriptions'].each { |sub|
              if !sub["type"]
                if sub["endpoint"].match(/^http:/i)
                  sub["type"] = "http"
                elsif sub["endpoint"].match(/^https:/i)
                  sub["type"] = "https"
                elsif sub["endpoint"].match(/^sqs:/i)
                  sub["type"] = "sqs"
                elsif sub["endpoint"].match(/^\+?[\d\-]+$/)
                  sub["type"] = "sms"
                elsif sub["endpoint"].match(/\A[\w+\-.]+@[a-z\d\-]+(\.[a-z]+)*\.[a-z]+\z/i)
                  sub["type"] = "email"
                else
                  MU.log "Notifier #{notifier['name']} subscription #{sub['endpoint']} did not specify a type, and I'm unable to guess one", MU::ERR
                  ok = false
                end
              end
            }
          end

          ok
        end


        # Subscribe to a notifier group. This can either be an email address, SQS queue, application endpoint, etc...
        # Will create the subscription only if it doesn't already exist.
        # @param arn [String]: The cloud provider's identifier of the notifier group.
        # @param protocol [String]: The type of the subscription (eg. email,https, etc..).
        # @param endpoint [String]: The endpoint of the subscription. This will depend on the 'protocol' (as an example if protocol is email, endpoint will be the email address) ..
        # @param region [String]: The cloud provider region.
        def self.subscribe(arn: nil, protocol: nil, endpoint: nil, region: MU.curRegion, credentials: nil)
          retries = 0
          begin 
            resp = MU::Cloud::AWS.sns(region: region, credentials: credentials).list_subscriptions_by_topic(topic_arn: arn).subscriptions
          rescue Aws::SNS::Errors::NotFound
            if retries < 5
              MU.log "Couldn't find topic #{arn}, retrying several times in case of a lagging resource"
              retries += 1
              sleep 30
              retry
            else
              raise MuError, "Couldn't find topic #{arn}, giving up"
            end
          end

          already_subscribed = false
          if resp && !resp.empty?
            resp.each { |subscription|
             already_subscribed = true if subscription.protocol == protocol && subscription.endpoint == endpoint
            }
          end

          unless already_subscribed
            MU::Cloud::AWS.sns(region: region, credentials: credentials).subscribe(topic_arn: arn, protocol: protocol, endpoint: endpoint)
            MU.log "Subscribed #{endpoint} to SNS topic #{arn}"
          end
        end

        # Test if a notifier group exists
        # Create a new notifier group. Will check if the group exists before creating it.
        # @param topic_name [String]: The cloud provider's name for the notifier group.
        # @param region [String]: The cloud provider region.
        # @param account_number [String]: The cloud provider account number.
        # @return [string]: The cloud provider's identifier.
        def self.topicExist(topic_name, region: MU.curRegion, account_number: MU.account_number, credentials: nil)
          arn = "arn:#{MU::Cloud::AWS.isGovCloud?(region) ? "aws-us-gov" : "aws"}:sns:#{region}:#{account_number}:#{topic_name}"
          match = nil
          MU::Cloud::AWS.sns(region: region, credentials: credentials).list_topics.topics.each { |topic|
            if topic.topic_arn == arn
              match = topic.topic_arn
              break
            end
          }
          return match
        end

      end
    end
  end
end
