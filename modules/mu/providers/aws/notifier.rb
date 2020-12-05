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

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          @cloud_id = @mu_name
          MU::Cloud::AWS.sns(region: @region, credentials: @credentials).create_topic(name: @cloud_id)
          MU.log "Created SNS topic #{@mu_name}"
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          if @config['subscriptions']
            @config['subscriptions'].each { |sub|
              if sub['resource'] and !sub['endpoint']
                endpoint_obj = nil
                MU.retrier([], max: 5, wait: 9, loop_if: Proc.new { endpoint_obj.nil? }) {
                  endpoint_obj = MU::Config::Ref.get(sub['resource']).kitten(@deploy)
                }
                sub['endpoint'] = endpoint_obj.arn
              end
              subscribe(sub['endpoint'], sub['type'])
            }
          end
        end

        # Subscribe something to this SNS topic
        # @param endpoint [String]: The address, identifier, or ARN of the resource being subscribed
        # @param protocol [String]: The protocol being subscribed
        def subscribe(endpoint, protocol)
          self.class.subscribe(arn, endpoint, protocol, region: @region, credentials: @credentials)
        end

        # Subscribe something to an SNS topic
        # @param cloud_id [String]: The short name or ARN of an existing SNS topic
        # @param endpoint [String]: The address, identifier, or ARN of the resource being subscribed
        # @param protocol [String]: The protocol being subscribed
        # @param region [String]: The region of the target SNS topic
        # @param credentials [String]: 
        def self.subscribe(cloud_id, endpoint, protocol, region: nil, credentials: nil)
          topic = find(cloud_id: cloud_id, region: region, credentials: credentials).values.first
          if !topic
            raise MuError, "Failed to find SNS Topic #{cloud_id} in #{region}"
          end
          arn = topic["TopicArn"]

          resp = MU::Cloud::AWS.sns(region: region, credentials: credentials).list_subscriptions_by_topic(topic_arn: arn).subscriptions

          resp.each { |subscription|
            return subscription if subscription.protocol == protocol and subscription.endpoint == endpoint
          }

          MU.log "Subscribing #{endpoint} (#{protocol}) to SNS topic #{arn}", MU::NOTICE
          MU::Cloud::AWS.sns(region: region, credentials: credentials).subscribe(topic_arn: arn, protocol: protocol, endpoint: endpoint)
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
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          MU.log "AWS::Notifier.cleanup: need to support flags['known']", MU::DEBUG, details: flags
          MU.log "Placeholder: AWS Notifier artifacts do not support tags, so ignoremaster cleanup flag has no effect", MU::DEBUG, details: ignoremaster

          MU::Cloud::AWS.sns(region: region, credentials: credentials).list_topics.topics.each { |topic|
            if topic.topic_arn.match(deploy_id)
              # We don't have a way to tag our SNS topics, so we will delete any topic that has the MU-ID in its ARN. 
              # This may fail to find notifier groups in some cases (eg. cache_cluster) so we might want to delete from each API as well.
              MU.log "Deleting SNS topic: #{topic.topic_arn}"
              if !noop
                MU::Cloud::AWS.sns(region: region, credentials: credentials).delete_topic(topic_arn: topic.topic_arn)
              end
            end
          }
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          @cloud_id ||= @mu_name
          "arn:"+(MU::Cloud::AWS.isGovCloud?(@region) ? "aws-us-gov" : "aws")+":sns:"+@region+":"+MU::Cloud::AWS.credToAcct(@credentials)+":"+@cloud_id
        end

        # Return the metadata for this user cofiguration
        # @return [Hash]
        def notify
          return nil if !@cloud_id or !cloud_desc(use_cache: false)
          desc = MU::Cloud::AWS.sns(region: @region, credentials: @credentials).get_topic_attributes(topic_arn: arn).attributes
          MU.structToHash(desc)
        end

        # Locate an existing notifier.
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching notifier.
        def self.find(**args)
          found = {}

          if args[:cloud_id]
            arn = if args[:cloud_id].match(/^arn:/)
              args[:cloud_id] 
            else
              "arn:"+(MU::Cloud::AWS.isGovCloud?(args[:region]) ? "aws-us-gov" : "aws")+":sns:"+args[:region]+":"+MU::Cloud::AWS.credToAcct(args[:credentials])+":"+args[:cloud_id]
            end
            begin
              desc = MU::Cloud::AWS.sns(region: args[:region], credentials: args[:credentials]).get_topic_attributes(topic_arn: arn).attributes
              found[args[:cloud_id]] = desc if desc
            rescue ::Aws::SNS::Errors::NotFound
            end
          else
            next_token = nil
            begin
              resp = MU::Cloud::AWS.sns(region: args[:region], credentials: args[:credentials]).list_topics(next_token: next_token)
              if resp and resp.topics
                resp.topics.each { |t|
                  found[t.topic_arn.sub(/.*?:([^:]+)$/, '\1')] =  MU::Cloud::AWS.sns(region: args[:region], credentials: args[:credentials]).get_topic_attributes(topic_arn: t.topic_arn).attributes
                }
              end
              next_token = resp.next_token
            end while next_token
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

          bok['name'] = cloud_desc["DisplayName"].empty? ? @cloud_id : cloud_desc["DisplayName"]
          svcmap = {
            "lambda" => "functions",
            "sqs" => "msg_queues"
          }
          MU::Cloud::AWS.sns(region: @region, credentials: @credentials).list_subscriptions_by_topic(topic_arn: cloud_desc["TopicArn"]).subscriptions.each { |sub|
            bok['subscriptions'] ||= []

            bok['subscriptions'] << if sub.endpoint.match(/^arn:[^:]+:(sqs|lambda):([^:]+):(\d+):.*?([^:\/]+)$/)
              _wholestring, service, region, account, id = Regexp.last_match.to_a
              {
                "type" => sub.protocol,
                "resource" => MU::Config::Ref.get(
                  type: svcmap[service],
                  region: region,
                  credentials: @credentials,
                  id: id,
                  cloud: "AWS",
                  habitat: MU::Config::Ref.get(
                    id: account,
                    cloud: "AWS",
                    credentials: @credentials
                  )
                )
              }
            else
              {
                "type" => sub.protocol,
                "endpoint" => sub.endpoint
              }
            end
          }

          bok
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {
            "subscriptions" => {
              "type" => "array",
              "items" => {
                "type" => "object",
                "properties" => {
                  "type" => {
                    "type" => "string",
                    "description" => "Type of endpoint or resource which should receive notifications. If not specified, will attempt to auto-detect.",
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
              if sub['resource'] and configurator.haveLitterMate?(sub['resource']['name'], sub['resource']['type'])
                sub['resource']['cloud'] = "AWS"
                MU::Config.addDependency(notifier, sub['resource']['name'], sub['resource']['type'])
              end
              if !sub["type"]
                sub['type'] = if sub['resource']
                  if sub['resource']['type'] == "functions"
                    "lambda"
                  elsif sub['resource']['type'] == "msg_queues"
                    "sqs"
                  end
                elsif sub['endpoint']
                  if sub["endpoint"].match(/^http:/i)
                    "http"
                  elsif sub["endpoint"].match(/^https:/i)
                    "https"
                  elsif sub["endpoint"].match(/:sqs:/i)
                    "sqs"
                  elsif sub["endpoint"].match(/:lambda:/i)
                    "lambda"
                  elsif sub["endpoint"].match(/^\+?[\d\-]+$/)
                    "sms"
                  elsif sub["endpoint"].match(/\A[\w+\-.]+@[a-z\d\-]+(\.[a-z]+)*\.[a-z]+\z/i)
                    "email"
                  end
                end

                if !sub['type']
                  MU.log "Notifier #{notifier['name']} subscription did not specify a type, and I'm unable to guess one", MU::ERR, details: sub
                  ok = false
                end
              end
            }
          end

          ok
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
