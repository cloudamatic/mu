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
      # A notification as configured in {MU::Config::BasketofKittens::notifications}
      class Notification < MU::Cloud::Notification

        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::notifications}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = kitten_cfg
          @cloud_id ||= cloud_id
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create


          @cloud_id = @mu_name
        end

        # Return the metadata for this notification(s)
        # @return [Hash]
        def notify
          deploy_struct = {
          }
          return deploy_struct
        end

        # Remove all notifications associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
          MU::Cloud::AWS.sns(region).list_topics.topics.each { |topic|
            if topic.topic_arn.match(MU.deploy_id)
              # We don't have a way to tag our SNS topics, so we will delete any topic that has the MU-ID in its ARN
              MU::Cloud::AWS.sns(region).delete_topic(topic_arn: topic.topic_arn)
              MU.log "Deleted SNS topic: #{topic.topic_arn}"
            end
          }
        end

        # Locate an existing notification.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching notification.
        def self.find(cloud_id: nil, region: MU.curRegion)
          # Not implemented
        end

        def self.createTopic(topic_name, region: MU.curRegion)
          unless topicExist(topic_name, region: region, account_number: MU.account_number)
            MU::Cloud::AWS.sns(region).create_topic(name: topic_name).topic_arn
            MU.log "Created SNS topic #{topic_name}"
          end
            topicExist(topic_name, region: region, account_number: MU.account_number)
        end

        def self.subscribeToTopic(arn: nil, protocol: nil, endpoint: nil, region: MU.curRegion)
          retries = 0
          begin 
            resp = MU::Cloud::AWS.sns(region).list_subscriptions_by_topic(topic_arn: arn).subscriptions
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
            MU::Cloud::AWS.sns(region).subscribe(topic_arn: arn, protocol: protocol, endpoint: endpoint)
            MU.log "Subscribed #{endpoint} to SNS topic #{arn}"
          end
        end
        
        def self.topicExist(topic_name, region: MU.curRegion, account_number: MU.account_number)
          arn = "arn:aws:sns:#{region}:#{account_number}:#{topic_name}"
          match = nil
          MU::Cloud::AWS.sns(region).list_topics.topics.each { |topic|
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
