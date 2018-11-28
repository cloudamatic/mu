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
  class Config
    # Basket of Kittens config schema and parser logic. See modules/mu/clouds/*/search_domain.rb
    class SearchDomain

      # Base configuration schema for a SearchDomain
      # @return [Hash]
      def self.schema
        {
          "type" => "object",
          "additionalProperties" => false,
          "description" => "Set up a cloud provider managed Elastic Search cluster.",
          "properties" => {
            "name" => { "type" => "string" },
            "region" => MU::Config.region_primitive,
            "vpc" => MU::Config::VPC.reference(MU::Config::VPC::ONE_SUBNET + MU::Config::VPC::MANY_SUBNETS, MU::Config::VPC::NO_NAT_OPTS, "all_private"),
            "tags" => MU::Config.tags_primitive,
            "add_firewall_rules" => MU::Config::FirewallRule.reference,
            "ingress_rules" => {
              "type" => "array",
              "items" => MU::Config::FirewallRule.ruleschema
            },
            "optional_tags" => {
              "type" => "boolean",
              "description" => "Tag the resource with our optional tags (MU-HANDLE, MU-MASTER-NAME, MU-OWNER).",
            },
            "instance_count" => {
              "type" => "integer",
              "default" => 1
            }
          }
        }
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::search_domains}, bare and unvalidated.
      # @param dom [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(dom, configurator)
        ok = true
        # This resource basically only exists in AWS, so the validation lives
        # there. If some other provider comes up with it we can factor
        # commonalities into this spot, but there may be few to none. The AWS
        # implementation is simple, but an odd duck.
        ok
      end

    end
  end
end
