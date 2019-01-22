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
    # Support for Microsoft Azure as a provisioning layer.
    class Azure
      @@is_in_azure = nil

      # Alias for #{MU::Cloud::AWS.hosted?}
      def self.hosted
        MU::Cloud::Azure.hosted?
      end

      # Determine whether we (the Mu master, presumably) are hosted in Azure.
      # @return [Boolean]
      def self.hosted?
        if !@@is_in_azure.nil?
          return @@is_in_azure
        end

        begin
          if getAzureMetaData("compute")
            
            @@is_in_azure = true
            return true
          end
        rescue
          # MU.log "Failed to get Azure MetaData. I assume I am not hosted in Azure", MU::DEBUG, details: resources
        end

        @@is_in_azure = false
        false
      end

      def self.hosted_config
        "TODO"
      end

      def self.required_instance_methods
        "TODO"
      end

      def self.myRegion
        "TODO"
      end

      def self.listRegions
        "TODO"
      end

      def self.listAZs
        "TODO"
      end

      def self.config_example
        "TODO"
      end

      def self.writeDeploySecret
        "TODO"
      end

      def self.listCredentials
        "TODO"
      end

      def self.credConfig
        "TODO"
      end

      def self.listInstanceTypes
        "TODO"
      end   
    end
  end
end



