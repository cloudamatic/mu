# Copyright:: Copyright (c) 2020 eGlobalTech, Inc., all rights reserved
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
  # Plugins under this namespace serve as interfaces to cloud providers and
  # other provisioning layers.
  class Cloud

    # List of known/supported Cloud providers. This may be modified at runtime
    # if an implemention is defective or missing required methods.
    @@supportedCloudList = ['AWS', 'CloudFormation', 'Google', 'Azure']

    # List of known/supported Cloud providers
    # @return [Array<String>]
    def self.supportedClouds
      @@supportedCloudList
    end

    # Raise an exception if the cloud provider specified isn't valid
    def self.cloudClass(cloud)
      if cloud.nil? or !supportedClouds.include?(cloud.to_s)
        raise MuError, "Cloud provider #{cloud} is not supported"
      end
      Object.const_get("MU").const_get("Cloud").const_get(cloud.to_s)
    end

    # List of known/supported Cloud providers for which we have at least one
    # set of credentials configured.
    # @return [Array<String>]
    def self.availableClouds
      available = []
      MU::Cloud.supportedClouds.each { |cloud|
        begin
          cloudbase = Object.const_get("MU").const_get("Cloud").const_get(cloud)
          next if cloudbase.listCredentials.nil? or cloudbase.listCredentials.empty?
          available << cloud
        rescue NameError
        end
      }

      available
    end

    # Raise an exception if the cloud provider specified isn't valid or we
    # don't have any credentials configured for it.
    def self.assertAvailableCloud(cloud)
      if cloud.nil? or availableClouds.include?(cloud.to_s)
        raise MuError, "Cloud provider #{cloud} is not available"
      end
    end

    # Load the container class for each cloud we know about, and inject autoload
    # code for each of its supported resource type classes.
    failed = []
    MU::Cloud.supportedClouds.each { |cloud|
      begin
        require "mu/providers/#{cloud.downcase}"
      rescue LoadError, Gem::MissingSpecError => e
        MU.log "Error loading #{cloud} library, calls into this provider will fail", MU::ERR, details: e.message
        next
      end
      cloudclass = Object.const_get("MU").const_get("Cloud").const_get(cloud)
      @@generic_class_methods_toplevel.each { |method|
        if !cloudclass.respond_to?(method)
          MU.log "MU::Cloud::#{cloud} has not implemented required class method #{method}, disabling", MU::ERR
          failed << cloud
        end
      }
    }
    failed.uniq!
    @@supportedCloudList = @@supportedCloudList - failed

  end

end
