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

    # Generic methods for all DNSZone implementations
    class DNSZone

      # Set a generic .platform-mu DNS entry for a resource, and return the name
      # that was set.
      def self.genericMuDNSEntry(**flags)
# XXX have this switch on a global config for where Mu puts its DNS
        MU::Cloud.resourceClass(MU::Config.defaultCloud, "DNSZone").genericMuDNSEntry(**flags)
      end

      # Wrapper for {MU::Cloud::AWS::DNSZone.manageRecord}. Spawns threads to create all
      # requested records in background and returns immediately.
      def self.createRecordsFromConfig(*flags)
        cloudclass = MU::Cloud.resourceClass(MU::Config.defaultCloud, "DNSZone")
        if !flags.nil? and flags.size == 1
          cloudclass.createRecordsFromConfig(flags.first)
        else
          cloudclass.createRecordsFromConfig(*flags)
        end
      end
    end

  end

end
