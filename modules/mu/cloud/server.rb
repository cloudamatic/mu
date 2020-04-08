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

    # Generic methods for all Server/ServerPool implementations
    class Server

      def windows?
        return true if %w{win2k16 win2k12r2 win2k12 win2k8 win2k8r2 win2k19 windows}.include?(@config['platform'])
        begin
          return true if cloud_desc.respond_to?(:platform) and cloud_desc.platform == "Windows"
# XXX ^ that's AWS-speak, doesn't cover GCP or anything else; maybe we should require cloud layers to implement this so we can just call @cloudobj.windows?
        rescue MU::MuError
          return false
        end
        false
      end

    end

  end

end
