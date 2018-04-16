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
    class Notification

      # XXX
      # This one is weird in that it kind of has a first-class implementation
      # but really should be a subclass of something else, except maybe not
      # because in an ideal world it'd be a subclass of MANY something elses?
      def self.schema
        {
        }
      end

      def self.validate
        ok = true
        ok
      end

      # Generic pre-processing of {MU::Config::BasketofKittens::notifications}, bare and unvalidated.
      # @param notification [Hash]: The resource to process and validate
      # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
      # @return [Boolean]: True if validation succeeded, False otherwise
      def self.validate(notification, configurator)
        ok = true
        ok
      end

    end
  end
end
