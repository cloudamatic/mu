# Copyright:: Copyright (c) 2019 eGlobalTech, Inc., all rights reserved
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
  class Adoption

    attr_reader :found

    def initialize(clouds: MU::Cloud.supportedClouds, types: MU::Cloud.resource_types.keys)
      @scraped = {}
      @clouds = clouds
      @types = types
      @reference_map = {}
    end

    def scrapeClouds()
      @clouds.each { |cloud|
        cloudclass = Object.const_get("MU").const_get("Cloud").const_get(cloud)
        next if cloudclass.listCredentials.nil?
        cloudclass.listCredentials.each { |credset|
          puts cloud+" "+credset
          @types.each { |type|
            @scraped[type] ||= []
      
            found = MU::MommaCat.findStray(
              cloud,
              type,
              credentials: credset,
              allow_multi: true,
              dummy_ok: true,
              debug: true
            )

            if found and found.size > 0
            end

          }
        }
      }
    end

    def generateBasket(appname: "mu")
      bok = { "appname" => appname }

      @clouds.each { |cloud|
        @scraped.each_pair { |type, resources|
          res_class = begin
            MU::Cloud.loadCloudType(cloud, type)
          rescue MU::Cloud::MuCloudResourceNotImplemented => e
            # XXX I don't think this can actually happen
            next
          end

          bok[res_class.cfg_plural] ||= []

          resources.each { |obj|
            resource_bok = obj.toKitten
            bok[res_class.cfg_plural] << resource_bok if resource_bok
          }
        }
      }
      
      bok
    end

  end
end
