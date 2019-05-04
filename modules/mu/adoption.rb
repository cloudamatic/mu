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
      
            found = MU::MommaCat.findStray(
              cloud,
              type,
              credentials: credset,
              allow_multi: true,
              dummy_ok: true,
              debug: true
            )

            if found and found.size > 0
              @scraped[type] ||= []
              @scraped[type].concat(found)
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
#          puts obj.mu_name
#          puts obj.config['name']
#          puts obj.cloud_id
#          puts obj.url
#          puts obj.arn
            resource_bok = obj.toKitten
#            pp resource_bok
            bok[res_class.cfg_plural] << resource_bok if resource_bok
          }
        }
      }

# Now walk through all of the Refs in these objects, resolve them, and minimize
# their config footprint

      vacuum(bok)
    end

    private

    # Recursively walk through a BoK hash, validate all {MU::Config::Ref}
    # objects, convert them to hashes, and pare them down to the minimal
    # representation (remove extraneous attributes that match the parent
    # object).
    # Do the same for our main objects: if they all use the same credentials,
    # for example, remove the explicit +credentials+ attributes and set that
    # value globally, once.
    def vacuum(bok)
      deploy = generateStubDeploy(bok)

      MU::Cloud.resource_types.each_pair { |typename, attrs|
        if bok[attrs[:cfg_plural]]
          MU.log "CHEWING #{bok[attrs[:cfg_plural]].size.to_s} #{attrs[:cfg_plural]} (#{bok[attrs[:cfg_plural]].map { |x| x['name'] }.uniq.size.to_s})", MU::WARN, details: bok[attrs[:cfg_plural]].map { |x| x['name'] }.uniq.sort
          bok[attrs[:cfg_plural]].each { |resource|
            obj = mommacat.findLitterMate(type: attrs[:cfg_plural], name: resource['name'])
            resource = cleanReferences(resource, deploy, obj)
          }
        end
      }

      bok
    end

    def cleanReferences(cfg, deploy, parent)
      if cfg.is_a?(MU::Config::Ref)
        if cfg.kitten
          cfg = if mommacat.findLitterMate(type: cfg.type, name: cfg.name)
            { "type" => cfg.type, "name" => cfg.name }
          # XXX other common cases: deploy_id, project, etc
          else
            cfg.to_h
          end
        else
          MU.log "Failed to resolve reference for #{parent}", MU::ERR, details: cfg
          raise MuError, "Failed to resolve reference"
        end
      elsif cfg.is_a?(Hash)
        cfg.each_pair { |key, value|
          cfg[key] = cleanReferences(value, deploy, parent)
        }
      elsif cfg.is_a?(Array)
        cfg.each { |value|
          cleanReferences(value, deploy, parent)
        }
      end

      cfg
    end

    # @return [MU::MommaCat]
    def generateStubDeploy(cfg)
#      hashify Ref objects before passing into here... or do we...?

      time = Time.new
      timestamp = time.strftime("%Y%m%d%H").to_s;
      timestamp.freeze

      retries = 0
      deploy_id = nil
      seed = nil
      begin
        raise MuError, "Failed to allocate an unused MU-ID after #{retries} tries!" if retries > 70
        seedsize = 1 + (retries/10).abs
        seed = (0...seedsize+1).map { ('a'..'z').to_a[rand(26)] }.join
        deploy_id = cfg['appname'].upcase + "-ADOPT-" + timestamp + "-" + seed.upcase
      end while MU::MommaCat.deploy_exists?(deploy_id) or seed == "mu" or seed[0] == seed[1]

      MU.setVar("deploy_id", deploy_id)
      MU.setVar("appname", cfg['appname'].upcase)
      MU.setVar("environment", "ADOPT")
      MU.setVar("timestamp", timestamp)
      MU.setVar("seed", seed)
      MU.setVar("handle", MU::MommaCat.generateHandle(seed))

      MU::MommaCat.new(
        deploy_id,
        create: true,
        config: cfg,
        environment: "adopt",
        nocleanup: true,
        no_artifacts: true,
        set_context_to_me: true,
        mu_user: MU.mu_user
      )

    end

    # Go through everything we've scraped and update our mappings of cloud ids
    # and bare name fields, so that resources can reference one another
    # portably by name.
    def catalogResources
    end

  end
end
