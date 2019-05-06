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

    class Incomplete < MU::MuNonFatal; end

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
              @scraped[type] ||= {}
              found.each { |obj|
                @scraped[type][obj.cloud_id] = obj
              }
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

          resources.each_pair { |cloud_id, obj|
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

      globals = {
        'cloud' => {},
        'credentials' => {},
        'region' => {},
      }
      clouds = {}
      credentials = {}
      regions = {}
      MU::Cloud.resource_types.each_pair { |typename, attrs|
        if bok[attrs[:cfg_plural]]
          processed = []
          bok[attrs[:cfg_plural]].each { |resource|
            globals.each_pair { |field, counts|
              if resource[field]
                counts[resource[field]] ||= 0
                counts[resource[field]] += 1
              end
            }
            obj = deploy.findLitterMate(type: attrs[:cfg_plural], name: resource['name'])
            begin
              processed << resolveReferences(resource, deploy, obj)
            rescue Incomplete
            end
            resource.delete("cloud_id")
          }
          bok[attrs[:cfg_plural]] = processed
        end
      }

      globals.each_pair { |field, counts|
        next if counts.size != 1
        bok[field] = counts.keys.first
        MU.log "Setting global default #{field} to #{counts.values.first}"
        MU::Cloud.resource_types.each_pair { |typename, attrs|
          if bok[attrs[:cfg_plural]]
            bok[attrs[:cfg_plural]].each { |resource|
              resource.delete(field)
            }
          end
        }
      }

      bok
    end

    def resolveReferences(cfg, deploy, parent)

      if cfg.is_a?(MU::Config::Ref)
        if cfg.kitten(deploy)
          cfg = if deploy.findLitterMate(type: cfg.type, name: cfg.name)
            MU.log "REPLACING THIS BISH #{cfg.to_s} WITH A MINIMAL HASH FOR #{parent}", MU::WARN, details: { "type" => cfg.type, "name" => cfg.name }
            { "type" => cfg.type, "name" => cfg.name }
          # XXX other common cases: deploy_id, project, etc
          else
            MU.log "REPLACING THIS BISH WITH A HASH", MU::WARN, details: cfg.to_h
            cfg.to_h
          end
        else
          MU.log "Failed to resolve reference on behalf of #{parent}", MU::ERR, details: cfg
          raise Incomplete, "Failed to resolve reference"
        end

      elsif cfg.is_a?(Hash)
        deletia = []
        cfg.each_pair { |key, value|
          begin
            cfg[key] = resolveReferences(value, deploy, parent)
          rescue Incomplete
            deletia << key
          end
        }
        deletia.each { |key|
          cfg.delete(key)
        }
      elsif cfg.is_a?(Array)
        new_array = []
        cfg.each { |value|
          begin
            new_array << resolveReferences(value, deploy, parent)
          rescue Incomplete
          end
        }
        cfg = new_array
      end

      cfg
    end

    # @return [MU::MommaCat]
    def generateStubDeploy(bok)
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
        deploy_id = bok['appname'].upcase + "-ADOPT-" + timestamp + "-" + seed.upcase
      end while MU::MommaCat.deploy_exists?(deploy_id) or seed == "mu" or seed[0] == seed[1]

      MU.setVar("deploy_id", deploy_id)
      MU.setVar("appname", bok['appname'].upcase)
      MU.setVar("environment", "ADOPT")
      MU.setVar("timestamp", timestamp)
      MU.setVar("seed", seed)
      MU.setVar("handle", MU::MommaCat.generateHandle(seed))

      deploy = MU::MommaCat.new(
        deploy_id,
        create: true,
        config: bok,
        environment: "adopt",
        nocleanup: true,
        no_artifacts: true,
        set_context_to_me: true,
        mu_user: MU.mu_user
      )
      MU::Cloud.resource_types.each_pair { |typename, attrs|
        if bok[attrs[:cfg_plural]]
          bok[attrs[:cfg_plural]].each { |kitten|
            deploy.addKitten(
              attrs[:cfg_plural],
              kitten['name'],
              @scraped[typename][kitten['cloud_id']]
            )
          }
        end
      }

      deploy
    end

    # Go through everything we've scraped and update our mappings of cloud ids
    # and bare name fields, so that resources can reference one another
    # portably by name.
    def catalogResources
    end

  end
end
