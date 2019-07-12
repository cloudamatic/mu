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

    def initialize(clouds: MU::Cloud.supportedClouds, types: MU::Cloud.resource_types.keys, parent: nil, billing: nil, sources: nil, destination: nil)
      @scraped = {}
      @clouds = clouds
      @types = types
      @parent = parent
      @billing = billing
      @reference_map = {}
      @sources = sources
      @destination = destination
    end

    def scrapeClouds()
      @default_parent = nil

      @clouds.each { |cloud|
        cloudclass = Object.const_get("MU").const_get("Cloud").const_get(cloud)
        next if cloudclass.listCredentials.nil?

        if cloud == "Google" and !@parent and @destination
          dest_org = MU::Cloud::Google.getOrg(@destination)
          if dest_org
            @default_parent = dest_org.name
          end
        end

        cloudclass.listCredentials.each { |credset|
          next if @sources and !@sources.include?(credset)
          puts cloud+" "+credset

          if @parent
# TODO handle different inputs (cloud_id, etc)
# TODO do something about vague matches
            found = MU::MommaCat.findStray(
              cloud,
              "folders",
              flags: { "display_name" => @parent },
              credentials: credset,
              allow_multi: false,
              dummy_ok: true,
              debug: false
            )
            if found and found.size == 1
              @default_parent = found.first
            end

          end

          @types.each { |type|
            resclass = Object.const_get("MU").const_get("Cloud").const_get(cloud).const_get(type)
            MU.log "Scraping #{cloud}/#{credset} for #{resclass.cfg_plural}"
            found = MU::MommaCat.findStray(
              cloud,
              type,
              credentials: credset,
              allow_multi: true,
              dummy_ok: true,
#              debug: true
            )


            if found and found.size > 0
              MU.log "Found #{found.size.to_s} #{resclass.cfg_plural}"
              @scraped[type] ||= {}
              found.each { |obj|
begin
if obj.cloud_desc.labels and obj.cloud_desc.labels["mu-id"]
  MU.log "skipping #{obj.cloud_id}", MU::WARN
  next
end
rescue NoMethodError => e
end
                @scraped[type][obj.cloud_id] = obj
              }
            end

          }
        }
      }

      if @parent and !@default_parent
        MU.log "Failed to locate a folder that resembles #{@parent}", MU::ERR
      end

    end

    def generateBasket(appname: "mu")
      bok = { "appname" => appname }
      if @destination
        bok["credentials"] = @destination
      end

      count = 0

      @clouds.each { |cloud|
        @scraped.each_pair { |type, resources|
          res_class = begin
            MU::Cloud.loadCloudType(cloud, type)
          rescue MU::Cloud::MuCloudResourceNotImplemented => e
            # XXX I don't think this can actually happen
            next
          end
          MU.log "Generating #{resources.size.to_s} #{res_class.cfg_plural} kittens from #{cloud}"

          bok[res_class.cfg_plural] ||= []

          class_semaphore = Mutex.new
          threads = []

          Thread.abort_on_exception = true
          resources.each_pair { |cloud_id_thr, obj_thr|
            if threads.size >= 10
              sleep 1
              begin
                threads.each { |t|
                  t.join(0.1)
                }
                threads.reject! { |t| !t.status }
              end while threads.size >= 10
            end
            threads << Thread.new(cloud_id_thr, obj_thr) { |cloud_id, obj|

              resource_bok = obj.toKitten(rootparent: @default_parent, billing: @billing)
              if resource_bok
                resource_bok.delete("credentials") if @destination

                # If we've got duplicate names in here, try to deal with it
                class_semaphore.synchronize {
                  bok[res_class.cfg_plural].each { |sibling|
                    if sibling['name'] == resource_bok['name']
                      MU.log "#{res_class.cfg_name} name #{sibling['name']} unavailable, will attempt to rename duplicate object", MU::DEBUG, details: resource_bok
                      if resource_bok['parent'] and resource_bok['parent'].respond_to?(:id) and resource_bok['parent'].id
                        resource_bok['name'] = resource_bok['name']+resource_bok['parent'].id
                      elsif resource_bok['project']
                        resource_bok['name'] = resource_bok['name']+resource_bok['project']
                      elsif resource_bok['cloud_id']
                        resource_bok['name'] = resource_bok['name']+resource_bok['cloud_id'].gsub(/[^a-z0-9]/i, "-")
                      else
                        raise MU::Config::DuplicateNameError, "Saw duplicate #{res_class.cfg_name} name #{sibling['name']} and couldn't come up with a good way to differentiate them"
                      end
                      MU.log "De-duplication: Renamed #{res_class.cfg_name} name #{sibling['name']} #{resource_bok['name']}", MU::NOTICE
                      break
                    end
                  }
                  bok[res_class.cfg_plural] << resource_bok
                }
                count += 1
              end
            }
          }

          threads.each { |t|
            t.join
          }
        }
      }


# Now walk through all of the Refs in these objects, resolve them, and minimize
# their config footprint
      MU.log "Minimizing footprint of #{count.to_s} found resources"

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
#      deploy.kittens["folders"].each_pair { |parent, children|
#        puts "under #{parent.to_s}:"
#        pp children.values.map { |o| o.mu_name+" "+o.cloud_id }
#      }
#      deploy.kittens["habitats"].each_pair { |parent, children|
#        puts "under #{parent.to_s}:"
#        pp children.values.map { |o| o.mu_name+" "+o.cloud_id }
#      }

      globals = {
        'cloud' => {},
        'credentials' => {},
        'region' => {},
        'billing_acct' => {},
        'us_only' => {},
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
        MU.log "Setting global default #{field} to #{bok[field]}"
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
          littermate = deploy.findLitterMate(type: cfg.type, name: cfg.name, cloud_id: cfg.id, habitat: cfg.habitat)
          cfg = if littermate
if !littermate.config['name']
MU.log "FAILED TO GET A NAME FROM REFERENCE", MU::WARN, details: cfg
end
            { "type" => cfg.type, "name" => littermate.config['name'] }
          elsif cfg.id
            littermate = deploy.findLitterMate(type: cfg.type, cloud_id: cfg.id, habitat: cfg.habitat)
            if littermate
MU.log "ID LITTERMATE MATCH => #{littermate.config['name']}", MU::WARN, details: {type: cfg.type, name: cfg.name, cloud_id: cfg.id, habitat: cfg.habitat}
              { "type" => cfg.type, "name" => littermate.config['name'] }
            else
MU.log "FAILED TO GET A LITTERMATE FROM REFERENCE", MU::WARN, details: {type: cfg.type, name: cfg.name, cloud_id: cfg.id, habitat: cfg.habitat}
              cfg.to_h
            end
          else
            cfg.to_h
          end
        else
          pp parent.cloud_desc
          raise Incomplete, "Failed to resolve reference on behalf of #{parent}"
        end

      elsif cfg.is_a?(Hash)
        deletia = []
        cfg.each_pair { |key, value|
          begin
            cfg[key] = resolveReferences(value, deploy, parent)
          rescue Incomplete
            MU.log "Dropping unresolved key #{key}", MU::WARN, details: cfg
            deletia << key
          end
        }
        deletia.each { |key|
          cfg.delete(key)
        }
        cfg = nil if cfg.empty? and deletia.size > 0
      elsif cfg.is_a?(Array)
        new_array = []
        cfg.each { |value|
          begin
            new_item = resolveReferences(value, deploy, parent)
            if !new_item
              MU.log "Dropping unresolved value", MU::WARN, details: value
            else
              new_array << new_item
            end
          rescue Incomplete
            MU.log "Dropping unresolved value", MU::WARN, details: value
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
        appname: bok['appname'].upcase,
        timestamp: timestamp,
        nocleanup: true,
        no_artifacts: true,
        set_context_to_me: true,
        mu_user: MU.mu_user
      )
      MU::Cloud.resource_types.each_pair { |typename, attrs|
        if bok[attrs[:cfg_plural]]
          bok[attrs[:cfg_plural]].each { |kitten|

            if !@scraped[typename][kitten['cloud_id']]
              MU.log "No object in scraped tree for #{attrs[:cfg_name]} #{kitten['cloud_id']} (#{kitten['name']})", MU::ERR, details: kitten
              next
            end

            MU.log "Inserting #{attrs[:cfg_name]} #{kitten['name']} (#{kitten['cloud_id']}) into stub deploy", MU::DEBUG, details: @scraped[typename][kitten['cloud_id']]

            @scraped[typename][kitten['cloud_id']].config!(kitten)

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
