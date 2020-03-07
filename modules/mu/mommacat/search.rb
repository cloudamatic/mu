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

  # MommaCat is in charge of managing metadata about resources we've created,
  # as well as orchestrating amongst them and bootstrapping nodes outside of
  # the normal synchronous deploy sequence invoked by *mu-deploy*.
  class MommaCat

    private

    def resolve_habitat(habitat, credentials: nil)
      return nil if habitat.nil?
      if habitat.is_a?(MU::Config::Ref) and habitat.id
        return habitat.id
      else
        realhabitat = findLitterMate(type: "habitat", name: habitat, credentials: credentials)
        if realhabitat and realhabitat.mu_name
          return realhabitat.cloud_id
        elsif debug
          MU.log "Failed to resolve habitat name #{habitat}", MU::WARN
        end
      end
    end

    def self.generate_dummy_object(type, cloud, name, mu_name, cloud_id, desc, region, habitat, tag_value, calling_deploy, credentials)
      resourceclass = MU::Cloud.loadCloudType(cloud, type)

      use_name = if (name.nil? or name.empty?)
        if !mu_name.nil?
          mu_name
        else
          guessName(descriptor, resourceclass, cloud_id: cloud_id, tag_value: tag_value)
        end
      else
        name
      end
      if use_name.nil?
        return
      end

      cfg = {
        "name" => use_name,
        "cloud" => cloud,
        "credentials" => credentials
      }
      if !r.nil? and !resourceclass.isGlobal?
       cfg["region"] = region
      end

      if !p.nil? and resourceclass.canLiveIn.include?(:Habitat)
        cfg["project"] = habitat
      end

      # If we can at least find the config from the deploy this will
      # belong with, use that, even if it's an ungroomed resource.
      if !calling_deploy.nil? and
         !calling_deploy.original_config.nil? and
         !calling_deploy.original_config[type+"s"].nil?
        calling_deploy.original_config[type+"s"].each { |s|
          if s["name"] == use_name
            cfg = s.dup
            break
          end
        }

        return resourceclass.new(mommacat: calling_deploy, kitten_cfg: cfg, cloud_id: cloud_id)
      else
        if !@@dummy_cache[type] or !@@dummy_cache[type][cfg.to_s]
          desc_semaphore.synchronize {
            @@dummy_cache[type] ||= {}
            @@dummy_cache[type][cfg.to_s] = resourceclass.new(mu_name: use_name, kitten_cfg: cfg, cloud_id: cloud_id, from_cloud_desc: desc)
          }
        end
        return @@dummy_cache[type][cfg.to_s]
      end
    end
    private_class_method :generate_dummy_object

    def self.search_cloud_provider(type, cloud, habitats, region, cloud_id: nil, tag_key: nil, tag_value: nil, credentials: nil)
      resourceclass = MU::Cloud.loadCloudType(cloud, type)

      # Decide what regions we'll search, if applicable for this resource
      # type.
      regions = if resourceclass.isGlobal?
        [nil]
      else
        region ? [region] : cloudclass.listRegions(credentials: credentials)
      end

      # Decide what habitats (accounts/projects/subscriptions) we'll
      # search, if applicable for this resource type.
      habitats ||= []
      if habitats.empty?
        if resourceclass.canLiveIn.include?(nil)
          habitats << nil
        end
        if resourceclass.canLiveIn.include?(:Habitat)
          habitats.concat(cloudclass.listProjects(credentials))
        end
      end
      habitats << nil if habitats.empty?
      habitats.uniq!


      cloud_descs = {}

      thread_waiter = Proc.new { |threads|
        begin
          threads.each { |t| t.join(0.1) }
          threads.reject! { |t| t.nil? or !t.status }
          sleep 1 if threads.size > 5
        end while threads.size > 5
      }

      habitat_threads = []
      desc_semaphore = Mutex.new

      found_the_thing = false
      habitats.each { |hab|
        thread_waiter.call(habitat_threads)

        habitat_threads << Thread.new(hab) { |habitat|
          cloud_descs[habitat] = {}
          region_threads = []
          regions.each { |reg|
            region_threads << Thread.new(reg) { |r|
              found = resourceclass.find(cloud_id: cloud_id, region: r, tag_key: tag_key, tag_value: tag_value, credentials: credentials, habitat: habitat)
  
              if found
                desc_semaphore.synchronize {
                  cloud_descs[habitat][r] = found
                }
              end
              # Stop if you found the thing by a specific cloud_id
              if cloud_id and found and !found.empty?
                found_the_thing = true
                Thread.exit
              end
            }
          }
          thread_waiter.call(region_threads)
        }
      }
      thread_waiter.call(habitat_threads)

      cloud_descs
    end
    private_class_method :search_cloud_provider

    def self.search_my_deploys(type, deploy_id: nil, name: nil, mu_name: nil, cloud_id: nil, credentials: nil)
      kittens = {}

      # Check our in-memory cache of live deploys before resorting to
      # metadata
      littercache = nil
      # Sometimes we're called inside a locked thread, sometimes not. Deal
      # with locking gracefully.
      begin
        @@litter_semaphore.synchronize {
          littercache = @@litters.dup
        }
      rescue ThreadError => e
        raise e if !e.message.match(/recursive locking/)
        littercache = @@litters.dup
      end

      # First, see what we have in deploys that already happen to be loaded in
      # memory.
      littercache.each_pair { |cur_deploy, momma|
        next if deploy_id and deploy_id != cur_deploy

        @@deploy_struct_semaphore.synchronize {
          @deploy_cache[deploy] = {
            "mtime" => Time.now,
            "data" => momma.deployment
          }
        }

        straykitten = momma.findLitterMate(type: type, cloud_id: cloud_id, name: name, mu_name: mu_name, credentials: credentials, created_only: true)
        if straykitten
          MU.log "Found matching kitten #{straykitten.mu_name} in-memory - #{sprintf("%.2fs", (Time.now-start))}", loglevel
          # Peace out if we found the exact resource we want
          if cloud_id and straykitten.cloud_id.to_s == cloud_id.to_s
            return { straykitten.cloud_id => straykitten }
          elsif mu_name and straykitten.mu_name == mu_name
            return { straykitten.cloud_id => straykitten }
          else
            kittens[straykitten.cloud_id] ||= straykitten
          end
        end
      }

      # Now go rifle metadata from any other deploys we have on disk, if they
      # weren't already there in memory.
      cacheDeployMetadata # freshen up @@deploy_cache
      mu_descs = {}
      if deploy_id.nil?
        @@deploy_cache.each_key { |deploy|
          next if littercache[deploy]
          next if !@@deploy_cache[deploy].has_key?('data')
          next if !@@deploy_cache[deploy]['data'].has_key?(type)
          if !name.nil?
            next if @@deploy_cache[deploy]['data'][type][name].nil?
            mu_descs[deploy] ||= []
            mu_descs[deploy] << @@deploy_cache[deploy]['data'][type][name].dup
          else
            mu_descs[deploy] ||= []
            mu_descs[deploy].concat(@@deploy_cache[deploy]['data'][type].values)
          end
        }
      elsif !@@deploy_cache[deploy_id].nil?
        if !@@deploy_cache[deploy_id]['data'].nil? and
            !@@deploy_cache[deploy_id]['data'][type].nil?
          if !name.nil? and !@@deploy_cache[deploy_id]['data'][type][name].nil?
            mu_descs[deploy_id] ||= []
            mu_descs[deploy_id] << @@deploy_cache[deploy_id]['data'][type][name].dup
          else
            mu_descs[deploy_id] = @@deploy_cache[deploy_id]['data'][type].values
          end
        end
      end

      mu_descs.each_pair { |deploy, matches|
        next if matches.nil? or matches.size == 0
        momma = MU::MommaCat.getLitter(deploy)

        straykitten = nil

        # If we found exactly one match in this deploy, use its metadata to
        # guess at resource names we weren't told.
        if matches.size > 1 and cloud_id
          straykitten = momma.findLitterMate(type: type, cloud_id: cloud_id, credentials: credentials, created_only: true)
        elsif matches.size == 1 and name.nil? and mu_name.nil?
          if cloud_id.nil?
            straykitten = momma.findLitterMate(type: type, name: matches.first["name"], cloud_id: matches.first["cloud_id"], credentials: credentials)
          else
            straykitten = momma.findLitterMate(type: type, name: matches.first["name"], cloud_id: cloud_id, credentials: credentials)
          end
        else
          # There's more than one of this type of resource in the target
          # deploy, so see if findLitterMate can narrow it down for us
          straykitten = momma.findLitterMate(type: type, name: name, mu_name: mu_name, cloud_id: cloud_id, credentials: credentials)
        end

        next if straykitten.nil?
        straykitten.intoDeploy(momma)

        if straykitten.cloud_id.nil?
          MU.log "findStray: kitten #{straykitten.mu_name} came back with nil cloud_id", MU::WARN
          next
        end

        # Peace out if we found the exact resource we want
        if (cloud_id and straykitten.cloud_id.to_s == cloud_id.to_s) or
           (!cloud_id and mu_descs.size == 1 and matches.size == 1) or
           (credentials and straykitten.credentials == credentials)
# XXX strictly speaking this last check is only valid if findStray is searching
# exactly one set of credentials

          return { straykitten.cloud_id => straykitten }
        end

        kittens[straykitten.cloud_id] ||= straykitten
      }

      kittens
    end
    private_class_method :search_my_deploys

  end #class
end #module
