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

    @@desc_semaphore = Mutex.new

    # A search which returned multiple matches, but is not allowed to
    class MultipleMatches < MuError
      def initialize(message = nil)
        super(message, silent: true)
      end
    end

    # Locate a resource that's either a member of another deployment, or of no
    # deployment at all, and return a {MU::Cloud} object for it.
    # @param cloud [String]: The Cloud provider to use.
    # @param type [String]: The resource type. Can be the full class name, symbolic name, or Basket of Kittens configuration shorthand for the resource type.
    # @param deploy_id [String]: The identifier of an outside deploy to search.
    # @param name [String]: The name of the resource as defined in its 'name' Basket of Kittens field, typically used in conjunction with deploy_id.
    # @param mu_name [String]: The fully-resolved and deployed name of the resource, typically used in conjunction with deploy_id.
    # @param cloud_id [String]: A cloud provider identifier for this resource.
    # @param region [String]: The cloud provider region
    # @param tag_key [String]: A cloud provider tag to help identify the resource, used in conjunction with tag_value.
    # @param tag_value [String]: A cloud provider tag to help identify the resource, used in conjunction with tag_key.
    # @param allow_multi [Boolean]: Permit an array of matching resources to be returned (if applicable) instead of just one.
    # @param dummy_ok [Boolean]: Permit return of a faked {MU::Cloud} object if we don't have enough information to identify a real live one.
    # @return [Array<MU::Cloud>]
    def self.findStray(cloud, type,
        dummy_ok: false,
        no_deploy_search: false,
        allow_multi: false,
        deploy_id: nil,
        name: nil,
        mu_name: nil,
        cloud_id: nil,
        credentials: nil,
        region: nil,
        tag_key: nil,
        tag_value: nil,
        calling_deploy: MU.mommacat,
        habitats: [],
        **flags
      ) 
      _shortclass, _cfg_name, type, _classname, _attrs = MU::Cloud.getResourceNames(type, true)

      cloudclass = MU::Cloud.cloudClass(cloud)
      return nil if cloudclass.virtual?

      if (tag_key and !tag_value) or (!tag_key and tag_value)
        raise MuError, "Can't call findStray with only one of tag_key and tag_value set, must be both or neither"
      end

      credlist = credentials ? [credentials] : cloudclass.listCredentials

      # Help ourselves by making more refined parameters out of mu_name, if
      # they weren't passed explicitly
      if mu_name
        # We can extract a deploy_id from mu_name if we don't have one already
        deploy_id ||= mu_name.sub(/^(\w+-\w+-\d{10}-[A-Z]{2})-/, '\1')
        if !tag_key and !tag_value
          tag_key = "Name"
          tag_value = mu_name
        end
      end

      # See if the thing we're looking for is a member of the deploy that's
      # asking after it.
      if !deploy_id.nil? and !calling_deploy.nil? and
          calling_deploy.deploy_id == deploy_id and (!name.nil? or !mu_name.nil?)
        kitten = calling_deploy.findLitterMate(type: type, name: name, mu_name: mu_name, cloud_id: cloud_id, credentials: credentials)
        return [kitten] if !kitten.nil?
      end

      # See if we have it in deployment metadata generally
      kittens = {}
      if !no_deploy_search and (deploy_id or name or mu_name or cloud_id)
        kittens = search_my_deploys(type, deploy_id: deploy_id, name: name, mu_name: mu_name, cloud_id: cloud_id, credentials: credentials)
        return kittens.values if kittens.size == 1

        # We can't refine any further by asking the cloud provider...
        if kittens.size > 1 and !allow_multi and
           !cloud_id and !tag_key and !tag_value
          raise MultipleMatches, "Multiple matches in MU::MommaCat.findStray where none allowed from #{cloud}, #{type}, name: #{name}, mu_name: #{mu_name}, cloud_id: #{cloud_id}, credentials: #{credentials}, habitats: #{habitats} (#{caller(1..1)})"
        end
      end

      if !cloud_id and !(tag_key and tag_value) and (name or mu_name or deploy_id)
        return kittens.values
      end
      matches = []

      credlist.each { |creds|
        cur_habitats = []

        if habitats and !habitats.empty?
          valid_habitats = cloudclass.listHabitats(creds)
          cur_habitats = (habitats & valid_habitats)
          next if cur_habitats.empty?
        else
          cur_habitats = cloudclass.listHabitats(creds)
        end

        cloud_descs = search_cloud_provider(type, cloud, cur_habitats, region, cloud_id: cloud_id, tag_key: tag_key, tag_value: tag_value, credentials: creds, flags: flags)

        cloud_descs.each_pair.each { |p, regions|
          regions.each_pair.each { |r, results|
            results.each_pair { |kitten_cloud_id, descriptor|

              # We already have a MU::Cloud object for this guy, use it
              if kittens.has_key?(kitten_cloud_id)
                matches << kittens[kitten_cloud_id]
              elsif dummy_ok and kittens.empty?
# XXX this is why this was threaded
                matches << generate_dummy_object(type, cloud, name, mu_name, kitten_cloud_id, descriptor, r, p, tag_value, calling_deploy, creds)
              end
            }
          }
        }
      }

      matches
    end

    @object_load_fails = false

    # Return the resource object of another member of this deployment
    # @param type [String,Symbol]: The type of resource
    # @param name [String]: The name of the resource as defined in its 'name' Basket of Kittens field
    # @param mu_name [String]: The fully-resolved and deployed name of the resource
    # @param cloud_id [String]: The cloud provider's unique identifier for this resource
    # @param created_only [Boolean]: Only return the littermate if its cloud_id method returns a value
    # @param return_all [Boolean]: Return a Hash of matching objects indexed by their mu_name, instead of a single match. Only valid for resource types where has_multiples is true.
    # @return [MU::Cloud]
    def findLitterMate(type: nil, name: nil, mu_name: nil, cloud_id: nil, created_only: false, return_all: false, credentials: nil, habitat: nil, ignore_missing: false, debug: false, **flags)
      _shortclass, _cfg_name, type, _classname, attrs = MU::Cloud.getResourceNames(type)

      # If we specified a habitat, which we may also have done by its shorthand
      # sibling name, or a Ref. Convert to something we can use.
      habitat = resolve_habitat(habitat, credentials: credentials)

      nofilter = (mu_name.nil? and cloud_id.nil? and credentials.nil?)

      does_match = Proc.new { |obj|

        (!created_only or !obj.cloud_id.nil?) and (nofilter or (
          (mu_name and obj.mu_name and mu_name.to_s == obj.mu_name) or
          (cloud_id and obj.cloud_id and cloud_id.to_s == obj.cloud_id.to_s) or
          (credentials and obj.credentials and credentials.to_s == obj.credentials.to_s) and
          !(
            (mu_name and obj.mu_name and mu_name.to_s != obj.mu_name) or
            (cloud_id and obj.cloud_id and cloud_id.to_s != obj.cloud_id.to_s) or
            (credentials and obj.credentials and credentials.to_s != obj.credentials.to_s)
          )
        ))
      }

      @kitten_semaphore.synchronize {

        if !@kittens.has_key?(type)
          return nil if !@original_config or @original_config[type].nil? or @original_config[type].empty?
          begin
            loadObjects(false)
          rescue ThreadError => e
            if e.message !~ /deadlock/
              raise e
            end
          end
          if @object_load_fails or !@kittens[type]
            if !ignore_missing
              MU.log "#{@deploy_id}'s original config has #{@original_config[type].size == 1 ? "a" : @original_config[type].size.to_s} #{type}, but loadObjects could not populate anything from deployment metadata", MU::ERR if !@object_load_fails
              @object_load_fails = true
            end
            return nil
          end
        end
        matches = {}
        @kittens[type].each { |habitat_group, sib_classes|
          next if habitat and habitat_group and habitat_group != habitat
          sib_classes.each_pair { |sib_class, cloud_objs|

            if attrs[:has_multiples]
              next if !name.nil? and name != sib_class or cloud_objs.empty?
              if !name.nil?
                if return_all
                  matches.merge!(cloud_objs.clone)
                  next
                elsif cloud_objs.size == 1 and does_match.call(cloud_objs.values.first)
                  return cloud_objs.values.first
                end
              end
              
              cloud_objs.each_value { |obj|
                if does_match.call(obj)
                  if return_all
                    matches.merge!(cloud_objs.clone)
                  else
                    return obj.clone
                  end
                end
              }
            # has_multiples is false, "cloud_objs" is actually a singular object
            elsif (name.nil? and does_match.call(cloud_objs)) or [sib_class, cloud_objs.virtual_name(name)].include?(name.to_s)
              matches[cloud_objs.config['name']] = cloud_objs.clone
            end
          }
        }

        return matches if return_all and matches.size >= 1

        return matches.values.first if matches.size == 1

      }

      return nil
    end


    private

    def resolve_habitat(habitat, credentials: nil, debug: false)
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
      resourceclass = MU::Cloud.resourceClass(cloud, type)

      use_name = if (name.nil? or name.empty?)
        if !mu_name.nil?
          mu_name
        else
          guessName(desc, resourceclass, cloud_id: cloud_id, tag_value: tag_value)
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
      if !region.nil? and !resourceclass.isGlobal? 
        cfg["region"] = region
      end

      if resourceclass.canLiveIn.include?(:Habitat) and habitat
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
          newobj = resourceclass.new(mu_name: use_name, kitten_cfg: cfg, cloud_id: cloud_id, from_cloud_desc: desc)
          @@desc_semaphore.synchronize {
            @@dummy_cache[type] ||= {}
            @@dummy_cache[type][cfg.to_s] = newobj
          }
        end
        return @@dummy_cache[type][cfg.to_s]
      end
    end
    private_class_method :generate_dummy_object

    def self.search_cloud_provider(type, cloud, habitats, region, cloud_id: nil, tag_key: nil, tag_value: nil, credentials: nil, flags: nil)
      cloudclass = MU::Cloud.cloudClass(cloud)
      resourceclass = MU::Cloud.resourceClass(cloud, type)

      # Decide what regions we'll search, if applicable for this resource
      # type.
      regions = if resourceclass.isGlobal?
        [nil]
      else
        if region
          if region.is_a?(Array) and !region.empty?
            region
          else
            [region]
          end
        else
          cloudclass.listRegions(credentials: credentials)
        end
      end

      # Decide what habitats (accounts/projects/subscriptions) we'll
      # search, if applicable for this resource type.
      habitats ||= []
      if habitats.empty?
        if resourceclass.canLiveIn.include?(nil)
          habitats << nil
        end
        if resourceclass.canLiveIn.include?(:Habitat)
          habitats.concat(cloudclass.listHabitats(credentials, use_cache: false))
        end
      end
      habitats << nil if habitats.empty?
      habitats.uniq!

      cloud_descs = {}

      thread_waiter = Proc.new { |threads, threshold|
        begin
          threads.each { |t| t.join(0.1) }
          threads.reject! { |t| t.nil? or !t.alive? or !t.status }
          sleep 1 if threads.size > threshold
        end while threads.size > threshold
      }

      habitat_threads = []
      found_the_thing = false
      habitats.each { |hab|
        break if found_the_thing
        thread_waiter.call(habitat_threads, 5)

        habitat_threads << Thread.new(hab) { |habitat|
          cloud_descs[habitat] = {}
          region_threads = []
          regions.each { |reg|
            break if found_the_thing
            region_threads << Thread.new(reg) { |r|
              found = resourceclass.find(cloud_id: cloud_id, region: r, tag_key: tag_key, tag_value: tag_value, credentials: credentials, habitat: habitat, flags: flags)

              if found
                @@desc_semaphore.synchronize {
                  cloud_descs[habitat][r] = found
                }
              end
              # Stop if you found the thing by a specific cloud_id
              if cloud_id and found and !found.empty?
                found_the_thing = true
              end
            }
          }
          thread_waiter.call(region_threads, 0)
        }
      }
      thread_waiter.call(habitat_threads, 0)

      cloud_descs
    end
    private_class_method :search_cloud_provider

    def self.search_my_deploys(type, deploy_id: nil, name: nil, mu_name: nil, cloud_id: nil, credentials: nil)
      kittens = {}
      _shortclass, _cfg_name, type, _classname, attrs = MU::Cloud.getResourceNames(type, true)

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
          @deploy_cache[deploy_id] = {
            "mtime" => Time.now,
            "data" => momma.deployment
          }
        }

        straykitten = momma.findLitterMate(type: type, cloud_id: cloud_id, name: name, mu_name: mu_name, credentials: credentials, created_only: true)
        if straykitten
          MU.log "Found matching kitten #{straykitten.mu_name} in-memory - #{sprintf("%.2fs", (Time.now-start))}", MU::DEBUG
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
      cacheDeployMetadata(deploy_id) # freshen up @@deploy_cache
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

        # If we found exactly one match in this deploy, use its metadata to
        # guess at resource names we weren't told.
        straykitten = if matches.size > 1 and cloud_id
          momma.findLitterMate(type: type, cloud_id: cloud_id, credentials: credentials, created_only: true)
        elsif matches.size == 1 and (!attrs[:has_multiples] or matches.first.size == 1) and name.nil? and mu_name.nil?
          actual_data = attrs[:has_multiples] ? matches.first.values.first : matches.first
          if cloud_id.nil?
            momma.findLitterMate(type: type, name: (actual_data["name"] || actual_data["MU_NODE_CLASS"]), cloud_id: actual_data["cloud_id"], credentials: credentials)
          else
            momma.findLitterMate(type: type, name: (actual_data["name"] || actual_data["MU_NODE_CLASS"]), cloud_id: cloud_id, credentials: credentials)
          end
        else
          # There's more than one of this type of resource in the target
          # deploy, so see if findLitterMate can narrow it down for us
          momma.findLitterMate(type: type, name: name, mu_name: mu_name, cloud_id: cloud_id, credentials: credentials)
        end

        next if straykitten.nil?
        straykitten.intoDeploy(momma)

        if straykitten.cloud_id.nil?
          MU.log "findStray: kitten #{straykitten.mu_name} came back with nil cloud_id", MU::WARN
          next
        end
        next if cloud_id and straykitten.cloud_id.to_s != cloud_id.to_s

        # Peace out if we found the exact resource we want
        if (cloud_id and straykitten.cloud_id.to_s == cloud_id.to_s) or
           (mu_descs.size == 1 and matches.size == 1) or
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
