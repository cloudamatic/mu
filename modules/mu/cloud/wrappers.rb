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

    # In this file: generic class method wrappers for all resource types.

    @@resource_types.keys.each { |name|
      Object.const_get("MU").const_get("Cloud").const_get(name).class_eval {

        def self.shortname
          name.sub(/.*?::([^:]+)$/, '\1')
        end

        def self.cfg_plural
          MU::Cloud.resource_types[shortname.to_sym][:cfg_plural]
        end

        def self.has_multiples
          MU::Cloud.resource_types[shortname.to_sym][:has_multiples]
        end

        def self.cfg_name
          MU::Cloud.resource_types[shortname.to_sym][:cfg_name]
        end

        def self.can_live_in_vpc
          MU::Cloud.resource_types[shortname.to_sym][:can_live_in_vpc]
        end

        def self.waits_on_parent_completion
          MU::Cloud.resource_types[shortname.to_sym][:waits_on_parent_completion]
        end

        def self.deps_wait_on_my_creation
          MU::Cloud.resource_types[shortname.to_sym][:deps_wait_on_my_creation]
        end

        # Defaults any resources that don't declare their release-readiness to
        # ALPHA. That'll learn 'em.
        def self.quality
          MU::Cloud::ALPHA
        end

        # Return a list of "container" artifacts, by class, that apply to this
        # resource type in a cloud provider. This is so methods that call find
        # know whether to call +find+ with identifiers for parent resources.
        # This is similar in purpose to the +isGlobal?+ resource class method,
        # which tells our search functions whether or not a resource scopes to
        # a region.  In almost all cases this is one-entry list consisting of
        # +:Habitat+. Notable exceptions include most implementations of
        # +Habitat+, which either reside inside a +:Folder+ or nothing at all;
        # whereas a +:Folder+ tends to not have any containing parent. Very few
        # resource implementations will need to override this.
        # A +nil+ entry in this list is interpreted as "this resource can be
        # global."
        # @return [Array<Symbol,nil>]
        def self.canLiveIn
          if self.shortname == "Folder"
            [nil, :Folder]
          elsif self.shortname == "Habitat"
            [:Folder]
          else
            [:Habitat]
          end
        end

        def self.find(*flags)
          allfound = {}

          MU::Cloud.availableClouds.each { |cloud|
            begin
              args = flags.first
              next if args[:cloud] and args[:cloud] != cloud
              # skip this cloud if we have a region argument that makes no
              # sense there
              cloudbase = MU::Cloud.cloudClass(cloud)
              next if cloudbase.listCredentials.nil? or cloudbase.listCredentials.empty? or cloudbase.credConfig(args[:credentials]).nil?
              if args[:region] and cloudbase.respond_to?(:listRegions)
                if !cloudbase.listRegions(credentials: args[:credentials])
                  MU.log "Failed to get region list for credentials #{args[:credentials]} in cloud #{cloud}", MU::ERR, details: caller
                else
                  next if !cloudbase.listRegions(credentials: args[:credentials]).include?(args[:region])
                end
              end
              begin
                cloudclass = MU::Cloud.resourceClass(cloud, shortname)
              rescue MU::MuError
                next
              end

              credsets = if args[:credentials]
                [args[:credentials]]
              else
                cloudbase.listCredentials
              end

              credsets.each { |creds|
                args[:credentials] = creds
                found = cloudclass.find(**args)
                if !found.nil?
                  if found.is_a?(Hash)
                    allfound.merge!(found)
                  else
                    raise MuError, "#{cloudclass}.find returned a non-Hash result"
                  end
                end
              }
            rescue MuCloudResourceNotImplemented
            end
          }
          allfound
        end

        # Wrapper for the cleanup class method of underlying cloud object implementations.
        def self.cleanup(*flags)
          ok = true
          params = flags.first
          clouds = MU::Cloud.supportedClouds
          if params[:cloud]
            clouds = [params[:cloud]]
            params.delete(:cloud)
          end
          params[:deploy_id] ||= MU.deploy_id
          if !params[:deploy_id] or params[:deploy_id].empty?
            raise MuError, "Can't call cleanup methods without a deploy id"
          end

          clouds.each { |cloud|
            begin
              cloudclass = MU::Cloud.resourceClass(cloud, shortname)

              if cloudclass.isGlobal?
                params.delete(:region)
              end

              raise MuCloudResourceNotImplemented if !cloudclass.respond_to?(:cleanup) or cloudclass.method(:cleanup).owner.to_s != "#<Class:#{cloudclass}>"
              MU.log "Invoking #{cloudclass}.cleanup from #{shortname}", MU::DEBUG, details: flags
              cloudclass.cleanup(**params)
            rescue MuCloudResourceNotImplemented
              MU.log "No #{cloud} implementation of #{shortname}.cleanup, skipping", MU::DEBUG, details: flags
            rescue StandardError => e
              in_msg = cloud
              if params and params[:region]
                in_msg += " "+params[:region]
              end
              if params and params[:flags] and params[:flags]["project"] and !params[:flags]["project"].empty?
                in_msg += " project "+params[:flags]["project"]
              end
              MU.log "Skipping #{shortname} cleanup method in #{in_msg} due to #{e.class.name}: #{e.message}", MU::WARN, details: e.backtrace
              ok = false
            end
          }
          MU::MommaCat.unlockAll

          ok
        end

      } # end dynamic class generation block
    } # end resource type iteration

  end

end
