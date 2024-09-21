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

    # Generic class methods (.find, .cleanup, etc) are defined in wrappers.rb
    require 'mu/cloud/wrappers'

    @@resource_types.each_key { |name|
      Object.const_get("MU").const_get("Cloud").const_get(name).class_eval {
        attr_reader :cloudclass
        attr_reader :cloudobj
        attr_reader :destroyed
        attr_reader :delayed_save

        # Print something palatable when we're called in a string context.
        def to_s
          fullname = "#{self.class.shortname}"
          if !@cloudobj.nil? and !@cloudobj.mu_name.nil?
            @mu_name ||= @cloudobj.mu_name
          end
          if !@mu_name.nil? and !@mu_name.empty?
            fullname = fullname + " '#{@mu_name}'"
          end
          if !@cloud_id.nil?
            fullname = fullname + " (#{@cloud_id})"
          end
          return fullname
        end

        # Set our +deploy+ and +deploy_id+ attributes, optionally doing so even
        # if they have already been set.
        #
        # @param mommacat [MU::MommaCat]: The deploy to which we're being told we belong
        # @param force [Boolean]: Set even if we already have a deploy object
        # @return [String]: Our new +deploy_id+
        def intoDeploy(mommacat, force: false)
          if force or (!@deploy)
            MU.log "Inserting #{self} [#{self.object_id}] into #{mommacat.deploy_id} as a #{@config['name']}", MU::DEBUG

            @deploy = mommacat
            @deploy.addKitten(@cloudclass.cfg_plural, @config['name'], self)
            @deploy_id = @deploy.deploy_id
            @cloudobj.intoDeploy(mommacat, force: force) if @cloudobj
          end
          @deploy_id
        end

        # Return the +virtual_name+ config field, if it is set.
        # @param name [String]: If set, will only return a value if +virtual_name+ matches this string
        # @return [String,nil]
        def virtual_name(name = nil)
          if @config and @config['virtual_name'] and
             (!name or name == @config['virtual_name'])
            return @config['virtual_name']
          end
          nil
        end

        # @param mommacat [MU::MommaCat]: The deployment containing this cloud resource
        # @param mu_name [String]: Optional- specify the full Mu resource name of an existing resource to load, instead of creating a new one
        # @param cloud_id [String]: Optional- specify the cloud provider's identifier for an existing resource to load, instead of creating a new one
        # @param kitten_cfg [Hash]: The parse configuration for this object from {MU::Config}
        def initialize(**args)
          raise MuError, "Cannot invoke Cloud objects without a configuration" if args[:kitten_cfg].nil?

          # We are a parent wrapper object. Initialize our child object and
          # housekeeping bits accordingly.
          if self.class.name =~ /^MU::Cloud::([^:]+)$/
            @live = true
            @delayed_save = args[:delayed_save]
            @method_semaphore = Mutex.new
            @method_locks = {}
            if args[:mommacat]
               MU.log "Initializing an instance of #{self.class.name} in #{args[:mommacat].deploy_id} #{mu_name}", MU::DEBUG, details: args[:kitten_cfg]
            elsif args[:mu_name].nil?
              raise MuError, "Can't instantiate a MU::Cloud object with a live deploy or giving us a mu_name"
            else
              MU.log "Initializing a detached #{self.class.name} named #{args[:mu_name]}", MU::DEBUG, details: args[:kitten_cfg]
            end

            my_cloud = args[:kitten_cfg]['cloud'].to_s || MU::Config.defaultCloud
            if (my_cloud.nil? or my_cloud.empty?) and args[:mommacat]
              my_cloud = args[:mommacat].original_config['cloud']
            end
            if my_cloud.nil? or !MU::Cloud.supportedClouds.include?(my_cloud)
              raise MuError, "Can't instantiate a MU::Cloud object without a valid cloud (saw '#{my_cloud}')"
            end
            @cloudclass = MU::Cloud.resourceClass(my_cloud, self.class.shortname)
            @cloud_desc_cache ||= args[:from_cloud_desc] if args[:from_cloud_desc]
            @cloudparentclass = MU::Cloud.cloudClass(my_cloud)
            @cloudobj = @cloudclass.new(
              mommacat: args[:mommacat],
              kitten_cfg: args[:kitten_cfg],
              cloud_id: args[:cloud_id],
              mu_name: args[:mu_name]
            )
            raise MuError, "Unknown error instantiating #{self}" if @cloudobj.nil?
# These should actually call the method live instead of caching a static value
            PUBLIC_ATTRS.each { |a|
              begin
                instance_variable_set(("@"+a.to_s).to_sym, @cloudobj.send(a))
              rescue NoMethodError => e
                MU.log "#{@cloudclass.name} failed to implement method '#{a}'", MU::ERR, details: e.message
                raise e
              end
            }
            @deploy ||= args[:mommacat]
            @deploy_id ||= @deploy.deploy_id if @deploy

            # Register with the containing deployment
            if !@deploy.nil? and !@cloudobj.mu_name.nil? and
               !@cloudobj.mu_name.empty? and !args[:delay_descriptor_load]
              describe # XXX is this actually safe here?
              @deploy.addKitten(self.class.cfg_name, @config['name'], self)
            elsif !@deploy.nil? and @cloudobj.mu_name.nil?
              MU.log "#{self} in #{@deploy.deploy_id} didn't generate a mu_name after being loaded/initialized, dependencies on this resource will probably be confused!", MU::ERR, details: [caller, args.keys]
            end

          # We are actually a child object invoking this via super() from its
          # own initialize(), so initialize all the attributes and instance
          # variables we know to be universal.
          else
            class << self
              # Declare attributes that everyone should have
              PUBLIC_ATTRS.each { |a|
                attr_reader a
              }
            end
# XXX this butchers ::Id and ::Ref objects that might be used by dependencies() to good effect, but we also can't expect our implementations to cope with knowing when a .to_s has to be appended to things at random
            @config = MU::Config.manxify(args[:kitten_cfg]) || MU::Config.manxify(args[:config])

            if !@config
              MU.log "Missing config arguments in setInstanceVariables, can't initialize a cloud object without it", MU::ERR, details: args.keys
              raise MuError, "Missing config arguments in setInstanceVariables"
            end

            @deploy = args[:mommacat] || args[:deploy]
            @cloud_desc_cache ||= args[:from_cloud_desc] if args[:from_cloud_desc]

            @credentials = args[:credentials]
            @credentials ||= @config['credentials']

            @cloud = @config['cloud']
            if !@cloud
              if self.class.name =~ /^MU::Cloud::([^:]+)(?:::.+|$)/
               cloudclass_name = Regexp.last_match[1]
                if MU::Cloud.supportedClouds.include?(cloudclass_name)
                  @cloud = cloudclass_name
                end
              end
            end
            if !@cloud
              raise MuError, "Failed to determine what cloud #{self} should be in!"
            end

            @environment = @config['environment']
            if @deploy
              @deploy_id = @deploy.deploy_id
              @appname = @deploy.appname
            end

            @cloudclass = MU::Cloud.resourceClass(@cloud, self.class.shortname)
            @cloudparentclass = MU::Cloud.cloudClass(@cloud)

            # A pre-existing object, you say?
            if args[:cloud_id]

# TODO implement ::Id for every cloud... and they should know how to get from
# cloud_desc to a fully-resolved ::Id object, not just the short string

              @cloud_id = args[:cloud_id]
              describe(cloud_id: @cloud_id)
              @habitat_id = habitat_id # effectively, cache this

              # If we can build us an ::Id object for @cloud_id instead of a
              # string, do so.
              begin
                idclass = @cloudparentclass.const_get(:Id)
                long_id = if @deploydata and @deploydata[idclass.idattr.to_s]
                  @deploydata[idclass.idattr.to_s]
                elsif self.respond_to?(idclass.idattr)
                  self.send(idclass.idattr)
                end

                @cloud_id = idclass.new(long_id) if !long_id.nil? and !long_id.empty?
# 1 see if we have the value on the object directly or in deploy data
# 2 set an attr_reader with the value
# 3 rewrite our @cloud_id attribute with a ::Id object
              rescue NameError, MU::Cloud::MuCloudResourceNotImplemented
              end

            end

            # Use pre-existing mu_name (we're probably loading an extant deploy)
            # if available
            if args[:mu_name]
              @mu_name = args[:mu_name].dup
            # If scrub_mu_isms is set, our mu_name is always just the bare name
            # field of the resource.
            elsif @config['scrub_mu_isms']
              @mu_name = @config['name'].dup
# XXX feck it insert an inheritable method right here? Set a default? How should resource implementations determine whether they're instantiating a new object?
            end

            @tags = {}
            if !@config['scrub_mu_isms']
              @tags = @deploy ? @deploy.listStandardTags : MU::MommaCat.listStandardTags
            end
            if @config['tags']
              @config['tags'].each { |tag|
                @tags[tag['key']] = tag['value']
              }
            end

            MU::MommaCat.listOptionalTags.each_pair { |k, v|
              @tags[k] ||= v if v
            }

            if @cloudparentclass.respond_to?(:resourceInitHook)
              @cloudparentclass.resourceInitHook(self, @deploy)
            end

            # Add cloud-specific instance methods for our resource objects to
            # inherit.
            if @cloudparentclass.const_defined?(:AdditionalResourceMethods)
              self.extend @cloudparentclass.const_get(:AdditionalResourceMethods)
            end

            if ["Server", "ServerPool"].include?(self.class.shortname) and @deploy
              @mu_name ||= @deploy.getResourceName(@config['name'], need_unique_string: @config.has_key?("basis"))
              if self.class.shortname == "Server"
                @groomer = MU::Groomer.new(self)
              end

              @groomclass = MU::Groomer.loadGroomer(@config["groomer"])

              if windows? or @config['active_directory'] and !@mu_windows_name
                describe # make sure @deploydata is populated
                if !@deploydata.nil? and !@deploydata['mu_windows_name'].nil?
                  @mu_windows_name = @deploydata['mu_windows_name']
                else
                  # Use the same random differentiator as the "real" name if we're
                  # from a ServerPool. Helpful for admin sanity.
                  unq = @mu_name.sub(/^.*?-(...)$/, '\1')
                  if @config['basis'] and !unq.nil? and !unq.empty?
                    @mu_windows_name = @deploy.getResourceName(@config['name'], max_length: 15, need_unique_string: true, use_unique_string: unq, reuse_unique_string: true)
                  else
                    @mu_windows_name = @deploy.getResourceName(@config['name'], max_length: 15, need_unique_string: true)
                  end
                end
              end
              class << self
                attr_reader :groomer
                attr_reader :groomerclass
                attr_accessor :mu_windows_name # XXX might be ok as reader now
                if @cloudparentclass.respond_to?(:customAttrReaders)
                  @cloudparentclass.customAttrReaders.each { |a|
                    attr_reader a
                  }
                end
              end 
            end
            @tags["Name"] ||= @mu_name if @mu_name
          end

        end

        def cloud
          if @cloud
            @cloud
          elsif @config and @config['cloud']
            @config['cloud']
          elsif self.class.name =~ /^MU::Cloud::([^:]+)::.+/
            cloudclass_name = Regexp.last_match[1]
            if MU::Cloud.supportedClouds.include?(cloudclass_name)
              cloudclass_name
            else
              nil
            end
          else
            nil
          end
        end


        # Remove all metadata and cloud resources associated with this object
        def destroy
          if self.class.cfg_name == "server"
            begin
              ip = canonicalIP
              MU::Master.removeIPFromSSHKnownHosts(ip) if ip
              if @deploy and @deploy.deployment and
                 @deploy.deployment['servers'] and @config['name']
                me = @deploy.deployment['servers'][@config['name']][@mu_name]
                if me
                  ["private_ip_address", "public_ip_address"].each { |field|
                    if me[field]
                      MU::Master.removeIPFromSSHKnownHosts(me[field])
                    end
                  }
                  if me["private_ip_list"]
                    me["private_ip_list"].each { |private_ip|
                      MU::Master.removeIPFromSSHKnownHosts(private_ip)
                    }
                  end
                end
              end
            rescue MU::MuError => e
              MU.log e.message, MU::WARN
            end
          end
          if !@cloudobj.nil? and !@cloudobj.groomer.nil?
            @cloudobj.groomer.cleanup
          elsif !@groomer.nil?
            @groomer.cleanup
          end
          if !@deploy.nil?
            if !@cloudobj.nil? and !@config.nil? and !@cloudobj.mu_name.nil?
              @deploy.notify(self.class.cfg_plural, @config['name'], nil, mu_name: @cloudobj.mu_name, remove: true, triggering_node: @cloudobj, delayed_save: @delayed_save)
            elsif !@mu_name.nil?
              @deploy.notify(self.class.cfg_plural, @config['name'], nil, mu_name: @mu_name, remove: true, triggering_node: self, delayed_save: @delayed_save)
            end
            @deploy.removeKitten(self)
          end
          # Make sure that if notify gets called again it won't go returning a
          # bunch of now-bogus metadata.
          @destroyed = true
          if !@cloudobj.nil?
            def @cloudobj.notify
              {}
            end
          else
            def notify
              {}
            end
          end
        end

        # Return the cloud object's idea of where it lives (project, account,
        # etc) in the form of an identifier. If not applicable for this object,
        # we expect to return +nil+.
        # @return [String,nil]
        def habitat(nolookup: true)
          return nil if ["folder", "habitat"].include?(self.class.cfg_name)
          if @cloudobj 
            @cloudparentclass.habitat(@cloudobj, nolookup: nolookup, deploy: @deploy)
          else
            @cloudparentclass.habitat(self, nolookup: nolookup, deploy: @deploy)
          end
        end

        def habitat_id(nolookup: false)
          @habitat_id ||= habitat(nolookup: nolookup)
          @habitat_id
        end

        # We're fundamentally a wrapper class, so go ahead and reroute requests
        # that are meant for our wrapped object.
        def method_missing(method_sym, *arguments)
          if @cloudobj
            MU.log "INVOKING #{method_sym} FROM PARENT CLOUD OBJECT #{self}", MU::DEBUG, details: arguments
            @cloudobj.method(method_sym).call(*arguments)
          else
            raise NoMethodError, "No such instance method #{method_sym} available on #{self.class.name}"
          end
        end

        # Merge the passed hash into the existing configuration hash of this
        # cloud object. Currently this is only used by the {MU::Adoption}
        # module. I don't love exposing this to the whole internal API, but I'm
        # probably overthinking that.
        # @param newcfg [Hash]
        def config!(newcfg)
          @config.merge!(newcfg)
        end
        
        def cloud_desc(use_cache: true)
          describe

          if !@cloudobj.nil?
            if @cloudobj.class.instance_methods(false).include?(:cloud_desc)
              @cloud_desc_cache ||= @cloudobj.cloud_desc
            end
          end
          if !@config.nil? and !@cloud_id.nil? and (!use_cache or @cloud_desc_cache.nil?)
            # The find() method should be returning a Hash with the cloud_id
            # as a key and a cloud platform descriptor as the value.
            begin
              args = {
                :region => @config['region'],
                :cloud => @config['cloud'],
                :cloud_id => @cloud_id,
                :credentials => @credentials,
                :project => habitat_id, # XXX this belongs in our required_instance_methods hack
                :flags => @config
              }
              @cloudparentclass.required_instance_methods.each { |m|
#                if respond_to?(m)
#                  args[m] = method(m).call
#                else
                  args[m] = instance_variable_get(("@"+m.to_s).to_sym)
#                end
              }

              matches = self.class.find(**args)
              if !matches.nil? and matches.is_a?(Hash)
# XXX or if the hash is keyed with an ::Id element, oh boy
#                puts matches[@cloud_id][:self_link]
#                puts matches[@cloud_id][:url]
#                if matches[@cloud_id][:self_link]
#                  @url ||= matches[@cloud_id][:self_link]
#                elsif matches[@cloud_id][:url]
#                  @url ||= matches[@cloud_id][:url]
#                elsif matches[@cloud_id][:arn]
#                  @arn ||= matches[@cloud_id][:arn]
#                end
                if matches[@cloud_id]
                  @cloud_desc_cache = matches[@cloud_id]
                else
                  matches.each_pair { |k, v| # flatten out ::Id objects just in case
                    if @cloud_id.to_s == k.to_s
                      @cloud_desc_cache = v
                      break
                    end
                  }
                end
              end

              if !@cloud_desc_cache
                MU.log "cloud_desc via #{self.class.name}.find() failed to locate a live object.\nWas called by #{caller(1..1)}", MU::WARN, details: args
              end
            rescue StandardError => e
              MU.log "Got #{e.inspect} trying to find cloud handle for #{self.class.shortname} #{@mu_name} (#{@cloud_id})", MU::WARN
              raise e
            end
          end

          return @cloud_desc_cache
        end

        # Retrieve all of the known metadata for this resource.
        # @param cloud_id [String]: The cloud platform's identifier for the resource we're describing. Makes lookups more efficient.
        # @return [Array<Hash>]: mu_name, config, deploydata
        def describe(cloud_id: nil)
          if cloud_id.nil? and !@cloudobj.nil?
            @cloud_id ||= @cloudobj.cloud_id
          end
          res_type = self.class.cfg_plural
          res_name = @config['name'] if !@config.nil?
          @credentials ||= @config['credentials'] if !@config.nil?
          deploydata = nil

          if !@deploy.nil? and @deploy.is_a?(MU::MommaCat) and
              !@deploy.deployment.nil? and
              !@deploy.deployment[res_type].nil? and
              !@deploy.deployment[res_type][res_name].nil?
            deploydata = @deploy.deployment[res_type][res_name]
          else
            # XXX This should only happen on a brand new resource, but we should
            # probably complain under other circumstances, if we can
            # differentiate them.
          end

          if self.class.has_multiples and !@mu_name.nil? and deploydata.is_a?(Hash) and deploydata.has_key?(@mu_name)
            @deploydata = deploydata[@mu_name]
          elsif deploydata.is_a?(Hash)
            @deploydata = deploydata
          end

          if @cloud_id.nil? and @deploydata.is_a?(Hash)
            if @mu_name.nil? and @deploydata.has_key?('#MU_NAME')
              @mu_name = @deploydata['#MU_NAME']
            end
            if @deploydata.has_key?('cloud_id')
              @cloud_id ||= @deploydata['cloud_id']
            end
          end

          return [@mu_name, @config, @deploydata]
        end

        # Fetch MU::Cloud objects for each of this object's dependencies, and
        # return in an easily-navigable Hash. This can include things listed in
        # @config['dependencies'], implicitly-defined dependencies such as
        # add_firewall_rules or vpc stanzas, and may refer to objects internal
        # to this deployment or external.  Will populate the instance variables
        # @dependencies (general dependencies, which can only be sibling
        # resources in this deployment), as well as for certain config stanzas
        # which can refer to external resources (@vpc, @loadbalancers,
        # @add_firewall_rules)
        def dependencies(use_cache: false, debug: false)
          @dependencies ||= {}
          @loadbalancers ||= []
          @firewall_rules ||= []

          if @config.nil?
            return [@dependencies, @vpc, @loadbalancers]
          end
          if use_cache and @dependencies.size > 0
            return [@dependencies, @vpc, @loadbalancers]
          end
          @config['dependencies'] = [] if @config['dependencies'].nil?

          loglevel = debug ? MU::NOTICE : MU::DEBUG

          # First, general dependencies. These should all be fellow members of
          # the current deployment.
          @config['dependencies'].each { |dep|
            @dependencies[dep['type']] ||= {}
            next if @dependencies[dep['type']].has_key?(dep['name'])
            handle = @deploy.findLitterMate(type: dep['type'], name: dep['name']) if !@deploy.nil?
            if !handle.nil?
              MU.log "Loaded dependency for #{self}: #{dep['name']} => #{handle}", loglevel
              @dependencies[dep['type']][dep['name']] = handle
            else
              # XXX yell under circumstances where we should expect to have
              # our stuff available already?
            end
          }

          # Special dependencies: my containing VPC
          if self.class.can_live_in_vpc and !@config['vpc'].nil?
            @vpc, @nat = myVpc(@config['vpc'], loglevel: loglevel, debug: debug)
          elsif self.class.cfg_name == "vpc"
            @vpc = self
          end

          # Special dependencies: LoadBalancers I've asked to attach to an
          # instance.
          if @config.has_key?("loadbalancers")
            @loadbalancers = [] if !@loadbalancers
            @config['loadbalancers'].each { |lb|
              MU.log "Loading LoadBalancer for #{self}", MU::DEBUG, details: lb
              if @dependencies.has_key?("loadbalancer") and
                  @dependencies["loadbalancer"].has_key?(lb['concurrent_load_balancer'])
                @loadbalancers << @dependencies["loadbalancer"][lb['concurrent_load_balancer']]
              else
                if !lb.has_key?("existing_load_balancer") and
                    !lb.has_key?("deploy_id") and !@deploy.nil?
                  lb["deploy_id"] = @deploy.deploy_id
                end
                lbs = MU::MommaCat.findStray(
                    @config['cloud'],
                    "loadbalancer",
                    deploy_id: lb["deploy_id"],
                    cloud_id: lb['existing_load_balancer'],
                    name: lb['concurrent_load_balancer'],
                    region: @config["region"],
                    calling_deploy: @deploy,
                    dummy_ok: true
                )
                @loadbalancers << lbs.first if !lbs.nil? and lbs.size > 0
              end
            }
          end

          # Munge in external resources referenced by the existing_deploys
          # keyword
          if @config["existing_deploys"] && !@config["existing_deploys"].empty?
            @config["existing_deploys"].each { |ext_deploy|
              if ext_deploy["cloud_id"]
                found = MU::MommaCat.findStray(
                  @config['cloud'],
                  ext_deploy["cloud_type"],
                  cloud_id: ext_deploy["cloud_id"],
                  region: @config['region'],
                  dummy_ok: false
                ).first
  
                MU.log "Couldn't find existing resource #{ext_deploy["cloud_id"]}, #{ext_deploy["cloud_type"]}", MU::ERR if found.nil?
                @deploy.notify(ext_deploy["cloud_type"], found.config["name"], found.deploydata, mu_name: found.mu_name, triggering_node: @mu_name)
              elsif ext_deploy["mu_name"] && ext_deploy["deploy_id"]
                MU.log "#{self}: Importing metadata for #{ext_deploy["cloud_type"]} #{ext_deploy["mu_name"]} from #{ext_deploy["deploy_id"]}", MU::DEBUG
                found = MU::MommaCat.findStray(
                  @config['cloud'],
                  ext_deploy["cloud_type"],
                  deploy_id: ext_deploy["deploy_id"],
                  mu_name: ext_deploy["mu_name"],
                  region: @config['region'],
                  dummy_ok: false
                ).first
  
                if found.nil?
                  MU.log "Couldn't find existing resource #{ext_deploy["mu_name"]}/#{ext_deploy["deploy_id"]}, #{ext_deploy["cloud_type"]}", MU::ERR
                else
                  @deploy.notify(ext_deploy["cloud_type"], found.config["name"], found.deploydata, mu_name: ext_deploy["mu_name"], triggering_node: @mu_name, no_write: true)
                end
              else
                MU.log "Trying to find existing deploy, but either the cloud_id is not valid or no mu_name and deploy_id where provided", MU::ERR
              end
            }
          end

          if @config['dns_records'] && !@config['dns_records'].empty?
            @config['dns_records'].each { |dnsrec|
              if dnsrec.has_key?("name")
                if dnsrec['name'].start_with?(@deploy.deploy_id.downcase) && !dnsrec['name'].start_with?(@mu_name.downcase)
                  MU.log "DNS records for #{@mu_name} seem to be wrong, deleting from current config", MU::WARN, details: dnsrec
                  dnsrec.delete('name')
                  dnsrec.delete('target')
                end
              end
            }
          end

          return [@dependencies, @vpc, @loadbalancers]
        end

        # Resolve a VPC block to an actual resource
        def myVpc(vpc_block = @config['vpc'], loglevel: MU::DEBUG, debug: false)
          vpc_obj = nat_obj = nil

          vpc_block['credentials'] ||= @credentials
          vpc_block["id"] ||= vpc_block["vpc_id"] # old deploys
          vpc_block["name"] ||= vpc_block["vpc_name"] # old deploys
          if vpc_block['habitat']
            vpc_block['habitat'] = MU::Config::Ref.get(vpc_block['habitat'])
          end
          habitats_arg = if vpc_block['habitat']
            [vpc_block['habitat'].id]
          else
            [@project_id]
          end

          # If something hash-ified a MU::Config::Ref here, fix it
          if !vpc_block["id"].nil? and vpc_block["id"].is_a?(Hash)
            vpc_block["id"] = MU::Config::Ref.new(vpc_block["id"])
          end
          if !vpc_block["id"].nil?
            if vpc_block["id"].is_a?(MU::Config::Ref) and !vpc_block["id"].kitten.nil?
              vpc_obj = vpc_block["id"].kitten(@deploy)
            else
              vpc_ref = MU::Config::Ref.get(vpc_block)
              vpc_obj = vpc_ref.kitten(@deploy)
            end
          elsif !vpc_block["name"].nil? and @deploy
            MU.log "Attempting findLitterMate on VPC for #{self}", loglevel, details: vpc_block

            sib_by_name = @deploy.findLitterMate(name: vpc_block['name'], type: "vpcs", return_all: true, habitat: vpc_block['project'], debug: debug)
            if sib_by_name.is_a?(Hash)
              if sib_by_name.size == 1
                vpc_obj = sib_by_name.values.first
                MU.log "Single VPC match for #{self}", loglevel, details: vpc_obj.to_s
              else
# XXX ok but this is the wrong place for this really the config parser needs to sort this out somehow
                # we got multiple matches, try to pick one by preferred subnet
                # behavior
                MU.log "Sorting a bunch of VPC matches for #{self}", loglevel, details: sib_by_name.map { |s| s.to_s }.join(", ")
                sib_by_name.values.each { |sibling|
                  all_private = sibling.subnets.map { |s| s.private? }.all?(true)
                  all_public = sibling.subnets.map { |s| s.private? }.all?(false)
                  names = sibling.subnets.map { |s| s.name }
                  ids = sibling.subnets.map { |s| s.cloud_id }
                  if all_private and ["private", "all_private"].include?(vpc_block['subnet_pref'])
                    vpc_obj = sibling
                    break
                  elsif all_public and ["public", "all_public"].include?(vpc_block['subnet_pref'])
                    vpc_obj = sibling
                    break
                  elsif vpc_block['subnet_name'] and
                        names.include?(vpc_block['subnet_name'])
#puts "CHOOSING #{vpc_obj.to_s} 'cause it has #{vpc_block['subnet_name']}"
                    vpc_obj = sibling
                    break
                  elsif vpc_block['subnet_id'] and
                        ids.include?(vpc_block['subnet_id'])
                    vpc_obj = sibling
                    break
                  end
                }
                if !vpc_obj
                  sibling = sib_by_name.values.sample
                  MU.log "Got multiple matching VPCs for #{self.class.cfg_name} #{@mu_name}, so I'm arbitrarily choosing #{sibling.mu_name}", MU::WARN, details: vpc_block
                  vpc_obj = sibling
                end
              end
            else
              vpc_obj = sib_by_name
              MU.log "Found exact VPC match for #{self}", loglevel, details: sib_by_name.to_s
            end
          else
            MU.log "No shortcuts available to fetch VPC for #{self}", loglevel, details: vpc_block
          end

          if !vpc_obj and !vpc_block["name"].nil? and
              @dependencies.has_key?("vpc") and
              @dependencies["vpc"].has_key?(vpc_block["name"])
            MU.log "Grabbing VPC I see in @dependencies['vpc']['#{vpc_block["name"]}'] for #{self}", loglevel, details: vpc_block
            vpc_obj = @dependencies["vpc"][vpc_block["name"]]
          elsif !vpc_obj
            tag_key, tag_value = vpc_block['tag'].split(/=/, 2) if !vpc_block['tag'].nil?
            if !vpc_block.has_key?("id") and
                !vpc_block.has_key?("deploy_id") and !@deploy.nil?
              vpc_block["deploy_id"] = @deploy.deploy_id
            end
            MU.log "Doing findStray for VPC for #{self}", loglevel, details: vpc_block
            vpcs = MU::MommaCat.findStray(
              @config['cloud'],
              "vpc",
              deploy_id: vpc_block["deploy_id"],
              cloud_id: vpc_block["id"],
              name: vpc_block["name"],
              tag_key: tag_key,
              tag_value: tag_value,
              habitats: habitats_arg,
              region: vpc_block["region"],
              calling_deploy: @deploy,
              credentials: vpc_block["credentials"],
              dummy_ok: true,
              debug: debug
            )
            vpc_obj = vpcs.first if !vpcs.nil? and vpcs.size > 0
          end
          if vpc_obj and vpc_obj.config and vpc_obj.config['bastion'] and
             vpc_obj.config['bastion'].to_h['name'] != @config['name']
            refhash = vpc_obj.config['bastion'].to_h
            refhash['deploy_id'] ||= vpc_obj.deploy.deploy_id
            natref = MU::Config::Ref.get(refhash)
            if natref and natref.kitten(vpc_obj.deploy)
              nat_obj = natref.kitten(vpc_obj.deploy)
            end
          end
          if nat_obj.nil? and !vpc_obj.nil? and (
            vpc_block.has_key?("nat_host_id") or
            vpc_block.has_key?("nat_host_tag") or
            vpc_block.has_key?("nat_host_ip") or
            vpc_block.has_key?("nat_host_name")
          )

            nat_tag_key, nat_tag_value = vpc_block['nat_host_tag'].split(/=/, 2) if !vpc_block['nat_host_tag'].nil?

            nat_obj = vpc_obj.findBastion(
              nat_name: vpc_block['nat_host_name'],
              nat_cloud_id: vpc_block['nat_host_id'],
              nat_tag_key: nat_tag_key,
              nat_tag_value: nat_tag_value,
              nat_ip: vpc_block['nat_host_ip']
            )

            if naa_obj.nil?
              if !vpc_obj.cloud_desc.nil?
                nat_obj = vpc_obj.findNat(
                  nat_cloud_id: vpc_block['nat_host_id'],
                  nat_filter_key: "vpc-id",
                  region: vpc_block["region"],
                  nat_filter_value: vpc_obj.cloud_id,
                  credentials: vpc_block['credentials']
                )
              else
                nat_obj = vpc_obj.findNat(
                  nat_cloud_id: vpc_block['nat_host_id'],
                  region: vpc_block["region"],
                  credentials: vpc_block['credentials']
                )
              end
            end
          end
          if vpc_obj.nil? and vpc_block
            feck = MU::Config::Ref.get(vpc_block)
            feck.kitten(@deploy, debug: true)
            pp feck
            raise MuError.new "#{self.class.cfg_name} #{@config['name']} failed to locate its VPC", details: vpc_block
          end

          # Google accounts usually have a useful default VPC we can use
          if vpc_obj.nil? and @project_id and @cloud == "Google" and
             self.class.can_live_in_vpc
            MU.log "Seeing about default VPC for #{self}", MU::NOTICE
            vpcs = MU::MommaCat.findStray(
              "Google",
              "vpc",
              cloud_id: "default",
              habitats: [@project_id],
              credentials: vpc_block['credentials'],
              dummy_ok: true,
              debug: debug
            )
            vpc_obj = vpcs.first if !vpcs.nil? and vpcs.size > 0
          end

          [vpc_obj, nat_obj]
        end

        # Using the automatically-defined +@vpc+ from {dependencies} in
        # conjunction with our config, return our configured subnets.
        # @return [Array<MU::Cloud::VPC::Subnet>]
        def mySubnets(vpc = @vpc, vpc_block = @config["vpc"])
          dependencies
          vpc ||= @vpc # in case dependencies worked it out for us
          if !vpc or !vpc_block
            return nil
          end

          if vpc_block["subnet_id"] or vpc_block["subnet_name"]
            vpc_block["subnets"] ||= []
            subnet_block = {}
            subnet_block["subnet_id"] = vpc_block["subnet_id"] if vpc_block["subnet_id"]
            subnet_block["subnet_name"] = vpc_block["subnet_name"] if vpc_block["subnet_name"]
            vpc_block["subnets"] << subnet_block
            vpc_block["subnets"].uniq!
          end

          if (!vpc_block["subnets"] or vpc_block["subnets"].empty?) and
             !vpc_block["subnet_id"]
            return vpc.subnets
          end

          subnets = []
          vpc_block["subnets"].each { |subnet|
            subnet_obj = vpc.getSubnet(cloud_id: subnet["subnet_id"].to_s, name: subnet["subnet_name"].to_s)
            raise MuError.new "Couldn't find a live subnet for #{self} matching #{subnet} in #{vpc}", details: vpc.subnets.map { |s| s.name }.join(",") if subnet_obj.nil?
            subnets << subnet_obj
          }

          subnets
        end

        # @return [Array<MU::Cloud::FirewallRule>]
        def myFirewallRules
          dependencies

          rules = []
          if @dependencies.has_key?("firewall_rule")
            rules = @dependencies['firewall_rule'].values
          end
# XXX what other ways are these specified?

          rules
        end

        # If applicable, allow this resource's NAT host blanket access via
        # rules in its associated +admin+ firewall rule set.
        def allowBastionAccess
          return nil if !@nat or !@nat.is_a?(MU::Cloud::Server)

          myFirewallRules.each { |acl|
            if acl.config["admin"]
              acl.addRule(@nat.listIPs, proto: "tcp")
              acl.addRule(@nat.listIPs, proto: "udp")
              acl.addRule(@nat.listIPs, proto: "icmp")
            end
          }
        end

        # A hook that is always called just before each instance method is
        # invoked, so that we can ensure that repetitive setup tasks (like
        # resolving +:resource_group+ for Azure resources) have always been
        # done.
        def resourceInitHook
          @cloud ||= cloud
          if @cloudparentclass.respond_to?(:resourceInitHook)
            @cloudparentclass.resourceInitHook(@cloudobj, @deploy)
          end
        end

        if File.exist?(MU.myRoot+"/modules/mu/cloud/#{cfg_name}.rb")
          require "mu/cloud/#{cfg_name}"
        end

        # Wrap the instance methods that this cloud resource type has to
        # implement.
        MU::Cloud.resource_types[name.to_sym][:instance].each { |method|

          define_method method do |*args|
            return nil if @cloudobj.nil?
            MU.log "Invoking #{@cloudobj}.#{method}", MU::DEBUG

            # Go ahead and guarantee that we can't accidentally trigger these
            # methods recursively.
            @method_semaphore.synchronize {
              # We're looking for recursion, not contention, so ignore some
              # obviously harmless things.
              if @method_locks.has_key?(method) and method != :findBastion and method != :cloud_id
                MU.log "Double-call to cloud method #{method} for #{self}", MU::DEBUG, details: caller + ["competing call stack:"] + @method_locks[method]
              end
              @method_locks[method] = caller
            }

            # Make sure the describe() caches are fresh
            @cloudobj.describe if method != :describe

            # Don't run through dependencies on simple attr_reader lookups
            if ![:dependencies, :cloud_id, :config, :mu_name, :active?].include?(method)
              @cloudobj.dependencies
            end

            retval = nil
            if !args.nil?
              if args.is_a?(Hash)
                retval = @cloudobj.method(method).call(**args)
              elsif args.is_a?(Array) 
                if args.size == 1 and args.first.is_a?(Hash)
                  retval = @cloudobj.method(method).call(**args.first)
                else
                  retval = @cloudobj.method(method).call(*args)
                end
              else
                retval = @cloudobj.method(method).call(args)
              end
            else
              retval = @cloudobj.method(method).call
            end
            if [:create, :groom, :postBoot, :toKitten].include?(method) and
               (!@destroyed and !@cloudobj.destroyed)
              deploydata = @cloudobj.method(:notify).call
              @deploydata ||= deploydata # XXX I don't remember why we're not just doing this from the get-go; maybe because we prefer some mangling occurring in @deploy.notify?
              if deploydata.nil? or !deploydata.is_a?(Hash)
                MU.log "#{self} notify method did not return a Hash of deployment data, attempting to fill in with cloud descriptor #{@cloudobj.cloud_id}", MU::WARN
                deploydata = MU.structToHash(@cloudobj.cloud_desc)
                raise MuError, "Failed to collect metadata about #{self}" if deploydata.nil?
              end
              deploydata['cloud_id'] ||= @cloudobj.cloud_id if !@cloudobj.cloud_id.nil?
              deploydata['mu_name'] = @cloudobj.mu_name if !@cloudobj.mu_name.nil?
              deploydata['nodename'] = @cloudobj.mu_name if !@cloudobj.mu_name.nil?
              deploydata.delete("#MUOBJECT")
              @deploy.notify(self.class.cfg_plural, @config['name'], deploydata, triggering_node: @cloudobj, delayed_save: @delayed_save) if !@deploy.nil?
            elsif method == :notify
              if retval.nil?
                MU.log self.to_s+" didn't return any metadata from notify", MU::WARN, details: @cloudobj.cloud_desc
              else
                retval['cloud_id'] = @cloudobj.cloud_id.to_s if !@cloudobj.cloud_id.nil?
                retval['mu_name'] = @cloudobj.mu_name if !@cloudobj.mu_name.nil?
                @deploy.notify(self.class.cfg_plural, @config['name'], retval, triggering_node: @cloudobj, delayed_save: @delayed_save) if !@deploy.nil?
              end
            end
            @method_semaphore.synchronize {
              @method_locks.delete(method)
            }

            @deploydata = @cloudobj.deploydata
            @config = MU::Config.manxify(@cloudobj.config)
            retval
          end
        } # end instance method list


      } # end dynamic class generation block
    } # end resource type iteration

    require 'mu/cloud/winrm_sessions'
    require 'mu/cloud/ssh_sessions'

  end

end
