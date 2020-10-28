# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
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

require "net/http"
require "net/smtp"
require 'json'
require 'rexml/document'

module MU
  # The Deploy class is the main interface for resource creation. It is
  # typically invoked from the *mu-deploy* utility. It consumes a configuration
  # parsed by {MU::Config} and generates cloud artifacts accordingly, ordering
  # them per their dependencies and handing off to OS management tools (e.g.
  # Chef) for application-level orchestration.
  class Deploy

    Thread.current.thread_variable_set("name", "main_thread");

    # These also exist as instance variables, but we end up needing versions of
    # them in static contexts too.
    @deploy_semaphore = Mutex.new

    # The name of the application which we're building.
    attr_reader :appname

    # The timestamp at which this deployment was begun
    attr_reader :timestamp

    # The environment into which we're deploying
    attr_reader :environment

    # The cloud provider's account identifier
    attr_reader :account_number

    # This flag indicates that cleanup operations should be skipped if a
    # failure occurs.
    attr_reader :nocleanup

    # We just pass this flag to MommaCat, telling it not to save any metadata.
    attr_reader :no_artifacts

    # The deployment object we create for our stack
    attr_reader :mommacat

    # Indicates whether we are updating an existing deployment, as opposed to
    # creating a new one.
    attr_reader :updating

    # @param environment [String]: The environment name for this application stack (e.g. "dev" or "prod")
    # @param verbosity [Integer]: Debug level for MU.log output
    # @param webify_logs [Boolean]: Toggles web-friendly log output
    # @param nocleanup [Boolean]: Toggles whether to skip cleanup of resources if this deployment fails.
    # @param cloudformation_path [String]: If we're outputting CloudFormation, here's where to put it
    # @param force_cloudformation [Boolean]: Output CloudFormation regardless of what cloud resources target
    # @param reraise_thread [Thread]: Raise any major exceptions to this thread
    # @param stack_conf [Hash]: A full application stack configuration parsed by {MU::Config}
    # @param no_artifacts [Boolean]: Do not save deploy metadata
    # @param deploy_id [String]: Reload and re-process an existing deploy
    def initialize(environment,
                   verbosity: MU::Logger::NORMAL,
                   color: true,
                   webify_logs: false,
                   nocleanup: false,
                   cloudformation_path: nil,
                   force_cloudformation: false,
                   reraise_thread: nil,
                   stack_conf: nil,
                   no_artifacts: false,
                   deploy_id: nil,
                   deploy_obj: nil)
      MU.setVar("verbosity", verbosity)
      MU.setVar("color", color)
      @webify_logs = webify_logs
      @verbosity = verbosity
      @color = color
      @nocleanup = nocleanup
      @no_artifacts = no_artifacts
      @reraise_thread = reraise_thread
      MU.setLogging(verbosity, webify_logs, STDOUT, color)

      MU::Cloud::CloudFormation.emitCloudFormation(set: force_cloudformation)
      @cloudformation_output = cloudformation_path

      if stack_conf.nil? or !stack_conf.is_a?(Hash)
        raise MuError, "Deploy objects require a stack_conf hash"
      end

      @my_threads = Array.new
      @last_sigterm = 0
      @dependency_threads = {}
      @dependency_semaphore = Mutex.new

      @main_config = stack_conf
      @original_config = Marshal.load(Marshal.dump(MU.structToHash(stack_conf.dup)))
      @original_config.freeze
      @admins = stack_conf["admins"]
      @mommacat = deploy_obj

      if deploy_id
        @mommacat ||= MU::MommaCat.new(deploy_id)
        @updating = true
      else
        @environment = environment
        @updating = false
        time=Time.new
        @appname = stack_conf["appname"]
        @timestamp = time.strftime("%Y%m%d%H").to_s
        @timestamp.freeze
        @timestart = time.to_s;
        @timestart.freeze

        retries = 0
        begin
          raise MuError, "Failed to allocate an unused MU-ID after #{retries} tries!" if retries > 70
          seedsize = 1 + (retries/10).abs
          seed = (0...seedsize+1).map { ('a'..'z').to_a[rand(26)] }.join
          deploy_id = @appname.upcase + "-" + @environment.upcase + "-" + @timestamp + "-" + seed.upcase
        end while MU::MommaCat.deploy_exists?(deploy_id) or seed == "mu"
        MU.setVar("deploy_id", deploy_id)
        MU.setVar("appname", @appname.upcase)
        MU.setVar("environment", @environment.upcase)
        MU.setVar("timestamp", @timestamp)
        MU.setVar("mommacat", @mommacat)
        MU.setVar("seed", seed)
        MU.setVar("handle", MU::MommaCat.generateHandle(seed))

        MU.log "Deployment id: #{MU.appname} \"#{MU.handle}\" (#{MU.deploy_id})"
      end

      @fromName = MU.muCfg['mu_admin_email']

      MU::Cloud.resource_types.values.each { |data|
        if !@main_config[data[:cfg_plural]].nil? and @main_config[data[:cfg_plural]].size > 0
          @main_config[data[:cfg_plural]].each { |resource|
            if force_cloudformation
              if resource['cloud'] == "AWS"
                resource['cloud'] = "CloudFormation"
                if resource.has_key?("vpc") and resource["vpc"].is_a?(Hash)
                  resource["vpc"]['cloud'] = "CloudFormation"
                elsif resource.has_key?("vpcs") and resource["vpcs"].is_a?(Array)
                  resource['vpcs'].each { |v| v['cloud'] = "CloudFormation" }
                end
              end
            end
          }
          _shortclass, _cfg_name, _cfg_plural, classname = MU::Cloud.getResourceNames(data[:cfg_plural])
          @main_config[data[:cfg_plural]].each { |resource|
            resource["#MU_CLOUDCLASS"] = classname
#            resource["#MU_CLOUDCLASS"] = MU::Cloud.resourceClass(resource['cloud'], data[:cfg_plural])
          }
          setThreadDependencies(@main_config[data[:cfg_plural]])
        end
      }
    end


    # Activate this deployment, instantiating all resources, orchestrating them,
    # and saving metadata about them.
    def run
      Signal.trap("INT") do
        # Don't use MU.log in here, it does a synchronize {} and that ain't
        # legal inside a trap.
        die = true if (Time.now.to_i - @last_sigterm) < 5
        if !die and !MU::MommaCat.trapSafeLocks.nil? and MU::MommaCat.trapSafeLocks.size > 0
          puts "------------------------------"
          puts "Thread and lock debugging data"
          puts "------------------------------"
          puts "Open flock() locks:"
          pp MU::MommaCat.trapSafeLocks
          puts "------------------------------"
        end
        Thread.list.each do |t|
          next if !t.status # skip threads that've been cleanly terminated
          if !die
            thread_name = t.thread_variable_get("name")
            puts "Thread #{thread_name} (#{t.object_id}): #{t.inspect} #{t.status}"
            t.thread_variables.each { |tvar|
              puts "#{tvar} = #{t.thread_variable_get(tvar)}"
            }
            pp t.backtrace
            if !@dependency_threads[thread_name].nil?
              puts ""
              puts "Waiting on #{@dependency_threads[thread_name]}"
              Thread.list.each { |parent|
                parent_name = parent.thread_variable_get("name")
                if @dependency_threads[thread_name].include?(parent_name)
                  puts "\t#{parent_name} (#{parent.object_id}): #{parent.inspect} #{parent.status}"
                  parent.thread_variables.each { |tvar|
                    puts "\t#{tvar} = #{parent.thread_variable_get(tvar)}"
                  }
                end
              }
            end
            puts "------------------------------"
            t.run
          end
        end
        if !die
          puts "Received SIGINT, hit ctrl-C again within five seconds to kill this deployment."
        else
          Thread.list.each do |t|
            next if !t.status
            if t.object_id != Thread.current.object_id and
               t.thread_variable_get("name") != "main_thread" and 
               t.thread_variable_get("owned_by_mu")
              t.kill
            end
          end

          if @main_thread
            @main_thread.raise "Terminated by user"
          else
            raise "Terminated by user"
          end
        end
        @last_sigterm = Time.now.to_i
      end

      begin
        @main_thread = Thread.current
        if !@mommacat
          metadata = {
            "appname" => @appname,
            "timestamp" => @timestamp,
            "environment" => @environment,
            "seed" => MU.seed,
            "deployment_start_time" => @timestart,
            "chef_user" => MU.chef_user,
            "mu_user" => MU.mu_user
          }
          @mommacat = MU::MommaCat.new(
            MU.deploy_id,
            create: true,
            config: @main_config,
            environment: @environment,
            nocleanup: @nocleanup,
            no_artifacts: @no_artifacts,
            set_context_to_me: true,
            deployment_data: metadata,
            mu_user: MU.mu_user
          )
          MU.setVar("mommacat", @mommacat)
        end

        @admins.each { |admin|
          @mommacat.notify("admins", admin['name'], admin)
        }
        if @mommacat.numKittens(types: ["Server", "ServerPool"]) > 0
          MU::MommaCat.start
        end

        @deploy_semaphore = Mutex.new
        parent_thread_id = Thread.current.object_id

        # Run cloud provider-specific deploy meta-artifact creation (ssh keys,
        # resource groups, etc)
        @mommacat.cloudsUsed.each { |cloud|
          cloudclass = MU::Cloud.cloudClass(cloud)
          cloudclass.initDeploy(@mommacat)
        }
        @mommacat.writeDeploySecret

        # Kick off threads to create each of our new servers.
        @my_threads << Thread.new {
          MU.dupGlobals(parent_thread_id)
          Thread.current.thread_variable_set("name", "mu_create_container")
#          Thread.abort_on_exception = false
          MU::Cloud.resource_types.values.each { |data|
            if !@main_config[data[:cfg_plural]].nil? and
                @main_config[data[:cfg_plural]].size > 0 and
                data[:instance].include?(:create)
              createResources(@main_config[data[:cfg_plural]], "create")
            end
          }
        }

        # Some resources have a "groom" phase too
        @my_threads << Thread.new {
          MU.dupGlobals(parent_thread_id)
          Thread.current.thread_variable_set("name", "mu_groom_container")
#          Thread.abort_on_exception = false
          MU::Cloud.resource_types.values.each { |data|
            if !@main_config[data[:cfg_plural]].nil? and
                @main_config[data[:cfg_plural]].size > 0 and
                data[:instance].include?(:groom)
              createResources(@main_config[data[:cfg_plural]], "groom")
            end
          }
        }

        # Poke child threads to make sure they're awake
        @my_threads.each do |t|
          t.run if t.alive?
        end

        sleep 5

        # Reap child threads.
        @my_threads.each do |t|
          t.join
        end

        @mommacat.save!

        # XXX Functions have a special behavior where we re-invoke their groom
        # methods one more time at the end, so we can guarantee their
        # environments are fully populated with all sibling resource idents
        # regardless of dependency order. This is, obviously, a disgusting
        # hack, and we should revisit our dependency language in the next big
        # release.
        if !@main_config["functions"].nil? and
            @main_config["functions"].size > 0
          createResources(@main_config["functions"], "groom")
        end

      rescue StandardError => e
        MU.log e.class.name, MU::ERR, details: caller

        @my_threads.each do |t|
          if t.object_id != Thread.current.object_id and
             t.thread_variable_get("name") != "main_thread" and
             t.object_id != parent_thread_id
            MU::MommaCat.unlockAll
            t.kill
          end
        end

        # If it was a regular old exit, we assume something deeper in already
        # handled logging and cleanup for us, and just quietly go away.
        if e.class.to_s != "SystemExit"
          MU.log e.class.name+": "+e.message, MU::ERR, details: e.backtrace if @verbosity != MU::Logger::SILENT
          if !@nocleanup

            # Wrap this in a thread to protect the Azure SDK from imploding
            # because it mistakenly thinks there's a deadlock.
            cleanup_thread = Thread.new {
              MU.dupGlobals(parent_thread_id)
              Thread.abort_on_exception = false
              MU::Cleanup.run(MU.deploy_id, skipsnapshots: true, verbosity: @verbosity, mommacat: @mommacat)
            }
            cleanup_thread.join
            @nocleanup = true # so we don't run this again later
          end
        end


        @reraise_thread.raise MuError, e.inspect, e.backtrace if @reraise_thread
        Thread.current.exit
      ensure
        if @mommacat and @mommacat.numKittens(clouds: ["CloudFormation"]) > 0
          MU::Cloud::CloudFormation.writeCloudFormationTemplate(tails: MU::Config.tails, config: @main_config, path: @cloudformation_output, mommacat: @mommacat)
          # If we didn't build anything besides CloudFormation, purge useless
          # metadata.
          if @mommacat.numKittens(clouds: ["CloudFormation"], negate: true) == 0
            Thread.list.each do |t|
              if t.object_id != Thread.current.object_id and t.thread_variable_get("name") != "main_thread" and t.object_id != parent_thread_id
                t.kill
              end
            end
            MU::Cleanup.run(MU.deploy_id, skipcloud: true, verbosity: MU::Logger::SILENT, mommacat: @mommacat)
            return
          end
        end
      end
      if @mommacat.numKittens(clouds: ["CloudFormation"], negate: true) > 0
        if !@mommacat.deployment['servers'].nil? and @mommacat.deployment['servers'].keys.size > 0
          # XXX some kind of filter (obey sync_siblings on nodes' configs)
          @mommacat.syncLitter(@mommacat.deployment['servers'].keys)
        end
        deployment = @mommacat.deployment
        deployment["deployment_end_time"]=Time.new.strftime("%I:%M %p on %A, %b %d, %Y").to_s;
        if MU.myCloud == "AWS" 
          MU::Cloud::AWS.openFirewallForClients # XXX add the other clouds, or abstract
        end
#        MU::MommaCat.getLitter(MU.deploy_id, use_cache: false)
        if @mommacat.numKittens(types: ["Server", "ServerPool"]) > 0
#          MU::MommaCat.syncMonitoringConfig # TODO only invoke if Server or ServerPool actually changed something when @updating
        end
      end


      # Send notifications
      sendMail
      if @mommacat.numKittens(clouds: ["AWS"]) > 0
        MU.log "Generating cost calculation URL for all Amazon Web Services resources."
        MU.setLogging(MU::Logger::SILENT)

        @environment ||= "dev"

        begin
        Thread.abort_on_exception = false
        t = Thread.new {
          Thread.abort_on_exception = true

          # I do not understand why this is necessary, but here we are.
          Thread.handle_interrupt(MU::Cloud::MuCloudResourceNotImplemented => :never) {
            begin
              Thread.handle_interrupt(MU::Cloud::MuCloudResourceNotImplemented => :immediate) {
                MU.log "Cost calculator not available for this stack, as it uses a resource not implemented in Mu's CloudFormation layer.", MU::DEBUG, verbosity: MU::Logger::NORMAL
                Thread.current.exit
              }
            ensure
            end
          }
          begin
            MU.setVar("deploy_id", nil) # make sure we won't ever accidentally blow away the parent deploy
            cost_dummy_deploy = MU::Deploy.new(
              @environment.dup,
              verbosity: MU::Logger::SILENT,
              force_cloudformation: true,
              cloudformation_path: "/dev/null",
              nocleanup: false, # make sure we clean up the cost allocation deploy
              stack_conf: @original_config,
              reraise_thread: @main_thread,
              no_artifacts: true
            )
            cost_dummy_deploy.run
          rescue MU::Cloud::MuCloudFlagNotImplemented, MU::Cloud::MuCloudResourceNotImplemented, MU::MuError => e
            # This doesn't seem to get caught and I don't know why and I don't care
#            MU.log "Failed to generate AWS cost-calculation URL. Skipping.", MU::WARN, details: "Deployment uses a feature not available in CloudFormation layer.", verbosity: MU::Logger::NORMAL
          end
        }

        t.join
        rescue MU::Cloud::MuCloudFlagNotImplemented, MU::Cloud::MuCloudResourceNotImplemented => e
          # already handled in the thread what did it
          MU.log "Failed to generate AWS cost-calculation URL. Skipping.", MU::WARN, details: "Deployment uses a feature not available in CloudFormation layer.", verbosity: MU::Logger::NORMAL
        ensure
          MU.setLogging(@verbosity)
          MU.log "Deployment #{MU.deploy_id} \"#{MU.handle}\" #{@updating ? "updated" : "complete"}", details: deployment, verbosity: @verbosity
        end
      else
        MU.log "Deployment #{MU.deploy_id} \"#{MU.handle}\" #{@updating ? "updated" : "complete"}", details: deployment, verbosity: @verbosity
      end


      if MU.summary.size > 0
        MU.summary.each { |msg|
          puts msg
        }
      end

      @mommacat.sendAdminSlack("Deploy #{MU.deploy_id} \"#{MU.handle}\" #{@updating ? "updated" : "complete"}", msg: MU.summary.join("\n"))
    end

    private

    def sendMail()

      $str = ""

      if MU.summary.size > 0
        MU.summary.each { |msg|
          $str += msg+"\n"
        }
      end

      $str += JSON.pretty_generate(@mommacat.deployment)

      admin_addrs = @admins.map { |admin|
        admin['name'] ||= ""
        admin['name']+" <"+admin['email']+">"
      }

      @admins.each do |data|

        message = <<MESSAGE_END
From: #{MU.handle} <#{@fromName}>
To:  #{admin_addrs.join(", ")}>
MIME-Version: 1.0
Content-type: text/html
Subject: Mu deployment #{MU.appname} \"#{MU.handle}\" (#{MU.deploy_id}) successfully completed
    
<br>
<pre>#{$str}</pre>
MESSAGE_END
        Net::SMTP.start('localhost') do |smtp|
          smtp.send_message message, @fromName, data["email"]
        end
      end
    end


    #########################################################################
    #########################################################################
    def waitOnThreadDependencies(dependent)
      if @dependency_threads[dependent].nil?
        MU.log "I don't see any dependencies for #{dependent}, moving on", MU::DEBUG
        return
      else
        MU.log "#{dependent} checking/waiting for parent threads...", MU::DEBUG, details: @dependency_threads[dependent]
      end

      retries = 0
      @dependency_threads[dependent].each { |dependent_thread|
        found = false
        @my_threads.each { |parent_thread|
          parent = parent_thread.thread_variable_get("name");
          if parent == dependent_thread
            found = true
            Thread.current.thread_variable_set("waiting_for", parent)
            parent_thread.join
            Thread.current.thread_variable_set("waiting_for", nil)
            MU.log "Thread #{parent} completed, thread #{dependent} proceeding", MU::DEBUG, details: @dependency_threads[dependent]
          end
        }
        # This vile hack brought to you by parent threads spawning after things
        # that depend on them. We're working around the slight race condition
        # that results. If the parent threads never show up, though, we have
        # a more serious problem.
        if !found and retries < 5
          sleep 5
          retries = retries + 1
          redo
        end
        if retries >= 5
          raise MuError, "#{dependent} tried five times but never saw #{dependent_thread} in live thread list...\n"+@my_threads.join("\t\n")
        end
      }
    end


    #########################################################################
    # Helper for setThreadDependencies
    #########################################################################
    def addDependentThread(parent, child)
      @dependency_semaphore.synchronize {
        @dependency_threads[child] = Array.new if !@dependency_threads[child]
        @dependency_threads[child] << parent
        MU.log "Thread #{child} will wait on #{parent}", MU::DEBUG, details: @dependency_threads[child]
      }
    end

    #########################################################################
    # Tell a service's deploy (and optionally, create) thread to wait on its
    # dependent service's create (and optionally, deploy) threads to finish.
    # XXX This nomenclature is unreasonably confusing.
    #########################################################################
    def setThreadDependencies(services)
      if services.nil? or services.size < 1
#        MU.log "Got nil service list in setThreadDependencies for called from #{caller_locations(1,1)[0].label}", MU::DEBUG
        return
      end

      services.each { |resource|
        if !resource["#MU_CLOUDCLASS"]
#          pp resource
        end
        res_type = resource["#MU_CLOUDCLASS"].cfg_name
        name = res_type+"_"+resource["name"]

        # All resources wait to "groom" until after their own "create" thread
        # finishes, and also on the main thread which spawns them (so all
        # siblings will exist for dependency checking before we start).
        @dependency_threads["#{name}_create"]=["mu_create_container"]
        @dependency_threads["#{name}_groom"]=["#{name}_create", "mu_groom_container"]

        MU.log "Setting dependencies for #{name}", MU::DEBUG, details: resource["dependencies"]
        if !resource["dependencies"].nil? then
          resource["dependencies"].each { |dependency|
            parent_class = MU::Cloud.loadBaseType(dependency['type'])

            parent_type = parent_class.cfg_name

            # our groom thread will always need to wait on our parent's create
            parent = parent_type+"_"+dependency["name"]+"_create"
            addDependentThread(parent, "#{name}_groom")

            # should our creation thread also wait on our parent's create?
            if !dependency["no_create_wait"] and
               (resource["#MU_CLOUDCLASS"].waits_on_parent_completion or
               dependency['phase'] == "create" or
               parent_class.deps_wait_on_my_creation)
              addDependentThread(parent, "#{name}_create")
            end


            # how about our groom thread waiting on our parents' grooms?
            if (dependency['phase'] == "groom" or resource["#MU_CLOUDCLASS"].waits_on_parent_completion) and parent_class.instance_methods(false).include?(:groom)
              parent = parent_type+"_"+dependency["name"]+"_groom"
              addDependentThread(parent, "#{name}_groom")
              if !dependency["no_create_wait"] and (
                   parent_class.deps_wait_on_my_creation or
                   resource["#MU_CLOUDCLASS"].waits_on_parent_completion or
                   dependency['phase'] == "groom"
                 )
                addDependentThread(parent, "#{name}_create")
              end
            end
          }
        end
        MU.log "Thread dependencies #{res_type}[#{name}]", MU::DEBUG, details: { "create" => @dependency_threads["#{name}_create"], "groom" => @dependency_threads["#{name}_groom"] }
        @dependency_threads["#{name}_groom"]=["#{name}_create", "mu_groom_container"]
      }
    end

    #########################################################################
    # Kick off a thread to create a resource.
    #########################################################################
    def createResources(services, mode="create")
      return if services.nil?

      parent_thread_id = Thread.current.object_id
      services.uniq!
      services.each do |service|
        begin
          @my_threads << Thread.new(service) { |myservice|
            MU.dupGlobals(parent_thread_id)
            threadname = myservice["#MU_CLOUDCLASS"].cfg_name+"_"+myservice["name"]+"_#{mode}"
            Thread.current.thread_variable_set("name", threadname)
            Thread.current.thread_variable_set("owned_by_mu", true)
#            Thread.abort_on_exception = false
            waitOnThreadDependencies(threadname)

            if myservice["#MU_CLOUDCLASS"].instance_methods(false).include?(:groom) and !myservice['dependencies'].nil? and !myservice['dependencies'].size == 0
              if mode == "create"
                MU::MommaCat.lock(myservice["#MU_CLOUDCLASS"].cfg_name+"_"+myservice["name"]+"-dependencies")
              elsif mode == "groom"
                MU::MommaCat.unlock(myservice["#MU_CLOUDCLASS"].cfg_name+"_"+myservice["name"]+"-dependencies")
              end
            end

            MU.log "Launching thread #{threadname}", MU::DEBUG
            begin
              if myservice['#MUOBJECT'].nil?
                if @mommacat
                  ext_obj = @mommacat.findLitterMate(type: myservice["#MU_CLOUDCLASS"].cfg_plural, name: myservice['name'], credentials: myservice['credentials'], created_only: true, return_all: false, ignore_missing: !@updating)
                  if @updating and ext_obj
                    ext_obj.config!(myservice)
                  end
                  myservice['#MUOBJECT'] = ext_obj
                end
                myservice['#MUOBJECT'] ||= myservice["#MU_CLOUDCLASS"].new(mommacat: @mommacat, kitten_cfg: myservice, delayed_save: @updating)
              end
            rescue RuntimeError => e
              # cloud implementations can iterate over these same hashes,
              # which can throw this if we catch them at the wrong moment.
              # here's your hacky workaround.
              if e.message.match(/can't add a new key into hash during iteration/)
                MU.log e.message+" in main deploy thread, probably transient", MU::DEBUG
                sleep 1
                retry
              else
                raise e
              end
            rescue StandardError => e
              MU::MommaCat.unlockAll
              @main_thread.raise MuError, "Error instantiating object from #{myservice["#MU_CLOUDCLASS"]} (#{e.inspect})", e.backtrace
              raise e
            end
            begin
              run_this_method = myservice['#MUOBJECT'].method(mode)
            rescue StandardError => e
              MU::MommaCat.unlockAll
              @main_thread.raise MuError, "Error invoking #{myservice["#MUOBJECT"].class.name}.#{mode} for #{myservice['name']} (#{e.inspect})", e.backtrace
              return
#              raise e
            end
            begin
              MU.log "Checking whether to run #{myservice['#MUOBJECT']}.#{mode} (updating: #{@updating})", MU::DEBUG
              if !@updating or mode != "create"
                myservice = run_this_method.call
              else

                # XXX experimental create behavior for --liveupdate flag, only works on a couple of resource types. Inserting new resources into an old deploy is tricky.
                opts = {}
                if myservice["#MU_CLOUDCLASS"].cfg_name == "loadbalancer"
                  opts['classic'] = myservice['classic'] ? true : false
                end

                found = MU::MommaCat.findStray(myservice['cloud'],
                                   myservice["#MU_CLOUDCLASS"].cfg_name,
                                   name: myservice['name'],
                                   credentials: myservice['credentials'],
                                   region: myservice['region'],
                                   deploy_id: @mommacat.deploy_id,
#                                 allow_multi: myservice["#MU_CLOUDCLASS"].has_multiple,
                                   tag_key: "MU-ID",
                                   tag_value: @mommacat.deploy_id,
                                   flags: opts,
                                   dummy_ok: false
                                  )

                found = found.delete_if { |x|
                  x.cloud_id.nil? and x.cloudobj.cloud_id.nil?
                }

                if found.size == 0
                  MU.log "#{myservice["#MU_CLOUDCLASS"].name} #{myservice['name']} not found, creating", MU::NOTICE
                  myservice = run_this_method.call
                else
                  real_descriptor = @mommacat.findLitterMate(type: myservice["#MU_CLOUDCLASS"].cfg_name, name: myservice['name'], created_only: true)

                  if !real_descriptor
                    MU.log "Invoking #{run_this_method.to_s} #{myservice['name']} #{myservice['name']}", MU::NOTICE
                    myservice = run_this_method.call
                  end
#MU.log "#{myservice["#MU_CLOUDCLASS"].cfg_name} #{myservice['name']}", MU::NOTICE
                end

              end
            rescue ThreadError => e
              MU.log "Waiting for threads to complete (#{e.message})", MU::NOTICE
              @my_threads.each do |thr|
                next if thr.object_id == Thread.current.object_id
                thr.join(0.1)
              end
              @my_threads.reject! { |thr| !thr.alive? }
              sleep 10+Random.rand(20)
              retry
            rescue StandardError => e
              MU.log e.inspect, MU::ERR, details: e.backtrace if @verbosity != MU::Logger::SILENT
              MU::MommaCat.unlockAll
              Thread.list.each do |t|
                if t.object_id != Thread.current.object_id and t.thread_variable_get("name") != "main_thread" and t.object_id != parent_thread_id and t.thread_variable_get("owned_by_mu")
                  t.kill
                end
              end
              if !@nocleanup
                MU::Cleanup.run(MU.deploy_id, verbosity: @verbosity, skipsnapshots: true)
                @nocleanup = true # so we don't run this again later
              end
              @main_thread.raise MuError, e.message, e.backtrace
            end
            MU.purgeGlobals
          }
        rescue ThreadError => e
          MU.log "Waiting for threads to complete (#{e.message})", MU::NOTICE
          @my_threads.each do |thr|
            next if thr.object_id == Thread.current.object_id
            thr.join(0.1)
          end
          @my_threads.reject! { |thr| !thr.alive? }
          sleep 10+Random.rand(20)
          retry
        end

      end

    end

  end #class
end #module
