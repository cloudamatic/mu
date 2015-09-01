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
require 'simple-password-gen'

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

    # @param environment [String]: The environment name for this application stack (e.g. "dev" or "prod")
    # @param verbosity [Boolean]: Toggles debug-level log verbosity
    # @param webify_logs [Boolean]: Toggles web-friendly log output
    # @param nocleanup [Boolean]: Toggles whether to skip cleanup of resources if this deployment fails.
    # @param stack_conf [Hash]: A full application stack configuration parsed by {MU::Config}
    def initialize(environment,
                   verbosity: nil,
                   webify_logs: nil,
                   nocleanup: nil,
                   stack_conf: nil)
      MU.setVar("verbose", verbosity)
      @webify_logs = webify_logs
      @nocleanup = nocleanup
      MU.setLogging(verbosity, webify_logs)

      if stack_conf.nil? or !stack_conf.is_a?(Hash)
        raise MuError, "Deploy objects require a stack_conf hash"
      end

      @my_threads = Array.new
      @last_sigterm = 0
      @dependency_threads = {}
      @dependency_semaphore = Mutex.new

      @main_config = stack_conf
      @admins = stack_conf["admins"]

      @environment = environment
      time=Time.new
      @appname = stack_conf["appname"]
      @timestamp = time.strftime("%Y%m%d%H").to_s;
      @timestamp.freeze
      @timestart = time.to_s;
      @timestart.freeze


      retries = 0
      begin
        raise MuError, "Failed to allocate an unused MU-ID after #{retries} tries!" if retries > 70
        seedsize = 1 + (retries/10).abs
        seed = Password.pronounceable(8).slice(0..seedsize)
        deploy_id = @appname.upcase + "-" + @environment.upcase + "-" + @timestamp + "-" + seed.upcase
      end while MU::MommaCat.deploy_exists?(deploy_id) or seed == "mu"
      MU.setVar("deploy_id", deploy_id)
      MU.setVar("appname", @appname.upcase)
      MU.setVar("environment", @environment.upcase)
      MU.setVar("timestamp", @timestamp)
      MU.setVar("seed", seed)
      MU.setVar("handle", MU::MommaCat.generateHandle(seed))

      MU.log "Deployment id: #{MU.appname} \"#{MU.handle}\" (#{MU.deploy_id})"

      # Instance variables that are effectively class variables
      @my_instance_id = MU::Cloud::AWS.getAWSMetaData("instance-id")
      @my_az = MU::Cloud::AWS.getAWSMetaData("placement/availability-zone")

      @fromName ='chef-server';

      MU::Cloud.resource_types.each { |cloudclass, data|
        if !@main_config[data[:cfg_plural]].nil? and @main_config[data[:cfg_plural]].size > 0
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
        if !die and !MU::MommaCat.locks.nil? and MU::MommaCat.locks.size > 0
          puts "------------------------------"
          puts "Thread and lock debugging data"
          puts "------------------------------"
          puts "Open flock() locks:"
          pp MU::MommaCat.locks
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
          raise "Terminated by user"
        end
        @last_sigterm = Time.now.to_i
      end

      begin
        metadata = {
            "appname" => @appname,
            "timestamp" => @timestamp,
            "environment" => @environment,
            "seed" => MU.seed,
            "deployment_start_time" => @timestart,
            "chef_user" => MU.chef_user
        }
        mommacat = MU::MommaCat.new(
            MU.deploy_id,
            create: true,
            config: @main_config,
            verbose: MU.verbose,
            environment: @environment,
            nocleanup: @nocleanup,
            set_context_to_me: true,
            deployment_data: metadata,
            mu_user: MU.mu_user
        )
        MU.setVar("mommacat", mommacat)

        @admins.each { |admin|
          mommacat.notify("admins", admin['name'], admin)
        }

        @deploy_semaphore = Mutex.new

        parent_thread_id = Thread.current.object_id

        # Kick off threads to create each of our new servers.
        @my_threads << Thread.new {
          MU.dupGlobals(parent_thread_id)
          Thread.current.thread_variable_set("name", "mu_create_container")
          Thread.abort_on_exception = true
          MU::Cloud.resource_types.each { |cloudclass, data|
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
          Thread.abort_on_exception = true
          MU::Cloud.resource_types.each { |cloudclass, data|
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
      rescue Exception => e

        @my_threads.each do |t|
          if t.object_id != Thread.current.object_id and t.thread_variable_get("name") != "main_thread"
            MU::MommaCat.unlockAll
            t.kill
          end
        end

        # If it was a regular old exit, we assume something deeper in already
        # handled logging and cleanup for us, and just quietly go away.
        if e.class.to_s != "SystemExit"
          MU.log e.inspect, MU::ERR, details: e.backtrace
          if !@nocleanup
            MU::Cleanup.run(MU.deploy_id, false, true, mommacat: mommacat)
          end
          MU.log e.inspect, MU::ERR
        end

        exit 1
      end
      if !MU.mommacat.deployment['servers'].nil? and MU.mommacat.deployment['servers'].keys.size > 0
        # XXX some kind of filter (obey sync_siblings on nodes' configs)
        MU.mommacat.syncLitter(MU.mommacat.deployment['servers'].keys)
      end
      deployment = MU.mommacat.deployment
      deployment["deployment_end_time"]=Time.new.strftime("%I:%M %p on %A, %b %d, %Y").to_s;
      MU::Cloud::AWS.openFirewallForClients # XXX only invoke if we're in AWS
      MU::MommaCat.getLitter(MU.deploy_id, use_cache: false)
      MU::MommaCat.syncMonitoringConfig

      # Send notifications
      sendMail
      MU.log "Deployment complete", details: deployment

    end

    private

    def sendMail()

      $str = JSON.pretty_generate(MU.mommacat.deployment)

      admin_addrs = @admins.map { |admin|
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
#				MU.log "Got nil service list in setThreadDependencies for called from #{caller_locations(1,1)[0].label}", MU::DEBUG
        return
      end

      services.each { |resource|
        res_type = resource["#MU_CLOUDCLASS"].cfg_name
        name = res_type+"_"+resource["name"]

        # All resources wait to "groom" until after their own "create" thread
        # finishes, and also on the main thread which spawns them (so all
        # siblings will exist for dependency checking before we start).
        @dependency_threads["#{name}_create"]=["mu_create_container"]
        @dependency_threads["#{name}_groom"]=["#{name}_create", "mu_groom_container"]

        MU.log "Setting dependencies for #{name}", MU::DEBUG
        if resource["dependencies"] != nil then
          resource["dependencies"].each { |dependency|
            parent_class = nil
            MU::Cloud.resource_types.each_pair { |name, attrs|
              if attrs[:cfg_name] == dependency['type']
                parent_class = Object.const_get("MU").const_get("Cloud").const_get(name)
                break
              end
            }

            parent_type = parent_class.cfg_name
            parent = parent_type+"_"+dependency["name"]+"_create"
            addDependentThread(parent, "#{name}_groom")
            if (parent_class.deps_wait_on_my_creation and parent_type != res_type) or resource["#MU_CLOUDCLASS"].waits_on_parent_completion or dependency['phase'] == "create"
              addDependentThread(parent, "#{name}_create")
            end
            if (dependency['phase'] == "groom" or resource["#MU_CLOUDCLASS"].waits_on_parent_completion) and parent_class.instance_methods(false).include?(:groom)
              parent = parent_type+"_"+dependency["name"]+"_groom"
              addDependentThread(parent, "#{name}_groom")
              if (parent_class.deps_wait_on_my_creation and parent_type != res_type) or resource["#MU_CLOUDCLASS"].waits_on_parent_completion or dependency['phase'] == "groom"
                addDependentThread(parent, "#{name}_create")
              end
            end
          }
        end
      }
    end

    #########################################################################
    # Kick off a thread to create a resource.
    #########################################################################
    def createResources(services, mode="create")
      return if services.nil?

      parent_thread_id = Thread.current.object_id
      services.each do |service|
        @my_threads << Thread.new(service) { |myservice|
          MU.dupGlobals(parent_thread_id)
          threadname = service["#MU_CLOUDCLASS"].cfg_name+"_"+myservice["name"]+"_#{mode}"
          Thread.current.thread_variable_set("name", threadname)
          Thread.abort_on_exception = true
          waitOnThreadDependencies(threadname)

          if service["#MU_CLOUDCLASS"].instance_methods(false).include?(:groom)
            if mode == "create"
              MU::MommaCat.lock(service["#MU_CLOUDCLASS"].cfg_name+"_"+myservice["name"]+"-dependencies")
            elsif mode == "groom"
              MU::MommaCat.unlock(service["#MU_CLOUDCLASS"].cfg_name+"_"+myservice["name"]+"-dependencies")
            end
          end

          MU.log "Launching thread #{threadname}", MU::DEBUG
          begin
            if service['#MUOBJECT'].nil?
              service['#MUOBJECT'] = service["#MU_CLOUDCLASS"].new(mommacat: MU.mommacat, kitten_cfg: myservice)
            end
          rescue Exception => e
            MU::MommaCat.unlockAll
            raise MuError, "Error instantiating object from #{service["#MU_CLOUDCLASS"]} (#{e.inspect})", e.backtrace
          end
          begin
            run_this_method = service['#MUOBJECT'].method(mode)
          rescue Exception => e
            MU::MommaCat.unlockAll
            raise MuError, "Error invoking #{service["#MU_CLOUDCLASS"]}.#{mode} for #{myservice['name']} (#{e.inspect})", e.backtrace
          end
          begin
            MU.log "Running #{service['#MUOBJECT']}.#{mode}", MU::DEBUG
            myservice = run_this_method.call
          rescue Exception => e
            MU.log e.inspect, MU::ERR, details: e.backtrace
            MU::MommaCat.unlockAll
            @my_threads.each do |t|
              if t.object_id != Thread.current.object_id and t.thread_variable_get("name") != "main_thread"
                t.kill
              end
            end
            if !@nocleanup
              MU::Cleanup.run(MU.deploy_id, false, true)
            end
            raise MuError, e.inspect, e.backtrace
          end
        }
      end
    end

  end #class
end #module
