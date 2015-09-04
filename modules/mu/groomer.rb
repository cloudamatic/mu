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

module MU
  # Plugins under this namespace serve as interfaces to configuration
  # management tools (Chef, Puppet, etc).
  class Groomer

    # An exception denoting a Groomer run that has failed
    class RunError < MuError;
    end

    # List of known/supported grooming agents (configuration management tools)
    def self.supportedGroomers
      ["Chef"]
    end

    # Instance methods that any Groomer plugin must implement
    def self.requiredMethods
      [:preClean, :bootstrap, :haveBootstrapped?, :run, :saveDeployData, :getSecret, :saveSecret, :deleteSecret]
    end

    # Class methods that any Groomer plugin must implement
    def self.requiredClassMethods
      [:getSecret, :cleanup, :saveSecret, :deleteSecret]
    end


    class Chef;
    end
    # @param groomer [String]: The grooming agent to load.
    # @return [Class]: The class object implementing this groomer agent
    def self.loadGroomer(groomer)
      if !File.size?(MU.myRoot+"/modules/mu/groomers/#{groomer.downcase}.rb")
        raise MuError, "Requested to use unsupported grooming agent #{groomer}"
      end
      require "mu/groomers/#{groomer.downcase}"
      myclass = Object.const_get("MU").const_get("Groomer").const_get(groomer)
      MU::Groomer.requiredMethods.each { |method|
        if !myclass.public_instance_methods.include?(method)
          raise MuError, "MU::Groom::#{groomer} has not implemented required instance method #{method}"
        end
      }
      MU::Groomer.requiredClassMethods.each { |method|
        if !myclass.respond_to?(method)
          raise MuError, "#{myclass} doesn't implement #{method}"
        end
      }

      return myclass
    end

    attr_reader :groomer_obj
    attr_reader :groomer_class

    # @param server [MU::Cloud::Server]: The server which this groomer will be configuring.
    def initialize(server)
      @server = server
      if !server.config.has_key?("groomer")
        @groomer_class = MU::Groomer.loadGroomer(MU::Config.defaultGroomer)
      else
        @groomer_class = MU::Groomer.loadGroomer(server.config['groomer'])
      end
      @groom_semaphore = Mutex.new
      @groom_locks = {}
      @groomer_obj = @groomer_class.new(server)
    end

    # Wrapper for Groomer implementations of the cleanup class method. We'll
    # helpfully provide the arguments we know the answer to.
    def cleanup
      raise MuError, "Called MU::Groomer.cleanup, but I don't have an instantiated server object to clean!" if @server.nil?
      @groomer_class.cleanup(@server.mu_name, @server.config['vault_access'])
    end

    MU::Groomer.requiredMethods.each { |method|
      define_method method do |*args|
        retval = nil

        # Go ahead and guarantee that we can't accidentally trigger these
        # methods recursively.
        @groom_semaphore.synchronize {
          if @groom_locks.has_key?(method)
            MU.log "Double-call to groomer method #{method} for #{@server}", MU::DEBUG, details: caller + ["Competing call stack"] + @groom_locks[method]
          end
          @groom_locks[method] = caller
        }
        if method != :saveSecret
          MU.log "Calling groomer method #{method}", MU::DEBUG, details: args
        else
          MU.log "Calling groomer method #{method}", MU::DEBUG, details: ["sensitive output suppress"]
        end
        begin
          if !args.nil? and args.size == 1
            retval = @groomer_obj.method(method).call(args.first)
          elsif !args.nil? and args.size > 0
            retval = @groomer_obj.method(method).call(*args)
          else
            retval = @groomer_obj.method(method).call
          end
        rescue Exception => e
          raise MU::Groomer::RunError, e.message, e.backtrace
        end
        @groom_semaphore.synchronize {
          @groom_locks.delete(method)
        }
        retval
      end
    }
  end
end
