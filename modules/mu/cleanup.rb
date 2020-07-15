# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#	  http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'json'
require 'net/http'
require 'net/smtp'
require 'optimist'
require 'fileutils'

Thread.abort_on_exception = true

module MU

  # Routines for removing cloud resources.
  class Cleanup

    @deploy_id = nil
    @noop = false
    @onlycloud = false
    @skipcloud = false

    # Resource types, in the order in which we generally have to clean them up
    # to disentangle them from one another.
    TYPES_IN_ORDER = ["Collection", "Endpoint", "Function", "ServerPool", "ContainerCluster", "SearchDomain", "Server", "MsgQueue", "Database", "CacheCluster", "StoragePool", "LoadBalancer", "NoSQLDB", "FirewallRule", "Alarm", "Notifier", "Log", "Job", "VPC", "Role", "Group", "User", "Bucket", "DNSZone", "Collection"]

    # Purge all resources associated with a deployment.
    # @param deploy_id [String]: The identifier of the deployment to remove (typically seen in the MU-ID tag on a resource).
    # @param noop [Boolean]: Do not delete resources, merely list what would be deleted.
    # @param skipsnapshots [Boolean]: Refrain from saving final snapshots of volumes and databases before deletion.
    # @param onlycloud [Boolean]: Purge cloud resources, but skip purging all Mu master metadata, ssh keys, etc.
    # @param verbosity [Integer]: Debug level for MU.log output
    # @param web [Boolean]: Generate web-friendly output.
    # @param ignoremaster [Boolean]: Ignore the tags indicating the originating MU master server when deleting.
    # @param regions [Array<String>]: Operate only on these regions
    # @param habitats [Array<String>]: Operate only on these accounts/projects/subscriptions
    # @return [void]
    def self.run(deploy_id, noop: false, skipsnapshots: false, onlycloud: false, verbosity: MU::Logger::NORMAL, web: false, ignoremaster: false, skipcloud: false, mommacat: nil, credsets: nil, regions: nil, habitats: nil)
      MU.setLogging(verbosity, web)
      @noop = noop
      @skipsnapshots = skipsnapshots
      @onlycloud = onlycloud
      @skipcloud = skipcloud
      @ignoremaster = ignoremaster
      @deploy_id = deploy_id

      if @skipcloud and @onlycloud # you actually mean noop
        @onlycloud = @skipcloud = false
        @noop = true
      end

      MU.setVar("dataDir", (MU.mu_user == "mu" ? MU.mainDataDir : Etc.getpwnam(MU.mu_user).dir+"/.mu/var"))

      # Load up our deployment metadata
      if !mommacat.nil?
        @mommacat = mommacat
      else
        begin
          deploy_dir = File.expand_path("#{MU.dataDir}/deployments/"+deploy_id)
          if Dir.exist?(deploy_dir)
#						key = OpenSSL::PKey::RSA.new(File.read("#{deploy_dir}/public_key"))
#						deploy_secret = key.public_encrypt(File.read("#{deploy_dir}/deploy_secret"))
            FileUtils.touch("#{deploy_dir}/.cleanup") if !@noop
          else
            MU.log "I don't see a deploy named #{deploy_id}.", MU::WARN
            MU.log "Known deployments:\n#{Dir.entries(deploy_dir).reject { |item| item.match(/^\./) or !File.exist?(deploy_dir+"/"+item+"/public_key") }.join("\n")}", MU::WARN
            MU.log "Searching for remnants of #{deploy_id}, though this may be an invalid MU-ID.", MU::WARN
          end
          @mommacat = MU::MommaCat.new(deploy_id, mu_user: MU.mu_user, delay_descriptor_load: true)
        rescue StandardError => e
          MU.log "Can't load a deploy record for #{deploy_id} (#{e.inspect}), cleaning up resources by guesswork", MU::WARN, details: e.backtrace
          MU.setVar("deploy_id", deploy_id)
        end
      end

      @regionsused = @mommacat.regionsUsed if @mommacat
      @credsused = @mommacat.credsUsed if @mommacat
      @habitatsused = @mommacat.habitatsUsed if @mommacat

      if !@skipcloud
        creds = listUsedCredentials(credsets)

        cloudthreads = []

        had_failures = false

        creds.each_pair { |provider, credsets_outer|
          cloudthreads << Thread.new(provider, credsets_outer) { |cloud, credsets_inner|
            Thread.abort_on_exception = false
            cleanCloud(cloud, habitats, regions, credsets_inner)
          } # cloudthreads << Thread.new(provider, credsets) { |cloud, credsets_outer|
          cloudthreads.each do |t|
            t.join
          end
        } # creds.each_pair { |provider, credsets|


        # Knock habitats and folders, which would contain the above resources,
        # once they're all done.
        creds.each_pair { |provider, credsets_inner|
          credsets_inner.keys.each { |credset|
            next if @credsused and !@credsused.include?(credset)
            ["Habitat", "Folder"].each { |t|
              flags = {
                "onlycloud" => @onlycloud,
                "skipsnapshots" => @skipsnapshots
              }
              if !call_cleanup(t, credset, provider, flags, nil)
                had_failures = true
              end
            }
          }
        }

        creds.each_pair { |provider, credsets_inner|
          cloudclass = MU::Cloud.cloudClass(provider)
          credsets_inner.keys.each { |c|
            cloudclass.cleanDeploy(MU.deploy_id, credentials: c, noop: @noop)
          }
        }
      end

      # Scrub any residual Chef records with matching tags
      if !@onlycloud and (@mommacat.nil? or @mommacat.numKittens(types: ["Server", "ServerPool"]) > 0) and !@noop
        MU.supportedGroomers.each { |g|
          groomer = MU::Groomer.loadGroomer(g)
          groomer.cleanup(MU.deploy_id, @noop)
        }
      end

      if had_failures
        MU.log "Had cleanup failures, exiting", MU::ERR
        File.unlink("#{deploy_dir}/.cleanup") if !@noop
        exit 1
      end

      if !@onlycloud and !@noop and @mommacat
        @mommacat.purge!
      end

      if !@onlycloud
        MU::Master.purgeDeployFromSSH(MU.deploy_id, noop: @noop)
      end

      if !@noop and !@skipcloud and (@mommacat.nil? or @mommacat.numKittens(types: ["Server", "ServerPool"]) > 0)
#        MU::Master.syncMonitoringConfig
      end

    end

    def self.listUsedCredentials(credsets)
      creds = {}
      MU::Cloud.availableClouds.each { |cloud|
        cloudclass = MU::Cloud.cloudClass(cloud)
        if $MU_CFG[cloud.downcase] and $MU_CFG[cloud.downcase].size > 0
          creds[cloud] ||= {}
          cloudclass.listCredentials.each { |credset|
            next if credsets and credsets.size > 0 and !credsets.include?(credset)
            next if @credsused and @credsused.size > 0 and !@credsused.include?(credset)
            MU.log "Will scan #{cloud} with credentials #{credset}"
            creds[cloud][credset] = cloudclass.listRegions(credentials: credset)
          }
        else
          if cloudclass.hosted?
            creds[cloud] ||= {}
            creds[cloud]["#default"] = cloudclass.listRegions
          end
        end
      }
      creds
    end
    private_class_method :listUsedCredentials

    def self.cleanCloud(cloud, habitats, regions, credsets)
      cloudclass = MU::Cloud.cloudClass(cloud)
      credsets.each_pair { |credset, acct_regions|
        next if @credsused and !@credsused.include?(credset)
        global_vs_region_semaphore = Mutex.new
        global_done = {}
        regionthreads = []
        acct_regions.each { |r|
          if @regionsused
            if @regionsused.size > 0
              next if !@regionsused.include?(r)
            else
              next if r != cloudclass.myRegion(credset)
            end
          end
          if regions and !regions.empty?
            next if !regions.include?(r)
            MU.log "Checking for #{cloud}/#{credset} resources from #{MU.deploy_id} in #{r}...", MU::NOTICE
          end
          regionthreads << Thread.new {
            Thread.abort_on_exception = false
            MU.setVar("curRegion", r)
            cleanRegion(cloud, credset, r, global_vs_region_semaphore, global_done, habitats)
          } # regionthreads << Thread.new {
        } # acct_regions.each { |r|
        regionthreads.each do |t|
          t.join
        end
      }
    end
    private_class_method :cleanCloud

    def self.cleanRegion(cloud, credset, region, global_vs_region_semaphore, global_done, habitats)
      had_failures = false
      cloudclass = MU::Cloud.cloudClass(cloud)
      habitatclass = MU::Cloud.resourceClass(cloud, "Habitat")

      projects = []
      if habitats
        projects = habitats
      else
        if $MU_CFG and $MU_CFG[cloud.downcase] and
           $MU_CFG[cloud.downcase][credset] and
           $MU_CFG[cloud.downcase][credset]["project"]
# XXX GCP credential schema needs an array for projects
          projects << $MU_CFG[cloud.downcase][credset]["project"]
        end
        begin
          projects.concat(cloudclass.listHabitats(credset, use_cache: false))
        rescue NoMethodError
        end
      end

      if projects == []
        projects << "" # dummy
        MU.log "Checking for #{cloud}/#{credset} resources from #{MU.deploy_id} in #{region}", MU::NOTICE
      end
      projects.uniq!

      # We do these in an order that unrolls dependent resources
      # sensibly, and we hit :Collection twice because AWS
      # CloudFormation sometimes fails internally.
      projectthreads = []
      projects.each { |project|
        if habitats and !habitats.empty? and project != ""
          next if !habitats.include?(project)
        end
        if @habitatsused and !@habitatsused.empty? and project != ""
          next if !@habitatsused.include?(project)
        end
        next if !habitatclass.isLive?(project, credset)

        projectthreads << Thread.new {
          Thread.abort_on_exception = false
          if !cleanHabitat(cloud, credset, region, project, global_vs_region_semaphore, global_done)
            had_failures = true
          end
        } # TYPES_IN_ORDER.each { |t|
      } # projects.each { |project|
      projectthreads.each do |t|
        t.join
      end

      had_failures
    end
    private_class_method :cleanRegion

    def self.cleanHabitat(cloud, credset, region, habitat, global_vs_region_semaphore, global_done)
      had_failures = false
      if habitat != ""
        MU.log "Checking for #{cloud}/#{credset} resources from #{MU.deploy_id} in #{region}, habitat #{habitat}", MU::NOTICE
      end

      flags = {
        "habitat" => habitat,
        "onlycloud" => @onlycloud,
        "skipsnapshots" => @skipsnapshots,
      }
      TYPES_IN_ORDER.each { |t|
        begin
          skipme = false
          global_vs_region_semaphore.synchronize {
            if MU::Cloud.resourceClass(cloud, t).isGlobal?
              global_done[habitat] ||= []
              if !global_done[habitat].include?(t)
                global_done[habitat] << t
                flags['global'] = true
              else
                skipme = true
              end
            end
          }
          next if skipme
        rescue MU::Cloud::MuDefunctHabitat, MU::Cloud::MuCloudResourceNotImplemented
          next
        rescue MU::MuError, NoMethodError => e
          MU.log "While checking mu/providers/#{cloud.downcase}/#{cloudclass.cfg_name} for global-ness in cleanup: "+e.message, MU::WARN
          next
        rescue ::Aws::EC2::Errors::AuthFailure, ::Google::Apis::ClientError => e
          MU.log e.message+" in "+region, MU::ERR
          next
        end

        begin
          if !call_cleanup(t, credset, cloud, flags, region)
            had_failures = true
          end
        rescue MU::Cloud::MuDefunctHabitat, MU::Cloud::MuCloudResourceNotImplemented
          next
        end
      }
      had_failures = true
    end
    private_class_method :cleanHabitat

    # Wrapper for dynamically invoking resource type cleanup methods.
    # @param type [String]:
    # @param credset [String]:
    # @param provider [String]:
    # @param flags [Hash]:
    # @param region [String]:
    def self.call_cleanup(type, credset, provider, flags, region)
      if @mommacat.nil? or @mommacat.numKittens(types: [type]) > 0
        if @mommacat

          found = @mommacat.findLitterMate(type: type, return_all: true, credentials: credset)

          if found
            flags['known'] = if found.is_a?(Array)
              found.map { |k| k.cloud_id }
            elsif found.is_a?(Hash)
              found.each_value.map { |k| k.cloud_id }
            else
              [found.cloud_id]
            end
          end
        end

        MU::Cloud.loadBaseType(type).cleanup(
          noop: @noop,
          ignoremaster: @ignoremaster,
          region: region,
          cloud: provider,
          flags: flags,
          credentials: credset,
          deploy_id: @deploy_id
        )
      else
        true
      end
    end
    private_class_method :call_cleanup

  end #class
end #module
