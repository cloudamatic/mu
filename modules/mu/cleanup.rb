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

      if @skipcloud and @onlycloud # you actually mean noop
        @onlycloud = @skipcloud = false
        @noop = true
      end

      if MU.mu_user != "mu"
        MU.setVar("dataDir", Etc.getpwnam(MU.mu_user).dir+"/.mu/var")
      else
        MU.setVar("dataDir", MU.mainDataDir)
      end


      types_in_order = ["Collection", "Endpoint", "Function", "ServerPool", "ContainerCluster", "SearchDomain", "Server", "MsgQueue", "Database", "CacheCluster", "StoragePool", "LoadBalancer", "NoSQLDB", "FirewallRule", "Alarm", "Notifier", "Log", "VPC", "Role", "Group", "User", "Bucket", "DNSZone", "Collection"]

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

      regionsused = @mommacat.regionsUsed if @mommacat
      credsused = @mommacat.credsUsed if @mommacat
      habitatsused = @mommacat.habitatsUsed if @mommacat

      if !@skipcloud
        creds = {}
        MU::Cloud.availableClouds.each { |cloud|
          cloudclass = Object.const_get("MU").const_get("Cloud").const_get(cloud)
          if $MU_CFG[cloud.downcase] and $MU_CFG[cloud.downcase].size > 0
            creds[cloud] ||= {}
            cloudclass.listCredentials.each { |credset|
              next if credsets and credsets.size > 0 and !credsets.include?(credset)
              next if credsused and credsused.size > 0 and !credsused.include?(credset)
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

        parent_thread_id = Thread.current.object_id
        cloudthreads = []
        keyname = "deploy-#{MU.deploy_id}"
        had_failures = false

        creds.each_pair { |provider, credsets_outer|
          cloudthreads << Thread.new(provider, credsets_outer) { |cloud, credsets_inner|
            MU.dupGlobals(parent_thread_id)
            Thread.abort_on_exception = false
            cloudclass = Object.const_get("MU").const_get("Cloud").const_get(cloud)
            habitatclass = Object.const_get("MU").const_get("Cloud").const_get(cloud).const_get("Habitat")
            credsets_inner.each_pair { |credset, acct_regions|
              next if credsused and !credsused.include?(credset)
              global_vs_region_semaphore = Mutex.new
              global_done = {}
              regionthreads = []
              acct_regions.each { |r|
                if regionsused
                  if regionsused.size > 0
                    next if !regionsused.include?(r)
                  else
                    next if r != cloudclass.myRegion(credset)
                  end
                end
                if regions and !regions.empty?
                  next if !regions.include?(r)
                  MU.log "Checking for #{cloud}/#{credset} resources from #{MU.deploy_id} in #{r}...", MU::NOTICE
                end
                regionthreads << Thread.new {
                  MU.dupGlobals(parent_thread_id)
                  Thread.abort_on_exception = false
                  MU.setVar("curRegion", r)
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
                      projects.concat(cloudclass.listProjects(credset))
                    rescue NoMethodError
                    end
                  end

                  if projects == []
                    projects << "" # dummy
                    MU.log "Checking for #{cloud}/#{credset} resources from #{MU.deploy_id} in #{r}", MU::NOTICE
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
                    if habitatsused and !habitatsused.empty? and project != ""
                      next if !habitatsused.include?(project)
                    end
                    next if !habitatclass.isLive?(project, credset)

                    projectthreads << Thread.new {
                      MU.dupGlobals(parent_thread_id)
                      MU.setVar("curRegion", r)
                      Thread.abort_on_exception = false
                      if project != ""
                        MU.log "Checking for #{cloud}/#{credset} resources from #{MU.deploy_id} in #{r}, project #{project}", MU::NOTICE
                      end

                      MU.dupGlobals(parent_thread_id)
                      flags = {
                        "project" => project,
                        "onlycloud" => @onlycloud,
                        "skipsnapshots" => @skipsnapshots,
                      }
                      types_in_order.each { |t|
                        begin
                          skipme = false
                          global_vs_region_semaphore.synchronize {
                            MU::Cloud.loadCloudType(cloud, t)
                            if Object.const_get("MU").const_get("Cloud").const_get(cloud).const_get(t).isGlobal?
                              global_done[project] ||= []
                              if !global_done[project].include?(t)
                                global_done[project] << t
                                flags['global'] = true
                              else
                                skipme = true
                              end
                            end
                          }
                          next if skipme
                        rescue MU::Cloud::MuDefunctHabitat, MU::Cloud::MuCloudResourceNotImplemented => e
                          next
                        rescue MU::MuError, NoMethodError => e
                          MU.log "While checking mu/clouds/#{cloud.downcase}/#{cloudclass.cfg_name} for global-ness in cleanup: "+e.message, MU::WARN
                          next
                        rescue ::Aws::EC2::Errors::AuthFailure, ::Google::Apis::ClientError => e
                          MU.log e.message+" in "+r, MU::ERR
                          next
                        end

                        begin
                          if !self.call_cleanup(t, credset, cloud, flags, r)
                            had_failures = true
                          end
                        rescue MU::Cloud::MuDefunctHabitat, MU::Cloud::MuCloudResourceNotImplemented => e
                          next
                        end
                      }
                    } # types_in_order.each { |t|
                  } # projects.each { |project|
                  projectthreads.each do |t|
                    t.join
                  end

                  # XXX move to MU::AWS
                  if cloud == "AWS"
                    resp = MU::Cloud::AWS.ec2(region: r, credentials: credset).describe_key_pairs(
                      filters: [{name: "key-name", values: [keyname]}]
                    )
                    resp.data.key_pairs.each { |keypair|
                      MU.log "Deleting key pair #{keypair.key_name} from #{r}"
                      MU::Cloud::AWS.ec2(region: r, credentials: credset).delete_key_pair(key_name: keypair.key_name) if !@noop
                    }
                  end
                } # regionthreads << Thread.new {
              } # acct_regions.each { |r|
              regionthreads.each do |t|
                t.join
              end

            } # credsets.each_pair { |credset, acct_regions|
          } # cloudthreads << Thread.new(provider, credsets) { |cloud, credsets_outer|
          cloudthreads.each do |t|
            t.join
          end
        } # creds.each_pair { |provider, credsets|


        # Knock habitats and folders, which would contain the above resources,
        # once they're all done.
        creds.each_pair { |provider, credsets_inner|
          credsets_inner.keys.each { |credset|
            next if credsused and !credsused.include?(credset)
            ["Habitat", "Folder"].each { |t|
              flags = {
                "onlycloud" => @onlycloud,
                "skipsnapshots" => @skipsnapshots
              }
              if !self.call_cleanup(t, credset, provider, flags, nil)
                had_failures = true
              end
            }
          }
        }

        MU::Cloud::Google.removeDeploySecretsAndRoles(MU.deploy_id) 
# XXX port AWS equivalent behavior and add a MU::Cloud wrapper

        creds.each_pair { |provider, credsets_inner|
          cloudclass = Object.const_get("MU").const_get("Cloud").const_get(provider)
          credsets_inner.keys.each { |c|
            cloudclass.cleanDeploy(MU.deploy_id, credentials: c, noop: @noop)
          }
        }
      end

      # Scrub any residual Chef records with matching tags
      if !@onlycloud and (@mommacat.nil? or @mommacat.numKittens(types: ["Server", "ServerPool"]) > 0) and !(Gem.paths and Gem.paths.home and !Dir.exist?("/opt/mu/lib"))
        begin
          MU::Groomer::Chef.loadChefLib
          if File.exist?(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
            Chef::Config.from_file(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
          end
          deadnodes = []
          Chef::Config[:environment] = MU.environment
          q = Chef::Search::Query.new
          begin
            q.search("node", "tags_MU-ID:#{MU.deploy_id}").each { |item|
              next if item.is_a?(Integer)
              item.each { |node|
                deadnodes << node.name
              }
            }
          rescue Net::HTTPServerException
          end

          begin
            q.search("node", "name:#{MU.deploy_id}-*").each { |item|
              next if item.is_a?(Integer)
              item.each { |node|
                deadnodes << node.name
              }
            }
          rescue Net::HTTPServerException
          end
          MU.log "Missed some Chef resources in node cleanup, purging now", MU::NOTICE if deadnodes.size > 0
          deadnodes.uniq.each { |node|
            MU::Groomer::Chef.cleanup(node, [], noop)
          }
        rescue LoadError
        end
      end

      if had_failures
        MU.log "Had cleanup failures, exiting", MU::ERR
        exit 1
      end

      if !@onlycloud and !@noop and @mommacat
        @mommacat.purge!
      end

      myhome = Etc.getpwuid(Process.uid).dir
      sshdir = "#{myhome}/.ssh"
      sshconf = "#{sshdir}/config"
      ssharchive = "#{sshdir}/archive"

      Dir.mkdir(sshdir, 0700) if !Dir.exist?(sshdir) and !@noop
      Dir.mkdir(ssharchive, 0700) if !Dir.exist?(ssharchive) and !@noop

      keyname = "deploy-#{MU.deploy_id}"
      if File.exist?("#{sshdir}/#{keyname}")
        MU.log "Moving #{sshdir}/#{keyname} to #{ssharchive}/#{keyname}"
        if !@noop
          File.rename("#{sshdir}/#{keyname}", "#{ssharchive}/#{keyname}")
        end
      end

      if File.exist?(sshconf) and File.open(sshconf).read.match(/\/deploy\-#{MU.deploy_id}$/)
        MU.log "Expunging #{MU.deploy_id} from #{sshconf}"
        if !@noop
          FileUtils.copy(sshconf, "#{ssharchive}/config-#{MU.deploy_id}")
          File.open(sshconf, File::CREAT|File::RDWR, 0600) { |f|
            f.flock(File::LOCK_EX)
            newlines = Array.new
            delete_block = false
            f.readlines.each { |line|
              if line.match(/^Host #{MU.deploy_id}\-/)
                delete_block = true
              elsif line.match(/^Host /)
                delete_block = false
              end
              newlines << line if !delete_block
            }
            f.rewind
            f.truncate(0)
            f.puts(newlines)
            f.flush
            f.flock(File::LOCK_UN)
          }
        end
      end

      # XXX refactor with above? They're similar, ish.
      hostsfile = "/etc/hosts"
      if File.open(hostsfile).read.match(/ #{MU.deploy_id}\-/)
        if Process.uid == 0
          MU.log "Expunging traces of #{MU.deploy_id} from #{hostsfile}"
          if !@noop
            FileUtils.copy(hostsfile, "#{hostsfile}.cleanup-#{deploy_id}")
            File.open(hostsfile, File::CREAT|File::RDWR, 0644) { |f|
              f.flock(File::LOCK_EX)
              newlines = Array.new
              f.readlines.each { |line|
                newlines << line if !line.match(/ #{MU.deploy_id}\-/)
              }
              f.rewind
              f.truncate(0)
              f.puts(newlines)
              f.flush
              f.flock(File::LOCK_UN)
            }
          end
        else
          MU.log "Residual /etc/hosts entries for #{MU.deploy_id} must be removed by root user", MU::WARN
        end
      end

      if !@noop and !@skipcloud
        if $MU_CFG['aws'] and $MU_CFG['aws']['account_number']
          MU::Cloud::AWS.s3(region: MU.myRegion).delete_object(
            bucket: MU.adminBucketName,
            key: "#{MU.deploy_id}-secret"
          )
        end
        if $MU_CFG['google'] and $MU_CFG['google']['project']
          begin
            MU::Cloud::Google.storage.delete_object(
              MU.adminBucketName,
              "#{MU.deploy_id}-secret"
            )
          rescue ::Google::Apis::ClientError => e
            raise e if !e.message.match(/^notFound: /)
          end
        end
        if MU.myCloud == "AWS"
          MU::Cloud::AWS.openFirewallForClients # XXX add the other clouds, or abstract
        end
      end

      if !@noop and !@skipcloud and (@mommacat.nil? or @mommacat.numKittens(types: ["Server", "ServerPool"]) > 0)
#        MU::MommaCat.syncMonitoringConfig
      end

    end

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
          flags['known'] ||= []
          if found.is_a?(Array)
            found.each { |k|
              flags['known'] << k.cloud_id
            }
          elsif found and found.is_a?(Hash)
            flags['known'] << found['cloud_id']
          elsif found
            flags['known'] << found.cloud_id                            
          end
        end
#        begin
          resclass = Object.const_get("MU").const_get("Cloud").const_get(type)

          resclass.cleanup(
            noop: @noop,
            ignoremaster: @ignoremaster,
            region: region,
            cloud: provider,
            flags: flags,
            credentials: credset
          )
#                        rescue ::Seahorse::Client::NetworkingError => e
#                          MU.log "Service not available in AWS region #{r}, skipping", MU::DEBUG, details: e.message
#                        end
      else
        true
      end
      private_class_method :call_cleanup
    end
  end #class
end #module
