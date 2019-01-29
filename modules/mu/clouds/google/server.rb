# Copyright:: Copyright (c) 2017 eGlobalTech, Inc., all rights reserved
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

require 'net/ssh'
require 'net/ssh/multi'
require 'net/ssh/proxy/command'
autoload :OpenStruct, "ostruct"
autoload :Timeout, "timeout"
autoload :ERB, "erb"
autoload :Base64, "base64"
require 'open-uri'

module MU
  class Cloud
    class Google
      # A server as configured in {MU::Config::BasketofKittens::servers}. In
      # Google Cloud, this amounts to a single Instance in an Unmanaged
      # Instance Group.
      class Server < MU::Cloud::Server

        attr_reader :mu_name
        attr_reader :config
        attr_reader :deploy
        attr_reader :cloud_id
        attr_reader :cloud_desc
        attr_reader :groomer
        attr_accessor :mu_windows_name

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::servers}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id = cloud_id

          if @deploy
            @userdata = MU::Cloud.fetchUserdata(
              platform: @config["platform"],
              cloud: "google",
              template_variables: {
                "deployKey" => Base64.urlsafe_encode64(@deploy.public_key),
                "deploySSHKey" => @deploy.ssh_public_key,
                "muID" => MU.deploy_id,
                "muUser" => MU.mu_user,
                "publicIP" => MU.mu_public_ip,
                "skipApplyUpdates" => @config['skipinitialupdates'],
                "windowsAdminName" => @config['windows_admin_username'],
                "resourceName" => @config["name"],
                "resourceType" => "server",
                "platform" => @config["platform"]
              },
              custom_append: @config['userdata_script']
            )
          end

          if !mu_name.nil?
            @mu_name = mu_name
            @config['mu_name'] = @mu_name
            # describe
            @mu_windows_name = @deploydata['mu_windows_name'] if @mu_windows_name.nil? and @deploydata
          else
            if kitten_cfg.has_key?("basis")
              @mu_name = @deploy.getResourceName(@config['name'], need_unique_string: true)
            else
              @mu_name = @deploy.getResourceName(@config['name'])
            end
            @config['mu_name'] = @mu_name

            @config['instance_secret'] = Password.random(50)
          end
          @config['ssh_user'] ||= "mu"
          @groomer = MU::Groomer.new(self)

        end

        # Generate a server-class specific service account, used to grant 
        # permission to do various API things to a node.
        # @param rolename [String]:
        # @param project [String]:
        # @param scopes [Array<String>]: https://developers.google.com/identity/protocols/googlescopes
        # XXX this should be a MU::Cloud::Google::User resource
        def self.createServiceAccount(rolename, deploy, project: nil, scopes: ["https://www.googleapis.com/auth/compute.readonly", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/cloud-platform"], credentials: nil)
          project ||= MU::Cloud::Google.defaultProject(credentials)
#https://www.googleapis.com/auth/devstorage.read_only ?
          name = deploy.getResourceName(rolename, max_length: 30).downcase

          saobj = MU::Cloud::Google.iam(:CreateServiceAccountRequest).new(
            account_id: name.gsub(/[^a-z]/, ""), # XXX this mangling isn't required in the console, so why is it here?
            service_account: MU::Cloud::Google.iam(:ServiceAccount).new(
              display_name: rolename,
# do NOT specify project_id or name, we know that much
            )
          )
          resp = MU::Cloud::Google.iam(credentials: credentials).create_service_account(
            "projects/#{project}",
            saobj
          )
          MU::Cloud::Google.compute(:ServiceAccount).new(
            email: resp.email,
            scopes: scopes
          )
        end

        # Retrieve the cloud descriptor for this machine image, which can be
        # a whole or partial URL. Will follow deprecation notices and retrieve
        # the latest version, if applicable.
        # @param image_id [String]: URL to a Google disk image
        # @return [Google::Apis::ComputeBeta::Image]
        def self.fetchImage(image_id, credentials: nil)
          img_proj = img_name = nil
          begin
            img_proj = image_id.gsub(/.*?\/?projects\/([^\/]+)\/.*/, '\1')
            img_name = image_id.gsub(/.*?([^\/]+)$/, '\1')
            img = MU::Cloud::Google.compute(credentials: credentials).get_image(img_proj, img_name)
            if !img.deprecated.nil? and !img.deprecated.replacement.nil?
              image_id = img.deprecated.replacement
            end
          end while !img.deprecated.nil? and img.deprecated.state == "DEPRECATED" and !img.deprecated.replacement.nil?
          MU::Cloud::Google.compute(credentials: credentials).get_image(img_proj, img_name)
        end

        # Generator for disk configuration parameters for a Compute instance
        # @param config [Hash]: The MU::Cloud::Server config hash for whom we're configuring disks
        # @param create [Boolean]: Actually create extra (non-root) disks, or just the one declared as the root disk of the image
        # @param disk_as_url [Boolean]: Whether to declare the disk type as a short string or full URL, which can vary depending on the calling resource
        # @return [Array]: The Compute :AttachedDisk objects describing disks that've been created
        def self.diskConfig(config, create = true, disk_as_url = true, credentials: nil)
          disks = []
          if config['image_id'].nil? and config['basis'].nil?
            pp config.keys
            raise MuError, "Can't generate disk configuration for server #{config['name']} without an image ID or basis specified"
          end

          img = fetchImage(config['image_id'] || config['basis']['launch_config']['image_id'], credentials: credentials)

# XXX slurp settings from /dev/sda or w/e by convention?
          disktype = "projects/#{config['project']}/zones/#{config['availability_zone']}/diskTypes/pd-standard"
          disktype = "pd-standard" if !disk_as_url
# disk_type: projects/project/zones/#{config['availability_zone']}/diskTypes/pd-standard Other values include pd-ssd and local-ssd
          imageobj = MU::Cloud::Google.compute(:AttachedDiskInitializeParams).new(
            source_image: img.self_link,
            disk_size_gb: 10, # this is binary? 2gb, that says
            disk_type: disktype,
          )
          disks << MU::Cloud::Google.compute(:AttachedDisk).new(
            auto_delete: true,
            boot: true,
            mode: "READ_WRITE",
            type: "PERSISTENT",
            initialize_params: imageobj
          )
          if config["storage"]
            config["storage"].each { |vol|
              devicename = vol['device'].gsub(/[^\w\-\.]/, "-").sub(/^[^\w]/, "")
              disk_desc = {
                :auto_delete => true,
                :device_name => devicename, # XXX empty string is also legit
                :mode => "READ_WRITE",
                :type => "PERSISTENT" # SCRATCH is equivalent of ephemeral? cheap virtual memory disk? maybe ship a standard set
              }

              if vol['snapshot_id']
                disk_desc[:source_snapshot] = vol['snapshot_id']
# XXX check existence in in validateConfig
              elsif vol['somekindofidforaloosevolume']
                disk_desc[:source] = vol['somekindofidforaloosevolume']
# XXX check existence in in validateConfig
              end
# XXX I don't know how to do this in managed instance groups
#next
next if !create
              diskname = MU::Cloud::Google.nameStr(config['mu_name']+"-"+devicename)
              newdiskobj = MU::Cloud::Google.compute(:Disk).new(
                size_gb: vol['size'],
                description: MU.deploy_id,
                zone: config['availability_zone'],
#                    type: "projects/#{config['project']}/zones/#{config['availability_zone']}/diskTypes/pd-ssd",
                type: "projects/#{config['project']}/zones/#{config['availability_zone']}/diskTypes/pd-standard",
                source_snapshot: vol['snapshot_id'],
# type: projects/project/zones/#{config['availability_zone']}/diskTypes/pd-standard Other values include pd-ssd and local-ssd
                name: diskname
              )
              MU.log "Creating disk #{diskname}", details: newdiskobj

              newdisk = MU::Cloud::Google.compute(credentials: credentials).insert_disk(
                config['project'],
                config['availability_zone'],
                newdiskobj
              )

              disk_desc[:source] = newdisk.self_link

              disks << MU::Cloud::Google.compute(:AttachedDisk).new(disk_desc)
            }
          end

          disks
        end

        # Generator for disk configuration parameters for a Compute instance
        # @param config [Hash]: The MU::Cloud::Server config hash for whom we're configuring network interfaces
        # @param vpc [MU::Cloud::Google::VPC]: The VPC in which this interface should reside
        # @return [Array]: Configuration objects for network interfaces, suitable for passing to the Compute API
        def self.interfaceConfig(config, vpc)
          subnet_cfg = config['vpc']
          if config['vpc']['subnets'] and
             !subnet_cfg['subnet_name'] and !subnet_cfg['subnet_id']
            subnet_cfg = config['vpc']['subnets'].sample

          end
          subnet = vpc.getSubnet(name: subnet_cfg['subnet_name'], cloud_id: subnet_cfg['subnet_id'])
          if subnet.nil?
            raise MuError, "Couldn't find subnet details while configuring Server #{config['name']} (VPC: #{vpc.mu_name})"
          end
          base_iface_obj = {
            :network => vpc.url,
            :subnetwork => subnet.url
          }
          if config['associate_public_ip']
            base_iface_obj[:access_configs] = [
              MU::Cloud::Google.compute(:AccessConfig).new
            ]
          end
          interfaces = [base_iface_obj]
          # XXX add more if they asked for it (e.g. config['private_ip'])

          interfaces
        end

        # Called automatically by {MU::Deploy#createResources}
        def create

          service_acct = MU::Cloud::Google::Server.createServiceAccount(
            @mu_name.downcase,
            @deploy,
            project: @config['project'],
            credentials: @config['credentials']
          )
          MU::Cloud::Google.grantDeploySecretAccess(service_acct.email)

          begin
            disks = MU::Cloud::Google::Server.diskConfig(@config, credentials: @config['credentials'])
            interfaces = MU::Cloud::Google::Server.interfaceConfig(@config, @vpc)

            if @config['routes']
              @config['routes'].each { |route|
                @vpc.cloudobj.createRouteForInstance(route, self)
              }
            end

            desc = {
              :name => MU::Cloud::Google.nameStr(@mu_name),
              :can_ip_forward => !@config['src_dst_check'],
              :description => @deploy.deploy_id,
              :service_accounts => [service_acct],
              :network_interfaces => interfaces,
              :machine_type => "zones/"+@config['availability_zone']+"/machineTypes/"+@config['size'],
              :metadata => {
                :items => [
                  {
                    :key => "ssh-keys",
                    :value => @config['ssh_user']+":"+@deploy.ssh_public_key
                  },
                  {
                    :key => "startup-script",
                    :value => @userdata
                  }
                ]
              },
              :tags => MU::Cloud::Google.compute(:Tags).new(items: [MU::Cloud::Google.nameStr(@mu_name)])
            }
            desc[:disks] = disks if disks.size > 0

            # Tags in GCP means something other than what we think of;
            # labels are the thing you think you mean
            desc[:labels] = {}
            MU::MommaCat.listStandardTags.each_pair { |name, value|
              if !value.nil?
                desc[:labels][name.downcase] = value.downcase.gsub(/[^a-z0-9\-\_]/i, "_")
              end
            }
            desc[:labels]["name"] = @mu_name.downcase


            instanceobj = MU::Cloud::Google.compute(:Instance).new(desc)

            MU.log "Creating instance #{@mu_name}"
            begin
              instance = MU::Cloud::Google.compute(credentials: @config['credentials']).insert_instance(
                @config['project'],
                @config['availability_zone'],
                instanceobj
              )
              if instance and instance.name
                @cloud_id = instance.name
              else
                sleep 10
              end
            rescue ::Google::Apis::ClientError => e
              MU.log e.message, MU::ERR
              raise e
            end while @cloud_id.nil?

            if !@config['async_groom']
              sleep 5
              MU::MommaCat.lock(@cloud_id+"-create")
              if !postBoot
                MU.log "#{@config['name']} is already being groomed, skipping", MU::NOTICE
              else
                MU.log "Node creation complete for #{@config['name']}"
              end
              MU::MommaCat.unlock(@cloud_id+"-create")
            end
            done = false

            @deploy.saveNodeSecret(@cloud_id, @config['instance_secret'], "instance_secret")
            @config.delete("instance_secret")

            if cloud_desc.nil? or cloud_desc.status != "RUNNING"
              raiseert MuError, "#{@cloud_id} appears to have gone sideways mid-bootstrap #{cloud_desc.status if cloud_desc.nil?}"
            end

            notify

          rescue Exception => e
            if !cloud_desc.nil? and !done
              MU.log "Aborted before I could finish setting up #{@config['name']}, cleaning it up. Stack trace will print once cleanup is complete.", MU::WARN if !@deploy.nocleanup
              MU::MommaCat.unlockAll
              if !@deploy.nocleanup
                parent_thread_id = Thread.current.object_id
                Thread.new {
                  MU.dupGlobals(parent_thread_id)
                  MU::Cloud::Google::Server.cleanup(noop: false, ignoremaster: false, flags: { "skipsnapshots" => true } )
                }
              end
            end
            raise e
          end

          return @config
        end

        # Return a BoK-style config hash describing a NAT instance. We use this
        # to approximate Amazon's NAT gateway functionality with a plain
        # instance.
        # @return [Hash]
        def self.genericNAT
          return {
            "cloud" => "Google",
            "size" => "g1-small",
            "run_list" => [ "mu-utility::nat" ],
            "platform" => "centos7",
            "ssh_user" => "centos",
            "associate_public_ip" => true,
            "static_ip" => { "assign_ip" => true },
            "routes" => [ {
              "gateway" => "#INTERNET",
              "priority" => 50,
              "destination_network" => "0.0.0.0/0"
            } ]
          }
        end

        # Ask the Google API to stop this node
        def stop
          MU.log "Stopping #{@cloud_id}"
          MU::Cloud::Google.compute(credentials: @config['credentials']).stop_instance(
            @config['project'],
            @config['availability_zone'],
            @cloud_id
          )
          begin
            sleep 5
          end while cloud_desc.status != "TERMINATED" # means STOPPED
        end

        # Ask the Google API to start this node
        def start
          MU.log "Starting #{@cloud_id}"
          MU::Cloud::Google.compute(credentials: @config['credentials']).start_instance(
            @config['project'],
            @config['availability_zone'],
            @cloud_id
          )
          begin
            sleep 5
          end while cloud_desc.status != "RUNNING"
        end

        # Ask the Google API to restart this node
        # XXX unimplemented
        def reboot(hard = false)
          return if @cloud_id.nil?

        end

        # Figure out what's needed to SSH into this server.
        # @return [Array<String>]: nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name, alternate_names
        def getSSHConfig
          node, config, deploydata = describe(cloud_id: @cloud_id)
# XXX add some awesome alternate names from metadata and make sure they end
# up in MU::MommaCat's ssh config wangling
          ssh_keydir = Etc.getpwuid(Process.uid).dir+"/.ssh"
          return nil if @config.nil? or @deploy.nil?

          nat_ssh_key = nat_ssh_user = nat_ssh_host = nil
          if !@config["vpc"].nil? and !MU::Cloud::Google::VPC.haveRouteToInstance?(cloud_desc, region: @config['region'], credentials: @config['credentials'])

            if !@nat.nil?
              if @nat.cloud_desc.nil?
                MU.log "NAT was missing cloud descriptor when called in #{@mu_name}'s getSSHConfig", MU::ERR
                return nil
              end
              foo, bar, baz, nat_ssh_host, nat_ssh_user, nat_ssh_key  = @nat.getSSHConfig
              if nat_ssh_user.nil? and !nat_ssh_host.nil?
                MU.log "#{@config["name"]} (#{MU.deploy_id}) is configured to use #{@config['vpc']} NAT #{nat_ssh_host}, but username isn't specified. Guessing root.", MU::ERR, details: caller
                nat_ssh_user = "root"
              end
            end
          end

          if @config['ssh_user'].nil?
            if windows?
              @config['ssh_user'] = "Administrator"
            else
              @config['ssh_user'] = "root"
            end
          end

          return [nat_ssh_key, nat_ssh_user, nat_ssh_host, canonicalIP, @config['ssh_user'], @deploy.ssh_key_name]

        end

        # Apply tags, bootstrap our configuration management, and other
        # administravia for a new instance.
        def postBoot(instance_id = nil)
          if !instance_id.nil?
            @cloud_id = instance_id
          end

          instance = cloud_desc

          node, config, deploydata = describe(cloud_id: @cloud_id)
          instance = cloud_desc
          raise MuError, "Couldn't find instance of #{@mu_name} (#{@cloud_id})" if !instance
          return false if !MU::MommaCat.lock(@cloud_id+"-orchestrate", true)
          return false if !MU::MommaCat.lock(@cloud_id+"-groom", true)

#          MU::MommaCat.createStandardTags(@cloud_id, region: @config['region'])
#          MU::MommaCat.createTag(@cloud_id, "Name", node, region: @config['region'])
#
#          if @config['optional_tags']
#            MU::MommaCat.listOptionalTags.each { |key, value|
#              MU::MommaCat.createTag(@cloud_id, key, value, region: @config['region'])
#            }
#          end
#
#          if !@config['tags'].nil?
#            @config['tags'].each { |tag|
#              MU::MommaCat.createTag(@cloud_id, tag['key'], tag['value'], region: @config['region'])
#            }
#          end
#          MU.log "Tagged #{node} (#{@cloud_id}) with MU-ID=#{MU.deploy_id}", MU::DEBUG
#
          # Make double sure we don't lose a cached mu_windows_name value.
          if windows? or !@config['active_directory'].nil?
            if @mu_windows_name.nil?
              @mu_windows_name = deploydata['mu_windows_name']
            end
          end

#          punchAdminNAT
#
#
#          # If we came up via AutoScale, the Alarm module won't have had our
#          # instance ID to associate us with itself. So invoke that here.
#          if !@config['basis'].nil? and @config["alarms"] and !@config["alarms"].empty?
#            @config["alarms"].each { |alarm|
#              alarm_obj = MU::MommaCat.findStray(
#                "AWS",
#                "alarms",
#                region: @config["region"],
#                deploy_id: @deploy.deploy_id,
#                name: alarm['name']
#              ).first
#              alarm["dimensions"] = [{:name => "InstanceId", :value => @cloud_id}]
#
#              if alarm["enable_notifications"]
#                topic_arn = MU::Cloud::AWS::Notification.createTopic(alarm["notification_group"], region: @config["region"])
#                MU::Cloud::AWS::Notification.subscribe(arn: topic_arn, protocol: alarm["notification_type"], endpoint: alarm["notification_endpoint"], region: @config["region"])
#                alarm["alarm_actions"] = [topic_arn]
#                alarm["ok_actions"]  = [topic_arn]
#              end
#
#              alarm_name = alarm_obj ? alarm_obj.cloud_id : "#{node}-#{alarm['name']}".upcase
#
#              MU::Cloud::AWS::Alarm.setAlarm(
#                name: alarm_name,
#                ok_actions: alarm["ok_actions"],
#                alarm_actions: alarm["alarm_actions"],
#                insufficient_data_actions: alarm["no_data_actions"],
#                metric_name: alarm["metric_name"],
#                namespace: alarm["namespace"],
#                statistic: alarm["statistic"],
#                dimensions: alarm["dimensions"],
#                period: alarm["period"],
#                unit: alarm["unit"],
#                evaluation_periods: alarm["evaluation_periods"],
#                threshold: alarm["threshold"],
#                comparison_operator: alarm["comparison_operator"],
#                region: @config["region"]
#              )
#            }
#          end
#
#          # We have issues sometimes where our dns_records are pointing at the wrong node name and IP address.
#          # Make sure that doesn't happen. Happens with server pools only
#          if @config['dns_records'] && !@config['dns_records'].empty?
#            @config['dns_records'].each { |dnsrec|
#              if dnsrec.has_key?("name")
#                if dnsrec['name'].start_with?(MU.deploy_id.downcase) && !dnsrec['name'].start_with?(node.downcase)
#                  MU.log "DNS records for #{node} seem to be wrong, deleting from current config", MU::WARN, details: dnsrec
#                  dnsrec.delete('name')
#                  dnsrec.delete('target')
#                end
#              end
#            }
#          end

          # Unless we're planning on associating a different IP later, set up a
          # DNS entry for this thing and let it sync in the background. We'll
          # come back to it later.
          if @config['static_ip'].nil? && !@named
            MU::MommaCat.nameKitten(self)
            @named = true
          end

          nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name = getSSHConfig
          if !nat_ssh_host and !MU::Cloud::Google::VPC.haveRouteToInstance?(cloud_desc, region: @config['region'], credentials: @config['credentials'])
# XXX check if canonical_ip is in the private ranges
#            raise MuError, "#{node} has no NAT host configured, and I have no other route to it"
          end

          # See if this node already exists in our config management. If it does,
          # we're done.
          if @groomer.haveBootstrapped?
            MU.log "Node #{node} has already been bootstrapped, skipping groomer setup.", MU::NOTICE
            @groomer.saveDeployData
            MU::MommaCat.unlock(@cloud_id+"-orchestrate")
            MU::MommaCat.unlock(@cloud_id+"-groom")
            return true
          end

          @groomer.bootstrap

          # Make sure we got our name written everywhere applicable
          if !@named
            MU::MommaCat.nameKitten(self)
            @named = true
          end

          MU::MommaCat.unlock(@cloud_id+"-groom")
          MU::MommaCat.unlock(@cloud_id+"-orchestrate")
          return true
        end #postBoot

        # Locate an existing instance or instances and return an array containing matching AWS resource descriptors for those that match.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region
        # @param tag_key [String]: A tag key to search.
        # @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
        # @param ip [String]: An IP address associated with the instance
        # @param flags [Hash]: Optional flags
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching instances
        def self.find(cloud_id: nil, region: MU.curRegion, tag_key: "Name", tag_value: nil, ip: nil, flags: {}, credentials: nil)
# XXX put that 'ip' value into flags
          instance = nil
          flags["project"] ||= MU::Cloud::Google.defaultProject(credentials)
          if !region.nil? and MU::Cloud::Google.listRegions.include?(region)
            regions = [region]
          else
            regions = MU::Cloud::Google.listRegions
          end

          found_instances = {}
          search_semaphore = Mutex.new
          search_threads = []

          # If we got an instance id, go get it
          if !cloud_id.nil? and !cloud_id.empty?
            parent_thread_id = Thread.current.object_id
            regions.each { |region|
              search_threads << Thread.new {
                Thread.abort_on_exception = false
                MU.dupGlobals(parent_thread_id)
                MU.log "Hunting for instance with cloud id '#{cloud_id}' in #{region}", MU::DEBUG
                MU::Cloud::Google.listAZs(region).each { |az|
                  resp = nil
                  begin
                    resp = MU::Cloud::Google.compute(credentials: credentials).get_instance(
                      flags["project"],
                      az,
                      cloud_id
                    )
                  rescue ::Google::Apis::ClientError => e
                    raise e if !e.message.match(/^notFound: /)
                  end
                  found_instances[cloud_id] = resp if !resp.nil?
                }
              }
            }
            done_threads = []
            begin
              search_threads.each { |t|
                joined = t.join(2)
                done_threads << joined if !joined.nil?
              }
            end while found_instances.size < 1 and done_threads.size != search_threads.size
          end

          if found_instances.size > 0
            return found_instances
          end

          # Ok, well, let's try looking it up by IP then
          if instance.nil? and !ip.nil?
            MU.log "Hunting for instance by IP '#{ip}'", MU::DEBUG
          end

          if !instance.nil?
            return {instance.name => instance} if !instance.nil?
          end

          # Fine, let's try it by tag.
          if !tag_value.nil?
            MU.log "Searching for instance by tag '#{tag_key}=#{tag_value}'", MU::DEBUG
          end

          return found_instances
        end

        # Return a description of this resource appropriate for deployment
        # metadata. Arguments reflect the return values of the MU::Cloud::[Resource].describe method
        def notify
          node, config, deploydata = describe(cloud_id: @cloud_id, update_cache: true)
          deploydata = {} if deploydata.nil?

          if cloud_desc.nil?
            raise MuError, "Failed to load instance metadata for #{@config['mu_name']}/#{@cloud_id}"
          end

          interfaces = []
          private_ips = []
          public_ips = []

          cloud_desc.network_interfaces.each { |iface|
            private_ips << iface.network_ip
            if iface.access_configs
              iface.access_configs.each { |acfg|
                public_ips << acfg.nat_ip if acfg.nat_ip
              }
            end
            interfaces << {
              "network_interface_id" => iface.name,
              "subnet_id" => iface.subnetwork,
              "vpc_id" => iface.network
            }
          }

          deploydata = {
              "nodename" => @mu_name,
              "run_list" => @config['run_list'],
              "image_created" => @config['image_created'],
#              "iam_role" => @config['iam_role'],
              "cloud_desc_id" => @cloud_id,
              "private_ip_address" => private_ips.first,
              "public_ip_address" => public_ips.first,
              "private_ip_list" => private_ips,
#              "key_name" => cloud_desc.key_name,
#              "subnet_id" => cloud_desc.subnet_id,
#              "cloud_desc_type" => cloud_desc.instance_type #,
              #				"network_interfaces" => interfaces,
              #				"config" => server
          }

          if !@mu_windows_name.nil?
            deploydata["mu_windows_name"] = @mu_windows_name
          end
          if !@config['chef_data'].nil?
            deploydata.merge!(@config['chef_data'])
          end
          deploydata["region"] = @config['region'] if !@config['region'].nil?
          if !@named
            MU::MommaCat.nameKitten(self)
            @named = true
          end

          return deploydata
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom

          MU::MommaCat.lock(@cloud_id+"-groom")
          
          node, config, deploydata = describe(cloud_id: @cloud_id)

          if node.nil? or node.empty?
            raise MuError, "MU::Cloud::Google::Server.groom was called without a mu_name"
          end

          # Make double sure we don't lose a cached mu_windows_name value.
          if windows? or !@config['active_directory'].nil?
            if @mu_windows_name.nil?
              @mu_windows_name = deploydata['mu_windows_name']
            end
          end

#          punchAdminNAT

#          MU::Cloud::AWS::Server.tagVolumes(@cloud_id)

          # If we have a loadbalancer configured, attach us to it
#          if !@config['loadbalancers'].nil?
#            if @loadbalancers.nil?
#              raise MuError, "#{@mu_name} is configured to use LoadBalancers, but none have been loaded by dependencies()"
#            end
#            @loadbalancers.each { |lb|
#              lb.registerNode(@cloud_id)
#            }
#          end

          # Let us into any databases we depend on.
          # This is probelmtic with autscaling - old ips are not removed, and access to the database can easily be given at the BoK level
          # if @dependencies.has_key?("database")
            # @dependencies['database'].values.each { |db|
              # db.allowHost(@deploydata["private_ip_address"]+"/32")
              # if @deploydata["public_ip_address"]
                # db.allowHost(@deploydata["public_ip_address"]+"/32")
              # end
            # }
          # end

          @groomer.saveDeployData

          begin
            @groomer.run(purpose: "Full Initial Run", max_retries: 15)
          rescue MU::Groomer::RunError
            MU.log "Proceeding after failed initial Groomer run, but #{node} may not behave as expected!", MU::WARN
          end

          if !@config['create_image'].nil? and !@config['image_created']
            img_cfg = @config['create_image']
            # Scrub things that don't belong on an AMI
            session = getSSHSession
            sudo = purgecmd = ""
            sudo = "sudo" if @config['ssh_user'] != "root"
            if windows?
              purgecmd = "rm -rf /cygdrive/c/mu_installed_chef"
            else
              purgecmd = "rm -rf /opt/mu_installed_chef"
            end
            if img_cfg['image_then_destroy']
              if windows?
                purgecmd = "rm -rf /cygdrive/c/chef/ /home/#{@config['windows_admin_username']}/.ssh/authorized_keys /home/Administrator/.ssh/authorized_keys /cygdrive/c/mu-installer-ran-updates /cygdrive/c/mu_installed_chef"
                # session.exec!("powershell -Command \"& {(Get-WmiObject -Class Win32_Product -Filter \"Name='UniversalForwarder'\").Uninstall()}\"")
              else
                purgecmd = "#{sudo} rm -rf /root/.ssh/authorized_keys /etc/ssh/ssh_host_*key* /etc/chef /etc/opscode/* /.mu-installer-ran-updates /var/chef /opt/mu_installed_chef /opt/chef ; #{sudo} sed -i 's/^HOSTNAME=.*//' /etc/sysconfig/network"
              end
            end
            session.exec!(purgecmd)
            session.close
            stop
            image_id = MU::Cloud::Google::Server.createImage(
                name: MU::Cloud::Google.nameStr(@mu_name),
                instance_id: @cloud_id,
                region: @config['region'],
                storage: @config['storage'],
                family: ("mu-"+@config['platform']+"-"+MU.environment).downcase,
                project: @config['project'],
                exclude_storage: img_cfg['image_exclude_storage'],
                make_public: img_cfg['public'],
                tags: @config['tags'],
                zone: @config['availability_zone'],
                credentials: @config['credentials']
            )
            @deploy.notify("images", @config['name'], {"image_id" => image_id})
            @config['image_created'] = true
            if img_cfg['image_then_destroy']
              MU.log "Image #{image_id} ready, removing source node #{node}"
              MU::Cloud::Google.compute(credentials: @config['credentials']).delete_instance(
                @config['project'],
                @config['availability_zone'],
                @cloud_id
              )
              destroy
            else
              start
            end
          end

          MU::MommaCat.unlock(@cloud_id+"-groom")
        end

        # Create an image out of a running server. Requires either the name of a MU resource in the current deployment, or the cloud provider id of a running instance.
        # @param name [String]: The MU resource name of the server to use as the basis for this image.
        # @param instance_id [String]: The cloud provider resource identifier of the server to use as the basis for this image.
        # @param storage [Hash]: The storage devices to include in this image.
        # @param exclude_storage [Boolean]: Do not include the storage device profile of the running instance when creating this image.
        # @param region [String]: The cloud provider region
        # @param tags [Array<String>]: Extra/override tags to apply to the image.
        # @return [String]: The cloud provider identifier of the new machine image.
        def self.createImage(name: nil, instance_id: nil, storage: {}, exclude_storage: false, project: nil, make_public: false, tags: [], region: nil, family: "mu", zone: MU::Cloud::Google.listAZs.sample, credentials: nil)
          project ||= MU::Cloud::Google.defaultProject(credentials)
          instance = MU::Cloud::Server.find(cloud_id: instance_id, region: region)
          if instance.nil?
            raise MuError, "Failed to find instance '#{instance_id}' in createImage"
          end

          labels = {}
          MU::MommaCat.listStandardTags.each_pair { |key, value|
            if !value.nil?
              labels[key.downcase] = value.downcase.gsub(/[^a-z0-9\-\_]/i, "_")
            end
          }

          bootdisk = nil
          threads = []
          parent_thread_id = Thread.current.object_id
          instance[instance_id].disks.each { |disk|
            threads << Thread.new {
              Thread.abort_on_exception = false
              MU.dupGlobals(parent_thread_id)
              if disk.boot
                bootdisk = disk.source
              else
                snapobj = MU::Cloud::Google.compute(:Snapshot).new(
                  name: name+"-"+disk.device_name,
                  description: "Mu image created from #{name} (#{disk.device_name})"
                )
                diskname = disk.source.gsub(/.*?\//, "")
                MU.log "Creating snapshot of #{diskname} in #{zone}", MU::NOTICE, details: snapobj
                snap = MU::Cloud::Google.compute(credentials: credentials).create_disk_snapshot(
                  project,
                  zone,
                  diskname,
                  snapobj
                )
                MU::Cloud::Google.compute(credentials: credentials).set_snapshot_labels(
                  project,
                  snap.name,
                  MU::Cloud::Google.compute(:GlobalSetLabelsRequest).new(
                    label_fingerprint: snap.label_fingerprint,
                    labels: labels.merge({
                      "mu-device-name" => disk.device_name,
                      "mu-parent-image" => name,
                      "mu-orig-zone" => zone
                    })
                  )
                )
              end
            }
          }
          threads.each do |t|
            t.join
          end

          labels["name"] = instance_id.downcase
          imageobj = MU::Cloud::Google.compute(:Image).new(
            name: name,
            source_disk: bootdisk,
            description: "Mu image created from #{name}",
            labels: labels,
            family: family
          )

          newimage = MU::Cloud::Google.compute(credentials: @config['credentials']).insert_image(
            project,
            imageobj
          )
          newimage.name
        end

#        def cloud_desc
#          max_retries = 5
#          retries = 0
#          if !@cloud_id.nil?
#            begin
#              return MU::Cloud::Google.compute(credentials: @config['credentials']).get_instance(
#                @config['project'],
#                @config['availability_zone'],
#                @cloud_id
#              )
#            rescue ::Google::Apis::ClientError => e
#              if e.message.match(/^notFound: /)
#                return nil
#              else
#                raise e
#              end
#            end
#          end
#          nil
#        end

        def cloud_desc
          MU::Cloud::Google::Server.find(cloud_id: @cloud_id, credentials: @config['credentials']).values.first
        end

        # Return the IP address that we, the Mu server, should be using to access
        # this host via the network. Note that this does not factor in SSH
        # bastion hosts that may be in the path, see getSSHConfig if that's what
        # you need.
        def canonicalIP
          mu_name, config, deploydata = describe(cloud_id: @cloud_id)

          if !cloud_desc
            raise MuError, "Couldn't retrieve cloud descriptor for server #{self}"
          end

          private_ips = []
          public_ips = []

          cloud_desc.network_interfaces.each { |iface|
            private_ips << iface.network_ip
            if iface.access_configs
              iface.access_configs.each { |acfg|
                public_ips << acfg.nat_ip if acfg.nat_ip
              }
            end
          }

          # Our deploydata gets corrupted often with server pools, this will cause us to use the wrong IP to identify a node
          # which will cause us to create certificates, DNS records and other artifacts with incorrect information which will cause our deploy to fail.
          # The cloud_id is always correct so lets use 'cloud_desc' to get the correct IPs
          if MU::Cloud::Google::VPC.haveRouteToInstance?(cloud_desc, credentials: @config['credentials']) or public_ips.size == 0
            @config['canonical_ip'] = private_ips.first
            return private_ips.first
          else
            @config['canonical_ip'] = public_ips.first
            return public_ips.first
          end
        end

        # return [String]: A password string.
        def getWindowsAdminPassword
        end

        # Add a volume to this instance
        # @param dev [String]: Device name to use when attaching to instance
        # @param size [String]: Size (in gb) of the new volume
        # @param type [String]: Cloud storage type of the volume, if applicable
        def addVolume(dev, size, type: "pd-standard")
          devname = dev.gsub(/.*?\/([^\/]+)$/, '\1')
          resname = MU::Cloud::Google.nameStr(@mu_name+"-"+devname)
          MU.log "Creating disk #{resname}"

          description = @deploy ? @deploy.deploy_id : @mu_name+"-"+devname

          newdiskobj = MU::Cloud::Google.compute(:Disk).new(
            size_gb: size,
            description: description,
            zone: @config['availability_zone'],
#            type: "projects/#{config['project']}/zones/#{config['availability_zone']}/diskTypes/pd-ssd",
            type: "projects/#{@config['project']}/zones/#{@config['availability_zone']}/diskTypes/pd-standard",
# Other values include pd-ssd and local-ssd
            name: resname
          )

          begin
            newdisk = MU::Cloud::Google.compute(credentials: @config['credentials']).insert_disk(
              @config['project'],
              @config['availability_zone'],
              newdiskobj
            )
          rescue ::Google::Apis::ClientError => e
            if e.message.match(/^alreadyExists: /)
              MU.log "Disk #{resname} already exists, ignoring request to create", MU::WARN
              return
            else
              raise e
            end
          end

          attachobj = MU::Cloud::Google.compute(:AttachedDisk).new(
            auto_delete: true,
            device_name: devname,
            source: newdisk.self_link,
            type: "PERSISTENT"
          )
          attachment = MU::Cloud::Google.compute(credentials: @config['credentials']).attach_disk(
            @config['project'],
            @config['availability_zone'],
            @cloud_id,
            attachobj
          )

        end

        # Determine whether the node in question exists at the Cloud provider
        # layer.
        # @return [Boolean]
        def active?
          true
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          false
        end

        # Remove all instances associated with the currently loaded deployment. Also cleans up associated volumes, droppings in the MU master's /etc/hosts and ~/.ssh, and in whatever Groomer was used.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          flags["project"] ||= MU::Cloud::Google.defaultProject(credentials)
          skipsnapshots = flags["skipsnapshots"]
          onlycloud = flags["onlycloud"]
# XXX make damn sure MU.deploy_id is set

          MU::Cloud::Google.listAZs(region).each { |az|
            disks = []
            resp = MU::Cloud::Google.compute(credentials: credentials).list_instances(
              flags["project"],
              az,
              filter: "description eq #{MU.deploy_id}"
            )
            if !resp.items.nil? and resp.items.size > 0
              resp.items.each { |instance|
                saname = instance.tags.items.first.gsub(/[^a-z]/, "") # XXX this nonsense again
                MU.log "Terminating instance #{instance.name}"
                if !instance.disks.nil? and instance.disks.size > 0
                  instance.disks.each { |disk|
                    disks << disk if !disk.auto_delete
                  }
                end
                deletia = MU::Cloud::Google.compute(credentials: credentials).delete_instance(
                  flags["project"],
                  az,
                  instance.name
                ) if !noop
                MU.log "Removing service account #{saname}"
                begin
                  MU::Cloud::Google.iam(credentials: credentials).delete_project_service_account(
                    "projects/#{flags["project"]}/serviceAccounts/#{saname}@#{flags["project"]}.iam.gserviceaccount.com"
                  ) if !noop
                rescue ::Google::Apis::ClientError => e
                  raise e if !e.message.match(/^notFound: /)
                end
# XXX wait-loop on pending?
#                pp deletia
              }
            end

            if disks.size > 0
# XXX make sure we don't miss anything that got created with dumb flags
            end
# XXX honor snapshotting
            MU::Cloud::Google.compute(credentials: credentials).delete(
              "disk",
              flags["project"],
              az,
              noop
            ) if !noop
          }
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "image_id" => {
              "type" => "string",
              "description" => "The Google Cloud Platform Image on which to base this instance. Will use the default appropriate for the platform, if not specified."
            },
            "routes" => {
              "type" => "array",
              "items" => MU::Config::VPC.routeschema
            }
          }
          [toplevel_required, schema]
        end

        # Confirm that the given instance size is valid for the given region.
        # If someone accidentally specified an equivalent size from some other cloud provider, return something that makes sense. If nothing makes sense, return nil.
        # @param size [String]: Instance type to check
        # @param region [String]: Region to check against
        # @return [String,nil]
        def self.validateInstanceType(size, region)
          types = (MU::Cloud::Google.listInstanceTypes(region))[region]
          if types and (size.nil? or !types.has_key?(size))
            # See if it's a type we can approximate from one of the other clouds
            atypes = (MU::Cloud::AWS.listInstanceTypes)[MU::Cloud::AWS.myRegion]
            foundmatch = false
            if atypes and atypes.size > 0 and atypes.has_key?(size)
              vcpu = atypes[size]["vcpu"]
              mem = atypes[size]["memory"]
              ecu = atypes[size]["ecu"]
              types.keys.sort.reverse.each { |type|
                features = types[type]
                next if ecu == "Variable" and ecu != features["ecu"]
                next if features["vcpu"] != vcpu
                if (features["memory"] - mem.to_f).abs < 0.10*mem
                  foundmatch = true
                  MU.log "You specified an Amazon instance type '#{size}.' Approximating with Google Compute type '#{type}.'", MU::WARN
                  size = type
                  break
                end
              }
            end
            if !foundmatch
              MU.log "Invalid size '#{size}' for Google Compute instance in #{region}. Supported types:", MU::ERR, details: types.keys.sort.join(", ")
              return nil
            end
          end
          size
        end


        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::servers}, bare and unvalidated.
        # @param server [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(server, configurator)
          ok = true

          server['size'] = validateInstanceType(server["size"], server["region"])
          ok = false if server['size'].nil?

          # If we're not targeting an availability zone, pick one randomly
          if !server['availability_zone']
            server['availability_zone'] = MU::Cloud::Google.listAZs(server['region']).sample
          end

          subnets = nil
          if !server['vpc']
            vpcs = MU::Cloud::Google::VPC.find
            if vpcs["default"]
              server["vpc"] ||= {}
              server["vpc"]["vpc_id"] = vpcs["default"].self_link
              subnets = vpcs["default"].subnetworks
              MU.log "No VPC specified for Server #{server['name']}, using default VPC for project #{server['project']}", MU::NOTICE
            else
              ok = false
              MU.log "You must specify a target VPC when creating a Server", MU::ERR
            end
          end

          if !server['vpc']['subnet_id'] and server['vpc']['subnet_name'].nil?
            if !subnets
              if server["vpc"]["vpc_id"]
                vpcs = MU::Cloud::Google::VPC.find(cloud_id: server["vpc"]["vpc_id"])
                subnets = vpcs["default"].subnetworks.sample
              end
            end

            if subnets
              server['vpc']['subnet_id'] = subnets.delete_if { |subnet|
                !subnet.match(/regions\/#{Regexp.quote(server['region'])}\/subnetworks/)
              }.sample
            end
            if server['vpc']['subnet_id'].nil?
              ok = false
              MU.log "Failed to identify a subnet in my region (#{server['region']})", MU::ERR, details: server["vpc"]["vpc_id"]
            end
          end

          if server['image_id'].nil?
            if MU::Config.google_images.has_key?(server['platform'])
              server['image_id'] = configurator.getTail("server"+server['name']+"Image", value: MU::Config.google_images[server['platform']], prettyname: "server"+server['name']+"Image", cloudtype: "Google::::Apis::ComputeBeta::Image")
            else
              MU.log "No image specified for #{server['name']} and no default available for platform #{server['platform']}", MU::ERR, details: server
              ok = false
            end
          end

          real_image = nil
          begin
            real_image = MU::Cloud::Google::Server.fetchImage(server['image_id'].to_s, credentials: server['credentials'])
          rescue ::Google::Apis::ClientError => e
            MU.log e.inspect, MU::WARN
          end

          if real_image.nil?
            MU.log "Image #{server['image_id']} for server #{server['name']} does not appear to exist", MU::ERR
            ok = false
          else
            server['image_id'] = real_image.self_link
            server['image_id'].match(/projects\/([^\/]+)\/.*?\/([^\/]+)$/)
            img_project = Regexp.last_match[1]
            img_name = Regexp.last_match[2]
            begin
              snaps = MU::Cloud::Google.compute(credentials: server['credentials']).list_snapshots(
                img_project,
                filter: "name eq #{img_name}-.*"
              )
              server['storage'] ||= []
              used_devs = server['storage'].map { |disk| disk['device'].gsub(/.*?\//, "") }
              snaps.items.each { |snap|
                next if !snap.labels.is_a?(Hash) or !snap.labels["mu-device-name"] or snap.labels["mu-parent-image"] != img_name
                devname = snap.labels["mu-device-name"]

                if used_devs.include?(devname)
                  MU.log "Device name #{devname} already declared in server #{server['name']} (snapshot #{snap.name} wants the name)", MU::ERR
                  ok = false
                end
                server['storage'] << {
                  "snapshot_id" => snap.self_link,
                  "size" => snap.disk_size_gb,
                  "delete_on_termination" => true, 
                  "device" => devname
                }
                used_devs << devname
              }
            rescue ::Google::Apis::ClientError => e
              # it's ok, sometimes we don't have permission to list snapshots
              # in other peoples' projects
              raise e if !e.message.match(/^forbidden: /)
            end
          end

          ok
        end

        private

      end #class
    end #class
  end
end #module
