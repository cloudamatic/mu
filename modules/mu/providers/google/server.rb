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

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super

          @userdata = if @config['userdata_script']
            @config['userdata_script']
          elsif @deploy and !@config['scrub_mu_isms']
            MU::Cloud.fetchUserdata(
              platform: @config["platform"],
              cloud: "Google",
              credentials: @config['credentials'],
              template_variables: {
                "deployKey" => Base64.urlsafe_encode64(@deploy.public_key),
                "deploySSHKey" => @deploy.ssh_public_key,
                "muID" => MU.deploy_id,
                "muUser" => MU.mu_user,
                "publicIP" => MU.mu_public_ip,
                "skipApplyUpdates" => @config['skipinitialupdates'],
                "windowsAdminName" => @config['windows_admin_username'],
                "adminBucketName" => MU::Cloud::Google.adminBucketName(@credentials),
                "chefVersion" => MU.chefVersion,
                "mommaCatPort" => MU.mommaCatPort,
                "resourceName" => @config["name"],
                "resourceType" => "server",
                "platform" => @config["platform"]
              },
              custom_append: @config['userdata_script']
            )
          end
# XXX writing things into @config at runtime is a bad habit and we should stop
          if !@mu_name.nil?
            @config['mu_name'] = @mu_name # XXX whyyyy
            # describe
            @mu_windows_name = @deploydata['mu_windows_name'] if @mu_windows_name.nil? and @deploydata
          else
            if kitten_cfg.has_key?("basis")
              @mu_name = @deploy.getResourceName(@config['name'], need_unique_string: true)
            else
              @mu_name = @deploy.getResourceName(@config['name'])
            end
            @config['mu_name'] = @mu_name

          end
          @config['instance_secret'] ||= Password.random(50)
          @config['ssh_user'] ||= "muadmin"

        end

        # Return the date/time a machine image was created.
        # @param image_id [String]: URL to a Google disk image
        # @param credentials [String]
        # @return [DateTime]
        def self.imageTimeStamp(image_id, credentials: nil)
          begin
            img = fetchImage(image_id, credentials: credentials)
            return DateTime.new if img.nil?
            return DateTime.parse(img.creation_timestamp)
          rescue ::Google::Apis::ClientError
          end

          return DateTime.new
        end

        @@image_id_map = {}

        # Retrieve the cloud descriptor for this machine image, which can be
        # a whole or partial URL. Will follow deprecation notices and retrieve
        # the latest version, if applicable.
        # @param image_id [String]: URL to a Google disk image
        # @param credentials [String]
        # @return [Google::Apis::ComputeV1::Image]
        def self.fetchImage(image_id, credentials: nil)
          return @@image_id_map[image_id] if @@image_id_map[image_id]

          img_proj = img_name = nil
          if image_id.match(/\//)
            img_proj = image_id.gsub(/(?:https?:\/\/.*?\.googleapis\.com\/compute\/.*?\/)?.*?\/?(?:projects\/)?([^\/]+)\/.*/, '\1')
            img_name = image_id.gsub(/.*?([^\/]+)$/, '\1')
          else
            img_name = image_id
          end

          begin
            @@image_id_map[image_id] = MU::Cloud::Google.compute(credentials: credentials).get_image_from_family(img_proj, img_name)
            return @@image_id_map[image_id]
          rescue ::Google::Apis::ClientError
            # This is fine- we don't know that what we asked for is really an
            # image family name, instead of just an image.
          end

          begin
            img = MU::Cloud::Google.compute(credentials: credentials).get_image(img_proj, img_name)
            if !img.deprecated.nil? and !img.deprecated.replacement.nil?
              image_id = img.deprecated.replacement
              img_proj = image_id.gsub(/(?:https?:\/\/.*?\.googleapis\.com\/compute\/.*?\/)?.*?\/?(?:projects\/)?([^\/]+)\/.*/, '\1')
              img_name = image_id.gsub(/.*?([^\/]+)$/, '\1')
            end
          rescue ::Google::Apis::ClientError => e
            # SOME people *cough* don't use deprecation or image family names
            # and just spew out images with a version appended to the name, so
            # let's try some crude semantic versioning list.
            if e.message.match(/^notFound: /) and img_name.match(/-[^\-]+$/)
              list = MU::Cloud::Google.compute(credentials: credentials).list_images(img_proj, filter: "name eq #{img_name.sub(/-[^\-]+$/, '')}-.*")
              if list and list.items
                latest = nil
                list.items.each { |candidate|
                  created = DateTime.parse(candidate.creation_timestamp)
                  if latest.nil? or created > latest
                    latest = created
                    img = candidate
                  end
                }
                if latest
                  MU.log "Mapped #{image_id} to #{img.name} with semantic versioning guesswork", MU::WARN
                  @@image_id_map[image_id] = img
                  return @@image_id_map[image_id]
                end
              end
            end
            raise e # if our little semantic versioning party trick failed
          end while !img.deprecated.nil? and img.deprecated.state == "DEPRECATED" and !img.deprecated.replacement.nil?
          final = MU::Cloud::Google.compute(credentials: credentials).get_image(img_proj, img_name)
          @@image_id_map[image_id] = final
          @@image_id_map[image_id]
        end

        # Generator for disk configuration parameters for a Compute instance
        # @param config [Hash]: The MU::Cloud::Server config hash for whom we're configuring disks
        # @param create [Boolean]: Actually create extra (non-root) disks, or just the one declared as the root disk of the image
        # @param disk_as_url [Boolean]: Whether to declare the disk type as a short string or full URL, which can vary depending on the calling resource
        # @return [Array]: The Compute :AttachedDisk objects describing disks that've been created
        def self.diskConfig(config, create = true, disk_as_url = true, credentials: nil)
          disks = []
          if config['image_id'].nil? and config['basis'].nil?
            raise MuError, "Can't generate disk configuration for server #{config['name']} without an image ID or basis specified"
          end

          img = fetchImage(config['image_id'] || config['basis']['launch_config']['image_id'], credentials: credentials)

#          if img.source_disk and img.source_disk.match(/projects\/([^\/]+)\/zones\/([^\/]+)\/disks\/(.*)/)
#            _junk, proj, az, name = Regexp.last_match
#            disk_desc = MU::Cloud::Google.compute(credentials: credentials).get_disk(proj, az, name)
#            pp disk_desc
#            raise "nah"
#          end

          disktype = "projects/#{config['project']}/zones/#{config['availability_zone']}/diskTypes/pd-standard"


          disktype.gsub!(/.*?\/([^\/])$/, '\1') if !disk_as_url

          imageobj = MU::Cloud::Google.compute(:AttachedDiskInitializeParams).new(
            source_image: img.self_link,
            disk_size_gb: img.disk_size_gb,
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
            # XXX if illegal subnets somehow creep in here, we'll need to be
            # picky by region or somesuch
            subnet_cfg = config['vpc']['subnets'].sample

          end

          subnet = vpc.getSubnet(name: subnet_cfg['subnet_name'], cloud_id: subnet_cfg['subnet_id'])
          if subnet.nil?
            if config['vpc']['name']
              subnet = vpc.getSubnet(name: config['vpc']['name']+subnet_cfg['subnet_name'], cloud_id: subnet_cfg['subnet_id'])
            end
            if subnet.nil?
              raise MuError, "Couldn't find subnet details for #{subnet_cfg['subnet_name'] || subnet_cfg['subnet_id']} while configuring Server #{config['name']} (VPC: #{vpc.mu_name})"
            end
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
          @project_id = MU::Cloud::Google.projectLookup(@config['project'], @deploy).cloud_id

          sa = nil
          retries = 0
          begin
            sa = MU::Config::Ref.get(@config['service_account'])
            if !sa or !sa.kitten or !sa.kitten.cloud_desc
              sleep 10
            end
          end while !sa or !sa.kitten or !sa.kitten.cloud_desc and retries < 5

          if !sa or !sa.kitten or !sa.kitten.cloud_desc
            raise MuError, "Failed to get service account cloud id from #{@config['service_account'].to_s}"
          end
          

          @service_acct = MU::Cloud::Google.compute(:ServiceAccount).new(
            email: sa.kitten.cloud_desc.email,
            scopes: @config['scopes']
          )
          if !@config['scrub_mu_isms']
            MU::Cloud::Google.grantDeploySecretAccess(@service_acct.email, credentials: @config['credentials'])
          end

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
              :service_accounts => [@service_acct],
              :network_interfaces => interfaces,
              :machine_type => "zones/"+@config['availability_zone']+"/machineTypes/"+@config['size'],
              :tags => MU::Cloud::Google.compute(:Tags).new(items: [MU::Cloud::Google.nameStr(@mu_name)])
            }
            desc[:disks] = disks if disks.size > 0

            metadata = {}
            if @config['metadata']
              metadata = Hash[@config['metadata'].map { |m|
                [m["key"], m["value"]]
              }]
            end
            metadata["startup-script"] = @userdata if @userdata and !@userdata.empty?

            deploykey = @config["ssh_user"]+":"+@deploy.ssh_public_key
            if metadata["ssh-keys"]
              metadata["ssh-keys"] += "\n"+deploykey
            else
              metadata["ssh-keys"] = deploykey
            end
            desc[:metadata] = MU::Cloud::Google.compute(:Metadata).new(
              :items => metadata.keys.map { |k|
                MU::Cloud::Google.compute(:Metadata)::Item.new(
                  key: k,
                  value: metadata[k]
                )
              }
            )

            # Tags in GCP means something other than what we think of;
            # labels are the thing you think you mean
            desc[:labels] = {}
            MU::MommaCat.listStandardTags.each_pair { |name, value|
              if !value.nil?
                desc[:labels][name.downcase] = value.downcase.gsub(/[^a-z0-9\-\_]/i, "_")
              end
            }
            desc[:labels]["name"] = @mu_name.downcase

            if @config['network_tags'] and @config['network_tags'].size > 0
              desc[:tags] = MU::Cloud::Google.compute(:Tags).new(
                items: @config['network_tags']
              )
            end

            instanceobj = MU::Cloud::Google.compute(:Instance).new(desc)

            MU.log "Creating instance #{@mu_name} in #{@project_id} #{@config['availability_zone']}", details: instanceobj

            begin
              instance = MU::Cloud::Google.compute(credentials: @config['credentials']).insert_instance(
                @project_id,
                @config['availability_zone'],
                instanceobj
              )
              if instance and instance.name
                @cloud_id = instance.name
              else
                sleep 10
              end
            rescue ::Google::Apis::ClientError => e
              MU.log e.message+" inserting instance into #{@project_id}/#{@config['availability_zone']}", MU::ERR, details: instanceobj
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

          rescue StandardError => e
            if !cloud_desc.nil? and !done
              MU.log "Aborted before I could finish setting up #{@config['name']}, cleaning it up. Stack trace will print once cleanup is complete.", MU::WARN if !@deploy.nocleanup
              MU::MommaCat.unlockAll
              if !@deploy.nocleanup
                parent_thread_id = Thread.current.object_id
                Thread.new {
                  MU.dupGlobals(parent_thread_id)
                  MU::Cloud::Google::Server.cleanup(noop: false, ignoremaster: false, flags: { "skipsnapshots" => true }, region: @config['region'] )
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
            "run_list" => [ "mu-nat" ],
            "groomer" => "Ansible",
            "platform" => "centos7",
            "src_dst_check" => false,
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
            @project_id,
            @config['availability_zone'],
            @cloud_id
          )
          begin
            sleep 5
          end while cloud_desc(use_cache: false).status != "TERMINATED" # means STOPPED
        end

        # Ask the Google API to start this node
        def start
          MU.log "Starting #{@cloud_id}"
          MU::Cloud::Google.compute(credentials: @config['credentials']).start_instance(
            @project_id,
            @config['availability_zone'],
            @cloud_id
          )
          begin
            sleep 5
          end while cloud_desc.status != "RUNNING"
        end

        # Ask the Google API to restart this node
        # @param _hard [Boolean]: [IGNORED] Force a stop/start. This is the only available way to restart an instance in Google, so this flag is ignored.
        def reboot(_hard = false)
          return if @cloud_id.nil?
          stop
          start
        end

        # Figure out what's needed to SSH into this server.
        # @return [Array<String>]: nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name, alternate_names
        def getSSHConfig
          describe(cloud_id: @cloud_id)
# XXX add some awesome alternate names from metadata and make sure they end
# up in MU::MommaCat's ssh config wangling
          return nil if @config.nil? or @deploy.nil?

          nat_ssh_key = nat_ssh_user = nat_ssh_host = nil
          if !@config["vpc"].nil? and !MU::Cloud.resourceClass("Google", "VPC").haveRouteToInstance?(cloud_desc, credentials: @config['credentials'])

            if !@nat.nil?
              if @nat.cloud_desc.nil?
                MU.log "NAT was missing cloud descriptor when called in #{@mu_name}'s getSSHConfig", MU::ERR
                return nil
              end
              _foo, _bar, _baz, nat_ssh_host, nat_ssh_user, nat_ssh_key  = @nat.getSSHConfig
              if nat_ssh_user.nil? and !nat_ssh_host.nil?
                MU.log "#{@config["name"]} (#{MU.deploy_id}) is configured to use #{@config['vpc']} NAT #{nat_ssh_host}, but username isn't specified. Guessing root.", MU::ERR, details: caller
                nat_ssh_user = "root"
              end
            end
          end

          if @config['ssh_user'].nil?
            if windows?
              @config['ssh_user'] = @config['windows_admin_user']
              @config['ssh_user'] ||= "Administrator"
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

          node, _config, deploydata = describe(cloud_id: @cloud_id)
          instance = cloud_desc
          raise MuError, "Couldn't find instance of #{@mu_name} (#{@cloud_id})" if !instance
          return false if !MU::MommaCat.lock(@cloud_id+"-orchestrate", true)
          return false if !MU::MommaCat.lock(@cloud_id+"-groom", true)

#          MU::Cloud::AWS.createStandardTags(@cloud_id, region: @config['region'])
#          MU::Cloud::AWS.createTag(@cloud_id, "Name", node, region: @config['region'])
#
#          if @config['optional_tags']
#            MU::MommaCat.listOptionalTags.each { |key, value|
#              MU::Cloud::AWS.createTag(@cloud_id, key, value, region: @config['region'])
#            }
#          end
#
#          if !@config['tags'].nil?
#            @config['tags'].each { |tag|
#              MU::Cloud::AWS.createTag(@cloud_id, tag['key'], tag['value'], region: @config['region'])
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

          _nat_ssh_key, _nat_ssh_user, nat_ssh_host, _canonical_ip, _ssh_user, _ssh_key_name = getSSHConfig
          if !nat_ssh_host and !MU::Cloud.resourceClass("Google", "VPC").haveRouteToInstance?(cloud_desc, credentials: @config['credentials'])
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
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching instances
        def self.find(**args)
          args = MU::Cloud::Google.findLocationArgs(args)

          if !args[:region].nil? and MU::Cloud::Google.listRegions.include?(args[:region])
            regions = [args[:region]]
          else
            regions = MU::Cloud::Google.listRegions
          end

          found = {}
          search_semaphore = Mutex.new
          search_threads = []

          # If we got an instance id, go get it
          parent_thread_id = Thread.current.object_id
          regions.each { |r|
            search_threads << Thread.new(r) { |region|
              Thread.abort_on_exception = false
              MU.dupGlobals(parent_thread_id)
              MU.log "Hunting for instance with cloud id '#{args[:cloud_id]}' in #{region}", MU::DEBUG
              MU::Cloud::Google.listAZs(region).each { |az|
                begin
                  if !args[:cloud_id].nil? and !args[:cloud_id].empty?
                    resp = MU::Cloud::Google.compute(credentials: args[:credentials]).get_instance(
                      args[:project],
                      az,
                      args[:cloud_id]
                    )
                    search_semaphore.synchronize {
                      found[args[:cloud_id]] = resp if !resp.nil?
                    }
                  else
                    resp = MU::Cloud::Google.compute(credentials: args[:credentials]).list_instances(
                      args[:project],
                      az
                    )
                    if resp and resp.items
                      resp.items.each { |instance|
                        search_semaphore.synchronize {
                          found[instance.name] = instance
                        }
                      }
                    end
                  end
                rescue ::OpenSSL::SSL::SSLError => e
                  MU.log "Got #{e.message} looking for instance #{args[:cloud_id]} in project #{args[:project]} (#{az}). Usually this means we've tried to query a non-functional region.", MU::DEBUG
                rescue ::Google::Apis::ClientError => e
                  raise e if !e.message.match(/^(?:notFound|forbidden): /)
                end
              }
            }
          }
          done_threads = []
          begin
            search_threads.reject! { |t| t.nil? }
            search_threads.each { |t|
              joined = t.join(2)
              done_threads << joined if !joined.nil?
            }
          end while found.size < 1 and done_threads.size != search_threads.size
          # Ok, well, let's try looking it up by IP then
#          if instance.nil? and !args[:ip].nil?
#            MU.log "Hunting for instance by IP '#{args[:ip]}'", MU::DEBUG
#          end

#          if !instance.nil?
#            return {instance.name => instance} if !instance.nil?
#          end

          # Fine, let's try it by tag.
#          if !args[:tag_value].nil?
#            MU.log "Searching for instance by tag '#{args[:tag_key]}=#{args[:tag_value]}'", MU::DEBUG
#          end

          return found
        end

        # Return a description of this resource appropriate for deployment
        # metadata. Arguments reflect the return values of the MU::Cloud::[Resource].describe method
        def notify
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
              "project_id" => @project_id,
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
          @project_id = MU::Cloud::Google.projectLookup(@config['project'], @deploy).cloud_id

          MU::MommaCat.lock(@cloud_id+"-groom")
          
          node, _config, deploydata = describe(cloud_id: @cloud_id)

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
                project: @project_id,
                exclude_storage: img_cfg['image_exclude_storage'],
                make_public: img_cfg['public'],
                tags: @tags,
                zone: @config['availability_zone'],
                family: img_cfg['family'],
                credentials: @config['credentials']
            )
            @deploy.notify("images", @config['name'], {"image_id" => image_id})
            @config['image_created'] = true
            if img_cfg['image_then_destroy']
              MU.log "Image #{image_id} ready, removing source node #{node}"
              MU::Cloud::Google.compute(credentials: @config['credentials']).delete_instance(
                @project_id,
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
        def self.createImage(name: nil, instance_id: nil, storage: {}, exclude_storage: false, project: nil, make_public: false, tags: [], region: nil, family: nil, zone: MU::Cloud::Google.listAZs.sample, credentials: nil)
          project ||= MU::Cloud::Google.defaultProject(credentials)
          instance = MU::Cloud::Server.find(cloud_id: instance_id, region: region)
          if instance.nil?
            raise MuError, "Failed to find instance '#{instance_id}' in createImage"
          end

          labels = Hash[tags.keys.map { |k|
            [k.downcase, tags[k].downcase.gsub(/[^-_a-z0-9]/, '-')] }
          ]
          labels["name"] = name

          bootdisk = nil
          threads = []
          parent_thread_id = Thread.current.object_id
          if !exclude_storage
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
          end
          threads.each do |t|
            t.join
          end

          labels["name"] = instance_id.downcase
          image_desc = {
            :name => name,
            :source_disk => bootdisk,
            :description => "Mu image created from #{name}",
            :labels => labels
          }
          image_desc[:family] = family if family

          MU.log "Creating image of #{name}", MU::NOTICE, details: image_desc
          newimage = MU::Cloud::Google.compute(credentials: credentials).insert_image(
            project,
            MU::Cloud::Google.compute(:Image).new(image_desc)
          )

          if make_public
            MU.log "Making image #{newimage.name} public"
            MU::Cloud::Google.compute(credentials: credentials).set_image_iam_policy(
              project,
              newimage.name,
              MU::Cloud::Google.compute(:GlobalSetPolicyRequest).new(
                bindings: [
                  MU::Cloud::Google.compute(:Binding).new(
                    members: ["allAuthenticatedUsers"],
                    role: "roles/compute.imageUser"
                  )
                ],
              )
            )
          end

          newimage.name
        end

        # Return the IP address that we, the Mu server, should be using to access
        # this host via the network. Note that this does not factor in SSH
        # bastion hosts that may be in the path, see getSSHConfig if that's what
        # you need.
        def canonicalIP
          describe(cloud_id: @cloud_id)

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
          if MU::Cloud.resourceClass("Google", "VPC").haveRouteToInstance?(cloud_desc, credentials: @config['credentials']) or public_ips.size == 0
            @config['canonical_ip'] = private_ips.first
            return private_ips.first
          else
            @config['canonical_ip'] = public_ips.first
            return public_ips.first
          end
        end

        # Return all of the IP addresses, public and private, from all of our
        # network interfaces.
        # @return [Array<String>]
        def listIPs
          ips = []
          cloud_desc.network_interfaces.each { |iface|
            ips << iface.network_ip
            if iface.access_configs
              iface.access_configs.each { |acfg|
                ips << acfg.nat_ip if acfg.nat_ip
              }
            end
          }
          ips
        end

        # return [String]: A password string.
        def getWindowsAdminPassword(use_cache: true)
          @config['windows_auth_vault'] ||= {
            "vault" => @mu_name,
            "item" => "windows_credentials",
            "password_field" => "password"
          }

          if use_cache
            begin
              win_admin_password = @groomer.getSecret(
                vault: @config['windows_auth_vault']['vault'],
                item: @config['windows_auth_vault']['item'],
                field: @config["windows_auth_vault"]["password_field"]
              )
              return win_admin_password if win_admin_password
            rescue MU::Groomer::MuNoSuchSecret, MU::Groomer::RunError
            end
          end

          require 'openssl/oaep'
          timeout = 300

          serial_out = nil
          key = OpenSSL::PKey::RSA.generate 2048

          missing_response = Proc.new {
            !serial_out or !serial_out.contents or serial_out.contents.empty? or JSON.parse(serial_out.contents)["userName"] != @config['windows_admin_username']
          }

          did_metadata = false
          MU.retrier(loop_if: missing_response, wait: 10, max: timeout/10) {
            serial_out = MU::Cloud::Google.compute(credentials: @credentials).get_instance_serial_port_output(@project_id, @config['availability_zone'], @cloud_id, port: 4)

            if missing_response.call and
               !cloud_desc(use_cache: false).metadata.items.map { |i| i.key }.include?("windows-keys")
              keybytes = Base64.decode64(key.public_key.export.gsub(/-----(?:BEGIN|END) PUBLIC KEY-----/, ''))
              modulus = keybytes.byteslice(33,256)
              exponent = keybytes.byteslice(291,3)
              keydata = {
                "userName" => @config['windows_admin_username'],
                "modulus" => Base64.strict_encode64(modulus),
                "exponent" => Base64.strict_encode64(exponent),
                "email" => MU.muCfg['mu_admin_email'],
                "expireOn" => (Time.now.utc+timeout).strftime('%Y-%m-%dT%H:%M:%SZ')
              }

              new_items = cloud_desc.metadata.items.map { |item|
                MU::Cloud::Google.compute(:Metadata)::Item.new(
                  key: item.key,
                  value: item.value
                )
              }
              new_items.reject! { |item| item.key == "windows-keys" }
              new_items << MU::Cloud::Google.compute(:Metadata)::Item.new(
                key: "windows-keys",
                value: JSON.generate(keydata)
              )
              new_metadata = MU::Cloud::Google.compute(:Metadata).new(
                fingerprint: cloud_desc(use_cache: false).metadata.fingerprint,
                items: new_items
              )

              MU::Cloud::Google.compute(credentials: @credentials).set_instance_metadata(@project_id, @config['availability_zone'], @cloud_id, new_metadata)
            end
          }

          return nil if missing_response.call

          pwdata = JSON.parse(serial_out.contents)
          if pwdata['encryptedPassword'] and pwdata['userName'] == @config['windows_admin_username']
            decrypted_pw = key.private_decrypt_oaep(Base64.strict_decode64(pwdata['encryptedPassword']))
            creds = {
              "username" => @config['windows_admin_username'],
              "password" => decrypted_pw,
              "sshd_username" => "sshd_service",
              "sshd_password" => decrypted_pw
            }
            @groomer.saveSecret(vault: @mu_name, item: "windows_credentials", data: creds, permissions: "name:#{@mu_name}")

            return decrypted_pw
          end

          nil
        end


        # Add a volume to this instance
        # @param dev [String]: Device name to use when attaching to instance
        # @param size [String]: Size (in gb) of the new volume
        # @param type [String]: Cloud storage type of the volume, if applicable
        # @param delete_on_termination [Boolean]: Value of delete_on_termination flag to set
        def addVolume(dev: nil, size: 0, type: "pd-standard", delete_on_termination: false)
          if dev.nil? or size == 0
            raise MuError, "Must specify a device name and a size for addVolume"
          end
                                        
          devname = dev.gsub(/.*?\/([^\/]+)$/, '\1')
          resname = MU::Cloud::Google.nameStr(@mu_name+"-"+devname)
          MU.log "Creating disk #{resname}"

          description = @deploy ? @deploy.deploy_id : @mu_name+"-"+devname

          newdiskobj = MU::Cloud::Google.compute(:Disk).new(
            size_gb: size,
            description: description,
            zone: @config['availability_zone'],
#            type: "projects/#{config['project']}/zones/#{config['availability_zone']}/diskTypes/pd-ssd",
            type: "projects/#{@project_id}/zones/#{@config['availability_zone']}/diskTypes/#{type}",
# Other values include pd-ssd and local-ssd
            name: resname
          )

          begin
            newdisk = MU::Cloud::Google.compute(credentials: @config['credentials']).insert_disk(
              @project_id,
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
            device_name: devname,
            source: newdisk.self_link,
            type: "PERSISTENT",
            auto_delete: delete_on_termination
          )

          MU.log "Attaching disk #{resname} to #{@cloud_id} at #{devname}"
          MU::Cloud::Google.compute(credentials: @config['credentials']).attach_disk(
            @project_id,
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

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(**_args)
          bok = {
            "cloud" => "Google",
            "credentials" => @config['credentials'],
            "cloud_id" => @cloud_id,
            "project" => @project_id
          }
          if !cloud_desc
            MU.log "toKitten failed to load a cloud_desc from #{@cloud_id}", MU::ERR, details: @config
            return nil
          end
          bok['name'] = cloud_desc.name

          # XXX we can have multiple network interfaces, and often do; need
          # language to account for this
          iface = cloud_desc.network_interfaces.first
          iface.network.match(/(?:^|\/)projects\/(.*?)\/.*?\/networks\/([^\/]+)(?:$|\/)/)
          vpc_proj = Regexp.last_match[1]
          vpc_id = Regexp.last_match[2]

          bok['vpc'] = MU::Config::Ref.get(
            id: vpc_id,
            cloud: "Google",
            habitat: MU::Config::Ref.get(
              id: vpc_proj,
              cloud: "Google",
              credentials: @credentials,
              type: "habitats"
            ),
            credentials: @credentials,
            type: "vpcs",
            subnet_id: iface.subnetwork.sub(/.*?\/([^\/]+)$/, '\1')
          )

          cloud_desc.disks.each { |disk|
            next if !disk.source
            disk.source.match(/\/projects\/([^\/]+)\/zones\/([^\/]+)\/disks\/(.*)/)
            proj = Regexp.last_match[1]
            az = Regexp.last_match[2]
            name = Regexp.last_match[3]
            begin
              disk_desc = MU::Cloud::Google.compute(credentials: @credentials).get_disk(proj, az, name)
              if disk_desc.source_image and disk.boot
                bok['image_id'] ||= disk_desc.source_image.sub(/^https:\/\/www\.googleapis\.com\/compute\/[^\/]+\//, '')
              else
                bok['storage'] ||= []
                storage_blob = {
                  "size" => disk_desc.size_gb,
                  "device" => "/dev/xvd"+(disk.index+97).chr.downcase
                }
                bok['storage'] <<  storage_blob
              end
            rescue ::Google::Apis::ClientError => e
              MU.log "Failed to retrieve disk #{name} attached to server #{@cloud_id} in #{proj}/#{az}", MU::WARN, details: e.message
              next
            end
            
          }

          if cloud_desc.labels
            bok['tags'] = cloud_desc.labels.keys.map { |k| { "key" => k, "value" => cloud_desc.labels[k] } }
          end
          if cloud_desc.tags and cloud_desc.tags.items and cloud_desc.tags.items.size > 0
            bok['network_tags'] = cloud_desc.tags.items
          end
          bok['src_dst_check'] = !cloud_desc.can_ip_forward
          bok['size'] = cloud_desc.machine_type.sub(/.*?\/([^\/]+)$/, '\1')
          bok['project'] = @project_id
          if cloud_desc.service_accounts
            bok['scopes'] = cloud_desc.service_accounts.map { |sa| sa.scopes }.flatten.uniq
          end
          if cloud_desc.metadata and cloud_desc.metadata.items
            bok['metadata'] = cloud_desc.metadata.items.map { |m| MU.structToHash(m) }
          end

          # Skip nodes that are just members of GKE clusters
          if bok['name'].match(/^gke-.*?-[a-f0-9]+-[a-z0-9]+$/) and
             bok['image_id'].match(/(:?^|\/)projects\/gke-node-images\//)
            found_gke_tag = false
            bok['network_tags'].each { |tag|
              if tag.match(/^gke-/)
                found_gke_tag = true
                break
              end
            }
            if found_gke_tag
              MU.log "Server #{bok['name']} appears to belong to a ContainerCluster, skipping adoption", MU::DEBUG
              return nil
            end
          end

          if bok['metadata']
            bok['metadata'].each { |item|
              if item[:key] == "created-by" and item[:value].match(/\/instanceGroupManagers\//)
                MU.log "Server #{bok['name']} appears to belong to a ServerPool, skipping adoption", MU::DEBUG, details: item[:value]
                return nil
              end
            }
          end


          bok
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          false
        end

        # Denote whether this resource implementation is experiment, ready for
        # testing, or ready for production use.
        def self.quality
          MU::Cloud::RELEASE
        end

        # Remove all instances associated with the currently loaded deployment. Also cleans up associated volumes, droppings in the MU master's /etc/hosts and ~/.ssh, and in whatever Groomer was used.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          flags["habitat"] ||= MU::Cloud::Google.defaultProject(credentials)
          return if !MU::Cloud.resourceClass("Google", "Habitat").isLive?(flags["habitat"], credentials)

# XXX make damn sure MU.deploy_id is set
          filter = %Q{(labels.mu-id = "#{MU.deploy_id.downcase}")}
          if !ignoremaster and MU.mu_public_ip
            filter += %Q{ AND (labels.mu-master-ip = "#{MU.mu_public_ip.gsub(/\./, "_")}")}
          end

          MU::Cloud::Google.listAZs(region).each { |az|
            disks = []
            resp = MU::Cloud::Google.compute(credentials: credentials).list_instances(
              flags["habitat"],
              az,
              filter: filter
            )
            if !resp.items.nil? and resp.items.size > 0
              resp.items.each { |instance|
                MU.log "Terminating instance #{instance.name}"
                if !instance.disks.nil? and instance.disks.size > 0
                  instance.disks.each { |disk|
                    disks << disk if !disk.auto_delete
                  }
                end
                MU::Cloud::Google.compute(credentials: credentials).delete_instance(
                  flags["habitat"],
                  az,
                  instance.name
                ) if !noop
                if instance.service_accounts
                  instance.service_accounts.each { |sa|
                    MU.log "Removing service account #{sa.email}"
                    begin
                      MU::Cloud::Google.iam(credentials: credentials).delete_project_service_account(
                        "projects/#{flags["habitat"]}/serviceAccounts/#{sa.email}"
                      ) if !noop
                    rescue ::Google::Apis::ClientError => e
                      raise e if !e.message.match(/^notFound: /)
                    end
                  }
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
              flags["habitat"],
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
            "roles" => MU::Cloud.resourceClass("Google", "User").schema(config)[1]["roles"],
            "windows_admin_username" => {
              "type" => "string",
              "default" => "muadmin"
            },
            "create_image" => {
              "properties" => {
                "family" => {
                  "type" => "string",
                  "description" => "Add a GCP image +family+ string to the created image(s)"
                }
              }
            },
            "availability_zone" => {
              "type" => "string",
              "description" => "Target this instance to a specific Availability Zone"
            },
            "ssh_user" => {
              "type" => "string",
              "description" => "Account to use when connecting via ssh. Google Cloud images don't come with predefined remote access users, and some don't work with our usual default of +root+, so we recommend using some other (non-root) username.",
              "default" => "muadmin"
            },
            "network_tags" => {
              "type" => "array",
              "items" => {
                "type" => "string",
                "description" => "Add a network tag to this host, which can be used to selectively apply routes or firewall rules."
              }
            },
            "service_account" => MU::Config::Ref.schema(
              type: "users",
              desc: "An existing service account to use instead of the default one generated by Mu during the deployment process."
            ),
            "metadata" => {
              "type" => "array",
              "items" => {
                "type" => "object",
                "description" => "Custom key-value pairs to be added to the metadata of Google Cloud virtual machines",
                "required" => ["key", "value"],
                "properties" => {
                  "key" => {
                    "type" => "string"
                  },
                  "value" => {
                    "type" => "string"
                  }
                }
              }
            },
            "routes" => {
              "type" => "array",
              "items" => MU::Config::VPC.routeschema
            },
            "scopes" => {
              "type" => "array",
              "items" => {
                "type" => "string",
                "description" => "API scopes to make available to this resource's service account."
              },
              "default" => ["https://www.googleapis.com/auth/compute.readonly", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/cloud-platform", "https://www.googleapis.com/auth/monitoring.write", "https://www.googleapis.com/auth/devstorage.read_only"]
            }
          }
          [toplevel_required, schema]
        end

        @@instance_type_cache = {}

        # Confirm that the given instance size is valid for the given region.
        # If someone accidentally specified an equivalent size from some other cloud provider, return something that makes sense. If nothing makes sense, return nil.
        # @param size [String]: Instance type to check
        # @param region [String]: Region to check against
        # @return [String,nil]
        def self.validateInstanceType(size, region, project: nil, credentials: nil)
          size = size.dup.to_s
          if @@instance_type_cache[project] and
             @@instance_type_cache[project][region] and
             @@instance_type_cache[project][region][size]
            return @@instance_type_cache[project][region][size]
          end

          if size.match(/\/?custom-(\d+)-(\d+)(?:-ext)?$/)
            cpus = Regexp.last_match[1].to_i
            mem = Regexp.last_match[2].to_i
            ok = true
            if cpus < 1 or cpus > 32 or (cpus % 2 != 0 and cpus != 1)
              MU.log "Custom instance type #{size} illegal: CPU count must be 1 or an even number between 2 and 32", MU::ERR
              ok = false
            end
            if (mem % 256) != 0
              MU.log "Custom instance type #{size} illegal: Memory must be a multiple of 256 (MB)", MU::ERR
              ok = false
            end
            if ok
              return "custom-#{cpus.to_s}-#{mem.to_s}"
            else
              return nil
            end
          end

          project ||= MU::Cloud::Google.defaultProject(credentials)

          @@instance_type_cache[project] ||= {}
          @@instance_type_cache[project][region] ||= {}
          types = MU::Cloud::Google.listInstanceTypes(region, project: project, credentials: credentials)[project][region]
          realsize = size.dup

          if types and (realsize.nil? or !types.has_key?(realsize))
            # See if it's a type we can approximate from one of the other clouds
            foundmatch = false
            MU::Cloud.availableClouds.each { |cloud|
              next if cloud == "Google"
              foreign_types = (MU::Cloud.cloudClass(cloud).listInstanceTypes).values.first
              if foreign_types.size == 1
                foreign_types = foreign_types.values.first
              end
              if foreign_types and foreign_types.size > 0 and foreign_types.has_key?(size)
                vcpu = foreign_types[size]["vcpu"]
                mem = foreign_types[size]["memory"]
                ecu = foreign_types[size]["ecu"]
                types.keys.sort.reverse.each { |type|
                  features = types[type]
                  next if ecu == "Variable" and ecu != features["ecu"]
                  next if features["vcpu"] != vcpu
                  if (features["memory"] - mem.to_f).abs < 0.10*mem
                    foundmatch = true
                    MU.log "You specified #{cloud} instance type '#{realsize}.' Approximating with Google Compute type '#{type}.'", MU::WARN
                    realsize = type
                    break
                  end
                }
              end
              break if foundmatch
            }

            if !foundmatch
              MU.log "Invalid size '#{realsize}' for Google Compute instance in #{region} (checked project #{project}). Supported types:", MU::ERR, details: types.keys.sort.join(", ")
              @@instance_type_cache[project][region][size] = nil
              return nil
            end
          end
          @@instance_type_cache[project][region][size] = realsize
          @@instance_type_cache[project][region][size]
        end


        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::servers}, bare and unvalidated.
        # @param server [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(server, configurator)
          ok = true

          server['project'] ||= MU::Cloud::Google.defaultProject(server['credentials'])

          size = validateInstanceType(server["size"], server["region"], project: server['project'], credentials: server['credentials'])

          if size.nil?
            MU.log "Failed to verify instance size #{server["size"]} for Server #{server['name']}", MU::WARN
          else
            server["size"] = size
          end

          # If we're not targeting an availability zone, pick one randomly
          if !server['availability_zone']
            server['availability_zone'] = MU::Cloud::Google.listAZs(server['region']).sample
          end

          if server['service_account']
            server['service_account'] = server['service_account'].to_h
            server['service_account']['cloud'] = "Google"
            server['service_account']['habitat'] ||= server['project']
            found = MU::Config::Ref.get(server['service_account'])
            if found.id and !found.kitten
              MU.log "GKE server #{server['name']} failed to locate service account #{server['service_account']} in project #{server['project']}", MU::ERR
              ok = false
            end
          else
            server = MU::Cloud.resourceClass("Google", "User").genericServiceAccount(server, configurator)
          end

          subnets = nil
          if !server['vpc']
            vpcs = MU::Cloud.resourceClass("Google", "VPC").find(credentials: server['credentials'])
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
                vpcs = MU::Cloud.resourceClass("Google", "VPC").find(cloud_id: server["vpc"]["vpc_id"])
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

          if server['vpc']
            server['vpc']['project'] ||= server['project']
          end

          if server['image_id'].nil?
            img_id = MU::Cloud.getStockImage("Google", platform: server['platform'])
            if img_id
              server['image_id'] = configurator.getTail("server"+server['name']+"Image", value: img_id, prettyname: "server"+server['name']+"Image", cloudtype: "Google::Apis::ComputeV1::Image")
            else
              MU.log "No image specified for #{server['name']} and no default available for platform #{server['platform']}", MU::ERR, details: server
              ok = false
            end
          end

          real_image = nil
          begin
            real_image = MU::Cloud::Google::Server.fetchImage(server['image_id'].to_s, credentials: server['credentials'])
          rescue ::Google::Apis::ClientError => e
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
              MU::Cloud::Google.compute(credentials: server['credentials']).get_image(img_project, img_name)
              snaps = MU::Cloud::Google.compute(credentials: server['credentials']).list_snapshots(
                img_project,
                filter: "name eq #{img_name}-.*"
              )
              server['storage'] ||= []
              used_devs = server['storage'].map { |disk| disk['device'].gsub(/.*?\//, "") }
              if snaps and snaps.items
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
                if snaps.items.size > 0
#                  MU.log img_name, MU::WARN, details: snaps.items
                end
              end
            rescue ::Google::Apis::ClientError => e
              # it's ok, sometimes we don't have permission to list snapshots
              # in other peoples' projects
#              MU.log img_name, MU::WARN, details: img
              raise e if !e.message.match(/^forbidden: /)
            end
          end

          ok
        end

      end #class
    end #class
  end
end #module
