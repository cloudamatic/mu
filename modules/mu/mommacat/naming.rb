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

    # Lookup table to translate the word "habitat" back to its
    # provider-specific jargon
    HABITAT_SYNONYMS = {
      "AWS" => "account",
      "CloudFormation" => "account",
      "Google" => "project",
      "Azure" => "subscription",
      "VMWare" => "sddc"
    }

    # Given a cloud provider's native descriptor for a resource, make some
    # reasonable guesses about what the thing's name should be.
    def self.guessName(desc, resourceclass, cloud_id: nil, tag_value: nil)
      if desc.respond_to?(:tags) and
         desc.tags.is_a?(Array) and
         desc.tags.first.respond_to?(:key) and
         desc.tags.map { |t| t.key }.include?("Name")
        desc.tags.select { |t| t.key == "Name" }.first.value
      else
        try = nil
        # Various GCP fields
        [:display_name, :name, (resourceclass.cfg_name+"_name").to_sym].each { |field|
          if desc.respond_to?(field) and desc.send(field).is_a?(String)
            try = desc.send(field)
            break
          end

        }
        try ||= if !tag_value.nil?
            tag_value
          else
            cloud_id
          end
        try
      end

    end

    # Given a piece of a BoK resource descriptor Hash, come up with shorthand
    # strings to give it a name for human readers. If nothing reasonable can be
    # extracted, returns nil.
    # @param obj [Hash]
    # @param array_of [String]
    # @param habitat_translate [String]
    # @return [Array<String,nil>]
    def self.getChunkName(obj, array_of = nil, habitat_translate: nil)
      return [nil, nil] if obj.nil?
      if [String, Integer, Boolean].include?(obj.class)
        return [obj, nil]
      end
      obj_type = array_of || obj['type']
      obj_name = obj['name'] || obj['id'] || obj['mu_name'] || obj['cloud_id']

      name_string = if obj_name
        if obj_type
          "#{obj_type}[#{obj_name}]"
        else
          obj_name.dup
        end
      else
        found_it = nil
        using = nil
        ["entity", "role"].each { |subtype|
          if obj[subtype] and obj[subtype].is_a?(Hash)
            found_it = if obj[subtype]["id"]
              obj[subtype]['id'].dup
            elsif obj[subtype]["type"] and obj[subtype]["name"]
              "#{obj[subtype]['type']}[#{obj[subtype]['name']}]"
            end
            break
          end
        }
        found_it
      end
      if name_string
        name_string.gsub!(/\[.+?\](\[.+?\]$)/, '\1')
        if habitat_translate and HABITAT_SYNONYMS[habitat_translate]
          name_string.sub!(/^habitats?\[(.+?)\]/i, HABITAT_SYNONYMS[habitat_translate]+'[\1]')
        end
      end

      location_list = []

      location = if obj['project']
        obj['project']
      elsif obj['habitat'] and (obj['habitat']['id'] or obj['habitat']['name'])
        obj['habitat']['name'] || obj['habitat']['id']
      else
        hab_str = nil
        ['projects', 'habitats'].each { |key|

          if obj[key] and obj[key].is_a?(Array)
            location_list = obj[key].sort.map { |p|
              (p["name"] || p["id"]).gsub(/^.*?[^\/]+\/([^\/]+)$/, '\1')
            }
            hab_str = location_list.join(", ")
            name_string.gsub!(/^.*?[^\/]+\/([^\/]+)$/, '\1') if name_string
            break
          end
        }
        hab_str
      end

      [name_string, location, location_list]
    end

    # Generate a three-character string which can be used to unique-ify the
    # names of resources which might potentially collide, e.g. Windows local
    # hostnames, Amazon Elastic Load Balancers, or server pool instances.
    # @return [String]: A three-character string consisting of two alphnumeric
    # characters (uppercase) and one number.
    def self.genUniquenessString
      begin
        candidate = SecureRandom.base64(2).slice(0..1) + SecureRandom.random_number(9).to_s
        candidate.upcase!
      end while candidate.match(/[^A-Z0-9]/)
      return candidate
    end

    @unique_map_semaphore = Mutex.new
    @name_unique_str_map = {}
    # Keep a map of the uniqueness strings we assign to various full names, in
    # case we want to reuse them later.
    # @return [Hash<String>]
    def self.name_unique_str_map
      @name_unique_str_map
    end

    # Keep a map of the uniqueness strings we assign to various full names, in
    # case we want to reuse them later.
    # @return [Mutex]
    def self.unique_map_semaphore
      @unique_map_semaphore
    end

    # Generate a name string for a resource, incorporate the MU identifier
    # for this deployment. Will dynamically shorten the name to fit for
    # restrictive uses (e.g. Windows local hostnames, Amazon Elastic Load
    # Balancers).
    # @param name [String]: The shorthand name of the resource, usually the value of the "name" field in an Mu resource declaration.
    # @param max_length [Integer]: The maximum length of the resulting resource name.
    # @param need_unique_string [Boolean]: Whether to forcibly append a random three-character string to the name to ensure it's unique. Note that this behavior will be automatically invoked if the name must be truncated.
    # @param scrub_mu_isms [Boolean]: Don't bother with generating names specific to this deployment. Used to generate generic CloudFormation templates, amongst other purposes.
    # @param disallowed_chars [Regexp]: A pattern of characters that are illegal for this resource name, such as +/[^a-zA-Z0-9-]/+
    # @return [String]: A full name string for this resource
    def getResourceName(name, max_length: 255, need_unique_string: false, use_unique_string: nil, reuse_unique_string: false, scrub_mu_isms: @original_config['scrub_mu_isms'], disallowed_chars: nil, never_gen_unique: false)
      if name.nil?
        raise MuError, "Got no argument to MU::MommaCat.getResourceName"
      end
      if @appname.nil? or @environment.nil? or @timestamp.nil? or @seed.nil?
        MU.log "getResourceName: Missing global deploy variables in thread #{Thread.current.object_id}, using bare name '#{name}' (appname: #{@appname}, environment: #{@environment}, timestamp: #{@timestamp}, seed: #{@seed}, deploy_id: #{@deploy_id}", MU::WARN, details: caller
        return name
      end
      need_unique_string = false if scrub_mu_isms

      muname = nil
      if need_unique_string
        reserved = 4
      else
        reserved = 0
      end

      # First, pare down the base name string until it will fit
      basename = @appname.upcase + "-" + @environment.upcase + "-" + @timestamp + "-" + @seed.upcase + "-" + name.upcase
      if scrub_mu_isms
        basename = @appname.upcase + "-" + @environment.upcase + name.upcase
      end

      subchar = if disallowed_chars
        if "-".match(disallowed_chars)
          if !"_".match(disallowed_chars)
            "_"
          else
            ""
          end
        end
      end
      subchar ||= "-"

      basename.gsub!(disallowed_chars, subchar) if disallowed_chars

      attempts = 0
      tried_left = tried_right = tried_both = false
      begin
        if (basename.length + reserved) > max_length
          MU.log "Stripping name down from #{basename}[#{basename.length.to_s}] (reserved: #{reserved.to_s}, max_length: #{max_length.to_s})", MU::DEBUG
          if basename == @appname.upcase + subchar + @seed.upcase + subchar + name.upcase
            # If we've run out of stuff to strip, truncate what's left and
            # just leave room for the deploy seed and uniqueness string. This
            # is the bare minimum, and probably what you'll see for most Windows
            # hostnames.
            basename = name.upcase + subchar + @appname.upcase
            basename.slice!((max_length-(reserved+3))..basename.length)
            basename.sub!(/-$/, "")
            basename = basename + subchar + @seed.upcase
            basename.gsub!(disallowed_chars, subchar) if disallowed_chars
          else
            # If we have to strip anything, assume we've lost uniqueness and
            # will have to compensate with #genUniquenessString.
            if !never_gen_unique
              need_unique_string = true
              reserved = 4
            end
            overrun = (basename.length + reserved) - max_length
puts overrun
            if overrun <= (name.length - 2) and name.length > 2 and !tried_right
              basename = @appname.upcase + subchar + environment.upcase + subchar + @timestamp + subchar + @seed.upcase + subchar + name.upcase.slice(0, name.length-overrun)
              tried_right = true
            elsif overrun <= (@appname.length - 2) and @appname.length > 2 and !tried_left
              basename = @appname.upcase.slice(0, @appname.length-overrun) + subchar + environment.upcase + subchar + @timestamp + subchar + @seed.upcase + subchar + name.upcase
              tried_left = true
            elsif overrun <= (@appname.length + name.length - 4) and name.length > 2 and @appname.length > 2 and !tried_both
              appshort = @appname.slice(0, (overrun % 2 == 0) ? overrun/2 : (overrun-1)/2)
              nameshort = name.slice(0, (overrun % 2 == 0) ? overrun/2 : (overrun+1)/2)
              basename = appshort.upcase + subchar + environment.upcase + subchar + @timestamp + subchar + @seed.upcase + subchar + nameshort.upcase
              tried_both = true
            else
              basename.sub!(/#{subchar}[^-]+#{subchar}#{@seed.upcase}#{subchar}#{Regexp.escape(name.upcase)}$/, "")
              basename = basename + subchar + @seed.upcase + subchar + name.upcase
            end
            basename.gsub!(disallowed_chars, subchar) if disallowed_chars
          end
        end
        attempts += 1
        raise MuError, "Failed to generate a reasonable name getResourceName(#{name}, max_length: #{max_length.to_s}, need_unique_string: #{need_unique_string.to_s}, use_unique_string: #{use_unique_string.to_s}, reuse_unique_string: #{reuse_unique_string.to_s}, scrub_mu_isms: #{scrub_mu_isms.to_s}, disallowed_chars: #{disallowed_chars})" if attempts > 10
      end while (basename.length + reserved) > max_length

      # Finally, apply our short random differentiator, if it's needed.
      if need_unique_string
        # Preferentially use a requested one, if it's not already in use.
        if !use_unique_string.nil?
          muname = basename + "-" + use_unique_string
          if !allocateUniqueResourceName(muname) and !reuse_unique_string
            MU.log "Requested to use #{use_unique_string} as differentiator when naming #{name}, but the name #{muname} is unavailable.", MU::WARN
            muname = nil
          end
        end
        if !muname
          begin
            unique_string = MU::MommaCat.genUniquenessString
            muname = basename + "-" + unique_string
          end while !allocateUniqueResourceName(muname)
          MU::MommaCat.unique_map_semaphore.synchronize {
            MU::MommaCat.name_unique_str_map[muname] = unique_string
          }
        end
      else
        muname = basename
      end
      muname.gsub!(disallowed_chars, subchar) if disallowed_chars

      return muname
    end

    # List the name/value pairs for our mandatory standard set of resource tags, which
    # should be applied to all taggable cloud provider resources.
    # @return [Hash<String,String>]
    def self.listStandardTags
      return {} if !MU.deploy_id
      {
        "MU-ID" => MU.deploy_id,
        "MU-APP" => MU.appname,
        "MU-ENV" => MU.environment,
        "MU-MASTER-IP" => MU.mu_public_ip
      }
    end
    # List the name/value pairs for our mandatory standard set of resource tags
    # for this deploy.
    # @return [Hash<String,String>]
    def listStandardTags
      {
        "MU-ID" => @deploy_id,
        "MU-APP" => @appname,
        "MU-ENV" => @environment,
        "MU-MASTER-IP" => MU.mu_public_ip
      }
    end

    # List the name/value pairs of our optional set of resource tags which
    # should be applied to all taggable cloud provider resources.
    # @return [Hash<String,String>]
    def self.listOptionalTags
      return {
        "MU-HANDLE" => MU.handle,
        "MU-MASTER-NAME" => Socket.gethostname,
        "MU-OWNER" => MU.mu_user
      }
    end

    # Make sure the given node has proper DNS entries, /etc/hosts entries,
    # SSH config entries, etc.
    # @param server [MU::Cloud::Server]: The {MU::Cloud::Server} we'll be setting up.
    # @param sync_wait [Boolean]: Whether to wait for DNS to fully synchronize before returning.
    def self.nameKitten(server, sync_wait: false, no_dns: false)
      node, config, _deploydata = server.describe

      mu_zone = nil
      # XXX GCP!
      if !no_dns and MU::Cloud::AWS.hosted? and !MU::Cloud::AWS.isGovCloud?
        zones = MU::Cloud::DNSZone.find(cloud_id: "platform-mu")
        mu_zone = zones.values.first if !zones.nil?
      end

      if !mu_zone.nil?
        MU::Cloud::DNSZone.genericMuDNSEntry(name: node.gsub(/[^a-z0-9!"\#$%&'\(\)\*\+,\-\/:;<=>\?@\[\]\^_`{\|}~\.]/, '-').gsub(/--|^-/, ''), target: server.canonicalIP, cloudclass: MU::Cloud::Server, sync_wait: sync_wait)
      else
        MU::Master.addInstanceToEtcHosts(server.canonicalIP, node)
      end

## TO DO: Do DNS registration of "real" records as the last stage after the groomer completes
      if config && config['dns_records'] && !config['dns_records'].empty?
        dnscfg = config['dns_records'].dup
        dnscfg.each { |dnsrec|
          if !dnsrec.has_key?('name')
            dnsrec['name'] = node.downcase
            dnsrec['name'] = "#{dnsrec['name']}.#{MU.environment.downcase}" if dnsrec["append_environment_name"] && !dnsrec['name'].match(/\.#{MU.environment.downcase}$/)
          end

          if !dnsrec.has_key?("target")
            # Default to register public endpoint
            public = true

            if dnsrec.has_key?("target_type")
              # See if we have a preference for pubic/private endpoint
              public = dnsrec["target_type"] == "private" ? false : true
            end
  
            dnsrec["target"] =
              if dnsrec["type"] == "CNAME"
                if public
                  # Make sure we have a public canonical name to register. Use the private one if we don't
                  server.cloud_desc.public_dns_name.empty? ? server.cloud_desc.private_dns_name : server.cloud_desc.public_dns_name
                else
                  # If we specifically requested to register the private canonical name lets use that
                  server.cloud_desc.private_dns_name
                end
              elsif dnsrec["type"] == "A"
                if public
                  # Make sure we have a public IP address to register. Use the private one if we don't
                  server.cloud_desc.public_ip_address ? server.cloud_desc.public_ip_address : server.cloud_desc.private_ip_address
                else
                  # If we specifically requested to register the private IP lets use that
                  server.cloud_desc.private_ip_address
                end
              end
          end
        }
        if !MU::Cloud::AWS.isGovCloud?
          MU::Cloud::DNSZone.createRecordsFromConfig(dnscfg)
        end
      end

      MU::Master.removeHostFromSSHConfig(node)
      if server and server.canonicalIP
        MU::Master.removeIPFromSSHKnownHosts(server.canonicalIP)
      end
# XXX add names paramater with useful stuff
      MU::Master.addHostToSSHConfig(
          server,
          ssh_owner: server.deploy.mu_user,
          ssh_dir: Etc.getpwnam(server.deploy.mu_user).dir+"/.ssh"
      )
    end

    # Manufactures a human-readable deployment name from the random
    # two-character seed in MU-ID. Cat-themed when possible.
    # @param seed [String]: A two-character seed from which we'll generate a name.
    # @return [String]: Two words
    def self.generateHandle(seed)
      word_one=word_two=nil

      # Unless we've got two letters that don't have corresponding cat-themed
      # words, we'll insist that our generated handle have at least one cat
      # element to it.
      require_cat_words = true
      if @catwords.select { |word| word.match(/^#{seed[0]}/i) }.size == 0 and
          @catwords.select { |word| word.match(/^#{seed[1]}/i) }.size == 0
        require_cat_words = false
        MU.log "Got an annoying pair of letters #{seed}, not forcing cat-theming", MU::DEBUG
      end
      allnouns = @catnouns + @jaegernouns
      alladjs = @catadjs + @jaegeradjs

      tries = 0
      begin
        # Try to avoid picking something "nouny" for the first word
        source = @catadjs + @catmixed + @jaegeradjs + @jaegermixed
        first_ltr = source.select { |word| word.match(/^#{seed[0]}/i) }
        if !first_ltr or first_ltr.size == 0
          first_ltr = @words.select { |word| word.match(/^#{seed[0]}/i) }
        end
        word_one = first_ltr.shuffle.first

        # If we got a paired set that happen to match our letters, go with it
        if !word_one.nil? and word_one.match(/-#{seed[1]}/i)
          word_one, word_two = word_one.split(/-/)
        else
          source = @words
          if @catwords.include?(word_one)
            source = @jaegerwords
          elsif require_cat_words
            source = @catwords
          end
          second_ltr = source.select { |word| word.match(/^#{seed[1]}/i) and !word.match(/-/i) }
          word_two = second_ltr.shuffle.first
        end
        tries = tries + 1
      end while tries < 50 and (word_one.nil? or word_two.nil? or word_one.match(/-/) or word_one == word_two or (allnouns.include?(word_one) and allnouns.include?(word_two)) or (alladjs.include?(word_one) and alladjs.include?(word_two)) or (require_cat_words and !@catwords.include?(word_one) and !@catwords.include?(word_two) and !@catwords.include?(word_one+"-"+word_two)))

      if tries >= 50 and (word_one.nil? or word_two.nil?)
        MU.log "I failed to generated a valid handle from #{seed}, faking it", MU::ERR
        return "#{seed[0].capitalize} #{seed[1].capitalize}"
      end

      return "#{word_one.capitalize} #{word_two.capitalize}"
    end

    private

    # Check to see whether a given resource name is unique across all
    # deployments on this Mu server. We only enforce this for certain classes
    # of names. If the name in question is available, add it to our cache of
    # said names.  See #{MU::MommaCat.getResourceName}
    # @param name [String]: The name to attempt to allocate.
    # @return [Boolean]: True if allocation was successful.
    def allocateUniqueResourceName(name)
      raise MuError, "Cannot call allocateUniqueResourceName without an active deployment" if @deploy_id.nil?
      path = File.expand_path(MU.dataDir+"/deployments")
      File.open(path+"/unique_ids", File::CREAT|File::RDWR, 0600) { |f|
        existing = []
        f.flock(File::LOCK_EX)
        f.readlines.each { |line|
          existing << line.chomp
        }
        begin
          existing.each { |used|
            if used.match(/^#{name}:/)
              if !used.match(/^#{name}:#{@deploy_id}$/)
                MU.log "#{name} is already reserved by another resource on this Mu server.", MU::WARN, details: caller
                return false
              else
                return true
              end
            end
          }
          f.puts name+":"+@deploy_id
          return true
        ensure
          f.flock(File::LOCK_UN)
        end
      }
    end

    # 2019-06-03 adding things from https://aiweirdness.com/post/185339301987/once-again-a-neural-net-tries-to-name-cats
    @catadjs = %w{fuzzy ginger lilac chocolate xanthic wiggly itty chonky norty slonky floofy heckin bebby}
    @catnouns = %w{bastet biscuits bobcat catnip cheetah chonk dot felix hamb hambina jaguar kitty leopard lion lynx maru mittens moggy neko nip ocelot panther patches paws phoebe purr queen roar saber sekhmet skogkatt socks sphinx spot tail tiger tom whiskers wildcat yowl floof beans ailurophile dander dewclaw grimalkin kibble quick tuft misty simba slonk mew quat eek ziggy whiskeridoo cromch monch screm}
    @catmixed = %w{abyssinian angora bengal birman bobtail bombay burmese calico chartreux cheshire cornish-rex curl devon egyptian-mau feline furever fumbs havana himilayan japanese-bobtail javanese khao-manee maine-coon manx marmalade mau munchkin norwegian pallas persian peterbald polydactyl ragdoll russian-blue savannah scottish-fold serengeti shorthair siamese siberian singapura snowshoe stray tabby tonkinese tortoiseshell turkish-van tuxedo uncia caterwaul lilac-point chocolate-point mackerel maltese knead whitenose vorpal chewie-bean chicken-whiskey fish-especially thelonious-monsieur tom-glitter serendipitous-kill sparky-buttons nip-nops murder-mittens bite}
    @catwords = @catadjs + @catnouns + @catmixed

    @jaegeradjs = %w{azure fearless lucky olive vivid electric grey yarely violet ivory jade cinnamon crimson tacit umber mammoth ultra iron zodiac}
    @jaegernouns = %w{horizon hulk ultimatum yardarm watchman whilrwind wright rhythm ocean enigma eruption typhoon jaeger brawler blaze vandal excalibur paladin juliet kaleidoscope romeo}
    @jaegermixed = %w{alpha ajax amber avenger brave bravo charlie chocolate chrome corinthian dancer danger dash delta duet echo edge elite eureka foxtrot guardian gold hyperion illusion imperative india intercept kilo lancer night nova november oscar omega pacer quickstrike rogue ronin striker tango titan valor victor vulcan warder xenomorph xenon xray xylem yankee yell yukon zeal zero zoner zodiac}
    @jaegerwords = @jaegeradjs + @jaegernouns + @jaegermixed

    @words = @catwords + @jaegerwords

  end #class
end #module
