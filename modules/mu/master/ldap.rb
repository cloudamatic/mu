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

require 'net-ldap'

module MU
  class Master
    # Routines for manipulating users and groups in 389 Directory Services or Active Directory.
    class LDAP

      # Exception class specifically for LDAP-related errors
      class MuLDAPError < MU::MuError;end
      require 'date'

      # Make sure the LDAP section of $MU_CFG makes sense.
      def self.validateConfig(skipvaults: false)
        ok = true
        supported = ["Active Directory", "389 Directory Services"]
        if !$MU_CFG
          raise MuLDAPError, "Configuration not loaded yet, but MU::Master::LDAP.validateConfig was called!"
        end
        if !$MU_CFG.has_key?("ldap")
          raise MuLDAPError "Missing 'ldap' section of config (files: #{$MU_CFG['config_files']})"
        end
        ldap = $MU_CFG["ldap"] # shorthand
        if !ldap.has_key?("type") or !supported.include?(ldap["type"])
          ok = false
          MU.log "Bad or missing 'type' of LDAP server (should be one of #{supported})", MU::ERR
        end
        ["base_dn", "user_ou", "domain_name", "domain_netbios_name", "user_group_dn", "user_group_name", "admin_group_dn", "admin_group_name"].each { |var|
          if !ldap.has_key?(var) or !ldap[var].is_a?(String)
            ok = false
            MU.log "LDAP config section parameter '#{var}' is missing or is not a String", MU::ERR
          end
        }
        if !ldap.has_key?("dcs") or !ldap["dcs"].is_a?(Array) or ldap["dcs"].size < 1
          ok = false
          MU.log "Missing or empty 'dcs' section of LDAP config"
        end
        ["bind_creds", "join_creds"].each { |creds|
          if !ldap.has_key?(creds) or !ldap[creds].is_a?(Hash) or
             !ldap[creds].has_key?("vault") or !ldap[creds].has_key?("item") or
             !ldap[creds].has_key?("username_field") or
             !ldap[creds].has_key?("password_field")
            MU.log "LDAP config subsection '#{creds}' misconfigured, should be hash containing: vault, item, username_field, password_field", MU::ERR
            ok = false
            next
          end
          if !skipvaults
            loaded = MU::Groomer::Chef.getSecret(vault: ldap[creds]["vault"], item: ldap[creds]["item"])
            if !loaded or !loaded.has_key?(ldap[creds]["username_field"]) or
                loaded[ldap[creds]["username_field"]].empty? or
                !loaded.has_key?(ldap[creds]["password_field"]) or
                loaded[ldap[creds]["password_field"]].empty?
              MU.log "LDAP config subsection '#{creds}' refers to a bogus vault or incorrect/missing item fields", MU::ERR, details: ldap[creds]
              ok = false
            end
          end
        }
        if !ok
          raise MuLDAPError, "One or more LDAP configuration errors from files #{$MU_CFG['config_files']}"
        end
      end

      @ldap_conn = nil
      @gid_attr = "cn"
      @gidnum_attr = "gidNumber"
      @member_attr = "memberUid"
      @uid_attr = "uid"
      @group_class = "posixGroup"
      @uid_range_start = 10000
      @gid_range_start = 10000
      # Create and return a connection to our directory service. If we've
      # already opened one, return that.
      # @param username [String]: Optional alternative bind user, usually just used to see if someone knows their password
      # @param password [String]: Optional alternative bind password
      # @return [Net::LDAP]
      def self.getLDAPConnection(username: nil, password: nil)
        return @ldap_conn if @ldap_conn
        validateConfig(skipvaults: (username and password))
        if $MU_CFG["ldap"]["type"] == "Active Directory"
          @gid_attr = "sAMAccountName"
          @member_attr = "member"
          @uid_attr = "sAMAccountName"
          @group_class = "group"
          @user_class = "user"
        end
        if (username and !password) or (password and !username)
          raise MuLDAPError, "When supply credentials to getLDAPConnection, both username and password must be specified"
        end
        if !username and !password
          bind_creds = MU::Groomer::Chef.getSecret(vault: $MU_CFG["ldap"]["bind_creds"]["vault"], item: "cfg_directory_adm")#$MU_CFG["ldap"]["bind_creds"]["item"])
          username = bind_creds[$MU_CFG["ldap"]["bind_creds"]["username_field"]]
          password = bind_creds[$MU_CFG["ldap"]["bind_creds"]["password_field"]]
        end
        @ldap_conn = Net::LDAP.new(
          :host => $MU_CFG["ldap"]["dcs"].first,
          :encryption => {
            :method => :simple_tls,
            :tls_options => {}
          },
          :port => 636,
          :base => $MU_CFG["ldap"]["base_dn"],
          :auth => {
            :method => :simple,
            :username => username,
            :password => password
          }
        )
        @ldap_conn
      end

      # If there is an active LDAP connection loaded, close it. Well, nil it
      # out. There's no close method, that's theoretically handled in garbage
      # collection.
      def self.dropLDAPConnection
        @ldap_conn = nil
      end

      # Fetch a list of numeric uids that are already allocated
      def self.getUsedUids
        used_uids = []
        if $MU_CFG["ldap"]["type"] == "389 Directory Services"
          user_filter = Net::LDAP::Filter.ne("objectclass", "computer") & Net::LDAP::Filter.ne("objectclass", "group")
          conn = getLDAPConnection
          conn.search(
            :filter => user_filter,
            :base => $MU_CFG["ldap"]["base_dn"],
            :attributes => ["employeeNumber"]
          ) do |acct|
            if acct[:employeenumber] and acct[:employeenumber].size > 0
              used_uids << acct[:employeenumber].first.to_i
            end
          end
        else
          Etc.passwd{ |u|
            if !user.nil? and u.name == user and mu_acct
              raise MuLDAPError, "Username #{user} already exists as a system user, cannot allocate in directory"
            end
            used_uids << u.uid
          }
        end
        used_uids
      end

      # Find a user ID not currently in use from the local system's perspective
      def self.allocateUID
        MU::MommaCat.lock("uid_generator", false, true)
        used_uids = getUsedUids

        for x in @uid_range_start..65535 do
          if !used_uids.include?(x)
            MU::MommaCat.unlock("uid_generator", true)
            return x.to_s
          end
        end
        MU::MommaCat.unlock("uid_generator", true)
        return nil
      end

      # Find a group ID not currently in use from the local system's perspective
      # XXX this is vulnerable to a race condition, and may not account for
      # things in the directory
      def self.allocateGID(group: nil)
        MU::MommaCat.lock("gid_generator", false, true)
        used_gids = []
        Etc.group{ |g|
          if !group.nil? and g.name == group
            raise MuLDAPError, "Group #{group} already exists as a local system group, cannot allocate in directory"
          end
          used_gids << g.gid
        }
        conn = getLDAPConnection
        conn.search(
          :filter => Net::LDAP::Filter.eq("objectClass", @group_class),
          :base => $MU_CFG['ldap']['base_dn'],
          :attributes => [@gidnum_attr]
        ) { |item|
          used_gids = used_gids + item[@gidnum_attr].map { |x| x.to_i }
        }
        for x in @gid_range_start..65535 do
          if !used_gids.include?(x)
            MU::MommaCat.unlock("gid_generator", true)
            return x.to_s
          end
        end
        MU::MommaCat.unlock("gid_generator", true)
        return nil
      end

      # Create a directory group. Valid for 389 DS only, will fail on AD.
      def self.createGroup(group, full_dn: nil)
        dn = "CN=#{group},"+$MU_CFG["ldap"]["group_ou"]
        dn = full_dn if !full_dn.nil?
        gid = allocateGID
        attr = {
          :cn => group,
          :description => "#{group} Group",
          :gidNumber => gid,
          :objectclass => ["top", "posixGroup"]
        }

        if !@ldap_conn.add(
              :dn => dn,
              :attributes => attr
            ) and @ldap_conn.get_operation_result.code != 68
          MU.log "Error creating #{dn}: "+getLDAPErr, MU::ERR, details: attr
          return false
        elsif @ldap_conn.get_operation_result.code != 68
          MU.log "Created group #{dn} with gid #{gid} (#{@ldap_conn.get_operation_result.message})", MU::NOTICE
        end
        return gid
      end

      # Intended to run when Mu's local LDAP server has been created. Use the
      # root credentials to populate our OU structure, create other users, etc.
      # This only needs to understand a 389 Directory style schema, since
      # obviously we're not running Active Directory locally on Linux.
      def self.initLocalLDAP
        validateConfig
        if $MU_CFG["ldap"]["type"] != "389 Directory Services" or
            # XXX this should check all of the IPs and hostnames we're known by
            (!$MU_CFG["ldap"]["dcs"].include?("localhost") and
            !$MU_CFG["ldap"]["dcs"].include?("127.0.0.1"))
          MU.log "Custom directory service configured, not initializing bundled schema", MU::NOTICE
          return
        end
        root_creds = MU::Groomer::Chef.getSecret(vault: "mu_ldap", item: "cfg_directory_adm")
        @ldap_conn = Net::LDAP.new(
          :host => "127.0.0.1",
          :encryption => {
            :method => :simple_tls,
            :tls_options => {}
          },
          :port => 636,
          :base => "",
          :auth => {
            :method => :simple,
            :username => root_creds["username"],
            :password => root_creds["password"]
          }
        )

        # Manufacture our OU tree and groups
        [ $MU_CFG["ldap"]["base_dn"],
          "OU=Mu-System,#{$MU_CFG["ldap"]["base_dn"]}",
          $MU_CFG["ldap"]["user_ou"],
          $MU_CFG["ldap"]["group_ou"],
          $MU_CFG["ldap"]["user_group_dn"],
          $MU_CFG["ldap"]["admin_group_dn"]
        ].each { |full_dn|
          dn = ""
          full_dn.split(/,/).reverse.each { |chunk|
            if dn.empty?
              dn = chunk
            else
              dn = "#{chunk},#{dn}"
            end
            next if chunk.match(/^DC=/i)
            if chunk.match(/^OU=(.*)/i)
              ou = $1
              if !@ldap_conn.add(
                    :dn => dn,
                    :attributes => {
                      :ou => ou, 
                      :objectclass =>"organizationalUnit"
                    }
                  ) and @ldap_conn.get_operation_result.code != 68 # "already exists"
                MU.log "Error creating #{dn}: "+getLDAPErr, MU::ERR
                return false
              elsif @ldap_conn.get_operation_result.code != 68
                MU.log "Created OU #{dn}", MU::NOTICE
              end
            elsif chunk.match(/^CN=(.*)/i)
              createGroup($1, full_dn: dn)
            end
          }
        }
         
        ["bind_creds", "join_creds"].each { |creds|
          data = MU::Groomer::Chef.getSecret(vault: $MU_CFG["ldap"][creds]["vault"], item: $MU_CFG["ldap"][creds]["item"])
          user_dn = data[$MU_CFG["ldap"][creds]["username_field"]]
          user_dn.match(/^CN=(.*?),/i)
          username = $1
          pw = data[$MU_CFG["ldap"][creds]["password_field"]]

          attr = {
            :cn => username,
            :displayName => "Mu Service Account",
            :objectclass => ["top", "person", "organizationalPerson", "inetorgperson"],
            :uid => username,
            :mail => $MU_CFG['mu_admin_email'],
            :givenName => "Mu",
            :sn => "Service",
            :userPassword => pw
          }
          if !@ldap_conn.add(
                :dn => data[$MU_CFG["ldap"][creds]["username_field"]],
                :attributes => attr
              ) and @ldap_conn.get_operation_result.code != 68
            raise MuLDAPError, "Failed to create user #{user_dn} (#{getLDAPErr})"
          elsif @ldap_conn.get_operation_result.code != 68
            MU.log "Created #{username} (#{user_dn})", MU::NOTICE
          end

          # Set the password
          if !@ldap_conn.replace_attribute(user_dn, :userPassword, [pw])
            MU.log "Couldn't update password for user #{username}.", MU::ERR, details: getLDAPErr
          end

          # Grant this user appropriate privileges
          targets = []
          if creds == "bind_creds"
            targets << $MU_CFG["ldap"]["user_ou"]
            targets << $MU_CFG["ldap"]["group_ou"]
            targets << $MU_CFG["ldap"]["user_group_dn"]
            targets << $MU_CFG["ldap"]["admin_group_dn"]
          elsif creds == "join_creds"
# XXX Some machine-related OU?
          end
          targets.each { | target|
            aci = "(targetattr=\"*\")(target=\"ldap:///#{target}\")(version 3.0; acl \"#{username} admin privileges for #{target}\"; allow (all) userdn=\"ldap:///#{user_dn}\";)"
            if !@ldap_conn.modify(:dn => $MU_CFG["ldap"]["base_dn"], :operations => [[:add, :aci, aci]]) and @ldap_conn.get_operation_result.code != 20
              MU.log "Couldn't modify permissions for user #{username}.", MU::ERR, details: getLDAPErr
            elsif @ldap_conn.get_operation_result.code != 20
              MU.log "Granted #{username} user admin privileges over #{target}", MU::NOTICE
            end
          }
        }
      end

      # Shorthand for fetching the most recent error on the active LDAP
      # connection
      def self.getLDAPErr
        return nil if !@ldap_conn
        return @ldap_conn.get_operation_result.code.to_s+" "+@ldap_conn.get_operation_result.message.to_s
      end

      # Approximate a current Microsoft timestamp. They count the number of
      # 100-nanoseconds intervals (1 nanosecond = one billionth of a second)
      # since Jan 1, 1601 UTC.
      def self.getMicrosoftTime
        ms_epoch = DateTime.new(1601,1,1)
        # this is in milliseconds, so multiply it for the right number of zeroes
        elapsed = DateTime.now.strftime("%Q").to_i - ms_epoch.strftime("%Q").to_i
        return elapsed*10000
      end

      # Convert a Microsoft timestamp to a Ruby Time object. See also #getMicrosoftTime.
      # @param stamp [Integer]: The MS-style timestamp, e.g. 130838184558490696
      # @return [Time]
      def self.convertMicrosoftTime(stamp)
#        ms_epoch = DateTime.new(1601,1,1).strftime("%Q").to_i
        unixtime = (stamp.to_i/10000) + DateTime.new(1601,1,1).strftime("%Q").to_i
        Time.at(unixtime/1000)
      end

      @can_write = nil
      # Test whether our LDAP binding user has permissions to create other
      # users, manipulate groups, and set passwords. Note that it's *not* fatal
      # if we can't, simply a design where most account management happens on
      # the directory side.
      # @return [Boolean]
      def self.canWriteLDAP?
        return @can_write if !@can_write.nil?

        conn = getLDAPConnection
        dn = "CN=Mu Testuser #{Process.pid},#{$MU_CFG["ldap"]["user_ou"]}"
        uid = "mu.testuser.#{Process.pid}"
        attr = {
          :cn => "Mu Testuser #{Process.pid}",
          @uid_attr.to_sym => uid
        }
        if $MU_CFG["ldap"]["type"] == "Active Directory"
          attr[:objectclass] = ["user"]
          attr[:userPrincipalName] = "#{uid}@#{$MU_CFG["ldap"]["domain_name"]}"
          attr[:pwdLastSet] = "-1"
          uid = dn
        elsif $MU_CFG["ldap"]["type"] == "389 Directory Services"
          attr[:objectclass] = ["top", "person", "organizationalPerson", "inetorgperson"]
          attr[:userPassword] = Password.pronounceable(12..14)
          attr[:displayName] = "Mu Test User #{Process.pid}"
          attr[:mail] = $MU_CFG['mu_admin_email']
          attr[:givenName] = "Mu"
          attr[:sn] = "TestUser"
        end

        @can_write = true
        if !conn.add(:dn => dn, :attributes => attr)
          MU.log "Couldn't create write-test user #{dn}, wll operate in read-only LDAP mode (#{getLDAPErr})", MU::NOTICE, details: attr
          return false
        end

        # Make sure we can write various fields that we might need to touch
        [:displayName, :mail, :givenName, :sn].each { |field|
          if !conn.replace_attribute(dn, field, "foo@bar.com")
            MU.log "Couldn't modify write-test user #{dn} field #{field.to_s}, will operate in read-only LDAP mode (#{getLDAPErr})", MU::NOTICE
            @can_write = false
            
          end
        }

        # Can we add them to the Mu membership group(s)
        [$MU_CFG["ldap"]["user_group_dn"], $MU_CFG["ldap"]["admin_group_dn"]].each { |group|
          if !conn.modify(:dn => group, :operations => [[:add, @member_attr, uid]])
            MU.log "Couldn't add write-test user #{dn} to #{@member_attr} in group #{group}, operating in read-only LDAP mode (#{getLDAPErr})", MU::NOTICE
            @can_write = false
          end
        }

        if !conn.delete(:dn => dn)
          MU.log "Couldn't delete write-test user #{dn}, operating in read-only LDAP mode", MU::NOTICE
          @can_write = false
        end

        @can_write
      end

      # Search for groups whose names contain any of the given search terms and
      # return their full DNs.
      # @param search [Array<String>]: Strings to search for.
      # @param exact [Boolean]: Return only exact matches for whole fields.
      # @param searchbase [String]: The DN under which to search.
      # @param whole_desc [Boolean]: Return whole descriptors instead of just the DNs
      # @return [Array<String>]
      def self.findGroups(search = [], exact: false, searchbase: "OU=Groups,"+$MU_CFG['ldap']['base_dn'], whole_desc: false)
#        if search.nil? or search.size == 0
#          raise MuLDAPError, "Need something to search for in MU::Master::LDAP.findGroups"
#        end
        conn = getLDAPConnection
        filter = nil
        search.each { |term|
          curfilter = Net::LDAP::Filter.contains(@gid_attr, "#{term}")
          if exact
            curfilter = Net::LDAP::Filter.eq(@gid_attr, "#{term}")
          end

          if !filter
            filter = curfilter
          else
            filter = filter | curfilter
          end
        }
        filter = if filter
          Net::LDAP::Filter.ne("objectclass", "computer") & (filter)
        else
          Net::LDAP::Filter.ne("objectclass", "computer")
        end
        groups = []
        conn.search(
          :filter => filter,
          :base => searchbase,
          :attributes => ["objectclass"] + (whole_desc ? ["description", @gidnum_attr, @member_attr] : [])
        ) do |group|
          next if group.dn == searchbase
          groups << (whole_desc ? group : group.dn)
        end
        groups
      end

      # See https://technet.microsoft.com/en-us/library/ee198831.aspx
      AD_PW_ATTRS = {
        'script' => 0x0001, #SCRIPT
#        'disable' => 0x0002, #ACCOUNTDISABLE
        'disable' => 0b0000010, #ACCOUNTDISABLE
        'homedirRequired' => 0x0008, #HOMEDIR_REQUIRED
        'lockout' => 0x0010, #LOCKOUT
        'noPwdRequired' => 0x0020, #ADS_UF_PASSWD_NOTREQD
        'cantChangePwd' => 0x0040, #ADS_UF_PASSWD_CANT_CHANGE
        'pwdStoredReversible' => 0x0080, #ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED
        'tempDuplicateAccount' => 0x0100, #NORMAL_ACCOUNT
        'normal' => 0x0200, #NORMAL_ACCOUNT
        'pwdNeverExpires' => 0x10000, #ADS_UF_DONT_EXPIRE_PASSWD
        'pwdExpired' => 0x80000, #ADS_UF_PASSWORD_EXPIRED
        'trustedToAuthForDelegation' => 0x1000000 #TRUSTED_TO_AUTH_FOR_DELEGATION
      }.freeze

      # Find a directory user with fuzzy string matching on sAMAccountName/uid, displayName, group memberships, or email
      # @param search [Array<String>]: Strings to search for.
      # @param exact [Boolean]: Return only exact matches for whole fields.
      # @param searchbase [String]: The DN under which to search.
      # @param extra_attrs [Array<String>]: Other LDAP attributes to search
      # @param matchgroups [Array<String>]: An array of groups. If supplied, a user must be a member of one of these in order to match.
      # @return [Array<Hash>]
      def self.findUsers(search = [], exact: false, searchbase: $MU_CFG['ldap']['base_dn'], extra_attrs: [], matchgroups: [])
        # We want to search groups, but can't search on memberOf with wildcards.
        # So search groups independently, build a list of full CNs, and use
        # those.
        if search.size > 0
          groups = findGroups(search, exact: exact, searchbase: searchbase)
        end
        searchattrs = [@uid_attr]
        getattrs = []
        if $MU_CFG["ldap"]["type"] == "389 Directory Services"
          getattrs = ["uid", "displayName", "mail"] + extra_attrs
        elsif $MU_CFG["ldap"]["type"] == "Active Directory"
          getattrs = ["sAMAccountName", "displayName", "mail", "lastLogon", "lockoutTime", "pwdLastSet", "memberOf", "userAccountControl"] + extra_attrs
        end
        if !exact
          searchattrs = searchattrs + ["displayName", "mail"] + extra_attrs
        end

        conn = getLDAPConnection
        users = {}
        filter = nil
        rejected = 0
        if search.size > 0
          search.each { |term|
            if term.nil? or (term.length < 4 and !exact)
              MU.log "Search term '#{term}' is too short, ignoring.", MU::WARN
              rejected = rejected + 1
              next
            end
            searchattrs.each { |attr|
              if !filter
                if exact
                  filter = Net::LDAP::Filter.eq(attr, "#{term}")
                else
                  filter = Net::LDAP::Filter.contains(attr, "#{term}")
                end
              else
                if exact
                  filter = filter |Net::LDAP::Filter.eq(attr, "#{term}")
                else
                  filter = filter |Net::LDAP::Filter.contains(attr, "#{term}")
                end
              end
            }
          }
          if rejected == search.size
            MU.log "No valid search strings provided.", MU::ERR
            return nil
          end
        end
        if groups
          groups.each { |group|
            filter = filter |Net::LDAP::Filter.eq("memberOf", group)
          }
        end
        if filter 
          filter = Net::LDAP::Filter.ne("objectclass", "computer") & Net::LDAP::Filter.ne("objectclass", "group") & (filter)
        else
          filter = Net::LDAP::Filter.ne("objectclass", "computer") & Net::LDAP::Filter.ne("objectclass", "group")
        end
        conn.search(
          :filter => filter,
          :base => searchbase,
          :attributes => getattrs
        ) do |acct|
          begin
            next if users.has_key?(acct[@uid_attr].first)
          rescue NoMethodError
            next
          end
          if matchgroups and matchgroups.size > 0
            next if (acct[:memberOf] & matchgroups).size < 1
          end
          users[acct[@uid_attr].first] = {}
          users[acct[@uid_attr].first]['dn'] = acct.dn
          getattrs.each { |attr|
            begin
              if acct[attr].size == 1
                users[acct[@uid_attr].first][attr] = acct[attr].first
              else
                users[acct[@uid_attr].first][attr] = acct[attr]
              end
              if attr == "userAccountControl"
                AD_PW_ATTRS.each_pair { |pw_attr, bitmask|
                  if (bitmask | acct[attr].first.to_i) == acct[attr].first.to_i
                    users[acct[@uid_attr].first][pw_attr] = true
                  end
                }
                users[acct[@uid_attr].first][attr] = acct[attr].first.to_i.to_s(2)
              end
            end rescue NoMethodError
          }
        end

        # Make all of the Net::BER::BerIdentifiedString leaves in a Hash into
        # normal strings.
        # @param tree
        def self.hashStringify(tree)
          newtree = nil
          if tree.is_a?(Hash)
            newtree = {}
            tree.each_pair { |key, leaf|
              newtree[key.to_s] = hashStringify(leaf)
            }
          elsif tree.is_a?(Array)
            newtree = []
            tree.each { |leaf|
              newtree << hashStringify(leaf)
            }
          elsif tree.is_a?(Net::BER::BerIdentifiedString)
            newtree = tree.to_s
          else
            newtree = tree
          end
          newtree
        end
        scrubbed_users = hashStringify(users)
        scrubbed_users
      end

      # Authenticate a user against our directory, optionally requiring them
      # to be a member of a particular group in order to return true.
      # @param username [String]: The bare username of the user to authorize
      # @param password [String]: The user's password
      # @return [Boolean]
      def self.authorize(username, password, require_group: nil)
        auth = nil

        begin
          # see if this user/pw combo works
          conn = getLDAPConnection(username: username, password: password)
          auth = conn.auth(username, password) if username and password
        rescue Net::LDAP::LdapError
          return false
        end
        if !conn.bind(auth)
          MU.log conn.get_operation_result.message, MU::ERR
          return false
        end
        
        return true if !require_group

        shortuser = username.sub(/\@.*/, "")
        user = findUsers([shortuser], exact: true)
        if user[shortuser]["memberOf"].is_a?(Array)
          user[shortuser]["memberOf"].each { |group|
            shortname = group.sub(/^CN=(.*?),.*/, '\1')
            return true if shortname == require_group
          }
        elsif user[shortuser]["memberOf"].is_a?(String)
          shortname = user[shortuser]["memberOf"].sub(/^CN=(.*?),.*/, '\1')
          return true if shortname == require_group
        end
        return false
      end

      # @return [Array<String>]
      def self.listUsers
        conn = getLDAPConnection
        users = {}

# XXX why doesn't this work?
#        group_membership_filter = Net::LDAP::Filter.eq("memberOf", $MU_CFG["ldap"]["admin_group_name"]) | Net::LDAP::Filter.eq("memberOf", $MU_CFG["ldap"]["user_group_name"])

        ["admin_group_name", "user_group_name"].each { |group|
          groupname_filter = Net::LDAP::Filter.eq(@gid_attr, $MU_CFG["ldap"][group])
          group_filter = Net::LDAP::Filter.eq("objectClass", @group_class)
          member_uids = []

          conn.search(
            :filter => Net::LDAP::Filter.join(groupname_filter, group_filter),
            :attributes => [@member_attr]
          ) do |item|
            member_uids = item[@member_attr].map { |u| u.to_s }
          end

          member_uids.each { |uid|
            username_filter = Net::LDAP::Filter.eq(@uid_attr, uid)
            if $MU_CFG["ldap"]["type"] == "Active Directory"
              # XXX this is a workaround, as we can't seem to look up the full
              # DN now for some reason.
              cn = uid.sub(/^CN=([^,]+?),.*/, "\\1")
              username_filter = Net::LDAP::Filter.eq("cn", cn)
            end
            user_filter = Net::LDAP::Filter.ne("objectclass", "computer") & Net::LDAP::Filter.ne("objectclass", "group")
            fetchattrs = ["cn", @uid_attr, "displayName", "mail", "departmentNumber"]
            fetchattrs << "employeeNumber" if $MU_CFG["ldap"]["type"] == "389 Directory Services"
            conn.search(
              :filter => username_filter & user_filter,
              :base => $MU_CFG["ldap"]["base_dn"],
              :attributes => fetchattrs
            ) do |acct|
              next if users.has_key?(acct[@uid_attr].first)
              users[acct[@uid_attr].first] = {}
              users[acct[@uid_attr].first]['dn'] = acct.dn
              if group == "admin_group_name"
                users[acct[@uid_attr].first]['admin'] = true
              else
                users[acct[@uid_attr].first]['admin'] = false
              end
              begin
                users[acct[@uid_attr].first]['realname'] = acct.displayname.first
              end rescue NoMethodError
              begin
                users[acct[@uid_attr].first]['email'] = acct.mail.first
              end rescue NoMethodError
              begin
                users[acct[@uid_attr].first]['uid'] = acct.employeenumber.first
              end rescue NoMethodError
              begin
                users[acct[@uid_attr].first]['gid'] = acct.departmentNumber.first
              end rescue NoMethodError
            end
          }
        }
        users
      end

      # Delete a user from our directory
      # @param user [String]: The username to remove.
      # @return [Boolean]: Success/Failure
      def self.deleteUser(user)
        if canWriteLDAP?
          conn = getLDAPConnection
          dn = nil
          conn.search(
            :filter => Net::LDAP::Filter.eq(@uid_attr, user),
            :base => $MU_CFG["ldap"]["base_dn"],
            :attributes => [@uid_attr]
          ) do |acct|
            dn = acct.dn
            break
          end

          # Our default LDAP server doesn't cascade user deletes through groups,
          # so help it out.
          if $MU_CFG["ldap"]["type"] == "389 Directory Services"
            conn.search(
              :filter => Net::LDAP::Filter.eq("objectclass", @group_class),
              :base => $MU_CFG["ldap"]["base_dn"],
              :attributes => ["cn", @member_attr]
            ) do |group|
              group[@member_attr].each { |member|
                next if member.nil?
                if member.downcase == user or (!dn.nil? and member.downcase == dn.downcase)
                  manageGroup(group.cn.first, remove_users: [user])
                end
              }
              if group.cn.first.downcase == "#{user}.mu-user" and !conn.delete(:dn => group.dn)
                MU.log "Couldn't delete user's default group #{group.dn}", MU::WARN, details: getLDAPErr
              else
                MU.log "Removed user's default group #{user}.mu-user", MU::NOTICE
              end
            end
          end
          if !dn.nil? and !conn.delete(:dn => dn)
            MU.log "Failed to delete #{user} from LDAP: #{getLDAPErr}", MU::WARN, details: dn
            return false
          end
          MU.log "Removed LDAP user #{user}", MU::NOTICE
          return true
        else
          MU.log "We are in read-only LDAP mode. You must manually delete #{user} from your directory.", MU::WARN
        end

        false
      end

      # Add/remove users to/from a group.
      # @param group [String]: The short name of the group
      # @param add_users [Array<String>]: The short names of users to add to the group
      # @param remove_users [Array<String>]: The short names of users to remove from the group
      def self.manageGroup(group, add_users: [], remove_users: [])
        group_dn = findGroups([group], exact: true).first
        if !group_dn or group_dn.empty?
          raise MuLDAPError, "Failed to find a Distinguished Name for group #{group}"
        end
        if (add_users & remove_users).size > 0
          raise MuError, "Can't both add and remove the same user (#{(add_users & remove_users).join(", ")}) from a group"
        end
        add_users = findUsers(add_users, exact: true) if add_users.size > 0
        remove_users = findUsers(remove_users, exact: true) if remove_users.size > 0

        conn = getLDAPConnection
        if add_users.size > 0
          add_users.each_pair { |user, data|
            uid = user
            uid = data["dn"] if $MU_CFG["ldap"]["type"] == "Active Directory"
            if !conn.modify(:dn => group_dn, :operations => [[:add, @member_attr, uid]]) and @ldap_conn.get_operation_result.code != 20
              MU.log "Couldn't add user #{user} (#{data['dn']}) to #{@member_attr} of group #{group} (#{group_dn}).", MU::WARN, details: getLDAPErr
            else
              MU.log "Added #{user} to group #{group}", MU::NOTICE
            end
          }
        end
        if remove_users.size > 0
          remove_users.each_pair { |user, data|
            uid = user
            uid = data["dn"] if $MU_CFG["ldap"]["type"] == "Active Directory"
            if !conn.modify(:dn => group_dn, :operations => [[:delete, @member_attr, uid]])
              MU.log "Couldn't remove user #{user} from group #{group} (#{group_dn}) via #{@member_attr}.", MU::WARN, details: getLDAPErr
            else
              MU.log "Removed #{user} from group #{group}", MU::NOTICE
            end
          }
        end
      end

      # Call when creating or modifying a user.
      # @param user [String]: The username on which to operate
      # @param password [String]: Set the user's password
      # @param name [String]: Full name of the user
      # @param email [String]: Set the user's email address
      # @param admin [Boolean]: Whether to flag this user as an admin
      # @param unlock [Boolean]: Unlock a locked account (Active Directory)
      # @param mu_acct [Boolean]: Whether to operate on users outside of Mu (generic directory users)
      # @param ou [String]: The OU into which to deposit new users.
      # @param disable [Boolean]: Disabled the user's account
      # @param enable [Boolean]: Re-enable the user's account if it's disabled
      def self.manageUser(user, name: nil, password: nil, email: nil, admin: false, mu_acct: true, unlock: false, ou: $MU_CFG["ldap"]["user_ou"], enable: false, disable: false, change_uid: -1)
        cur_users = listUsers

        first = last = nil
        if !name.nil?
          last = name.split(/\s+/).pop
          first = name.split(/\s+/).shift
        end
        conn = getLDAPConnection

        # If we're operating on users that aren't specifically Mu users,
        # fetch generic directory information about them instead of the Mu
        # user descriptor.
        if !mu_acct
          cur_users = findUsers([user], exact: true)
        end

        # Oh, Microsoft. Slap quotes around it, convert it to Unicode, and call
        # it Sally. *Then* it's a password.
        password_attr = :userPassword
        if !password.nil? and $MU_CFG["ldap"]["type"] == "Active Directory"
          password = ('"'+password+'"').encode("utf-16le").force_encoding("utf-8")
          password_attr = :unicodePwd
        end

        ok = true
        if !cur_users.has_key?(user)
          # Creating a new user
          if canWriteLDAP?
            if password.nil? or email.nil? or name.nil?
              raise MuLDAPError, "Missing one or more required fields (name, password, email) creating new user #{user}"
            end
            user_dn = "CN=#{name},#{ou}"
            conn = getLDAPConnection
            attr = {
              :cn => name,
              :displayName => name,
              :givenName => first,
              :sn => last,
              :mail => email
            }
            attr[password_attr] = password
            gid = nil
            groups = []
            if $MU_CFG["ldap"]["type"] == "389 Directory Services"
              attr[:objectclass] = ["top", "person", "organizationalPerson", "inetorgperson"]
              attr[:uid] = user
              if change_uid > 0
                used_uids = getUsedUids
                if used_uids.include?(change_uid)
                  raise MuLDAPError, "Uid #{change_uid} is unavailable, cannot allocate to user #{user}"
                end
                MU.log "Forcing uid #{change_uid} to user #{user}", MU::NOTICE, details: used_uids
                attr[:employeeNumber] = change_uid.to_s
              else
                attr[:employeeNumber] = allocateUID
              end
              if mu_acct
                gid = createGroup("#{user}.mu-user")
                groups << "#{user}.mu-user"
              else
                gid = createGroup(user)
                groups << user
              end
              attr[:departmentNumber] = gid
            elsif $MU_CFG["ldap"]["type"] == "Active Directory"
              attr[:objectclass] = ["user"]
              attr[:samaccountname] = user
              attr[:userAccountControl] = AD_PW_ATTRS['normal'].to_s
              attr[:userPrincipalName] = "#{user}@#{$MU_CFG["ldap"]["domain_name"]}"
              attr[:pwdLastSet] = "-1"
              attr.delete(:userPassword)
              if mu_acct
                attr[:userAccountControl] = (attr[:userAccountControl].to_i & AD_PW_ATTRS['pwdNeverExpires']).to_s
              end
              if disable
                attr[:userAccountControl] = (attr[:userAccountControl].to_i & AD_PW_ATTRS['disable']).to_s
              end
            end
            if !conn.add(:dn => user_dn, :attributes => attr)
              if getLDAPErr.match(/53 Unwilling to perform/)
                raise MuLDAPError, "Failed to create user #{user} (#{getLDAPErr}). Most likely the LDAP password policy objected to the password '#{password}'"
              else
                raise MuLDAPError, "Failed to create user #{user} (#{getLDAPErr}) from add(:dn => #{user_dn}, :attributes => #{attr.to_s})"
              end
            end
            attr[password_attr] = "********"
            MU.log "Created new LDAP user #{user}", details: attr
            if mu_acct
              groups << $MU_CFG["ldap"]["user_group_name"]
              groups << $MU_CFG["ldap"]["admin_group_name"] if admin
            end
            groups.each { |group|
              manageGroup(group, add_users: [user])
            }

# XXX SSSD is completely broken on Amazon 2023 for now. None of the below works.
# We're currently relying on MU::Master.manageUser to set up a unix-side
# user, old-school /etc/passwd style, in parallel to these LDAP entries.
#            wait = 10
#            begin
#              %x{/usr/bin/getent passwd ; /usr/bin/getent group} # winbind is slow sometimes
#              Etc.getpwnam(user)
#            rescue ArgumentError
#              if wait >= 30
#                MU.log "User #{user} has been created in LDAP, but local system can't see it. Are PAM/LDAP configured correctly?", MU::ERR
#                return false
#              end
#              MU.log "User #{user} has been created in LDAP, but not yet visible to local system, waiting #{wait}s and checking again.", MU::WARN
#              sleep wait
#              wait = wait + 5
#              retry
#            end if user != "mu"
            %x{/sbin/restorecon -r /home} # SELinux stupidity that oddjob misses
#            MU::Master.setLocalDataPerms(user) if Etc.getpwuid(Process.uid).name == "root" and mu_acct
          else
            MU.log "We are in read-only LDAP mode. You must first create #{user} in your directory and add it to #{$MU_CFG["ldap"]["user_group_dn"]}. If the user is intended to be an admin, also add it to #{$MU_CFG["ldap"]["admin_group_dn"]}.", MU::WARN
            return true
          end
        else
          gid = MU::Master.setLocalDataPerms(user) if Etc.getpwuid(Process.uid).name == "root" and mu_acct
          # Modifying an existing user

          if canWriteLDAP?
            conn = getLDAPConnection
            user_dn = cur_users[user]['dn']
            if $MU_CFG["ldap"]["type"] == "389 Directory Services"
              # Make sure we have a sensible default gid
              conn.replace_attribute(user_dn, :departmentNumber, gid.to_s)
              if change_uid > 0
                used_uids = getUsedUids
                if used_uids.include?(change_uid)
                  raise MuLDAPError, "Uid #{change_uid} is unavailable, cannot allocate to user #{user}"
                end
                MU.log "Forcing uid #{change_uid} to user #{user}", MU::NOTICE, details: used_uids
                conn.replace_attribute(user_dn, :employeeNumber, change_uid.to_s)
              end
            end
            if !name.nil? and cur_users[user]['realname'] != name
              MU.log "Updating display name for #{user} to #{name}", MU::NOTICE
              conn.replace_attribute(user_dn, :displayName, name)
              conn.replace_attribute(user_dn, :givenName, first)
              conn.replace_attribute(user_dn, :sn, last)
              cur_users[user]['realname'] = name
            end
            if disable
              findUsers([user], exact: true)
              MU.log "Disabling #{user}", MU::WARN
              conn.replace_attribute(user_dn, :userAccountControl, AD_PW_ATTRS['disable'].to_i.to_s(2))
            elsif enable
              user_props = findUsers([user], exact: true)
              MU.log "Re-enabling #{user}", MU::NOTICE
              uac = (("0b"+user_props[user]["userAccountControl"]).to_i & AD_PW_ATTRS['disable'])
              conn.replace_attribute(user_dn, :userAccountControl, uac.to_s(2))
            end
            if unlock
              conn.replace_attribute(user_dn, :lockoutTime, "0")
            end
            if !email.nil? and cur_users[user]['email'] != email
              MU.log "Updating email for #{user} to #{email}", MU::NOTICE
              conn.replace_attribute(user_dn, :mail, email)
              cur_users[user]['email'] = email
            end
            if !password.nil?
              MU.log "Updating password for #{user}", MU::NOTICE
              if !conn.replace_attribute(user_dn, password_attr, [password])
                MU.log "Couldn't update password for user #{user}.", MU::WARN, details: getLDAPErr
                ok = false
              end
            end
            if admin and !cur_users[user]['admin']
              MU.log "Granting Mu admin privileges to #{user}", MU::NOTICE
              manageGroup($MU_CFG["ldap"]["admin_group_name"], add_users: [user])
            elsif !admin and cur_users[user]['admin']
              MU.log "Revoking Mu admin privileges from #{user}", MU::NOTICE
              manageGroup($MU_CFG["ldap"]["admin_group_name"], remove_users: [user])
            end
          else
            MU.log "We are in read-only LDAP mode. You must manage #{user} in your directory.", MU::WARN
            ok = false
          end
        end
        return ok if !mu_acct # everything below is Mu-specific

        cur_users = listUsers
        if cur_users.has_key?(user)
          stubdir = File.join($MU_CFG['datadir'], "users", user)
          if !Dir.exist?(stubdir)
            Dir.mkdir(stubdir)
          end
          ["realname", "email", "monitoring_email"].each { |field|
            next if !cur_users[user].has_key?(field)
            File.open("#{stubdir}/#{field}", File::CREAT|File::RDWR, 0640) { |f|
              f.puts cur_users[user][field]
            }
          }
        else
          MU.log "Load of current user list didn't include #{user}, even though we just created them!", MU::WARN
        end

#        MU::Master.setLocalDataPerms(user) if Etc.getpwuid(Process.uid).name == "root" and mu_acct
        ok
      end

    end
  end
end
