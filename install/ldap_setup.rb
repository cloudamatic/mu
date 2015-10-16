#!/usr/local/ruby-current/bin/ruby
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

require File.realpath(File.expand_path(File.dirname(__FILE__)+"/../modules/mu-load-config.rb"))
# now we have our global config available as the read-only hash $MU_CFG

require 'mu'
require 'simple-password-gen'

# Generate credentials if they don't already exist
$BIND_DN = $BIND_PW = nil
["bind_creds", "join_creds"].each { |creds|
  data = nil
  begin
    data = MU::Groomer::Chef.getSecret(
      vault: $MU_CFG["ldap"][creds]["vault"],
      item: $MU_CFG["ldap"][creds]["item"]
    )
  rescue MU::Groomer::Chef::MuNoSuchSecret
    data = {
      $MU_CFG["ldap"][creds]["username_field"] => "CN=mu_#{creds},OU=Mu-System,#{$MU_CFG["ldap"]['base_dn']}",
      $MU_CFG["ldap"][creds]["password_field"] => Password.random(14..16)
    }
    MU::Groomer::Chef.saveSecret(
      vault: $MU_CFG["ldap"][creds]["vault"],
      item: $MU_CFG["ldap"][creds]["item"],
      data: data
    )
  end
  if creds == "bind_creds"
    $BIND_DN = data[$MU_CFG["ldap"][creds]["username_field"]]
    $BIND_PW = data[$MU_CFG["ldap"][creds]["password_field"]]
  end
}

# install an LDAP server

# initialize things in its schema

# XXX uncomment when you actually have a working directory server
#MU::Master::Chef.configureChefForLDAP
