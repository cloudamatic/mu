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

# How to completely undo all of this: service dirsrv stop ; pkill ns-slapd ; yum erase -y 389-ds 389-ds-console 389-ds-base 389-admin 389-adminutil 389-console 389-ds-base-libs; rm -rf /etc/dirsrv /var/lib/dirsrv /var/log/dirsrv /var/lock/dirsrv /var/run/dirsrv /etc/sysconfig/dirsrv* /usr/lib64/dirsrv /usr/share/dirsrv; knife data bag delete -y mu_ldap

# Retrieve credentials we need to do LDAP things. Generate from scratch if they
# haven't been provided.
$CREDS = {
  "bind_creds" => {
    "user" => "CN=mu_bind_creds,#{$MU_CFG["ldap"]['user_ou']}"
  },
  "join_creds" => {
    "user" => "CN=mu_join_creds,#{$MU_CFG["ldap"]['user_ou']}"
  },
  "cfg_directory_adm" => {
    "user" => "admin"
  },
  "root_dn_user" => {
    "user" => "CN=root_dn_user"
  }
} 
$CREDS.each_pair { |creds, cfg|
  user = pw = nil
  begin
    data = nil
    if $MU_CFG["ldap"].has_key?(creds)
      data = MU::Groomer::Chef.getSecret(
        vault: $MU_CFG["ldap"][creds]["vault"],
        item: $MU_CFG["ldap"][creds]["item"]
      )
      user = data[$MU_CFG["ldap"][creds]["username_field"]]
      pw = data[$MU_CFG["ldap"][creds]["password_field"]]
      MU::Groomer::Chef.grantSecretAccess("MU-MASTER", $MU_CFG["ldap"][creds]["vault"], $MU_CFG["ldap"][creds]["item"])
    else
      data = MU::Groomer::Chef.getSecret(vault: "mu_ldap", item: creds)
      user = data["username"]
      pw = data["password"]
      MU::Groomer::Chef.grantSecretAccess("MU-MASTER", "mu_ldap", creds)
    end
  rescue MU::Groomer::Chef::MuNoSuchSecret
    user = cfg["user"]
    pw = Password.pronounceable(14..16)
    if $MU_CFG["ldap"].has_key?(creds)
      data = {
        $MU_CFG["ldap"][creds]["username_field"] => user,
        $MU_CFG["ldap"][creds]["password_field"] => pw
      }
      MU::Groomer::Chef.saveSecret(
        vault: $MU_CFG["ldap"][creds]["vault"],
        item: $MU_CFG["ldap"][creds]["item"],
        data: data,
        permissions: "name:MU-MASTER"
      )
    else
      MU::Groomer::Chef.saveSecret(
        vault: "mu_ldap",
        item: creds,
        data: { "username" => user, "password" => pw },
        permissions: "name:MU-MASTER"
      )
    end
  end
  $CREDS[creds]['user'] = user if !$CREDS[creds]['user']
  $CREDS[creds]['pw'] = pw if !$CREDS[creds]['pw']
}
ENV['PATH'] = "/opt/mu/bin:/usr/local/ruby-current/bin:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/opt/opscode/embedded/bin:/root/bin:#{ENV['PATH']}"
ENV['LOGNAME'] = "root"

if $MU_CFG["ldap"]["type"] == "389 Directory Services"
  %x{/usr/sbin/setenforce 0}
  log = File.open("/root/ldap_setup_log.#{Process.pid}", File::CREAT|File::TRUNC|File::RDWR, 0600)
  ENV.each_pair { |k,v|
    log.puts "#{k} = #{v}"
  }
  # Install and bootstrap the LDAP server
  %x{/usr/bin/yum -y install 389-ds 389-ds-console}
  if !Dir.exists?("/etc/dirsrv/slapd-#{$MU_CFG["host_name"]}")
    vars = {
      "hostname" => $MU_CFG["host_name"],
      "domain" => $MU_CFG["ldap"]["domain_name"],
      "domain_dn" => $MU_CFG["ldap"]["domain_name"].split(/\./).map{ |x| "DC=#{x}" }.join(","),
      "creds" => $CREDS
    }
    cfg = Erubis::Eruby.new(File.read("#{$MU_CFG['libdir']}/install/389-directory-setup.inf.erb")).result(vars)
    File.open("/root/389-directory-setup.inf", File::CREAT|File::TRUNC|File::RDWR, 0600) { |f|
      f.puts cfg
    }
    output = %x{/usr/sbin/setup-ds-admin.pl -s --debug --logfile /root/setup_ds_admin_log.#{Process.pid} -f /root/389-directory-setup.inf}
    if $?.exitstatus != 0
      puts cfg
      log.puts cfg
      log.puts output
      MU.log "Error setting up LDAP services with /usr/sbin/setup-ds-admin.pl -s -f /root/389-directory-setup.inf", MU::ERR, details: output
      %x{/sbin/service dirsrv stop ; /usr/sbin/stop-dirsrv ; pkill ns-slapd ; yum erase -y 389-ds 389-ds-console 389-ds-base 389-admin 389-adminutil 389-console 389-ds-base-libs; rm -rf /etc/dirsrv /var/lib/dirsrv /var/log/dirsrv /var/lock/dirsrv /var/run/dirsrv /etc/sysconfig/dirsrv* /usr/lib64/dirsrv /usr/share/dirsrv; knife data bag delete -y mu_ldap}
      exit 1
    end
    puts output
    log.puts output
  #  File.unlink("/root/389-directory-setup.inf")
  end
  # Ram TLS into the LDAP server's snout

  # Why is this utility interactive-only? So much hate.
  puts certimportcmd = "echo "" > /root/blank && /usr/bin/pk12util -i /opt/mu/var/ssl/ldap.p12 -d /etc/dirsrv/slapd-#{$MU_CFG["host_name"]} -w /root/blank -W \"\""
  require 'pty'
  require 'expect'
  PTY.spawn(certimportcmd) { |r, w, pid|
    begin
      r.expect("Enter new password:") do
        w.puts
      end
      r.expect("Re-enter password:") do
        w.puts
      end
    rescue Errno::EIO
      break
    end
  }

  puts caimportcmd = "/usr/bin/certutil -d /etc/dirsrv/slapd-#{$MU_CFG["host_name"]} -A -n \"Mu Master CA\" -t CT,, -a -i /opt/mu/var/ssl/Mu_CA.pem"
  puts %x{#{caimportcmd}}

  ["ssl_enable.ldif", "addRSA.ldif"].each { |ldif|
    puts ldapmodcmd = "/usr/bin/ldapmodify -x -D #{$CREDS["root_dn_user"]['user']} -w #{$CREDS["root_dn_user"]['pw']} -f #{$MU_CFG['libdir']}/install/#{ldif}"
    puts %x{#{ldapmodcmd}}
  }
  %x{/sbin/service dirsrv restart}
  %x{/sbin/chkconfig dirsrv on}
  %x{/sbin/chkconfig dirsrv-admin on}
  %x{/usr/sbin/stop-dirsrv}
  %x{/usr/sbin/start-dirsrv}
  if File.exists?("/usr/bin/systemctl")
    %x{/usr/bin/systemctl enable dirsrv-admin}
  end

  # Manufacture some groups and management users.
  MU::Master::LDAP.initLocalLDAP
  log.close
  %x{/usr/sbin/setenforce 1}
end

# XXX figure out how to do this without mu_setup stepping on it
#MU::Master::Chef.configureChefForLDAP
