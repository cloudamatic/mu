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

case node['platform']
  when "windows"
    execute "del c:\\Mu-Bootstrap*"
    %w{c:\\mu-installer-ran-update c:\\mu-configure-initial-ssh-user}.each { |file|
      file file do
        action :delete
      end
    }
    file "C:\\Program Files\\Amazon\\Ec2ConfigService\\Scripts\\UserScript.ps1" do
        action :delete
    end
    powershell_script "clean up WinRM" do
      code <<-EOH
        winrm delete winrm/config/Listener?Address=*+Transport=HTTP
        winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
        Remove-Item -Path WSMan:/localhost/ClientCertificate/* -Force -Recurse
        Remove-Item -Path Cert:/LocalMachine/My/* -Force -Recurse
# XXX Would need a thumbprint to get this, so there's a whole find-by-name op
#        Remove-Item -Path Cert:/LocalMachine/Root/Mu_CA.pem -Force -Recurse
        Remove-Item -Path Cert:/LocalMachine/TrustedPeople/* -Force -Recurse
      EOH
    end

    # admin_username = powershell_out("(Get-WmiObject -Query 'Select * from Win32_UserAccount Where (LocalAccount=True and SID like \"%-500\")').name").stdout.strip
    # XXX can't do this here, Mu still needs to get back in
    #	["Administrator", admin_username].each { |user|
    #		file "c:\\bin\\cygwin\\home\\#{user}\\.ssh\\authorized_keys" do
    #			action :delete
    #		end
    #	}

    %w{config.xml BundleConfig.xml}.each { |file|
      template "C:\\Program Files\\Amazon\\Ec2ConfigService\\Settings\\#{file}" do
        source "#{file}.erb"
        variables(
            :auto_gen_password => node[:auto_generate_windows_password]
        )
      end
    }

    execute "sc config Ec2Config obj= \".\\LocalSystem\" password= \"\""
    execute "sc config sshd obj= \".\\LocalSystem\" password= \"\""

    %w{run-chef-client run-userdata}.each { |task|
      windows_task task do
        action :delete
      end
    }

    user "ec2config" do
      action :remove
    end

# XXX this breaks Chef mid-run
#	if Dir.exist?("C:\\chef")
#		%w{client.rb first-boot.json client.pem validation.pem}.each { |file|
#			if File.exist?("C:\\chef\\#{file}")
#				file "C:\\Users\\Administrator\\AppData\\Local\\Temp\\#{file}" do
#					content IO.read("C:\\chef\\#{file}")
#				end
#
#				file "C:\\chef\\#{file}" do
#					action :delete
#				end
#			end
#		}
#	end
  when platform_family?('rhel')
    if node['platform_version'].to_i == 7
      execute "sed -i '/^preserve_hostname/d' /etc/cloud/cloud.cfg" do
        only_if "grep 'preserve_hostname: true' /etc/cloud/cloud.cfg"
      end
    end

    execute "sed -i '/user-data.*$/d' /etc/rc.d/rc.local" do
      only_if "grep '/bin/sh /var/lib/cloud/' /etc/rc.d/rc.local"
    end

    file "/.mu-installer-ran-updates" do
      action :delete
    end

    file "/etc/yum.repos.d/mu-platform.repo" do
      action :delete
    end

    directory "/etc/chef" do
      action :delete
      recursive true
    end
  when "ubuntu"
    file "/.mu-installer-ran-updates" do
      action :delete
    end

    execute "sed -i '_^/bin/sh /var/lib/cloud/instance/user-data.txt_d' /etc/rc.local" do
      only_if "grep '/bin/sh /var/lib/cloud/instance/user-data.txt' /etc/rc.local"
    end

    directory "/etc/chef" do
      action :delete
      recursive true
    end
end
