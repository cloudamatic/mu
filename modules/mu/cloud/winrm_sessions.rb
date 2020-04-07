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

autoload :WinRM, "winrm"

module MU
  # Plugins under this namespace serve as interfaces to cloud providers and
  # other provisioning layers.
  class Cloud

    [:Server, :ServerPool].each { |name|
      Object.const_get("MU").const_get("Cloud").const_get(name).class_eval {

        # Gracefully message and attempt to accommodate the common transient errors peculiar to Windows nodes
        # @param e [Exception]: The exception that we're handling
        # @param retries [Integer]: The current number of retries, which we'll increment and pass back to the caller
        # @param rebootable_fails [Integer]: The current number of reboot-worthy failures, which we'll increment and pass back to the caller
        # @param max_retries [Integer]: Maximum number of retries to attempt; we'll raise an exception if this is exceeded
        # @param reboot_on_problems [Boolean]: Whether we should try to reboot a "stuck" machine
        # @param retry_interval [Integer]: How many seconds to wait before returning for another attempt
        def handleWindowsFail(e, retries, rebootable_fails, max_retries: 30, reboot_on_problems: false, retry_interval: 45)
          msg = "WinRM connection to https://"+@mu_name+":5986/wsman: #{e.message}, waiting #{retry_interval}s (attempt #{retries}/#{max_retries})"
          if e.class.name == "WinRM::WinRMAuthorizationError" or e.message.match(/execution expired/) and reboot_on_problems
            if rebootable_fails > 0 and (rebootable_fails % 7) == 0
              MU.log "#{@mu_name} still misbehaving, forcing Stop and Start from API", MU::WARN
              reboot(true) # vicious API stop/start
              sleep retry_interval*3
              rebootable_fails = 0
            else
              if rebootable_fails == 5
                MU.log "#{@mu_name} misbehaving, attempting to reboot from API", MU::WARN
                reboot # graceful API restart
                sleep retry_interval*2
              end
              rebootable_fails = rebootable_fails + 1
            end
          end
          if retries < max_retries
            if retries == 1 or (retries/max_retries <= 0.5 and (retries % 3) == 0 and retries != 0)
              MU.log msg, MU::NOTICE
            elsif retries/max_retries > 0.5
              MU.log msg, MU::WARN, details: e.inspect
            end
            sleep retry_interval
            retries = retries + 1
          else
            raise MuError, "#{@mu_name}: #{e.inspect} trying to connect with WinRM, max_retries exceeded", e.backtrace
          end
          return [retries, rebootable_fails]
        end

        def windowsRebootPending?(shell = nil)
          if shell.nil?
            shell = getWinRMSession(1, 30)
          end
#              if (Get-Item "HKLM:/SOFTWARE/Microsoft/Windows/CurrentVersion/WindowsUpdate/Auto Update/RebootRequired" -EA Ignore) { exit 1 }
          cmd = %Q{
            if (Get-ChildItem "HKLM:/Software/Microsoft/Windows/CurrentVersion/Component Based Servicing/RebootPending" -EA Ignore) {
              echo "Component Based Servicing/RebootPending is true"
              exit 1
            }
            if (Get-ItemProperty "HKLM:/SYSTEM/CurrentControlSet/Control/Session Manager" -Name PendingFileRenameOperations -EA Ignore) {
              echo "Control/Session Manager/PendingFileRenameOperations is true"
              exit 1
            }
            try { 
              $util = [wmiclass]"\\\\.\\root\\ccm\\clientsdk:CCM_ClientUtilities"
              $status = $util.DetermineIfRebootPending()
              if(($status -ne $null) -and $status.RebootPending){
                echo "WMI says RebootPending is true"
                exit 1
              }
            } catch {
              exit 0
            }
            exit 0
          }
          resp = shell.run(cmd)
          returnval = resp.exitcode == 0 ? false : true
          shell.close
          returnval
        end

        # Basic setup tasks performed on a new node during its first WinRM 
        # connection. Most of this is terrible Windows glue.
        # @param shell [WinRM::Shells::Powershell]: An active Powershell session to the new node.
        def initialWinRMTasks(shell)
          retries = 0
          rebootable_fails = 0
          begin
            if !@config['use_cloud_provider_windows_password']
              pw = @groomer.getSecret(
                vault: @config['mu_name'],
                item: "windows_credentials",
                field: "password"
              )
              win_check_for_pw = %Q{Add-Type -AssemblyName System.DirectoryServices.AccountManagement; $Creds = (New-Object System.Management.Automation.PSCredential("#{@config["windows_admin_username"]}", (ConvertTo-SecureString "#{pw}" -AsPlainText -Force)));$DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine); $DS.ValidateCredentials($Creds.GetNetworkCredential().UserName, $Creds.GetNetworkCredential().password); echo $Result}
              resp = shell.run(win_check_for_pw)
              if resp.stdout.chomp != "True"
                win_set_pw = %Q{(([adsi]('WinNT://./#{@config["windows_admin_username"]}, user')).psbase.invoke('SetPassword', '#{pw}'))}
                resp = shell.run(win_set_pw)
                puts resp.stdout
                MU.log "Resetting Windows host password", MU::NOTICE, details: resp.stdout
              end
            end

            # Install Cygwin here, because for some reason it breaks inside Chef
            # XXX would love to not do this here
            pkgs = ["bash", "mintty", "vim", "curl", "openssl", "wget", "lynx", "openssh"]
            admin_home = "c:/bin/cygwin/home/#{@config["windows_admin_username"]}"
            install_cygwin = %Q{
              If (!(Test-Path "c:/bin/cygwin/Cygwin.bat")){
                $WebClient = New-Object System.Net.WebClient
                $WebClient.DownloadFile("http://cygwin.com/setup-x86_64.exe","$env:Temp/setup-x86_64.exe")
                Start-Process -wait -FilePath $env:Temp/setup-x86_64.exe -ArgumentList "-q -n -l $env:Temp/cygwin -R c:/bin/cygwin -s http://mirror.cs.vt.edu/pub/cygwin/cygwin/ -P #{pkgs.join(',')}"
              }
              if(!(Test-Path #{admin_home})){
                New-Item -type directory -path #{admin_home}
              }
              if(!(Test-Path #{admin_home}/.ssh)){
                New-Item -type directory -path #{admin_home}/.ssh
              }
              if(!(Test-Path #{admin_home}/.ssh/authorized_keys)){
                New-Item #{admin_home}/.ssh/authorized_keys -type file -force -value "#{@deploy.ssh_public_key}"
              }
            }
            resp = shell.run(install_cygwin)
            if resp.exitcode != 0
              MU.log "Failed at installing Cygwin", MU::ERR, details: resp
            end

            hostname = nil
            if !@config['active_directory'].nil?
              if @config['active_directory']['node_type'] == "domain_controller" && @config['active_directory']['domain_controller_hostname']
                hostname = @config['active_directory']['domain_controller_hostname']
                @mu_windows_name = hostname
              else
                # Do we have an AD specific hostname?
                hostname = @mu_windows_name
              end
            else
              hostname = @mu_windows_name
            end
            resp = shell.run(%Q{hostname})

            if resp.stdout.chomp != hostname
              resp = shell.run(%Q{Rename-Computer -NewName '#{hostname}' -Force -PassThru -Restart; Restart-Computer -Force})
              MU.log "Renaming Windows host to #{hostname}; this will trigger a reboot", MU::NOTICE, details: resp.stdout
              reboot(true)
              sleep 30
            end
          rescue WinRM::WinRMError, HTTPClient::ConnectTimeoutError => e
            retries, rebootable_fails = handleWindowsFail(e, retries, rebootable_fails, max_retries: 10, reboot_on_problems: true, retry_interval: 30)
            retry
          end
        end

        # Get a privileged Powershell session on the server in question, using SSL-encrypted WinRM with certificate authentication.
        # @param max_retries [Integer]:
        # @param retry_interval [Integer]:
        # @param timeout [Integer]:
        # @param winrm_retries [Integer]:
        # @param reboot_on_problems [Boolean]:
        def getWinRMSession(max_retries = 40, retry_interval = 60, timeout: 30, winrm_retries: 2, reboot_on_problems: false)
          _nat_ssh_key, _nat_ssh_user, _nat_ssh_host, canonical_ip, _ssh_user, _ssh_key_name = getSSHConfig
          @mu_name ||= @config['mu_name']

          shell = nil
          opts = nil
          # and now, a thing I really don't want to do
          MU::Master.addInstanceToEtcHosts(canonical_ip, @mu_name)

          # catch exceptions that circumvent our regular call stack
          Thread.abort_on_exception = false
          Thread.handle_interrupt(WinRM::WinRMWSManFault => :never) {
            begin
              Thread.handle_interrupt(WinRM::WinRMWSManFault => :immediate) {
                MU.log "(Probably harmless) Caught a WinRM::WinRMWSManFault in #{Thread.current.inspect}", MU::DEBUG, details: Thread.current.backtrace
              }
            ensure
              # Reraise something useful
            end
          }

          retries = 0
          rebootable_fails = 0
          begin
            loglevel = retries > 4 ? MU::NOTICE : MU::DEBUG
            MU.log "Calling WinRM on #{@mu_name}", loglevel, details: opts
            opts = {
              retry_limit: winrm_retries,
              no_ssl_peer_verification: true, # XXX this should not be necessary; we get 'hostname "foo" does not match the server certificate' even when it clearly does match
              ca_trust_path: "#{MU.mySSLDir}/Mu_CA.pem",
              transport: :ssl,
              operation_timeout: timeout,
            }
            if retries % 2 == 0 # NTLM password over https
              opts[:endpoint] = 'https://'+canonical_ip+':5986/wsman'
              opts[:user] = @config['windows_admin_username']
              opts[:password] = getWindowsAdminPassword
            else # certificate auth over https
              opts[:endpoint] = 'https://'+@mu_name+':5986/wsman'
              opts[:client_cert] = "#{MU.mySSLDir}/#{@mu_name}-winrm.crt"
              opts[:client_key] = "#{MU.mySSLDir}/#{@mu_name}-winrm.key"
            end
            conn = WinRM::Connection.new(opts)
            conn.logger.level = :debug if retries > 2
            MU.log "WinRM connection to #{@mu_name} created", MU::DEBUG, details: conn
            shell = conn.shell(:powershell)
            shell.run('ipconfig') # verify that we can do something
          rescue Errno::EHOSTUNREACH, Errno::ECONNREFUSED, HTTPClient::ConnectTimeoutError, OpenSSL::SSL::SSLError, SocketError, WinRM::WinRMError, Timeout::Error => e
            retries, rebootable_fails = handleWindowsFail(e, retries, rebootable_fails, max_retries: max_retries, reboot_on_problems: reboot_on_problems, retry_interval: retry_interval)
            retry
          ensure
            MU::Master.removeInstanceFromEtcHosts(@mu_name)
          end

          shell
        end

      }
    }

  end

end
