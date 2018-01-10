control 'base_repositories' do
  title 'mu-tools cookbook'
    
    describe directory('/tmp') do
      it { should exist }
    end
  
    node = json('/tmp/chef_node.json').params
    node['default']['application_attributes']['skip_recipes'] = []
    if !node['default']['application_attributes']['skip_recipes'].include?('base_repositories')
      case os[:family]
        when "redhat"
          # Workaround for EOL CentOS 5 repos
          if os[:name] != "amazon" and os[:release].to_i == 5
             
             describe file("/etc/yum.repos.d/CentOS-Base.repo") do
              it { should exist }
              it { should be_file }
            end
            
            describe parse_config_file('/etc/yum.repos.d/CentOS-Base.repo') do
              params = {
                        'CentOS-$releasever - Base':'name', 'http://vault.centos.org/5.11/os/$basearch/':'baseurl',
                        '1':'gpgcheck','file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-5':'gpgkey'
                        }
              params.each do |val,var|
                its(var){should eq val}
              end
            end

          end
          describe file('/etc/yum.repos.d/epel.repo') do
            it { should exist }
            it { should be_owned_by 'root' }
            it { should be_grouped_into 'root' }
          end
        end
    end
end


control 'set_mu_hostname' do
  title 'mu-tools cookbook'

    node = json('/tmp/chef_node.json').params
    @platform = os[:name]
    if !node['default']['application_attributes']['skip_recipes'].include?('set_mu_hostname')
      $hostname = node['default']['name']
    if !node['default']['ad']['computer_name'].nil? and !node['default']['ad']['computer_name'].empty?
      $hostname = node['default']['ad']['computer_name']
    end rescue NoMethodError
      $ipaddress = node['default']['ipaddress']

     
    case os[:name]
      when "centos", "redhat","amazon"
        
        describe file('/etc/sysconfig/network') do
          it { should exist }
          it { should be_file }
          its('content'){should match /NETWORKING=yes/}
          its('content'){ should match /NETWORKING_IPV6=no/n}
          its('content'){should match /#{node['name']}/}
        end

        describe sys_info do
          its('hostname') { should eq node['name'] }
        end
        
      end
    end
  end


control 'disable-requiretty' do
  title 'mu-tools cookbook'
    
  case os[:name]
  when "centos", "redhat"
    
    describe file('/etc/sudoers') do
      it { should exist }
      its('content') { should match /Defaults   !requiretty/}
    end  
  end

end


control 'set_local_fw' do
  title 'mu-tools cookbook'
  
  case os[:name]
  when "centos", "redhat"
    if os[:release].to_i >= 7
      describe package('firewall_config') do
        it { should be_installed }
      end
      
      describe service('iptables') do
        it { should be_running }
      end
    end
    
    if os[:release].to_i <= 6
      describe iptables do
        it { should have_rule('-A INPUT -i lo -j ACCEPT') }
        it { should have_rule('-A OUTPUT -o lo -j ACCEPT') }
      end

      #### missing resource test here -- where is get_mu_master_ips

    end
  end
end 


control 'rsyslog' do
  title 'mu-tools cookbook'
  node = json('/tmp/chef_node.json').params
  
  if !node['default']['application_attributes']['skip_recipes'].include?('rsyslog')
  case os[:family]
  when 'redhat', 'debian'
    %w(rsyslog rsyslog-gnutls).each do |p|
      describe package(p) do
        it { should be_installed }
      end
    end

    describe service('rsyslog') do
      it { should be_running }
      it { should be_enabled }
    end

    if os[:family] == 'redhat'
      $rsyslog_ssl_ca_path = "/etc/pki/Mu_CA.pem"
      if os[:name] == 'amazon'
        describe package('policycoreutils-python') do
          it { should be_installed }
        end
        describe command("/usr/sbin/semanage port -l | grep '^syslogd_port_t.*10514'") do
          its('exit_status') { should eq 0 }
        end
      end
    elsif os[:family] == 'debian'
      $rsyslog_ssl_ca_path = "/etc/ssl/Mu_CA.pem"
      describe package('policycoreutils') do
        it { should be_installed }
      end
    end

    if node['name'] != 'MU-MASTER'
      ### missing get_mu_master_ips
      
      describe file('/etc/rsyslog.d/0-mu-log-client.conf') do
        it { should exist }
        its('content') { should match /\$LocalHostName #{node['name']}/ }
        its('content') { should match /\$DefaultNetstreamDriverCAFile #{$rsyslog_ssl_ca_path}/ }
        its('content') { should match /\$DefaultNetstreamDriver gtls/ }
        its('content') { should match /\$ActionSendStreamDriverMode 1/ }
        its('content') { should match /\$ActionSendStreamDriverAuthMode anon/}
     end

     describe file($rsyslog_ssl_ca_path) do
      it { should exist }
      it { should be_file }
     end
      
    end
  end 
  end 
end 



control 'nrpe' do
  title 'mu-tools cookbook'

  node = json('/tmp/chef_node.json').params

  if !node['default']['application_attributes']['skip_recipes'].include?('nrpe')
    case os[:family]
    when "redhat"

      ['nrpe', 'nagios-plugins-disk', 'nagios-plugins-nrpe', 'nagios-plugins-ssh'].each do |p|
        describe package(p) do
          it { should be_installed }
        end
      end
      
      describe file('/etc/nagios/nrpe.cfg') do
        it { should exist }
        it { should be_file }
        its('mode') { should cmp '0644' }
      end

      describe parse_config_file('/etc/nagios/nrpe.cfg') do
        # missing master ips..........
        params = {
          'log_facility': 'daemon', 'pid_file':'/var/run/nrpe/nrpe.pid', 'server_port':'5666',
          'nrpe_group':'nrpe', 'dont_blame_nrpe':'0','allow_bash_command_substitution':'0',
          'debug':'0', 'command_timeout':'60', 'connection_timeout':'300',
          'command[check_users]':'/usr/lib64/nagios/plugins/check_users -w 5 -c 10',
          'command[check_load]':'/usr/lib64/nagios/plugins/check_load -w 15,10,5 -c 30,25,20',
          'command[check_zombie_procs]':'/usr/lib64/nagios/plugins/check_procs -w 5 -c 10 -s Z',
          'command[check_total_procs]': '/usr/lib64/nagios/plugins/check_procs -w 150 -c 200',
          'command[check_disk]':'/usr/lib64/nagios/plugins/check_disk -w 15% -c 5% -X nfs -X nfs4',
          'include_dir': '/etc/nagios/nrpe.d/'
        }
        params.each do |var,val|
          its(var){ should eq val }
        end
      end

      describe service('nrpe') do
        it { should be_running }
        it { should be_enabled }
      end

      describe directory('/etc/nagios/nrpe.d') do
        it { should exist }
        its('owner') { should eq 'nrpe' }
        its('group') { should eq 'nrpe' }
        its('mode') { should cmp '0755' }
      end
      
      
      case os[:release].to_i
      when 7
        

      end ## end nested case



    end # case
  
  end #if

end

