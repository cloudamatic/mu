require 'etc'
require 'open-uri'
require 'socket'
require 'json'


## read on master
node_meta = JSON.parse(File.read("/tmp/MU-MASTER-INSTALL-TEST.json")) if File.exists?("/tmp/MU-MASTER-INSTALL-TEST.json")
chef_server_url = node_meta[0]['pub_ip']
$MU_CFG = '/opt/mu/var'


control 'init' do
  title 'mu-master init recipe tests'
  node = json('/tmp/chef_node.json').params  
  NODE_PUB_IP=node_meta[0]['pub_ip']
  CHEF_SERVER_VERSION="12.17.15-1"
  CHEF_CLIENT_VERSION="18.2.7"
  KNIFE_WINDOWS="1.9.0"
  MU_BASE="/opt/mu"
  f = "/etc/ssh/sshd_config"
  if File.read(f).match(/^AllowUsers\s+([^\s]+)(?:\s|$)/)
    SSH_USER = Regexp.last_match[1].chomp
  else
    SSH_USER="root"
  end
  RUNNING_STANDALONE=node['default']['application_attributes'].nil?
  describe service('iptables') do
    it { should be_running }
  end

  describe directory('/var/run/postgresql') do
    it { should exist }
    it { should be_directory }
    its('mode'){ should cmp '0755' }
  end

  describe file('/var/run/postgresql/.s.PGSQL.5432') do
    it { should exist }
    it { should be_linked_to '/tmp/.s.PGSQL.5432' }
  end
  
  describe file('/etc/hosts.muinstaller') do
    it { should exist }
    it { should be_file }
  end

  if RUNNING_STANDALONE
    describe file('/etc/hosts') do
      it { should exist }
      its('content') { should match /127.0.0.1/ }
      its('content') { should match /localhost6.localdomain6 localhost6/}
    end
  end
  
  basepackages = []
  removepackages = []
  rpms = {}
  dpkgs = {}  


  if os[:family] == "redhat"
    basepackages = ["git", "curl", "diffutils", "patch", "gcc", "gcc-c++", "make", "postgresql-devel", "libyaml"]
    rpms = {
        "epel-release" => "http://dl.fedoraproject.org/pub/epel/epel-release-latest-#{os[:release].to_i}.noarch.rpm",
            "chef-server-core" => "https://packages.chef.io/files/stable/chef-server/#{CHEF_SERVER_VERSION.sub(/\-\d+$/, "")}/el/#{os[:release].to_i}/chef-server-core-#{CHEF_SERVER_VERSION}.el#{os[:release].to_i}.x86_64.rpm"
    }

    if os[:release].to_i < 6 or os[:release].to_i >= 8
      raise "Mu Masters on RHEL-family hosts must be equivalent to RHEL6 or RHEL7"
    elsif os[:release].to_i < 7
      basepackages.concat(["mysql-devel"])
      rpms["ruby23"] = "https://s3.amazonaws.com/cloudamatic/ruby23-2.3.1-1.el6.x86_64.rpm"
      removepackages = ["nagios"]
    
    elsif os[:release].to_i < 8
      basepackages.concat(["libX11", "tcl", "tk", "mariadb-devel"])
      rpms["ruby23"] = "https://s3.amazonaws.com/cloudamatic/ruby23-2.3.1-1.el7.centos.x86_64.rpm"
      removepackages = ["nagios", "firewalld"]
    end
  else
    raise "Mu Masters are currently only supported on RHEL-family hosts."
  end

  basepackages.each do |pack|
    describe package(pack) do
      it { should be_installed }
    end
  end 

  describe directory(MU_BASE) do
    it { should exist }
    it { should be_directory }
    its('mode') { should cmp '0755'}
  end

  ["#{MU_BASE}/lib","#{MU_BASE}/lib/cookbooks", "#{MU_BASE}/lib/.git/hooks"].each do |dir|
    describe directory(dir) do
      it { should exist }
      it { should be_directory }
    end
  end
  
  ["post-merge", "post-checkout", "post-rewrite", "pre-commit"].each { |hook| 
    describe file("#{MU_BASE}/lib/.git/hooks/#{hook}") do
      it { should exist }
      it { should be_file }
      its('mode'){ should cmp '0755' }
    end
  }


  ["#{MU_BASE}/var", "#{MU_BASE}/deprecated-bash-library.sh"].each do |a|
    describe directory(a) do
      it { should exist }
      its('mode'){should cmp '0755' }
    end
  end

  {"#{MU_BASE}/var/mu-chef-client-version"=> CHEF_CLIENT_VERSION, "#{MU_BASE}/var/mu-chef-server-version"=>CHEF_SERVER_VERSION}.each do |f,c|
    describe file(f) do
      its('content') {should match /#{c}/}
      its('mode'){ should cmp '0644'}
    end
  end

  describe directory('/opt/opscode.upgrading.backup') do
    it { should_not exist }
  end

  if RUNNING_STANDALONE
    rpms.each_pair do |pkg,src|
      describe command("rpm -q #{pkg}") do
        its('exit_status'){should eq 0 }
      end
    end
  end

  describe package('jq') do
    it { should be_installed }
  end

  removepackages.each do |rm|
    describe package(rm) do
      it { should_not be_installed }
    end
  end

  describe directory('/opt/rubies/ruby-2.1.6') do
    it { should_not exist }
  end

  describe file('/etc/opscode/chef-server.rb') do
    it { should exist }
    it { should be_file }
    its('content'){should match /api_fqdn server_name/ } 
  end

  describe parse_config_file('/etc/opscode/chef-server.rb') do
    params = {
     'server_name' => "'#{chef_server_url}'","nginx['server_name']" => "server_name",
     "nginx['enable_non_ssl']" => "false","nginx['non_ssl_port']"=>"81",
     "nginx['ssl_port']"=>"7443","nginx['ssl_protocols']"=>"'TLSv1.2'","bookshelf['external_url']"=>"'https://'+server_name+':7443'","bookshelf['vip_port']"=>"7443"
    }
    if ::File.size?("/etc/opscode/chef-server.rb") 
      params.each do |var,val|
        its(var){should eq val}
      end
    end
  end

  ["bin", "etc", "lib", "var/users/mu", "var/deployments", "var/orgs/mu"].each { |mudir|
    describe directory("#{MU_BASE}/#{mudir}") do
      it { should exist }
      its('mode') { should cmp mudir.match(/^var\//) ? '0700' : '0755'}
      its('owner') { should eq 'root'}
    end
  }
  
  {"#{MU_BASE}/var/users/mu/email"=>"root@example.com","#{MU_BASE}/var/users/mu/realname"=>
  "Mu Administrator"}.each do |file,content|
    describe file(file) do
      it { should exist }
      its('content') { should match /#{content}/}
    end
  end

  ["mu-aws-setup", "mu-cleanup", "mu-configure", "mu-deploy", "mu-firewall-allow-clients", "mu-gen-docs", "mu-load-config.rb", "mu-node-manage", "mu-tunnel-nagios", "mu-upload-chef-artifacts", "mu-user-manage", "mu-ssh"].each { |exe|
    describe file("#{MU_BASE}/bin/#{exe}") do
      it { should exist }
      it { should be_linked_to "#{MU_BASE}/lib/bin/#{exe}" }
      its('mode'){should cmp '0755'}
    end
  }

  describe directory("/root/.chef") do
    it { should exist }
  end
 
  ["/opt/opscode/bin/chef-server-ctl org-list | grep '^mu$'", "/opt/opscode/bin/chef-server-ctl user-list | grep '^mu$'"].each do |cmd|
    describe command(cmd) do
      its('exit_status'){ should eq 0 }
      its('stdout'){ should eq "mu\n"}
    end
  end

  describe file("/root/.chef/knife.rb") do
    chef_server_url = node_meta[0]['pub_ip']
    it { should exist }
    its('content'){should match /node_name\s*'mu'/}
    its('content'){should match /validation_client_name\s*'mu-validator'/}
    its('content'){should match /validation_key\s*'#{MU_BASE}\/var\/orgs\/mu\/mu.org.key'/}
    its('content'){should match /client_key\s*'#{MU_BASE}\/var\/users\/mu\/mu.user.key'/}
    its('content'){should match /chef_server_url\s*'https:\/\/#{chef_server_url}:7443\/organizations\/mu'/}
    its('content'){should match /chef_server_root\s*'https:\/\/#{chef_server_url}:7443\/organizations\/mu'/}
    its('content'){should match /syntax_check_cache_path\s*'\/root\/.chef\/syntax_check_cache'/}
    its('content'){should match /cookbook_path \[ '\/root\/.chef\/cookbooks', '\/root\/.chef\/site_cookbooks' \]/}
    its('content'){should match /knife\[:vault_mode\] = 'client'/}
    its('content'){should match /knife\[:vault_admins\] = \['mu'\]/}
  end

=begin
  ruby code is executed on host machine not on target
  
  SSH_DIR = "#{Etc.getpwnam(SSH_USER).dir}/.ssh"
  ROOT_SSH_DIR = "#{Etc.getpwuid(0).dir}/.ssh"

  describe command("cat #{SSH_DIR}/authorized_keys | grep $(cat #{ROOT_SSH_DIR}/id_rsa.pub)") do
      its('exit_status'){should eq 0 }
  end
=end

  %w(/etc/chef/client.pem /etc/chef/validation.pem).each do |fi| 
    describe file(fi) do
      it { should_not exist }
    end
  end
  
  describe file("#{MU_BASE}/etc/mu.rc") do
    it { should exist }
    its('content'){should match /export MU_INSTALLDIR="#{MU_BASE}"/}
    its('content'){should match /export MU_DATADIR="#{MU_BASE}\/var/}
    its('content'){should match /export PATH="#{MU_BASE}\/bin:\/usr\/local\/ruby-current\/bin:\${PATH}:\/opt\/opscode\/embedded\/bin"/}
    its('mode'){should cmp '0644' }
  end 
  
  describe command("chef-server-ctl status") do
    its('exit_status'){should eq 0 }
    services = ["run: nginx", "run: bookshelf", "run: oc_bifrost", "run: oc_id:","run: opscode-erchef",
    "run: opscode-expander","run: opscode-solr4","run: postgresql","run: rabbitmq","run: redis_lb"]
    services.each do |ser|
      its('stdout'){should match /#{ser}/}
    end
  end

end ## end init control


control "basepackages" do
  title "mu-master basepackages recipe test"
  node = json('/tmp/chef_node.json').params

  basepackages = []
  removepackages = []
  rpms = {}
  dpkgs = {}

  if os[:family] == 'redhat'
    basepackages = ["vim-enhanced", "zip", "unzip", "java-1.8.0-openjdk", "libxml2-devel", "libxslt-devel", "cryptsetup-luks", "python-pip", "lsof", "mlocate", "strace", "nmap", "openssl-devel", "readline-devel", "python-devel", "diffutils", "patch", "bind-utils", "httpd-tools", "mailx", "openssl", "libyaml", "graphviz", "ImageMagick-devel", "graphviz-devel", "jq", "vim"]

    if os[:release].to_i < 6 or os[:release].to_i >= 8
      raise "Mu Masters on RHEL-family hosts must be equivalent to RHEL6 or RHEL7"
    
    elsif os[:release].to_i < 7
      basepackages.concat(["java-1.5.0-gcj", "mysql-server", "autoconf"])
      basepackages << "gecode-devel" if node[:platform] == "amazon"
    
    elsif os[:release].to_i < 8
      basepackages.concat(["gecode-devel", "mariadb", "qt", "qt-x11", "iptables-services"])
    end
  else
    raise "Mu Masters are currently only supported on RHEL-family hosts."
  end


  basepackages.each do |pack|
    describe package(pack) do
      it { should be_installed }
    end
  end

  rpms.each_pair { |pkg, src|
    describe command("rpm -q #{pkg}") do
      its('exit_status'){ should eq 0 }
    end
  }
end




control 'firewall-holes' do
  title 'mu-master firewall-holes recipe test'


  [2260, 7443, 8443, 9443, 10514, 443, 80, 25].each do |port|
    describe command("netstat -ant | grep #{port}") do
      its('exit_status'){should eq 0 }
    end
  end

end


control 'ssl-certs' do
  title 'mu-master ssl-certs recipe test'
    
  service_certs = ["rsyslog", "mommacat", "ldap", "consul", "vault"]
  
  describe directory("#{$MU_CFG}/ssl") do
    it { should exist }
  end

  describe file("#{$MU_CFG}/ssl/Mu_CA.key") do
    it { should exist }
    its('mode') { should cmp '0400'}
  end

  describe file("#{$MU_CFG}/ssl/openssl.cnf") do
    it { should exist }
    it { should be_file }
    its('content'){should match /dir\s*=\s*#{$MU_CFG}\/ssl/ }
    its('content'){should match /certs\s*=\s*\$dir/}
    its('content'){should match /certificate\s*=\s*\$dir\/Mu_CA.pem/}
    its('content'){should match /private_key\s*= \$dir\/Mu_CA.key/}
  end

  service_certs.each do |cert|
    
    describe file("#{$MU_CFG}/ssl/#{cert}.crt") do
      it { should exist }
      its('mode') { should cmp '0444' }
    end
    
    describe file("#{$MU_CFG}/ssl/#{cert}.key") do
      it { should exist }
      its('mode'){should cmp '0400' }
    end

    describe file("#{$MU_CFG}/ssl/#{cert}.p12") do
      it { should exist }
      its('mode') { should cmp '0444' }
    end

    describe file("#{$MU_CFG}/ssl/#{cert}.csr") do
      it { should_not exist }
    end
    
  end

 describe file("#{$MU_CFG}/ssl/CA-command.txt") do
  it { should exist }
  its('content') { should match /openssl req -subj/ }
  its('content') { should match /-x509 -new -nodes -key Mu_CA.key -days 1024 -out Mu_CA.pem -sha512 -extensions v3_ca -config/}
 end
  
  describe file("#{$MU_CFG}/ssl/Mu_CA.pem") do
    it { should exist }
    its('mode') { should cmp '0444' }
  end
  
  describe file("/etc/pki/ca-trust/source/anchors/Mu_CA.pem") do
    it { should exist }
  end

  describe file("/opt/mu/lib/cookbooks/mu-tools/files/default/Mu_CA.pem") do
    it { should exist }
  end

end


control 'vault' do
  title 'mu-master ssl-certs recipe test'
  node = json('/tmp/chef_node.json').params
  

  ["consul", "vault"].each { |cert|
    describe directory("/opt/#{cert}") do
      it { should exist }
      its('mode') { should cmp '0755' }
    end

    describe file("#{$MU_CFG}/ssl/#{cert}.key") do
      its('owner') { should eq cert }
    end

    describe file("#{$MU_CFG}/ssl/#{cert}.key") do
      its('owner') { should eq cert }
    end

    describe service(cert) do
      it { should be_enabled }
      it { should be_running }
    end
  
  }

  describe directory("/etc/consul/ssl") do
    it { should exist }
    its('owner'){should eq 'consul'}
    its('group'){should eq 'consul'}
    its('mode'){should cmp '0755'}
  end

  %w(/etc/vault /etc/vault/ssl /etc/consul/ssl/CA).each do |dir|
    describe directory(dir) do
      it { should exist }
      its('owner'){should eq 'root'}
      its('mode'){should cmp '0755'}
    end
  end

  describe file("/etc/consul/ssl/CA/ca.crt") do
    it { should exist }
    its('mode'){should cmp '0644'}
  end
end


control 'default' do
  title 'mu-master default recipe tests'
 
  node = json('/tmp/chef_node.json').params
  
  describe sys_info do
    its('hostname') { should eq 'mu-master' }
  end
  
  describe file('/root/.vimrc') do
    it { should exist }
  end

  describe file('/etc/profile.d/usr_local_bin.sh') do
    it { should exist }
    its('content') { should match /export PATH="\${PATH}:\/usr\/local\/bin"/}
    its('mode'){should cmp '0644'}
  end

  describe file('/var/www/html/cloudamatic.png') do
    it { should exist }
    its('mode'){should cmp '0644'}
  end
  
  
  describe package('nagios') do
    it { should_not be_installed }
  end

  only_if do
    !node['default']['update_nagios_only']
    
    describe package('nagios-plugins-all') do
      it { should be_installed }
    end
  
    %w(/home/nagios /home/nagios/.ssh).each do |dir|
      describe directory(dir) do
        it { should exist }
        its('owner') { should eq 'nagios'}
        its('mode') { should cmp '0711' }
      end 
    end
    
    describe file("/home/nagios/.ssh/config") do
      it { should exist }
      its('mode') { should cmp '0600' }
      its('owner'){ should cmp 'nagios' }
    end

    describe file('/etc/dhcp/dhclient-eth0.conf') do
      it { should exist }
      ins_id = node_meta[0]['ins_id']
      its('content') { should match /interface\s*"eth0"\s*{/ }
      its('content') { should match /#\s*ec2.internal,\s*server.#{ins_id}.platform-mu,\s*platform-mu/ }
      its('content') { should match /supersede\s*domain-search\s*"ec2.internal",\s*"server.#{ins_id}.platform-mu",\s*"platform-mu"/ }
      its('mode'){should cmp '0644' }
    end

    describe command("/usr/sbin/getsebool httpd_can_network_connect | grep -cim1 ^.*on$") do
      its('exit_status'){should eq 0 }
    end
    
    %w(mu_docs https_proxy).each do |conf|
      describe file("/etc/httpd/sites-enabled/#{conf}.conf") do
        it { should exist }
      end
    end

    describe file('/usr/lib64/nagios/cgi-bin') do
      it { should exist }
      it { should be_linked_to "/usr/lib/cgi-bin"}
    end

    describe directory("/var/www/html/docs") do
      it { should exist }
      its('owner'){ should eq 'apache' }
      its('owner'){ should eq 'apache' }
    end 

    describe file('/var/www/html/index.html') do
      it { should exist }
      its('owner'){ should eq 'apache' }
      its('owner'){ should eq 'apache' }
      its('content') { should match /<a href='http:\/\/#{chef_server_url}\/docs\/frames.html'>Mu API documentation<\/a>/ }
    end
    
    describe directory('/Mu_Logs') do
      it { should exist }
    end

    describe file('/etc/rsyslog.d/0-mu-log-server.conf') do
      it { should exist }
      its('content'){ should match /\$DefaultNetstreamDriver gtls/}
      its('content'){ should match /\$InputTCPServerStreamDriverMode 1/ }
    end
   
    describe file("/etc/rsyslog.d/0-mu-log-client.conf") do
      it { should_not exist }
    end

    ["grep ^/opt/chef/bin/chef-client /etc/rc.d/rc.local","grep '^/sbin/restorecon -r /home' /etc/rc.d/rc.local"].each do |cmd|
      describe command(cmd) do
        its('exit_status'){should eq 0}
      end
    end

    describe directory("/etc/pki/rsyslog") do
      it { should exist }
    end
    
    describe package('logrotate') do
      it { should be_installed }
    end
   
    describe service('mu-momma-cat') do
      it { should be_running }
      it { should be_enabled }
    end

    describe service('nagios') do
      it { should be_running }
    end
  end # end only_if


end
