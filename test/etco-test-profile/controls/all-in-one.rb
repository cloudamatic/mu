require 'yaml'

mongo = YAML.load_file("/tmp/etco-mongo_attr.yaml")
cas = YAML.load_file("/tmp/etco-app_attr.yaml")
mongo_dns = mongo['fqdn']
cas_dns= cas['load_balancers'][0]['cas-elb']
app_elb = cas['load_balancers'][1]['app-elb']

  

control 'app' do
  title 'app tests'
  
  node = json('/tmp/chef_node.json').params

  
  describe package('java-1.7.0-openjdk-devel') do
    it { should be_installed }
  end
  
  describe directory(node['default']['apps_dir']) do
    it { should exist }
    it { should be_directory}
    its('owner'){ should eq 'root'}
  end

  describe file("#{node['default']['apps_dir']}/#{node['default']['play_package']}") do
    it { should exist }
    it { should be_file }
    its('owner') { should eq 'root'}    
  end

  describe directory("#{node['default']['apps_dir']}/tmp") do
    it { should exist }
    it { should be_directory}
    its('owner'){ should eq 'root'}
  end

  describe directory("#{node['default']['apps_dir']}/tmp/tcm-*-SNAPSHOT") do
    it { should_not exist }
  end

  describe file("#{node['default']['apps_dir']}/application.conf") do
    it { should exist }
    it { should be_file }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should cmp '0755' }
    its('content') { should match /mongodb.uri="mongodb:\/\/#{mongo_dns}:27017\/tco_test_db"/}
    its('content') { should match /app.casClient = "http:\/\/#{cas_dns}\/cas-etco"/}
  end
  
  describe command('iptables --list-rule | grep 9000') do
    its('exit_status'){ should eq 0 }
  end

  describe directory("#{node['default']['apps_dir']}/log") do
    it { should be_directory }
    its('owner') { should eq 'root'}
  end
  
  describe command("curl #{app_elb}") do
    its('exit_status'){should eq 0}
    its('stdout'){should match 'eTCO'}
  end
  
end # end app control

#******************************************************************************

control 'cas' do
  title 'cas tests'
  
  node = json('/tmp/chef_node.json').params
  catalina_home = node['default']['tomcat_dir']
  cas_dir="#{node['default']['cas_dir']}"
  cas_download_url="#{node['default']['cas_download_url']}"
  tomcat_dir = node['default']['tomcat_dir']

  %w(unzip java-1.7.0-openjdk-devel).each do |pack|
    describe package(pack) do
      it { should be_installed }
    end
  end
  
  describe file('/etc/init.d/tomcat') do
    it { should exist }
    it { should be_file}
    its('mode') { should cmp '0755'}
    its('owner'){ should eq 'root' }
    its('group'){ should eq 'root' }
    its('content'){ should match /PATH=\$JAVA_HOME\/bin:\$PATH/ }
    its('content'){ should match /CATALINA_HOME=#{catalina_home}/}
  end
 
  [tomcat_dir, cas_dir].each do
    describe directory(node['default']['tomcat_dir']) do
      it { should exist }
      it { should be_directory }
    end
  end

  describe file("#{cas_dir}/cas-server.tar.gz") do
    it { should be_file }
    it { should exist }
  end

  describe file("#{tomcat_dir}/webapps/cas-etco.war") do
    it { should exist }
  end
  
  describe file("#{node['default']['tomcat_dir']}/webapps/cas-etco/WEB-INF/deployerConfigContext.xml") do
    it { should exist }
    it { should be_file }
    its('owner'){ should eq 'root' }
    its('group') { should eq 'root' }
    its('mode'){ should cmp '0755'}
    its('content'){should match /\        <property name="users">/}
  end

  describe service('tomcat') do
    it { should be_enabled }
    it { should be_running }
  end
  
  describe command('iptables --list-rule | grep 8080') do
    its('exit_status'){ should eq 0 }
  end
end # end cas control

#******************************************************************************

control 'mongo' do
  title 'mongo tests' 

  %w(git mongodb-org-server mongodb-org-shell mongodb-org-tools sysstat java-1.7.0-openjdk-devel).each do |pack|
    describe package(pack) do
      it { should be_installed }
    end
  end
  
  %w(/data /log /journal /data/journal).each do |dir|
    describe directory(dir) do
      it { should exist }
      it { should be_directory }
      its('owner'){should eq 'mongod'}
      its('group'){should eq 'mongod'}
    end
  end
  
  describe file('/etc/init.d/mongod') do
    it { should exist }
    it { should be_file }
  end
 
  describe file('/etc/mongod.conf') do
    it { should be_file }
    it { should exist }
    its('owner') { should eq 'mongod'}
    its('group') { should eq 'mongod'}
    its('mode') { should cmp '0755'}
  end
  
  describe parse_config_file('/etc/mongod.conf') do
    params = {'logpath': '/log/mongod.log', 'logappend':'true', 'dbpath':'/data', 'pidfilepath': '/var/run/mongodb/mongod.pid'}
    params.each do |var,val|
      its (var) { should eq val }
    end
  end

  describe service('mongod') do
    it { should be_running }
    it { should be_enabled }
  end

  describe command('iptables --list-rule | grep 27017') do
    its('exit_status'){ should eq 0 }
  end
  
end # end mongo control
