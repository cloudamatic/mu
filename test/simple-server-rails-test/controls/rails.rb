
include_controls 'mu-tools-test'

control 'rails' do
  title 'rails test'

  node = json('/tmp/chef_node.json').params
  #####################################
  ### Node Attrs
  #####################################
  service_name = node['normal']['service_name']
  chef_environment = node['default']['chef_environment']
  application_dir = node['default']['dev']['rails']['apps_dir']
  repo_path = 'concerto/concerto.git'
  version = '2.3.5'
  application_repo = "https://github.com/#{repo_path}"


  ###################################
  ### Tests
  ###################################
  %w(sqlite3 libsqlite3-dev libmysqlclient-dev software-properties-common libxml2-dev  libmagickwand-dev make build-essential g++ git).each do |pack|
    describe package(pack) do
      it { should be_installed }
    end
  end


  if os[:family] == 'debian' && os[:release].to_i == 9
    describe package('runit-systemd') do
      it { should be_installed }
    end
  end

  describe package('runit') do
    it { should be_installed }
  end

  describe processes('runsvdir') do
    it { should exist }
  end

  describe file('/etc/service') do
    it { should be_directory }
    its('mode') { should cmp '0755' }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end

  describe command('node -v') do
    its('exit_status') { should eq 0 }
  end

  describe command('npm -v') do
    its('exit_status') { should eq 0 }
  end


  describe service('nginx') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end


  describe package('nginx') do
    it { should be_installed }
  end

  describe apt('http://ppa.launchpad.net/brightbox/ruby-ng/ubuntu') do
    it { should exist }
    it { should be_enabled }
  end

  # Unicorn config
  unicorn_log_dir = '/var/log/unicorn'
  unicorn_log = "#{unicorn_log_dir}/unicorn.log"
  unicorn_error_log = "#{unicorn_log_dir}/error.log"
  # RDS config
  db = node['normal']['deployment']['databases']['concerto'].first.last
  db_name = db['db_name']
  db_username = db['username']
  db_host = db['endpoint']
  db_port = db['port']
  #db_password = chef_vault_item(db.vault_name, db.vault_item)[db.password_field]
  default_root= "#{application_dir}/"
  
   %w(ruby2.2 ruby2.2-dev).each do |pack|
    describe package(pack) do
      it { should be_installed }
    end
  end

  describe gem('bundler', '/usr/bin/gem') do
    it { should be_installed }
  end

  describe directory(unicorn_log_dir) do
    it { should exist }
    it { should be_directory }
    its('owner') { should eq 'www-data' }
    its('group') { should eq 'www-data' }
    its('mode') { should cmp '00555' }
  end

  [unicorn_log, unicorn_error_log].each do |f|
    describe file(f) do
      it { should exist }
      it { should be_file }
      its('owner') { should eq 'www-data' }
      its('group') { should eq 'www-data' }
    end
  end

  describe file('/etc/nginx/sites-available/default') do
    it { should exist }
    it { should be_file }
    its('content') { should match /proxy_pass http:\/\/127\.0\.0\.1:9000/ }
    its('content') { should match /listen 80/}
  end

  describe directory(application_dir) do
    it { should exist }
    it { should be_directory }
    its('owner') { should eq 'www-data' }
  end

  ### this is git resource really...
  describe directory("#{application_dir}/rails") do
    it { should exist }
    it { should be_directory }
    #its('owner') { should eq 'www-data' }
    #its('group') { should eq 'www-data' }
  end

  rails_env = 'development'
  database = {
    'adapter' => 'mysql2',
    'encoding' => 'utf8',
    'database' => db_name,
    'username' => db_username,
    'port' => db_port
}



  describe file("#{application_dir}/rails/config/database.yml") do
    it { should exist }
    it { should be_file }
    its('content') { should match /#{rails_env}/ }
    its('content') { should match /#{db_host}/ }
  end

  describe file("#{application_dir}/rails/config/concerto.yml") do
    it { should exist }
    it { should be_file }
    its('content'){should match /automatic_bundle_installation: false/}
    its('content'){ should match /automatic_database_installation: false/}
    its('content'){should match /compile_production_assets: true/ }
    its('content'){ should match /airbrake_enabled_initially: true/}
    its('content'){should match /bundle_install_options: "--path vendor\/bundle"/} 
  end

  describe file("#{application_dir}/rails/Gemfile-plugins") do
    its('content'){should_not match /gem \"concerto_simple_rss\"/ }
    its('content'){should_not match /gem \"concerto_remote_video\"/ }
  end

  describe file('/etc/nginx/nginx.conf') do
    it { should exist }
    it { should be_file }
    its('content'){ should match // }
    its('content') { should match // }
  end
 
  ## is rails running?
  describe command('sudo lsof -wni tcp:9000') do
    its('exit_status'){ should eq 0 }
  end

  describe command("curl http://#{node['normal']['ec2']['public_dns_name']}") do
    its('exit_status') { should eq 0 }
    its('stdout'){should_not match 'Welcome to nginx!'}
  end



end ## end of control
