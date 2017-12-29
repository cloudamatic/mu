control 'Demo Cookbook' do
  title 'rails.rb'

  node = json('/tmp/chef_node.json').params
  
  #####################################
  ### Node Attrs
  #####################################
  service_name = node['normal']['service_name']
  chef_environment = node['default']['chef_environment']
  application_dir = node[chef_environment][service_name]['apps_dir']
  repo_path = node[chef_environment][service_name][application]['rails_repo']
  version = node[chef_environment][service_name]['application']['version']
  application_repo = "https://github.com/#{repo_path}"


  ###################################
  ### Tests
  ###################################
  %w(sqlite3 libsqlite3-dev libmysqlclient-dev software-properties-common libxml2-dev libxslt-dev libmagickwand-dev make build-essential g++ git runit nodejs nginx).each do |pack|
    describe package(pack) do
      it { should be_installed }
    end
  end

  describe service('nginx') do
    it { should be_running }
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
  db = node['deployment'['databases']['concert']['first']['last']
  db_name = db.db_name
  db_username = db.username
  db_host = db.endpoint
  db_port = db.port
  db_password = chef_vault_item(db.vault_name, db.vault_item)[db.password_field]
  node.set['nginx']['default_root'] = "#{application_dir}/"
  
   %w(ruby2.2 ruby2.2-dev).each do |pack|
    describe packahe(pack) do
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
    its('group') { should eq 'www-data' }
  end

  ### this is git resource really...
  describe directory("#{applicattion_dir}/rails") do
    it { should exist }
    it { should be_directory }
    its('owner') { should eq 'www-data' }
    its('group') { should eq 'www-data' }
  end

  rails_env = 'development'

  describe file("#{application_dir}/rails/config/database.yml") do
    it { should exist }
    it { should be_file }
    its('content') { should match /#{database}/ }
    its('cotnent') { should match /#{rails_env}/ }
    its('conteny') { should matct /#{db_host}/ }
  end

  describe file("#{application_dir}/rails/config/concerto.yml") do
    it { should exist }
    it { should be_file }
  end

  describe command("curl http://#{node['ec2']['public_dns_name']}") do
    its('stdout') { should eq 0 }
  end




end ## end of control

### maybe I should start treating control as a recipe in a run_list
### so multiple recipes in a Bok will result into multiple controls (better organization) 
