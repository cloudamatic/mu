require 'yaml'

include_controls 'mu-tools-test'

control 'flask' do
  title 'flask.rb'

  ### get the attrs json
  node = json('/tmp/chef_node.json').params

  ### test the attr i guess
  service_name = node['normal']['service_name']
  application_dir = node['default'][node['chef_environment']]['flask']['apps_dir']
  virtual_environment = "#{application_dir}/envs/demo"


  %w(python nginx).each do |pack|
    describe package(pack) do
      it { should be_installed }
    end
  end

  describe service('nginx') do
    it { should be_running }
  end

  directories = virtual_environment.split('/')
  (0..directories.size).each do |i|
    directory = directories.slice(0..i).join '/'
    next if directory.empty?
    
    describe directory(directory) do
      it { should exist }
      it { should_not be_file }
      its('mode') { should cmp '00644' }
      its('owner') { should eq 'root' }
      its('group') { should eq 'root' }
    end
  end


  describe file("#{virtual_environment}/demo.py") do
    it { should exist }
    it { should be_file }
    its('content') { should match /"Hello World!"/ }
  end

  describe file('/etc/nginx/sites-available/default') do
    it { should exist }
    it { should be_file }
    its('content') { should match /proxy_pass http:\/\/127\.0\.0\.1:9000;/ }
  end

  describe file('/etc/ld.so.conf') do
    it { should exist }
    it { should be_file }
    its('content') { should match /\/opt\/rh\/python27\/root\/usr\/lib64\// }
  end
  
  %w(gunicorn flask).each do |pip_pack|
    describe file("#{virtual_environment}/bin/#{pip_pack}") do
      it { should exist }
    end
  end

  describe user('www-data') do
    it { should exist }
  end
  
  describe file('/etc/gunicorn/demo.py') do
    it { should be_file}
    it { should exist }
    its('owner') { should eq 'www-data'}
    its('group') { should eq 'www-data'}
    its('content') { should match /127.0.0.1:9000/ }
  end

  describe command("curl localhost:9000") do
    its('exit_status') { should eq 0 }
    its('stdout') { should eq "Hello World!" }
  end

end ## end control

