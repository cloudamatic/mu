
include_controls 'mu-tools-test'

control 'Demo Cookbook' do
  title 'wordpress.rb'

  node = json('/tmp/chef_node.json').params
  $database=node['default']['deployment']['databases'].first.last.first.last
  $loadbalancer=node['default']['deployment']['loadbalancers']
  lb_url=$loadbalancer['default']['lb']['dns'].downcase
  $db_schema_name="wordpress_db"
  $db_user=$database.username
  $db_password=chef_vault_item($database.vault_name, $database.vault_item)[$database.password_field]
  $db_endpoint=$database.endpoint
  $loadbalancer=node['default']['deployment']['loadbalancers']
  $app_url=$loadbalancer['lb']['dns'].downcase
  $title="mu wordpress demo"
  $admin_user="admin"
  $admin_password="admin"
  $admin_email="admin@example.com"

  %w(apache2 php-mysql mysql).each do |pack|
    describe package(pack) do
      it { should be_installed }
    end
  end

  ### check if mysql db exists
  ## exits 0 if it db exists
  describe command("mysql -u root -e 'use #{$db_schema_name}'") do
    its('exit_status') { should eq 0 }
  end

  describe file('/etc/httpd/mods-enabled/ext_filter.load') do
    it { should be_symlink }
    it { should be_linked_to '/etc/httpd/mods-available/ext_filter.load' }
  end
  

  ### check if remote_file is downloaded


  describe file('/var/www/html/wp-config.php') do
    it { should exist }
    it { should be_file }
  end

  describe file('/var/www/html/heartbeat.php') do
    it { should be_file }
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should eq '00644' }
    its('content') { should match /<\?php\n
    echo "lub dub lub dub \.\.\.";/ }
  end

  describe file('/var/www/html/.htaccess') do
    it { should exist }
    it { should be_file }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should eq '00644' }
    its('content') { should match /RewriteRule ^wp-admin$ wp-admin\/ [R=301,L]/}
  end


  ## recursively check owner:group on a dir
  Dir.chdir('/var/www/html')
  file_paths = Dir['**/*']
  file_paths.each do |each|
    if File.directory(each)
      describe directory(each) do
        its('owner') { should eq 'apache' }
        its('group') { should eq 'apache' }
      end
    elsif File.file?(each)
      describe directory(each) do
        its('owner') { should eq 'apache' }
        its('group') { should eq 'apache' }
      end
    end
  end
 
 
 ## setsebool command?
  
  [80, 443].each do |port|
    describe iptables do
      it { should_have_rule ("I INPUT -p tcp --dport #{port} -j ACCEPT" }
    end
  end


end ## ends control
