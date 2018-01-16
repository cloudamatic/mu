include_controls 'mu-tools-test'

control 'wordpress' do
  title 'wordpress.rb'

  node = json('/tmp/chef_node.json').params
  $database=node['normal']['deployment']['databases'].first.last.first.last
  $loadbalancer=node['normal']['deployment']['loadbalancers']
  $lb_url=$loadbalancer['lb']['dns'].downcase
  $db_user=$database['username']
  $db_endpoint=$database['endpoint']
  $loadbalancer=node['normal']['deployment']['loadbalancers']
  $app_url=$loadbalancer['lb']['dns'].downcase
  $db_schema_name="wordpress_db"
  $title="mu wordpress demo"
  $admin_user="admin"
  $admin_password="admin"
  $admin_email="admin@example.com"
  p $lb_url
  %w(php-mysql mysql).each do |pack|
    describe package(pack) do
      it { should be_installed }
    end
  end


  describe file('/etc/httpd/mods-enabled/ext_filter.load') do
    it { should be_symlink }
    it { should be_linked_to '/etc/httpd/mods-available/ext_filter.load' }
  end
  
  if node['normal']['deployment']['environment'] == 'dev'  
    describe file('/var/www/html/heartbeat.php') do
      it { should be_file }
      it { should exist }
      its('owner') { should eq 'apache' }
      its('group') { should eq 'apache' }
      its('mode') { should cmp '0644' }
      its('content') { should match /echo "lub dub lub dub \.\.\.";/}
    end
  end

  ### check if remote_file is downloaded
  describe file("/var/chef/cache/wordpress.tar.gz") do
    it { should exist}
    it { should be_file }
  end

  describe file('/var/www/html/.htaccess') do
    it { should exist }
    it { should be_file }
    its('owner') { should eq 'apache' }
    its('group') { should eq 'apache' }
    its('mode') { should cmp '0644' }
    its('content'){ should match /RewriteEngine On/}
    its('content'){ should match /RewriteBase \//}
    its('content'){ should match /RewriteRule \. index\.php \[L\]/}
  end

  describe command("getsebool httpd_can_network_connect | grep ' on$'") do
    its('exit_status'){ should eq 0 }
    its('stdout'){ should match /httpd_can_network_connect --> on/}
  end
  
  [80,443].each do |p|
    describe port(p) do
      it { should be_listening }
    end
  end

  ## recursively check owner:group on a dir
  ## 3 => owner
  ## 4 => group
  [3,4].each do |n|
    describe command("ls -rl /var/www/html/* | awk 'NR==1 {print $#{n}}'") do
      its('stdout'){ should eq "apache\n"}
    end
  end


  describe file('/var/www/html/wp-config.php') do
    it { should be_file }
    its('mode'){should cmp 0644 }
    its('content'){should match /define\('DB_NAME', '#{$db_schema_name}'\);/}
    its('content') { should match /define\('DB_USER', '#{$db_user}'\);/ }
    its('content') { should match /define\('DB_HOST', '#{$db_endpoint}:3306'\);/ }
  end

  describe file('/etc/httpd/sites-enabled/wordpress.conf') do
    it { should be_file }
    its('content'){ should match /AllowOverride All/}
    its('content'){ should match /<VirtualHost \*:80>/ }
    its('content'){ should match /ServerName www\.cloudamatic\.com/ }
    its('content'){ should match /#{$lb_url}/}  
  end

end ## ends control
