if !ENV.include?('MU_LIBDIR')
	if !ENV.include?('MU_INSTALLDIR')
		raise "Can't find MU_LIBDIR or MU_INSTALLDIR in my environment!"
	end
	ENV['MU_LIBDIR'] = ENV['MU_INSTALLDIR']+"/lib"
end
cookbookPath = "#{ENV['MU_LIBDIR']}/cookbooks"
siteCookbookPath = "#{ENV['MU_LIBDIR']}/site_cookbooks"

source "https://supermarket.getchef.com"

cookbook 'apache2', '~> 3.0.0'
cookbook 'application', '~> 3.0.0'
cookbook 'application_python', '~> 3.0.0'
cookbook 'application_ruby', '~> 2.1.4'
cookbook 'apt', '~> 2.7.0'
cookbook 'aws', '~> 2.7.0'
cookbook 'awscli', path: "#{cookbookPath}/awscli"
cookbook 'bluepill', '~> 2.3.1'
cookbook 'build-essential', '~> 2.2.2'
cookbook 'mu-master', path: "#{cookbookPath}/mu-master"
cookbook 'mu-php54', path: "#{cookbookPath}/mu-php54"
cookbook 'mu-tools', path: "#{cookbookPath}/mu-tools"
cookbook 'mu-utility', path: "#{cookbookPath}/mu-utility"
cookbook 'chef_handler', '~> 1.1.4'
cookbook 'chef-splunk', path: "#{cookbookPath}/chef-splunk"
cookbook 'chef-sugar', '~> 2.0.0'
cookbook 'chef-vault', '~> 1.3.0'
cookbook 'demo', path: "#{siteCookbookPath}/demo"
cookbook 'database', '~> 4.0.5'
cookbook 'dmg', '~> 2.2.0'
cookbook 'ec2-s3-api-tools', path: "#{cookbookPath}/ec2-s3-api-tools"
cookbook 'freebsd', '~> 0.1.9'
cookbook 'git', '~> 4.2.2'
cookbook 'gunicorn', '~> 1.1.2'
cookbook 'iis', '~> 4.1.0'
cookbook 'iptables', '~> 1.0.0'
cookbook 'logrotate', '~> 1.9.1'
cookbook 'java', '~> 1.31.0'
cookbook 'memcached', '~> 1.7.2'
cookbook 'mongodb', '~> 0.16.2'
cookbook 'mysql', '~> 5.2.12'
cookbook 'nagios', '~> 6.1.2'
cookbook 'nginx', '~> 2.7.6'
cookbook 'nginx_simplecgi', '~> 0.1.2'
cookbook 'nginx-passenger', path: "#{cookbookPath}/nginx-passenger"
cookbook 'nodejs', '~> 2.4.0'
cookbook 'ohai', '~> 2.0.0'
cookbook 'openssl', '~> 4.0.0'
cookbook 'oracle-instantclient', '~> 1.1.0'
cookbook 'pacman', '~> 1.1.1'
cookbook 'passenger_apache2', '~> 2.1.2'
cookbook 'perl', '~> 1.2.2'
cookbook 'php', '~> 1.4.6'
cookbook 'postfix', '~> 3.6.2'
cookbook 'postgresql', '~> 3.4'
cookbook 'python', path: "#{cookbookPath}/python"
cookbook 'rsyslog', '~> 1.15.0'
cookbook 'ruby_build', '~> 0.8.0'
cookbook 'ruby-cookbook', path: "#{cookbookPath}/ruby-cookbook"
cookbook 'runit', '~> 1.5.10'
cookbook 'rvm', path: "#{cookbookPath}/rvm"
cookbook 's3fs', path: "#{cookbookPath}/s3fs"
cookbook 'simple_iptables', '~> 0.7.0'
cookbook 'supervisor', '~> 0.4.10'
cookbook 'unicorn', '~> 1.3.0'
cookbook 'windows', '~> 1.36.6'
cookbook 'xfs', '~> 1.1.0'
cookbook 'xml', '~> 1.2.4'
cookbook 'yum', '~> 3.6.0'
cookbook 'yum-epel', '~> 0.6.0'
