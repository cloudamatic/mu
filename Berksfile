if !ENV.include?('MU_LIBDIR')
	if !ENV.include?('MU_INSTALLDIR')
		raise "Can't find MU_LIBDIR or MU_INSTALLDIR in my environment!"
	end
	ENV['MU_LIBDIR'] = ENV['MU_INSTALLDIR']+"/lib"
end
cookbookPath = "#{ENV['MU_LIBDIR']}/cookbooks"
siteCookbookPath = "#{ENV['MU_LIBDIR']}/site_cookbooks"

source "https://supermarket.getchef.com"

cookbook 'apache2', '~> 3.1.0'
cookbook 'application', '~> 3.0.0'
cookbook 'application_python', '~> 3.0.0'
cookbook 'application_ruby', '~> 2.1.4'
cookbook 'apt', '~> 2.9.2'
cookbook 'aws', '~> 2.9.3'
cookbook 'awscli', path: "#{cookbookPath}/awscli"
cookbook 'bind', '~> 1.1.2'
cookbook 'bind9-ng', '~> 0.1.0'
cookbook 'bluepill', '~> 2.3.1'
cookbook 'build-essential', '~> 2.3.1'
cookbook 'mu-master', path: "#{cookbookPath}/mu-master"
cookbook 'mu-php54', path: "#{cookbookPath}/mu-php54"
cookbook 'mu-tools', path: "#{cookbookPath}/mu-tools"
cookbook 'mu-utility', path: "#{cookbookPath}/mu-utility"
cookbook 'mu-openvpn', path: "#{cookbookPath}/mu-openvpn"
cookbook 'mu-jenkins', path: "#{cookbookPath}/mu-jenkins"
cookbook 'tomcat', path: "#{cookbookPath}/tomcat"
cookbook 'chef_handler', '~> 1.3.0'
cookbook 'chef-splunk', path: "#{cookbookPath}/chef-splunk"
cookbook 'chef-sugar', '~> 3.3.0'
cookbook 'chef-vault', '~> 1.3.3'
cookbook 'demo', path: "#{siteCookbookPath}/demo"
cookbook 'database', '~> 4.0.9'
cookbook 'dmg', '~> 2.2.0'
cookbook 'ec2-s3-api-tools', path: "#{cookbookPath}/ec2-s3-api-tools"
cookbook 'freebsd', '~> 0.1.9'
cookbook 'git', '~> 4.3.7'
cookbook 'gunicorn', '~> 1.1.2'
cookbook 'iis', '~> 4.1.1'
cookbook 'iptables', '~> 1.0.0'
cookbook 'logrotate', '~> 1.9.2'
cookbook 'java', '~> 1.39.0'
cookbook 'jenkins', '~> 2.4.1'
cookbook 'memcached', '~> 1.7.2'
cookbook 'mongodb', '~> 0.16.2'
cookbook 'mysql', '~> 6.1.3'
cookbook 'nagios', path: "#{cookbookPath}/nagios"
cookbook 'nginx', '~> 2.7.6'
cookbook 'nrpe', '~> 1.5.2'
cookbook 'nginx_simplecgi', '~> 0.1.2'
cookbook 'mu-activedirectory', path: "#{cookbookPath}/mu-activedirectory"
cookbook 'nginx-passenger', path: "#{cookbookPath}/nginx-passenger"
cookbook 'nodejs', '~> 2.4.4'
cookbook 'ohai', '~> 2.1.0'
cookbook 'openssl', '~> 4.4.0'
cookbook 'oracle-instantclient', '~> 1.1.0'
cookbook 'pacman', '~> 1.1.1'
cookbook 'passenger_apache2', '~> 2.1.2'
cookbook 'perl', '~> 1.2.2'
cookbook 'php', '~> 1.4.6'
cookbook 'postfix', '~> 3.7.0'
cookbook 'postgresql', '~> 3.4'
cookbook 'python', path: "#{cookbookPath}/python"
cookbook 'rsyslog', '~> 2.1.0'
cookbook 'ruby_build', '~> 0.8.0'
cookbook 'ruby-cookbook', path: "#{cookbookPath}/ruby-cookbook"
cookbook 'runit', '~> 1.7.2'
cookbook 'rvm', path: "#{cookbookPath}/rvm"
cookbook 's3fs', path: "#{cookbookPath}/s3fs"
cookbook 'simple_iptables', '~> 0.7.2'
cookbook 'supervisor', '~> 0.4.12'
cookbook 'unicorn', '~> 1.3.0'
cookbook 'windows', '~> 1.39.1'
cookbook 'xfs', '~> 1.1.0'
cookbook 'xml', '~> 1.2.4'
cookbook 'yum', '~> 3.10.0'
cookbook 'yum-epel', '~> 0.6.6'
