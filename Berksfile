if !ENV.include?('MU_LIBDIR')
	if !ENV.include?('MU_INSTALLDIR')
		raise "Can't find MU_LIBDIR or MU_INSTALLDIR in my environment!"
	end
	ENV['MU_LIBDIR'] = ENV['MU_INSTALLDIR']+"/lib"
end
cookbookPath = "#{ENV['MU_LIBDIR']}/cookbooks"
siteCookbookPath = "#{ENV['MU_LIBDIR']}/site_cookbooks"

source "https://supermarket.getchef.com"

cookbook 'apache2', '~> 3.2.2'
cookbook 'apt', '~> 2.9.2'
cookbook 'aws', '~> 3.3.3'
cookbook 'awscli', '~> 1.1.2'
cookbook 'bind', '~> 1.1.2'
cookbook 'bind9-ng', '~> 0.1.0'
cookbook 'mu-master', path: "#{cookbookPath}/mu-master"
cookbook 'mu-php54', path: "#{cookbookPath}/mu-php54"
cookbook 'mu-tools', path: "#{cookbookPath}/mu-tools"
cookbook 'mu-utility', path: "#{cookbookPath}/mu-utility"
cookbook 'mu-openvpn', path: "#{cookbookPath}/mu-openvpn"
cookbook 'mu-jenkins', path: "#{cookbookPath}/mu-jenkins"
cookbook 'tomcat', '~> 2.2.3'
cookbook 'chef_handler', '~> 1.4.0'
cookbook 'chef-splunk', path: "#{cookbookPath}/chef-splunk"
cookbook 'chef-sugar', '~> 3.3.0'
cookbook 'chef-vault', '~> 1.3.3'
cookbook 'demo', path: "#{siteCookbookPath}/demo"
cookbook 'database', '~> 5.1.2'
cookbook 'git', '~> 4.5.0'
cookbook 'gunicorn', '~> 1.2.1'
cookbook 'iis', '~> 4.1.8'
cookbook 'iptables', '~> 2.2.0'
cookbook 'logrotate', '~> 1.9.2'
cookbook 'java', '~> 1.39.0'
cookbook 'jenkins', '~> 2.6.0'
cookbook 'mongodb', '~> 0.16.2'
cookbook 'mysql', '~> 7.1.1'
cookbook 'nagios', path: "#{cookbookPath}/nagios"
cookbook 'nginx', '~> 2.7.6'
cookbook 'nginx_simplecgi', '~> 0.1.2'
cookbook 'mu-activedirectory', path: "#{cookbookPath}/mu-activedirectory"
cookbook 'nginx-passenger', path: "#{cookbookPath}/nginx-passenger"
cookbook 'nodejs', '~> 2.4.4'
cookbook 'oracle-instantclient', '~> 1.1.0'
cookbook 'perl', '~> 3.0.0'
cookbook 'php', '~> 1.9.0'
cookbook 'postfix', '~> 3.8.0'
cookbook 'postgresql', '~> 4.0.6'
cookbook 'python', path: "#{cookbookPath}/python"
cookbook 'rsyslog', '~> 4.0.0'
cookbook 'runit', '~> 1.7.2'
cookbook 's3fs', path: "#{cookbookPath}/s3fs"
cookbook 'simple_iptables', '~> 0.7.4'
cookbook 'supervisor', '~> 0.4.12'
cookbook 'windows', '~> 1.44.0'
cookbook 'yum', '~> 3.11.0'
cookbook 'yum-epel', '~> 0.7.0'
cookbook 'tar', '~> 0.7.0'
