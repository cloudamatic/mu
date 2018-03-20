
if !ENV.include?('MU_COOKBOOK_ROOT')
  if !ENV.include?('MU_LIBDIR')
	  if !ENV.include?('MU_INSTALLDIR')
  		raise "Can't find MU_LIBDIR or MU_INSTALLDIR in my environment!"
	  end
  	ENV['MU_LIBDIR'] = ENV['MU_INSTALLDIR']+"/lib"
  end
  ENV['MU_COOKBOOK_ROOT'] = ENV['MU_LIBDIR']
end
cookbookPath = "#{ENV['MU_COOKBOOK_ROOT']}/cookbooks"

source "https://supermarket.chef.io"

# Supermarket Cookbooks
cookbook 'apache2', '< 4.0'
cookbook 'chef-vault', '< 3.0'
cookbook 'aws', '~> 2.9.3'
cookbook 'freebsd', '~> 0.1.9'
cookbook 'logrotate', '~> 1.9.2'
cookbook 'memcached', '~> 1.7.2'
cookbook 'chef_nginx', '~> 6.1.1'
cookbook 'build-essential', '~> 8.0'
cookbook 'runit', '~> 1.7'
cookbook 'zipfile', '~> 0.1.0'
cookbook 'windows', '= 3.2.0'

# Mu Cookbooks
cookbook 'awscli', path: "#{cookbookPath}/awscli"
cookbook 'mu-splunk', path: "#{cookbookPath}/mu-splunk"
cookbook 'mu-firewall', path: "#{cookbookPath}/mu-firewall"
cookbook 'mu-glusterfs', path: "#{cookbookPath}/mu-glusterfs"
cookbook 'mu-jenkins', path: "#{cookbookPath}/mu-jenkins"
cookbook 'mu-master', path: "#{cookbookPath}/mu-master"
cookbook 'mu-mongo', path: "#{cookbookPath}/mu-mongo"
cookbook 'mu-openvpn', path: "#{cookbookPath}/mu-openvpn"
cookbook 'mu-php54', path: "#{cookbookPath}/mu-php54"
cookbook 'mu-tools', path: "#{cookbookPath}/mu-tools"
cookbook 'mu-utility', path: "#{cookbookPath}/mu-utility"
cookbook 'mysql-chef_gem', path: "#{cookbookPath}/mysql-chef_gem"
cookbook 'nagios', path: "#{cookbookPath}/nagios"
cookbook 's3fs', path: "#{cookbookPath}/s3fs"
