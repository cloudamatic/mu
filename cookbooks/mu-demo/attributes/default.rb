default['apache']['mod_ssl']['cipher_suite'] = "ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW"
default['apache']['traceenable'] = 'Off'
default['s3_bucket'] = 'egt-labs'
default['s3_bucket_path'] = "cap-public"
default['s3_public_url'] = "https://s3.amazonaws.com/cap-public/cap-demo"
default['winapps']['jackrabbit'] = "jackrabbit-webapp-2.8.0.war"
default['winapps']['sample'] = "sample.war"
default['winapps']['razuna'] = "razuna.war"
default['linux_apps'] = ["drupal"]
default['application_attributes']['tiered_apps']['domain_name'] = "example.com"

if platform_family?("windows")
	default.java.max_heap_size = '2G'
	node.normal.java.java_home = "C:\\bin\\java"
	node.normal.java.windows.package_name = 'Java SE Development Kit 7 Update 80 (64-bit)'
    node.normal.java.windows.url = "https://s3.amazonaws.com/cap-public/jdk-7u80-windows-x64.exe"
	# node.normal.java.windows.package_name = 'Java SE Development Kit 8 Update 45 (64-bit)'
    # node.normal.java.windows.url = "https://s3.amazonaws.com/ps-boundless-public/jdk-8u45-windows-x64.exe"
    # node.normal.java.windows.checksum = "979ec7d6c93c6f36b32b8d532d736015"
else
	default.java.max_heap_size = "#{(node.memory.total.to_i * 0.6 ).floor / 1024}m"
	node.normal.java.oracle.accept_oracle_download_terms = true
	node.normal.java.java_home = '/usr/lib/jvm/java'
	node.normal.java.install_flavor = 'oracle'
	node.normal.java.jdk_version = 8
    node.normal.java.jdk['8']["x86_64"]["url"] = "http://download.oracle.com/otn-pub/java/jdk/8u45-b14/jdk-8u45-linux-x64.tar.gz"
    node.normal.java.jdk["8"]["x86_64"]["checksum"] = "1ad9a5be748fb75b31cd3bd3aa339cac"
end

node.normal.tomcat.generate_ssl_cert = false
