default['apache']['listen_ports'] = [80]
default['apache']['mod_ssl']['cipher_suite'] = "ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW"
default['apache']['traceenable'] = 'Off'
default['s3_bucket'] = 'egt-labs'
default['s3_bucket_path'] = "cap-public"
default['s3_public_url'] = "https://s3.amazonaws.com/cap-public/mu-demo"
default['java']['windows']['url'] = "#{node.s3_public_url}/jre-7u67-windows-x64.exe"
default['java']['java_home'] = "C:\\bin\\java"
default['tomcat']['home'] = "C:\\bin\\tomcat\\7"
default['tomcat']['display_name'] = "Apache Tomcat 7.0 Tomcat7 (remove only)"
default['tomcat']['zip'] = "apache-tomcat-7.0.55.zip"
default['winapps']['jackrabbit'] = "jackrabbit-webapp-2.8.0.war"
default['winapps']['sample'] = "sample.war"
default['winapps']['razuna'] = "razuna.war"

default['linux_apps'] = ["drupal"]
default['application_attributes']['tiered_apps']['domain_name'] = "example.com"
