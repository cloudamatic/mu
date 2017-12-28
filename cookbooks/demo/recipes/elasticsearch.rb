#
# Cookbook Name:: demo
# Recipe:: elasticsearch
#
# Copyright:: Copyright (c) 2017 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#     http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

case node['platform_family']
when 'debian'
    javaPackage = 'default-jre'
    nginxConfFile = '/etc/nginx/sites-available/default'
when 'rhel'
    javaPackage = 'java-1.8.0-openjdk'
    nginxConfFile = '/etc/nginx/conf.d/default.conf'
end

stackVersion = '5.x'
elasticNode = 'localhost'
elasticPort = 9200
logstashNode = 'localhost'
logstashPort =  5044
kibanaNode = 'localhost'
kibanaPort = 5601
kibanaProxyName = node['ec2']['public_dns_name']

# Set an attribute to identify the node as the ELK server
node.default['elk']['is_server'] = true
node.default['elk']['version'] = stackVersion
node.default['elk']['kibanaURL'] = node['ec2']['public_dns_name']
node.default['elk']['elasticPort'] = elasticPort
node.default['elk']['logstashPort'] = logstashPort

#Add some swap space to ensure the node has a minimal amount of memory to run the applications
swap_file '/mnt/swap' do
    size      2000    # MBs
end

# Install Java Runtime
package javaPackage do
    action :install
end

# Install NGINX to proxy for Kibana
package 'nginx' do
    action :install
end

service "nginx" do
    action [:start, :enable]
end

case node['platform_family']
when 'debian'

    apt_repository 'elastic-5.x' do
        uri 'https://artifacts.elastic.co/packages/5.x/apt'
        components ['stable', 'main']
        distribution ''
        key 'D88E42B4'
        keyserver 'pgp.mit.edu'
        action :add
    end
    
when 'rhel'

    yum_repository 'elastic-5.x' do
        description "ELK Repo"
        baseurl "https://artifacts.elastic.co/packages/5.x/yum"
        gpgkey 'https://artifacts.elastic.co/GPG-KEY-elasticsearch'
        action :create
    end

end

package 'elasticsearch' do
    action [:install, :upgrade]
end

service "elasticsearch" do
    action [ :enable, :start ]
end

package 'logstash' do
    action [:install, :upgrade]
end

service "logstash" do
    action [ :enable, :start ]
end

package 'kibana' do
    action [:install, :upgrade]
end

service "kibana" do
    action [ :enable, :start ]
end

execute 'Install X-Pack Elasticsearch' do
    command  "/usr/share/elasticsearch/bin/elasticsearch-plugin install x-pack -sb"
    notifies :restart, "service[elasticsearch]", :delayed
    not_if { File.exist?("/etc/elasticsearch/x-pack/log4j2.properties") }
end

execute 'Install X-Pack Logstash' do
    command  "/usr/share/logstash/bin/logstash-plugin install x-pack -sb"
    notifies :restart, "service[logstash]", :delayed
    not_if { File.exist?("/usr/share/logstash/plugins/x-pack/LICENSE.txt") }
end

execute 'Install X-Pack Kibana' do
    command  "/usr/share/kibana/bin/kibana-plugin install x-pack -q -t 0"
    notifies :restart, "service[kibana]", :delayed
    not_if { File.exist?("/usr/share/kibana/plugins/x-pack/LICENSE.txt") }
end

file '/etc/elasticsearch/elasticsearch.yml' do
    content <<-EOH
    cluster.name: "CLUSTER NAME"
    node.name: "#{node['ec2']['public_dns_name']}"
    network.host: "localhost"
    http.port: #{elasticPort}
    xpack.security.authc.realms.ldap1.type: ldap
    xpack.security.authc.realms.ldap1.order: 0
    xpack.security.authc.realms.ldap1.url: "ldaps://ip-10-100-0-204.ec2.internal:389"
    xpack.security.authc.realms.ldap1.bind_dn: "CN=mu_bind_creds,OU=Users,OU=Mu,DC=platform-mu"
    xpack.security.authc.realms.ldap1.bind_password: "nyshocizutruro"
    EOH
    notifies :restart, "service[elasticsearch]", :delayed
end

# NEED TO SET PROPER PERMISSIONS ON THESE FILES ON MONDAY FOR CENTOS 7 SUPPORT

# CREATE LOGSTASH CONFIG FILES.
file '/etc/logstash/conf.d/02-beats-input.conf' do
    content <<-EOH
    input {
        beats {
          port => #{logstashPort}
        }
      }
    EOH
    notifies :restart, "service[logstash]", :delayed
end

file '/etc/logstash/conf.d/10-syslog-filter.conf' do
    content <<-EOH
    filter {
        if [type] == "syslog" {
          grok {
            match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
            add_field => [ "received_at", "%{@timestamp}" ]
            add_field => [ "received_from", "%{host}" ]
          }
          syslog_pri { }
          date {
            match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
          }
        }
    }
    EOH
    notifies :restart, "service[logstash]", :delayed
end

file '/etc/logstash/conf.d/30-elasticsearch-output.conf' do
    content <<-EOH
    output {
        elasticsearch {
          hosts => ["#{elasticNode}:#{elasticPort}"]
          sniffing => true
          manage_template => false
          index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
          document_type => "%{[@metadata][type]}"
        }
      }
    EOH
  notifies :restart, "service[logstash]", :delayed
end

file '/etc/kibana/kibana.yml' do
    content <<-EOH
    server.host: "localhost" 
    server.port: #{kibanaPort}
    server.name: "#{kibanaProxyName}"
    elasticsearch.url: "http://#{elasticNode}:#{elasticPort}"
    EOH
    notifies :restart, "service[elasticsearch]", :delayed
end

# BEGIN CONFIGURATION OF FRONT END PROXY SERVER FOR SECURITY

# SHOULD USE A REAL CERT. BUT THIS IS HERE FOR NOW...
openssl_x509 '/etc/nginx/cert.pem' do
    common_name kibanaProxyName
    org 'Foo Bar'
    org_unit 'Lab'
    country 'US'
end

file nginxConfFile do
    content <<-EOH
      server {
        listen 443;
        server_name kibana;

        ssl_certificate           /etc/nginx/cert.pem;
        ssl_certificate_key       /etc/nginx/cert.key;
    
        ssl on;
        ssl_session_cache  builtin:1000  shared:SSL:10m;
        ssl_protocols  TLSv1 TLSv1.1 TLSv1.2;
        ssl_ciphers HIGH:!aNULL:!eNULL:!EXPORT:!CAMELLIA:!DES:!MD5:!PSK:!RC4;
        ssl_prefer_server_ciphers on;

        error_log   /var/log/nginx/kibana.error.log;
        access_log  /var/log/nginx/kibana.access.log;
  
        location / {
            rewrite ^/(.*) /$1 break;
            proxy_ignore_client_abort on;
            proxy_pass http://#{kibanaNode}:#{kibanaPort};
            proxy_set_header  X-Real-IP  $remote_addr;
            proxy_set_header  X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header  Host $http_host;
        }
      }
    EOH
    notifies :restart, "service[nginx]", :delayed
    notifies :create, "ruby_block[kibanaNotify]", :delayed
end

# THIS IS NOT THE RIGHT WAY OF DOING THIS... IT IS JUST FOR NOW
if node['platform_family'] == 'rhel'
    execute 'firewall-cmd --zone=drop --permanent  --add-service=https' do end
    execute 'firewall-cmd --zone=drop --permanent  --add-port=5044/tcp' do end
    execute 'setenforce permissive' do end
end

# Notify Users of kibana instalation
ruby_block "kibanaNotify" do
    block do
        puts "\n######################################## End of Run Information ########################################"
        puts "# Your Kibana Server is running at https://#{kibanaProxyName}"
        puts "########################################################################################################\n\n"
    end
    action :nothing
end


# sudo /usr/share/elasticsearch/bin/elasticsearch-plugin install x-pack -sb
# sudo /usr/share/logstash/bin/logstash-plugin install x-pack -sb
# sudo /usr/share/kibana/bin/kibana-plugin install x-pack -q