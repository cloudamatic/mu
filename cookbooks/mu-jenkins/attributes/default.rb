
default['jenkins_users'] = [
#  {:user_name => "mu_user", :fullname => "Mu-Demo-User", :email => ENV['MU_ADMIN_EMAIL'], :vault => "jenkins", :vault_item => "users"}
]

default['jenkins_ssh_urls'] = [node['ipaddress']]
default['jenkins_plugins'] = %w{
  token-macro git github deploy ldap scm-api git-client active-directory
  ansicolor matrix-auth matrix-project workflow-scm-step
  workflow-step-api scm-api ssh credentials mailer display-url-api structs
  script-security
}

default['jenkins_ports_direct'] = %w{8080 443}
default['jenkins']['master']['jenkins_args'] = "" if default['jenkins']['master']['jenkins_args'].nil?
jenkins_args = "" if node['jenkins']['master']['jenkins_args'].nil?
override['jenkins']['master']['jenkins_args'] = "#{jenkins_args} --prefix=/jenkins"
default['jenkins']['master']['jvm_options'] = '-Xmx1024m -Djenkins.install.runSetupWizard=false'

# This isn't really true, but the Java libraries lose their minds over
# self-signed SSL certs like the one you'll usually find on
# https://#{$MU_CFG['public_address']}/jenkins (the real URL)
default['jenkins']['master']['endpoint'] = "http://localhost:8080/jenkins"
default['jenkins_ssh_vault'] = {
    :vault => "jenkins", :item => "ssh"
}

default['jenkins_admin_vault'] = {
    :vault => "jenkins", :item => "admin"
}

override['java']['jdk_version'] = 8
override['java']['flavor'] = 'oracle'
override['java']['jdk']['8']['x86_64']['url'] = 'http://download.oracle.com/otn-pub/java/jdk/8u131-b11/d54c1d3a095b4ff2b6607d096fa80163/jdk-8u131-linux-x64.tar.gz'
override['java']['jdk']['8']['x86_64']['checksum'] = '75b2cb2249710d822a60f83e28860053'
override["java"]["oracle"]["accept_oracle_download_terms"] = true
override['java']['oracle']['jce']['enabled'] = true
