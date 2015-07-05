default.jenkins_users = [
	{:user_name => "testuser", :fullname => "testuser", :email => "testuser@email.com", :vault => "jenkins", :vault_item => "testuser"}
]

default.jenkins_ssh_urls = [node.ipaddress]

node.normal.java.oracle.accept_oracle_download_terms = true
node.normal.java.java_home = '/usr/lib/jvm/java'
node.normal.java.install_flavor = 'oracle'
node.normal.java.jdk_version = 8
node.normal.java.jdk['8']["x86_64"]["url"] = "http://download.oracle.com/otn-pub/java/jdk/8u45-b14/jdk-8u45-linux-x64.tar.gz"
node.normal.java.jdk["8"]["x86_64"]["checksum"] = "1ad9a5be748fb75b31cd3bd3aa339cac"

default.jenkins_ssh_vault = {
	:vault => "jenkins", :item => "ssh"
}

default.jenkins_admin_vault = {
	:vault => "jenkins", :item => "admin"
}
