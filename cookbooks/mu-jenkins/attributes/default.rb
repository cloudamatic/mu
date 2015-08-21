default.jenkins_users = [
    {:user_name => "mu_user", :fullname => "Mu-Demo-User", :email => ENV['MU_ADMIN_EMAIL'], :vault => "jenkins", :vault_item => "users"}
]

default.jenkins_ssh_urls = [node.ipaddress]
default.jenkins_plugins = %w{github ssh deploy}
default.jenkins_ports_direct = %w{8080 443}

node.normal.java.oracle.accept_oracle_download_terms = true
node.normal.java.java_home = "/usr/lib/jvm/java"
node.normal.java.install_flavor = "oracle"
node.normal.java.jdk_version = 8
node.normal["java"]["jdk"]["8"]["x86_64"]["url"] = "http://download.oracle.com/otn-pub/java/jdk/8u51-b16/jdk-8u51-linux-x64.tar.gz"
node.normal["java"]["jdk"]["8"]["x86_64"]["checksum"] = "b34ff02c5d98b6f372288c17e96c51cf"

default.jenkins_ssh_vault = {
    :vault => "jenkins", :item => "ssh"
}

default.jenkins_admin_vault = {
    :vault => "jenkins", :item => "admin"
}
