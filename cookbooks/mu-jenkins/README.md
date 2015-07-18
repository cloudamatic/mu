mu-jenkins Cookbook
===================
This cookbook creates a working Jenkins installation.  It can be deployed on a standalone node (see demo/jenkins.yaml) or as a Jenkins server on the mu-master itself.  

Requirements
------------
This is a wrapper cookbook that is meant to be run after a Jenkins install using the Jenkins community cookbook. The recipe uses some groovy scripts to manage jenkins authentication from chef itself, and create an additional administrave Jenkins user for interactive work.

A jenkins vault must be present before invoking.  Two items are required
-  A users item containing passwords for each user enumerated in the default.jenkins_users attribute (see below).  The mu-user password is required, as we need at least one interactive Jenkins user
-  An admin item containing a public and private keypair that will be used by chef to authenticate to Jenkins after disabling anonymous authentication, and a username for this user

A third optional ssh item is used to store a keypair used by Jenkins to SSH to other nodes, to allow Jenkins to run code locally as part of a Jenkins job.

Create the vault items along these lines:

admin:
```
#!/usr/local/ruby-current/bin/ruby
require "openssl"
require 'net/ssh'
key = OpenSSL::PKey::RSA.new 2048
public_key = "#{key.public_key.ssh_type} #{[key.public_key.to_blob].pack('m0')}"
vault_opts="--mode client -u mu -F json"
vault_cmd = "knife vault create jenkins admin '{ \"public_key\":\"#{public_key}\", \"private_key\":\"#{key.to_pem.chomp!.gsub(/\n/, "\\n")}\", \"username\": \"master_user\" }' #{vault_opts} --search name:MU-MASTER"
exec vault_cmd
```

users:
```knife vault create jenkins users '{"mu_user_password":"feefiefoefum"}'  --mode client -F json -u mu --search name:MU-MASTER```


#### packages
- `java` - jenkins needs Java to run
- `jenkins` - mu-jenkins needs jenkins to actually be installed

Attributes
----------
Some basic attributes on the java install and node address, plus Jenkins specifics:

#### mu-jenkins::default
<table>
  <tr>
    <th>Key</th>
    <th>Type</th>
    <th>Description</th>
    <th>Default</th>
  </tr>
  <tr>
    <td><tt>default.jenkins_users</tt></td>
    <td>Hash</td>
    <td>Jenkins users to create with their properties (excepting password) and a single vault to retrieve creds from</td>
    <td><tt>:user_name => "mu_user", :fullname => "Mu-Demo-User", :email => "mu-developers@googlegroups.com", :vault => "jenkins", :vault_item => "users"}</tt></td>
  </tr>
  <tr>
    <td><tt>default.jenkins_ssh_urls</tt></td>
    <td>Array</td>
    <td>IP addresses / DNS names of nodes Jenkins will SSH into</td>
    <td><tt>[node.ipaddress]</tt></td>
  </tr>
  <tr>
    <td><tt>default.jenkins_plugins</tt></td>
    <td>Whitespace string</td>
    <td>plugins to install</td>
    <td><tt>%w{github ssh deploy}</tt></td>
  </tr>
  <tr>
    <td><tt>default.jenkins_ssh_vault</tt></td>
    <td>Hash</td>
    <td>Preexisting vault containing a public private keypair that will be used to SSH to other nodes</td>
    <td><tt>:vault => "jenkins", :item => "ssh"</tt></td>
  </tr>
  <tr>
    <td><tt>default.jenkins_admin_vault</tt></td>
    <td>Hash</td>
    <td>Preexisting vault containing a public private keypair used by Chef to authenticate to Jenkins. This also include the username of the Jenkins user</td>
    <td><tt>:vault => "jenkins", :item => "admin"</tt></td>
  </tr>
</table>

Usage
-----
#### mu-jenkins::default
This cookbook can run in a standalone mode which creates a basic Jenkins install on a target node, or a mu-master mode which creates a Jenkins server on a mu master.

In either case the runlist will look like:
```    run_list:
    - recipe[java]
    - recipe[jenkins::master]
    - recipe[mu-jenkins]
```

In the mu-master mode the cookbook is invoked with the role[mu-master-jenkins], which adds some attributes to trigger the jenkins-apache recipe, which places Jenkins behind a mu-master apache reverse proxy:

    chef-client -l info -o recipe[java],recipe[jenkins::master],recipe[mu-jenkins]


Contributing
------------
Usual Cloudamatic process via pull request


License and Authors
-------------------
Authors: Ami Rahav, Robert Patt-Corner
