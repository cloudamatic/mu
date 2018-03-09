- name: "bastion"
  ssh_user: "root"
  size: "t2.micro"
  skipinitialupdates: true
  src-dst-check: false
  static_ip: 
    assign_ip: true
  vpc: 
    vpc_name: <%= vpc_name %>
    subnet_pref: "public"
  ingress_rules: 
  - proto: "icmp"
    hosts: 
    - "10.0.0.0/16"
  - proto: "tcp"
    port-range: "1-65535"
    hosts: 
    - "10.0.0.0/16"
  - proto: "udp"
    port-range: "1-65535"
    hosts: 
    - "10.0.0.0/16"
  run_list: 
  - "recipe[mu-utility::nat]"
  - "recipe[demo::store_attr]"
