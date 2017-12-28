- name: "vpc"
  route-tables:
  - name: internet
    routes:
    - destination_network: 0.0.0.0/0
      gateway: "#INTERNET"
  - name: private
    routes:
    - destination_network: 0.0.0.0/0
      nat_host_name: "bastion"
  dependencies:
  - type: server
    name: "bastion"
