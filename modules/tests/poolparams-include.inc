- name: env
  prettyname: "Environment"
  default: <%= $environment.upcase %>
- name: dnsbase
  prettyname: "Base Domain"
  default: ".smoketest<%= $environment == 'prod' ? '' : $environment %>.com"
  description: "Domain under which all hosts will be accessed. Used be applications to configure properly for name-based virtual hosting and to communicate with other applications in the stack."
