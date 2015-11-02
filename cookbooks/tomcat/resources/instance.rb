actions :configure
default_action :configure

# These would conflict if shared between instances and so don't make sense
# to inherit from attributes
attribute :name,
          :kind_of => String,
          :required => true,
          :name_attribute => true
attribute :port,
          :kind_of => Fixnum
attribute :proxy_port,
          :kind_of => Fixnum
attribute :ssl_port,
          :kind_of => Fixnum
attribute :ssl_proxy_port,
          :kind_of => Fixnum
attribute :ajp_port,
          :kind_of => Fixnum
attribute :shutdown_port,
          :kind_of => Fixnum,
          :required => true

# The rest will inherit from node attributes
attribute :config_dir,
          :kind_of => String
attribute :log_dir,
          :kind_of => String
attribute :work_dir,
          :kind_of => String
attribute :context_dir,
          :kind_of => String
attribute :webapp_dir,
          :kind_of => String
attribute :app_base,
          :kind_of => String
attribute :jndi_connections,
          :kind_of => Array
attribute :jndi,
          :kind_of => String,
          :equal_to => ['true', 'false']
attribute :catalina_options,
          :kind_of => String
attribute :java_options,
          :kind_of => String
attribute :use_security_manager,
          :kind_of => [TrueClass, FalseClass]
attribute :authbind,
          :kind_of => String,
          :equal_to => ['yes', 'no']
attribute :max_threads,
          :kind_of => Fixnum
attribute :ssl_max_threads,
          :kind_of => Fixnum
attribute :generate_ssl_cert,
          :kind_of => String
attribute :ssl_cert_file,
          :kind_of => String
attribute :ssl_key_file,
          :kind_of => String
attribute :ssl_chain_files,
          :kind_of => Array
attribute :keystore_file,
          :kind_of => String
attribute :keystore_type,
          :kind_of => String,
          :equal_to => ['jks', 'pkcs11', 'pkcs12']
attribute :truststore_file,
          :kind_of => String
attribute :truststore_type,
          :kind_of => String,
          :equal_to => ['jks', 'pkcs11', 'pkcs12']
attribute :certificate_dn,
          :kind_of => String
attribute :loglevel,
          :kind_of => String
attribute :tomcat_auth,
          :kind_of => String,
          :equal_to => ['true', 'false']
attribute :cors_enabled,
          :kind_of => String,
          :equal_to => ['true', 'false']
attribute :redirect_http_to_https,
          :kind_of => String,
          :equal_to => ['true', 'false']
attribute :ldap_enabled,
          :kind_of => String,
          :equal_to => ['true', 'false']
attribute :ldap_servers,
          :kind_of => Array
attribute :ldap_port,
          :kind_of => Fixnum
attribute :ldap_bind_user,
          :kind_of => String
attribute :ldap_bind_pwd,
          :kind_of => String
attribute :ldap_user_base,
          :kind_of => String
attribute :ldap_role_base,
          :kind_of => String
attribute :ldap_domain_name,
          :kind_of => String
attribute :ldap_group,
          :kind_of => String
attribute :ldap_user_search,
          :kind_of => String
attribute :ldap_role_search,
          :kind_of => String

attribute :user,
          :kind_of => String
attribute :group,
          :kind_of => String
attribute :home,
          :kind_of => String
attribute :base,
          :kind_of => String
attribute :tmp_dir,
          :kind_of => String
attribute :lib_dir,
          :kind_of => String
attribute :endorsed_dir,
          :kind_of => String
