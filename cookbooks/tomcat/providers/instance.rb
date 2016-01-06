action :configure do
  base_instance = node['tomcat']['base_instance']

  # Set defaults for resource attributes from node attributes. We can't do
  # this in the resource declaration because node isn't populated yet when
  # that runs
  [:catalina_options, :java_options, :use_security_manager, :authbind,
   :max_threads, :ssl_max_threads, :ssl_cert_file, :ssl_key_file, :generate_ssl_cert,
   :ssl_chain_files, :keystore_file, :keystore_type, :truststore_file, :client_auth,
   :truststore_type, :certificate_dn, :loglevel, :tomcat_auth, :user,
   :group, :tmp_dir, :lib_dir, :endorsed_dir, :jndi_connections, :jndi, :cors_enabled, :redirect_http_to_https,
   :app_base, :ldap_enabled, :ldap_servers, :ldap_port, :ldap_bind_user, :ldap_bind_pwd,
   :ldap_user_base, :ldap_role_base, :ldap_domain_name, :ldap_group, :ldap_user_search,
   :ldap_role_search].each do |attr|
    unless new_resource.instance_variable_get("@#{attr}")
      new_resource.instance_variable_set("@#{attr}", node['tomcat'][attr])
    end
  end

  if new_resource.name == 'base'
    instance = base_instance

    # If they weren't set explicitly, set these paths to the default
    [:base, :home, :config_dir, :log_dir, :work_dir, :context_dir,
     :webapp_dir].each do |attr|
      unless new_resource.instance_variable_get("@#{attr}")
        new_resource.instance_variable_set("@#{attr}", node['tomcat'][attr])
      end
    end
  else
    # Use a unique name for this instance
    instance = "#{base_instance}-#{new_resource.name}"

    # If they weren't set explicitly, set these paths to the default with
    # the base instance name replaced with our own
    [:base, :home, :config_dir, :log_dir, :work_dir, :context_dir,
     :webapp_dir].each do |attr|
      if !new_resource.instance_variable_get("@#{attr}") && node['tomcat'][attr]
        new = node['tomcat'][attr].sub(base_instance, instance)
        new_resource.instance_variable_set("@#{attr}", new)
      end
    end

    # Create the directories, since the OS package wouldn't have
    [:base, :config_dir, :context_dir].each do |attr|
      directory new_resource.instance_variable_get("@#{attr}") do
        mode '0755' if node.platform_family != 'windows'
        recursive true
      end
    end
    [:log_dir, :work_dir, :webapp_dir].each do |attr|
      directory new_resource.instance_variable_get("@#{attr}") do
        mode '0755' if node.platform_family != 'windows'
        recursive true
        user new_resource.user if node.platform_family != 'windows'
        group new_resource.group if node.platform_family != 'windows'
      end
    end

    # Don't make a separate home, just link to base
    if new_resource.home != new_resource.base
      link new_resource.home do
        to new_resource.base
      end
    end

    # config_dir needs symlinks to the files we're not going to create
    %w(catalina.policy catalina.properties context.xml
       tomcat-users.xml web.xml).each do |file|
      link "#{new_resource.config_dir}/#{file}" do
        to "#{node['tomcat']['config_dir']}/#{file}"
      end
    end

    # The base also needs a bunch of to symlinks inside it
    %w(bin lib).each do |dir|
      link "#{new_resource.base}/#{dir}" do
        to "#{node['tomcat']['base']}/#{dir}"
      end
    end
    { 'conf' => 'config_dir', 'logs' => 'log_dir', 'temp' => 'tmp_dir',
      'work' => 'work_dir', 'webapps' => 'webapp_dir' }.each do |name, attr|
      link "#{new_resource.base}/#{name}" do
        to new_resource.instance_variable_get("@#{attr}")
      end
    end

    # Make a copy of the init script for this instance
    if node['init_package'] == 'systemd' && !platform_family?('debian')
      template "/usr/lib/systemd/system/#{instance}.service" do
        source 'tomcat.service.erb'
        variables(
          instance: instance,
          user: new_resource.user,
          group: new_resource.group
        )
        owner 'root'
        group 'root'
        mode '0644'
      end
    else
      execute "/etc/init.d/#{instance}" do
        command <<-EOH
          cp /etc/init.d/#{base_instance} /etc/init.d/#{instance}
          perl -i -pe 's/#{base_instance}/#{instance}/g' /etc/init.d/#{instance}
        EOH
      end
    end
  end

  # Even for the base instance, the OS package may not make this directory
  directory new_resource.endorsed_dir do
    mode '0755' if node.platform_family != 'windows'
    recursive true
  end

  unless new_resource.truststore_file.nil?
    java_options = new_resource.java_options.to_s
    java_options << " -Djavax.net.ssl.trustStore=#{new_resource.config_dir}/#{new_resource.truststore_file}"
    java_options << " -Djavax.net.ssl.trustStorePassword=#{new_resource.truststore_password}"
    new_resource.java_options = java_options
  end

  case node['platform_family']
  when 'rhel', 'fedora'
    template "/etc/sysconfig/#{instance}" do
      source 'sysconfig_tomcat6.erb'
      variables(
        user: new_resource.user,
        home: new_resource.home,
        base: new_resource.base,
        java_options: new_resource.java_options,
        use_security_manager: new_resource.use_security_manager,
        tmp_dir: new_resource.tmp_dir,
        catalina_options: new_resource.catalina_options,
        endorsed_dir: new_resource.endorsed_dir
      )
      owner 'root'
      group 'root'
      mode '0644'
      notifies :restart, "service[#{instance}]"
    end
  when 'suse'
    template '/etc/tomcat/tomcat.conf' do
      source 'sysconfig_tomcat7.erb'
      variables(
        user: new_resource.user,
        home: new_resource.home,
        base: new_resource.base,
        java_options: new_resource.java_options,
        use_security_manager: new_resource.use_security_manager,
        tmp_dir: new_resource.tmp_dir,
        catalina_options: new_resource.catalina_options,
        endorsed_dir: new_resource.endorsed_dir
      )
      owner 'root'
      group 'root'
      mode '0644'
      notifies :restart, "service[#{instance}]"
    end
  when 'smartos'
    # SmartOS doesn't support multiple instances
    template "#{new_resource.base}/bin/setenv.sh" do
      source 'setenv.sh.erb'
      owner 'root'
      group 'root'
      mode '0644'
      notifies :restart, "service[#{instance}]"
    end
  when 'windows'
    registry_key "HKLM\\SOFTWARE\\Wow6432Node\\Apache Software Foundation\\Procrun 2.0\\Tomcat#{node.tomcat.base_version}\\Parameters\\Stop" do
      values [{
        :name => 'Timeout',
        :type => :dword,
        :data => 30
      }]
      recursive true
      notifies :restart, "service[#{instance}]", :delayed
    end

    java_opts = [
      "-Dcatalina.home=#{new_resource.home}", "-Dcatalina.base=#{new_resource.base}", "-Djava.endorsed.dirs=#{new_resource.endorsed_dir}", "-Djava.io.tmpdir=#{new_resource.tmp_dir}",
      "-Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager", "-Djava.util.logging.config.file=#{new_resource.config_dir}\\logging.properties"
    ]

    max_heap = nil
    min_heap = nil

    new_resource.java_options.split.each { |opt|
      if opt.downcase.start_with?("-xmx")
        max_heap =
          if opt.downcase.end_with?("g")
            opt.downcase.gsub(/[^\d]/, '').to_i * 1024
          elsif opt.downcase.end_with?("m")
            opt.downcase.gsub(/[^\d]/, '').to_i
          end
      elsif opt.downcase.start_with?("-xms")
        min_heap =
          if opt.downcase.end_with?("g")
            opt.downcase.gsub(/[^\d]/, '').to_i * 1024
          elsif opt.downcase.end_with?("m")
            opt.downcase.gsub(/[^\d]/, '').to_i
          end
      else
        java_opts << opt
      end
    }

    min_heap = 128 if min_heap.nil?
    max_heap = min_heap if max_heap.nil?

    registry_key "HKLM\\SOFTWARE\\Wow6432Node\\Apache Software Foundation\\Procrun 2.0\\Tomcat#{node.tomcat.base_version}\\Parameters\\Java" do
      values [{
        :name => 'JvmMs',
        :type => :dword,
        :data => min_heap
      }]
      recursive true
      notifies :restart, "service[#{instance}]", :delayed
    end

    registry_key "HKLM\\SOFTWARE\\Wow6432Node\\Apache Software Foundation\\Procrun 2.0\\Tomcat#{node.tomcat.base_version}\\Parameters\\Java" do
      values [{
        :name => 'JvmMx',
        :type => :dword,
        :data => max_heap
      }]
      recursive true
      notifies :restart, "service[#{instance}]", :delayed
    end

    registry_key "HKLM\\SOFTWARE\\Wow6432Node\\Apache Software Foundation\\Procrun 2.0\\Tomcat#{node.tomcat.base_version}\\Parameters\\Java" do
      values [{
        :name => 'Options',
        :type => :multi_string,
        :data => java_opts
      }]
      recursive true
      notifies :restart, "service[#{instance}]", :delayed
    end
  else
    template "/etc/default/#{instance}" do
      source 'default_tomcat6.erb'
      variables(
        user: new_resource.user,
        group: new_resource.group,
        home: new_resource.home,
        base: new_resource.base,
        java_options: new_resource.java_options,
        use_security_manager: new_resource.use_security_manager,
        tmp_dir: new_resource.tmp_dir,
        authbind: new_resource.authbind,
        catalina_options: new_resource.catalina_options,
        endorsed_dir: new_resource.endorsed_dir
      )
      owner 'root'
      group 'root'
      mode '0644'
      notifies :restart, "service[#{instance}]"
    end
end

  template "#{new_resource.config_dir}/server.xml" do
    source 'server.xml.erb'
    variables(
      port: new_resource.port,
      proxy_port: new_resource.proxy_port,
      proxy_name: new_resource.proxy_name,
      secure: new_resource.secure,
      scheme: new_resource.scheme,
      ssl_port: new_resource.ssl_port,
      ssl_proxy_port: new_resource.ssl_proxy_port,
      ajp_port: new_resource.ajp_port,
      ajp_redirect_port: new_resource.ajp_redirect_port,
      shutdown_port: new_resource.shutdown_port,
      max_threads: new_resource.max_threads,
      ssl_max_threads: new_resource.ssl_max_threads,
      keystore_file: new_resource.keystore_file,
      keystore_type: new_resource.keystore_type,
      tomcat_auth: new_resource.tomcat_auth,
      client_auth: new_resource.client_auth,
      config_dir: new_resource.config_dir,
      app_base: new_resource.app_base,
      ldap_enabled: new_resource.ldap_enabled,
      ldap_servers: new_resource.ldap_servers,
      ldap_port: new_resource.ldap_port,
      ldap_bind_user: new_resource.ldap_bind_user,
      ldap_bind_pwd: new_resource.ldap_bind_pwd,
      ldap_user_base: new_resource.ldap_user_base,
      ldap_role_base: new_resource.ldap_role_base,
      ldap_domain_name: new_resource.ldap_domain_name,
      ldap_group: new_resource.ldap_group,
      ldap_user_search: new_resource.ldap_user_search,
      ldap_role_search: new_resource.ldap_role_search
    )
    owner new_resource.user if node.platform_family != 'windows'
    group new_resource.group if node.platform_family != 'windows'
    mode '0644' if node.platform_family != 'windows'
    notifies :restart, "service[#{instance}]"
  end

  if platform_family?('windows')
    # Needs to run every time - requires re-factoring. Creating a definition and trying to rescue the definition call still doesn't work    
    if !::File.exists?("#{new_resource.config_dir}\\first_run")
      execute "echo restarting #{instance}" do
        notifies :stop, "service[#{instance}]", :immediately
      end

      execute "powershell -Command \"& {rm #{new_resource.config_dir}/web.xml}\"" do
        notifies :create, "file[#{new_resource.config_dir}\\first_run]", :immediately
      end

      # file "#{new_resource.config_dir}\\web.xml" do 
      # action :delete
      # end

      file "#{new_resource.config_dir}\\first_run" do
        action :nothing
      end
    end
  end

  template "#{new_resource.config_dir}/web.xml" do
    source 'web.xml.erb'
    owner new_resource.user if node.platform_family != 'windows'
    group new_resource.group if node.platform_family != 'windows'
    mode '0644' if node.platform_family != 'windows'
    notifies :restart, "service[#{instance}]"
    variables(
      cors_enabled: new_resource.cors_enabled,
      redirect_http_to_https: new_resource.redirect_http_to_https
    )
  end

  template "#{new_resource.config_dir}/context.xml" do
    source 'context.xml.erb'
    variables(
      jndi: new_resource.jndi,
      jndi_connections: new_resource.jndi_connections
    )
    owner new_resource.user if node.platform_family != 'windows'
    group new_resource.group if node.platform_family != 'windows'
    mode '0644' if node.platform_family != 'windows'
    notifies :restart, "service[#{instance}]"
  end

  template "#{new_resource.config_dir}/logging.properties" do
    source 'logging.properties.erb'
    owner new_resource.user if node.platform_family != 'windows'
    group new_resource.group if node.platform_family != 'windows'
    mode '0644' if node.platform_family != 'windows'
    notifies :restart, "service[#{instance}]"
  end

  if new_resource.generate_ssl_cert
    if new_resource.ssl_cert_file.nil?
      execute 'Create Tomcat SSL certificate' do
        group new_resource.group
        command <<-EOH
          #{node['tomcat']['keytool']} \
           -genkey \
           -keystore "#{new_resource.config_dir}/#{new_resource.keystore_file}" \
           -storepass "#{node['tomcat']['keystore_password']}" \
           -keypass "#{node['tomcat']['keystore_password']}" \
           -dname "#{node['tomcat']['certificate_dn']}" \
           -keyalg "RSA"
        EOH
        umask 0007 if node.platform_family != 'windows'
        creates "#{new_resource.config_dir}/#{new_resource.keystore_file}"
        action :run
        notifies :restart, "service[#{instance}]"
      end
    else
      script "create_keystore-#{instance}" do
        interpreter 'bash'
        action :nothing
        cwd new_resource.config_dir
        code <<-EOH
          cat #{new_resource.ssl_chain_files.join(' ')} > cacerts.pem
          openssl pkcs12 -export \
           -inkey #{new_resource.ssl_key_file} \
           -in #{new_resource.ssl_cert_file} \
           -chain \
           -CAfile cacerts.pem \
           -password pass:#{node['tomcat']['keystore_password']} \
           -out #{new_resource.keystore_file}
        EOH
        notifies :restart, "service[#{instance}]"
      end

      cookbook_file "#{new_resource.config_dir}/#{new_resource.ssl_cert_file}" do
        mode '0644' if node.platform_family != 'windows'
        notifies :run, "script[create_keystore-#{instance}]"
      end

      cookbook_file "#{new_resource.config_dir}/#{new_resource.ssl_key_file}" do
        mode '0644' if node.platform_family != 'windows'
        notifies :run, "script[create_keystore-#{instance}]"
      end

      new_resource.ssl_chain_files.each do |cert|
        cookbook_file "#{new_resource.config_dir}/#{cert}" do
          mode '0644' if node.platform_family != 'windows'
          notifies :run, "script[create_keystore-#{instance}]"
        end
      end
    end

    unless new_resource.truststore_file.nil?
      cookbook_file "#{new_resource.config_dir}/#{new_resource.truststore_file}" do
        mode '0644' if node.platform_family != 'windows'
      end
    end
  end

  new_resource.updated_by_last_action(true)
end
