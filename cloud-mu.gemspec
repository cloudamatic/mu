whereami = File.realpath(File.expand_path(File.dirname(__FILE__)))

def self.build_file_list(dir, strip = dir)
  list = []
  Dir.entries(dir).each { |entry|
    next if entry.match(/^\.|.*?\.gem$/)
    next if %{. .. .git Gemfile.lock}.include?(entry)
    path = dir+"/"+entry
    if File.directory?(path)
      list.concat(build_file_list(path, strip))
    else
      list << path.sub(/^#{Regexp.quote(strip)}\//, "")
    end
  }
  list
end

Gem::Specification.new do |s|
  s.name        = 'cloud-mu'
  s.version     = '3.6.14'
  s.date        = '2025-04-27'
  s.require_paths = ['modules']
  s.required_ruby_version = '>= 3'
  s.summary     = "The eGTLabs Mu toolkit for unified cloud deployments"
  s.description = <<-EOF
The eGTLabs Mu toolkit for unified cloud deployments. This gem contains the Mu deployment interface to cloud provider APIs. It will generate a sample configuration the first time it is invoked.

Mu will attempt to autodetect when it's being run in a virtual machine on a known cloud provider and activate the appropriate API with machine-based credentials. Installing this gem on an Amazon Web Service instance, for example, should automatically enable the MU::Cloud::AWS layer and attempt to use the machine's IAM Profile to communicate with the AWS API.

EOF
  s.authors     = ["John Stange", "Robert Patt-Corner", "Ryan Bolyard", "Zach Rowe"]
  s.email       = 'eGTLabs@eglobaltech.com'
  s.files       = build_file_list(whereami)
  if Dir.exist?(whereami+"/bin")
    s.executables = Dir.entries(whereami+"/bin").reject { |f| File.directory?(f) }
  end
  s.homepage    =
    'https://github.com/cloudamatic/mu'
  s.license       = 'BSD-3-Clause-Attribution'
  s.add_runtime_dependency 'addressable'#, '~> 2.5'

  s.add_runtime_dependency 'bundler'#, "~> 2.2"
  s.add_runtime_dependency 'chronic_duration'#, "~> 0.10"
  s.add_runtime_dependency 'color', "~> 1.8"
  s.add_runtime_dependency 'colorize', "~> 0.8"
  s.add_runtime_dependency 'erubis'#, "~> 2.7"
  s.add_runtime_dependency 'faraday-multipart', "<= 1.0.4"
  s.add_runtime_dependency 'inifile', "~> 3.0"
  s.add_runtime_dependency 'json-schema', "~> 2.8"
  s.add_runtime_dependency 'net-ldap'#, "~> 0.16"
  s.add_runtime_dependency 'net-ssh', "~> 7.2"
  s.add_runtime_dependency 'net-ssh-multi'#, '~> 1.2', '>= 1.2.1'
  s.add_runtime_dependency 'netaddr'#, '~> 2.0'
  s.add_runtime_dependency 'nokogiri'#, "~> 1.10"
  s.add_runtime_dependency 'openssl-oaep', "~> 0.1"
  s.add_runtime_dependency 'optimist'#, "~> 3.0"
  s.add_runtime_dependency 'ruby-graphviz', "~> 1.2"
  s.add_runtime_dependency 'rubocop'#, '~> 0.58'
  s.add_runtime_dependency 'rubyzip'#, "~> 2.3"
  s.add_runtime_dependency 'simple-password-gen', "~> 0.1"
  s.add_runtime_dependency 'slack-notifier', "~> 2.3"
  s.add_runtime_dependency 'solve'#, '~> 4.0'
  s.add_runtime_dependency 'yard'#, "~> 0.9"

  s.post_install_message = "If you're running a gem-only installation, cloud provider gems must be installed separately.\n\nAWS: aws-sdk-core aws-sdk\n\nGCP: google-api-client googleauth"
end
