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
  s.name        = 'mu'
  s.version     = '1.9.0-alpha'
  s.date        = '2018-12-11'
  s.require_paths = ['modules']
  s.required_ruby_version = '>= 2.4'
  s.summary     = "Mu"
  s.description = File.read(whereami+"/README.md")
  s.authors     = ["John Stange"]
  s.email       = 'eGTLabs@eglobaltech.com'
  s.files       = build_file_list(whereami)
  s.executables = Dir.entries(whereami+"/bin")
  s.homepage    =
    'https://github.com/cloudamatic/mu'
  s.license       = 'BSD-3-Clause-Attribution'
  s.add_runtime_dependency 'yard', "~> 0.9"
  s.add_runtime_dependency 'ruby-graphviz', "~> 1.2"
  s.add_runtime_dependency "aws-sdk-core", "< 3"
  s.add_runtime_dependency 'chronic_duration', "~> 0.10"
  s.add_runtime_dependency 'simple-password-gen', "~> 0.1"
  s.add_runtime_dependency 'optimist', "~> 3.0"
  s.add_runtime_dependency 'json-schema', "~> 2.8"
  s.add_runtime_dependency 'colorize', "~> 0.8"
  s.add_runtime_dependency 'color', "~> 1.8"
  s.add_runtime_dependency 'netaddr', '~> 2.0'
  s.add_runtime_dependency 'nokogiri', "~> 1.8"
  s.add_runtime_dependency 'solve', '~> 4.0'
  s.add_runtime_dependency 'net-ldap', "~> 0.16"
  s.add_runtime_dependency 'googleauth', "~> 0.6"
  s.add_runtime_dependency 'google-api-client', "~> 0.25"
  s.add_runtime_dependency 'rubocop', '~> 0.58'
  s.add_runtime_dependency 'addressable', '~> 2.5'
  s.add_runtime_dependency 'slack-notifier', "~> 2.3"
end
