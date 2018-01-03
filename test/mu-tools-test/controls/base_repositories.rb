control 'mu-tools' do
  title 'base_repositories.rb'
    
    node = json('/tmp/chef_node.json').params

    
    node['default']['application_attributes']['skip_recipes'] = []
    if !node['default']['application_attributes']['skip_recipes'].include?('base_repositories')
      case os[:family]
        when "rhel"
          # Workaround for EOL CentOS 5 repos
          if os[:name] != "amazon" and os[:release].to_i == 5
             describe file("/etc/yum.repos.d/CentOS-Base.repo") do
              it { should exist }
              it { should be_file }
              its('content') { should match /baseurl=http:\/\/vault.centos.org\/5.11\/os\/$basearch\// }
              its('content') { should match /name=CentOS-$releasever - Updates/ }
              its('content') { should match /name=CentOS-$releasever - Extras/ }
              its('content') { should match /name=CentOS-$releasever - Plus/}
              its('conten') { should match /name=CentOS-$releasever - Contrib/}
            end
          end
          describe file('/etc/yum.repos.d/epel.repo') do
            it { should exist }
            it { should be_owned_by 'root' }
            it { should be_grouped_into 'root' }
          end
        end
    end
end
