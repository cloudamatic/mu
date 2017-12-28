

case os[:family]
  when 'redhat'

  %w(/etc/httpd/sites-available/ etc/httpd/sites-enabled/).each do |dir|
    describe dir do
      it { should exist }
    end
  end

  describe file('/etc/httpd/conf/httpd.conf') do
    it { should exist }
    it { should_not be_directory }
    its('mode') { should cmp '00644' }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    ### check contents? Wait entire file?
  end

  describe file('/etc/httpd/sites-available/wordpress') do
    it { should exist }
    it { should_not be_directory }
    its('mode') { should cmp '00644' }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end

end ## ends case
