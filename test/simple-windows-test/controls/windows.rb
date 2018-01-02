control 'Mu-Utility Cookbook' do
  title 'windows_basics'

=begin    
  describe windows_feature('AWS Tools for Windows Powershell') do
    it{ should be_installed }
  end

    describe windows_feature('Google Chrome') do
      it{ should be_installed }
    end
=end
  describe package('7-Zip') do
    it{ should be_installed }
  end
end
