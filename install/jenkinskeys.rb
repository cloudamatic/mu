#!/usr/local/ruby-current/bin/ruby
require "openssl"
require 'net/ssh'
key = OpenSSL::PKey::RSA.new 2048
public_key = "#{key.public_key.ssh_type} #{[key.public_key.to_blob].pack('m0')}"
vault_opts="--mode client -u mu -F json"
vault_cmd = "knife vault create jenkins admin '{ \"public_key\":\"#{public_key}\", \"private_key\":\"#{key.to_pem.chomp!.gsub(/\n/, "\\n")}\", \"username\": \"master_user\" }' #{vault_opts} --search name:MU-MASTER"
exec vault_cmd
