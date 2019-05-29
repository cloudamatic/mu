#!/usr/local/ruby-current/bin/ruby
# Copyright:: Copyright (c) 2019 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#     http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

module MU
  class Master
    # Create and manage our own internal SSL signing authority
    class SSL

      SERVICES = ["rsyslog", "mommacat", "ldap", "consul", "vault"]

      # Exception class for when we can't find the +openssl+ command
      class MuSSLNotFound < MU::MuError;end

# TODO set file/dir ownerships to honor for_user if we were invoked as root

      # @param for_user [String]
      def self.bootstrap(for_user: MU.mu_user)
        ssldir = MU.dataDir(for_user)+"/ssl"
        Dir.mkdir(ssldir, 0755) if !Dir.exists?(ssldir)

        alt_names = [MU.mu_public_ip, MU.my_private_ip, MU.mu_public_addr, Socket.gethostbyname(Socket.gethostname).first, "localhost", "127.0.0.1"].uniq
        alt_names.reject! { |s| s.nil? }

        getCert("Mu_CA", "/CN=#{MU.mu_public_addr}/OU=Mu Server at #{MU.mu_public_addr}/O=eGlobalTech/C=US", sans: alt_names, ca: true)

        SERVICES.each { |service|
          getCert(service, "/CN=#{MU.mu_public_addr}/OU=Mu #{service}/O=eGlobalTech/C=US", sans: alt_names)
        }

      end

      # @param name [String]
      # @param for_user [String]
      # @return [OpenSSL::PKey::RSA]
      def self.getKey(name, for_user: MU.mu_user)
        ssldir = MU.dataDir(for_user)+"/ssl"
        if !File.exists?(ssldir+"/"+name+".key")
          key = OpenSSL::PKey::RSA.new 4096
          File.write(ssldir+"/"+name+".key", key)
        end
        File.chmod(0400, ssldir+"/"+name+".key")
        OpenSSL::PKey::RSA.new(File.read(ssldir+"/"+name+".key"))
      end

      # @param for_user [String]
      # @return [Integer]
      def self.incrementCASerial(for_user: MU.mu_user)
        ssldir = MU.dataDir(for_user)+"/ssl"
        cur = 0
        if File.exists?(ssldir+"/serial")
          cur = File.read(ssldir+"/serial").chomp.to_i
        end
        File.open("#{ssldir}/serial", File::CREAT|File::RDWR, 0600) { |f|
          f.flock(File::LOCK_EX)
          cur += 1
          f.rewind
          f.truncate(0)
          f.puts cur
          f.flush
          f.flock(File::LOCK_UN)
        }
        cur
      end

      # @param name [String]
      # @param cn_str [String]
      # @param sans [Array<String>]
      # @param ca [Array<String>]
      # @param for_user [String]
      # @return [OpenSSL::X509::Certificate]
      def self.getCert(name, cn_str = nil, sans: [], ca: false, for_user: MU.mu_user)
        ssldir = MU.dataDir(for_user)+"/ssl"

        if File.exists?("#{ssldir}/#{name}.pem")
          return OpenSSL::X509::Certificate.new(File.read("#{ssldir}/#{name}.pem"))
        end

        if cn_str.nil?
          raise MuError, "Can't generate an SSL cert without a CN"
        end

        key = getKey(name, for_user: for_user)

        cn = OpenSSL::X509::Name.parse(cn_str)

        # If we're generating our local CA, we're not really doing a CSR, but
        # the operation is close to identical.
        csr = if ca
          MU.log "Generating Mu CA certificate", MU::NOTICE, details: "#{ssldir}/#{name}.pem"
          csr = OpenSSL::X509::Certificate.new
          csr.not_before = Time.now
          csr.not_after = Time.now + 180000000
          csr 
        else
          MU.log "Generating Mu-signed certificate for #{name}", MU::NOTICE, details: "#{ssldir}/#{name}.pem"
          OpenSSL::X509::Request.new
        end

        csr.version = 0x2 # by which we mean '3'
        csr.subject = cn
        csr.public_key = key.public_key

        ef = OpenSSL::X509::ExtensionFactory.new
        sans_parsed = sans.map { |s|
          if s.match(/^\d+\.\d+\.\d+\.\d+$/)
            "IP:"+s
          else
            "DNS:"+s
          end
        }.join(",")

        # If we're the CA certificate, declare ourselves our own issuer and
        # write, instead of going through the rest of the motions.
        if ca
          csr.issuer = csr.subject
          csr.serial = 1
          ef.subject_certificate = csr
          ef.issuer_certificate = csr
          csr.add_extension(ef.create_extension("subjectAltName",sans_parsed,false))
          csr.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
          csr.add_extension(ef.create_extension("keyUsage","keyCertSign, cRLSign", true))
          csr.add_extension(ef.create_extension("subjectKeyIdentifier", "hash", false))
          csr.add_extension(ef.create_extension("authorityKeyIdentifier", "keyid:always", false))
        end

        csr.sign key, OpenSSL::Digest::SHA256.new

        cert = if !ca
          File.open("#{ssldir}/#{name}.csr", 'w', 0644) { |f|
            f.write csr.to_pem
          }
          cakey = getKey("Mu_CA")
          cacert = getCert("Mu_CA")
          cert = OpenSSL::X509::Certificate.new
          cert.serial = incrementCASerial(for_user: for_user)
          cert.version = 0x2
          cert.not_before = Time.now
          cert.not_after = Time.now + 180000000
          cert.subject = csr.subject
          cert.public_key = csr.public_key
          cert.issuer = cacert.subject
					ef.issuer_certificate = cacert
          ef.subject_certificate = cert
          ef.subject_request = csr
          cert.add_extension(ef.create_extension("subjectAltName",sans_parsed,false))
          cert.add_extension(ef.create_extension("keyUsage","nonRepudiation,digitalSignature,keyEncipherment", false))
          cert.add_extension(ef.create_extension("extendedKeyUsage","clientAuth,serverAuth,codeSigning,emailProtection",false))
          cert.sign cakey, OpenSSL::Digest::SHA256.new
          cert
        else
          csr
        end

        File.open("#{ssldir}/#{name}.pem", 'w', 0644) { |f|
          f.write cert.to_pem
        }

        cert
      end

    end
  end
end
