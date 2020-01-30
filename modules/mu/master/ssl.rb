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

      # List of Mu services for which we'll generate SSL certs signed by our
      # authority.
      SERVICES = ["rsyslog", "mommacat", "ldap", "consul", "vault"]

      # Exception class for when we can't find the +openssl+ command
      class MuSSLNotFound < MU::MuError;end

# TODO set file/dir ownerships to honor for_user if we were invoked as root

      # @param for_user [String]
      def self.bootstrap(for_user: MU.mu_user)
        ssldir = MU.dataDir(for_user)+"/ssl"
        Dir.mkdir(ssldir, 0755) if !Dir.exist?(ssldir)

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
      def self.getKey(name, for_user: MU.mu_user, keysize: 4096)
        ssldir = MU.dataDir(for_user)+"/ssl"
        if !File.exist?(ssldir+"/"+name+".key")
          key = OpenSSL::PKey::RSA.new keysize
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
        if File.exist?(ssldir+"/serial")
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


      # Given a Certificate Signing Request, sign it with our internal CA and
      # write the resulting signed certificate. Only works on local files.
      # @param csr_path [String]: The CSR to sign, as a file.
      def self.sign(csr_path, sans = [], for_user: MU.mu_user)
        certdir = File.dirname(csr_path)
        certname = File.basename(csr_path, ".csr")
        if File.exist?("#{certdir}/#{certname}.crt")
          MU.log "Not re-signing SSL certificate request #{csr_path}, #{certdir}/#{certname}.crt already exists", MU::DEBUG
          return
        end
        MU.log "Signing SSL certificate request #{csr_path} with #{MU.mySSLDir}/Mu_CA.pem"

        begin
          csr = OpenSSL::X509::Request.new File.read csr_path
        rescue StandardError => e
          MU.log e.message, MU::ERR, details: File.read(csr_path)
          raise e
        end

        cakey = getKey("Mu_CA")
        cacert = getCert("Mu_CA", ca: true).first

        cert = OpenSSL::X509::Certificate.new
        cert.serial = incrementCASerial(for_user: for_user)
        cert.version = 0x2
        cert.not_before = Time.now
        cert.not_after = Time.now + 180000000
        cert.subject = csr.subject
        cert.public_key = csr.public_key
        cert.issuer = cacert.subject
        ef = OpenSSL::X509::ExtensionFactory.new
        ef.issuer_certificate = cacert
        ef.subject_certificate = cert
        ef.subject_request = csr
        if !sans.nil? and !sans.empty? and
           !formatSANS(sans).nil? and !formatSANS(sans).empty?
          cert.add_extension(ef.create_extension("subjectAltName",formatSANS(sans),false))
        end
        cert.add_extension(ef.create_extension("keyUsage","nonRepudiation,digitalSignature,keyEncipherment", false))
        cert.add_extension(ef.create_extension("extendedKeyUsage","clientAuth,serverAuth,codeSigning,emailProtection",false))
        cert.sign cakey, OpenSSL::Digest::SHA256.new

        File.open("#{certdir}/#{certname}.crt", 'w', 0644) { |f|
          f.write cert.to_pem
        }

        cert
      end

      # @param name [String]
      # @param cn_str [String]
      # @param sans [Array<String>]
      # @param ca [Array<String>]
      # @param for_user [String]
      # @return [OpenSSL::X509::Certificate]
      def self.getReq(name, cn_str = nil, sans: [], ca: false, for_user: MU.mu_user)
      end

      # @param name [String]
      # @param cn_str [String]
      # @param sans [Array<String>]
      # @param ca [Array<String>]
      # @param for_user [String]
      # @param pfx [Boolean]
      # @return [OpenSSL::X509::Certificate]
      def self.getCert(name, cn_str = nil, sans: [], ca: false, for_user: MU.mu_user, pfx: false)
        ssldir = MU.dataDir(for_user)+"/ssl"
        filename = ca ? "#{ssldir}/#{name}.pem" : "#{ssldir}/#{name}.crt"
        keyfile = "#{ssldir}/#{name}.key"
        pfxfile = "#{ssldir}/#{name}.pfx"
        pfx_cert = nil

        if File.exist?(filename)
          pfx_cert = toPfx(filename, keyfile, pfxfile) if pfx
          cert = OpenSSL::X509::Certificate.new(File.read(filename))
          return [cert, pfx_cert]
        end

        if cn_str.nil?
          raise MuError, "Can't generate an SSL cert for #{name} without a CN"
        end

        key = getKey(name, for_user: for_user)

puts cn_str
        cn = OpenSSL::X509::Name.parse(cn_str)

        # If we're generating our local CA, we're not really doing a CSR, but
        # the operation is close to identical.
        csr = if ca
          MU.log "Generating Mu CA certificate", MU::NOTICE, details: filename
          csr = OpenSSL::X509::Certificate.new
          csr.not_before = Time.now
          csr.not_after = Time.now + 180000000
          csr 
        else
          MU.log "Generating Mu-signed certificate for #{name}", MU::NOTICE, details: filename
          OpenSSL::X509::Request.new
        end

        csr.version = 0x2 # by which we mean '3'
        csr.subject = cn
        csr.public_key = key.public_key


        # If we're the CA certificate, declare ourselves our own issuer and
        # write, instead of going through the rest of the motions.
        if ca
          csr.issuer = csr.subject
          ef = OpenSSL::X509::ExtensionFactory.new
          csr.serial = 1
          ef.subject_certificate = csr
          ef.issuer_certificate = csr
          csr.add_extension(ef.create_extension("subjectAltName",formatSANS(sans),false))
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
					sign("#{ssldir}/#{name}.csr", sans, for_user: for_user)
        else
          csr
        end

        File.open(filename, 'w', 0644) { |f|
          f.write cert.to_pem
        }
        pfx_cert = toPfx(filename, keyfile, pfxfile) if pfx

        if MU.mu_user != "mu" and Process.uid == 0
          owner_uid = Etc.getpwnam(for_user).uid
          File.chown(owner_uid, nil, filename)
          File.chown(owner_uid, nil, pfxfile) if pfx
        end


        [cert, pfx_cert]
      end

      private

      private_class_method :toPfx
      def self.toPfx(certfile, keyfile, pfxfile)
        cacert = getCert("Mu_CA", ca: true).first
        cert = OpenSSL::X509::Certificate.new(File.read(certfile))
        key = OpenSSL::PKey::RSA.new(File.read(keyfile))
        pfx = OpenSSL::PKCS12.create(nil, nil, key, cert, [cacert], nil, nil, nil, nil)
        File.open(pfxfile, 'w', 0644) { |f|
          f.write pfx.to_der
        }
        pfx
      end

      private_class_method :formatSANS
      def self.formatSANS(sans)
        sans.map { |s|
          if s.match(/^\d+\.\d+\.\d+\.\d+$/)
            "IP:"+s
          else
            "DNS:"+s
          end
        }.join(",")
      end

    end
  end
end
