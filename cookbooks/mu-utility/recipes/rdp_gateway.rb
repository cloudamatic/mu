#
# Cookbook Name:: mu-utility
# Recipe:: rdp_gateway
#
# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
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

if !platform_family?("windows")
  Chef::Log.info "I don't know how to enable RDP gateway behavior on a non-Windows host"
else

  powershell_script "Install Remote Desktop Gateway services" do
    guard_interpreter :powershell_script
    not_if "Import-Module RemoteDesktopServices"
    code <<-EOH
			Add-WindowsFeature -Name RDS-Gateway -IncludeAllSubFeature
    EOH
  end

  powershell_script "Configure Remote Desktop Gateway services" do
    guard_interpreter :powershell_script
    code <<-EOH
			Import-Module RemoteDesktopServices
			cd RDS:\\GatewayServer\\CAP
			New-Item -Name StandardAccess -UserGroups 'Remote Desktop Users@BUILTIN' -AuthMethod 1
			New-Item -Name AdminAccess -UserGroups 'Administrators@BUILTIN' -AuthMethod 1
			cd RDS:\\GatewayServer\\RAP
			New-Item -Name StandardAccess -UserGroups 'Remote Desktop Users@BUILTIN' -ComputerGroupType 2
			New-Item -Name AdminAccess -UserGroups 'Administrators@BUILTIN' -ComputerGroupType 2

			# This bleeding horror lifted from: http://blogs.technet.com/b/vishalagarwal/archive/2009/08/22/generating-a-certificate-self-signed-using-powershell-and-certenroll-interfaces.aspx
			$name = new-object -com "X509Enrollment.CX500DistinguishedName.1"
			$name.Encode("CN=RDS", 0)

			$key = new-object -com "X509Enrollment.CX509PrivateKey.1"
			$key.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
			$key.KeySpec = 1
			$key.Length = 1024
			$key.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
			$key.MachineContext = 1
			$key.Create()

			$serverauthoid = new-object -com "X509Enrollment.CObjectId.1"
			$serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
			$ekuoids = new-object -com "X509Enrollment.CObjectIds.1"
			$ekuoids.add($serverauthoid)
			$ekuext = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
			$ekuext.InitializeEncode($ekuoids)

			$cert = new-object -com "X509Enrollment.CX509CertificateRequestCertificate.1"
			$cert.InitializeFromPrivateKey(2, $key, "")
			$cert.Subject = $name
			$cert.Issuer = $cert.Subject
			$cert.NotBefore = get-date
			$cert.NotAfter = $cert.NotBefore.AddDays(3650)
			$cert.X509Extensions.Add($ekuext)
			$cert.Encode()

			$enrollment = new-object -com "X509Enrollment.CX509Enrollment.1"
			$enrollment.InitializeFromRequest($cert)
			$certdata = $enrollment.CreateRequest(0)
			$enrollment.InstallResponse(2, $certdata, 0, "")

			# Thumbprint bit: http://www.frontiertown.co.uk/jclouds/activate-winrm.ps1
			$thumbprints = Get-Childitem -path cert:\\LocalMachine\\My | Where-Object { $_.Subject -eq "CN=RDS" } | Select-Object -Property Thumbprint
			$thumbprint = @($thumbprints)[0].Thumbprint
			Set-Item -Path RDS:\\GatewayServer\\SSLCertificate\\Thumbprint -Value $thumbprint

			Restart-Service TSGateway
    EOH
  end
end
