#
# Cookbook Name:: mu-utility
# Recipe:: wsfc
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
#
# Windows Server Failover Clustering
 
if !platform_family?("windows")
	Chef::Log.info "I don't know how to Windows Server Failover Clusting on a non-Windows host"
else

	powershell_script "Install Windows Server Failover Clustering" do
		guard_interpreter :powershell_script
		not_if "Import-Module FailoverClusters"
		code <<-EOH
			Add-WindowsFeature 'Failover-Clustering', 'RSAT-Clustering'
		EOH
	end

	powershell_script "Configure Windows Server Failover Clustering" do
		guard_interpreter :powershell_script
		not_if "Get-Cluster"
		code <<-EOH
#			New-Cluster -Name TESTCLUSTER -NoStorage -Node $env:COMPUTERNAME
			New-Cluster -Name TESTCLUSTER -NoStorage -Node #{node.normal.ec2.private_dns_name}
			$ClusterNameResource = Get-ClusterResource TESTCLUSTER
			$ClusterNameResource | Start-ClusterResource -Wait 60
			if ((Get-ClusterResource TESTCLUSTER).State -ne "Online")
			{
				exit 1
			}
			Set-Service ClusSvc -StartupType Automatic
		Start-Service ClusSvc
		EOH
	end
end
