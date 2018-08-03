# Cookbook Name:: mu-tools
# Recipe:: eks
#
# Copyright:: Copyright (c) 2018 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#		 http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Client-side behavior for interfacing with Amazon Elastic File System

if node['deployment'].has_key?('container_clusters')
  pp node['deployment']['container_clusters']
  region = node['deployment']['container_clusters'][node['service_name']]['region']
  cluster = node['deployment']['container_clusters'][node['service_name']]['name']
  max_pods = node['deployment']['container_clusters'][node['service_name']]['max_pods']
  ca = node['deployment']['container_clusters'][node['service_name']]['certificate_authority']['data']
  endpoint = node['deployment']['container_clusters'][node['service_name']]['endpoint']

  if platform_family?("rhel") and node[:platform_version].to_i >= 7
    execute "rpm --import https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg"
    file "/etc/yum.repos.d/kubernetes.repo" do
      content "[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg
        https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
"
    end
    execute "yum -q makecache -y --disablerepo='*' --enablerepo=kubernetes"
    package "docker"
  elsif platform_family?("debian")
    package "apt-transport-https"
    package "ca-certificates"
    package "software-properties-common"
    package "curl"
    bash "install docker" do
      code <<EOH
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
        add-apt-repository "deb https://download.docker.com/linux/$(. /etc/os-release; echo "$ID") $(lsb_release -cs) stable"
        apt-get update && apt-get install -y docker-ce=$(apt-cache madison docker-ce | grep 17.03 | head -1 | awk '{print $3}')
EOH
    end

    execute "curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -"
    file "/etc/apt/sources.list.d/kubernetes.list" do
      content "deb http://apt.kubernetes.io/ kubernetes-xenial main\n"
    end
  else
    raise "#{node['platform']} #{node[:platform_version].to_s} isn't supported as a Kubernetes worker"
  end
  package "kubeadm"
  package "kubelet"
  package "kubectl"

  directory "/etc/kubernetes/pki/" do
    recursive true
    action :create
  end
  file "/etc/kubernetes/pki/ca.crt" do
    content ca
  end
  bash "install EKS node client" do
    code <<EOH
      CA_CERTIFICATE_DIRECTORY=/etc/kubernetes/pki
      CA_CERTIFICATE_FILE_PATH=$CA_CERTIFICATE_DIRECTORY/ca.crt
      MODEL_DIRECTORY_PATH=~/.aws/eks
      MODEL_FILE_PATH=$MODEL_DIRECTORY_PATH/eks-2017-11-01.normal.json
      mkdir -p $CA_CERTIFICATE_DIRECTORY
      mkdir -p $MODEL_DIRECTORY_PATH
      curl -o $MODEL_FILE_PATH https://s3-us-west-2.amazonaws.com/amazon-eks/1.10.3/2018-06-05/eks-2017-11-01.normal.json
      aws configure add-model --service-model file://$MODEL_FILE_PATH --service-name eks
      INTERNAL_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
      sed -i s,MASTER_ENDPOINT,"#{endpoint}",g /var/lib/kubelet/kubeconfig
      sed -i s,CLUSTER_NAME,"#{cluster}",g /var/lib/kubelet/kubeconfig
      sed -i s,REGION,"#{region}",g /etc/systemd/system/kubelet.service
      sed -i s,MAX_PODS,"#{max_pods}",g /etc/systemd/system/kubelet.service
      sed -i s,MASTER_ENDPOINT,$MASTER_ENDPOINT,g /etc/systemd/system/kubelet.service
      sed -i s,INTERNAL_IP,$INTERNAL_IP,g /etc/systemd/system/kubelet.service
      DNS_CLUSTER_IP=10.100.0.10
      if [[ $INTERNAL_IP == 10.* ]] ; then DNS_CLUSTER_IP=172.20.0.10; fi
      sed -i s,DNS_CLUSTER_IP,$DNS_CLUSTER_IP,g  /etc/systemd/system/kubelet.service
      sed -i s,CERTIFICATE_AUTHORITY_FILE,$CA_CERTIFICATE_FILE_PATH,g /var/lib/kubelet/kubeconfig
      sed -i s,CLIENT_CA_FILE,$CA_CERTIFICATE_FILE_PATH,g  /etc/systemd/system/kubelet.service
EOH
  end
end
