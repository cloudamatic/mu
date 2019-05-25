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
  cluster_short_name = node['service_name'].sub(/-?workers$/, "")
  region = node['deployment']['container_clusters'][cluster_short_name]['region']
  cluster = node['deployment']['container_clusters'][cluster_short_name]['name']
  max_pods = node['deployment']['container_clusters'][cluster_short_name]['max_pods']
  ca = node['deployment']['container_clusters'][cluster_short_name]['certificate_authority']['data']
  endpoint = node['deployment']['container_clusters'][cluster_short_name]['endpoint']
#  admin_role = node['deployment']['container_clusters'][cluster_short_name]['k8s_admin_role']

  if platform_family?("rhel") and node['platform_version'].to_i >= 7
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
    package "awscli"
    package "kubeadm"
    package "kubelet"
    package "kubectl"
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
    package "kubeadm"
    package "kubelet"
    package "kubectl"
  else
    Chef::Log.info("I don't know how to turn this #{node['platform']} AMI (#{node['platform_version']}) into a Kubernetes worker, hopefully it's the official, pre-configured AMI")
  end

  service "docker" do
    action [:start, :enable]
  end
  service "kubelet" do
    action [:start, :enable]
  end

  directory "/etc/kubernetes/pki/" do
    recursive true
    action :create
  end
  file "/etc/kubernetes/pki/ca.crt" do
    content Base64.decode64(ca)
  end

  directory "/root/.aws/eks" do
    recursive true
    action :create
  end

  remote_file "/root/.aws/eks/eks-2017-11-01.normal.json" do
    source "https://s3-us-west-2.amazonaws.com/amazon-eks/1.10.3/2018-06-05/eks-2017-11-01.normal.json"
  end

  execute "aws configure add-model --service-model file://root/.aws/eks/eks-2017-11-01.normal.json --service-name eks"

  execute "systemctl daemon-reload" do
    action :nothing
  end

  template "/etc/systemd/system/kubelet.service" do
    source "kubelet.service.erb"
    mode 0644
#    :pod_infra_container? :region?
#    --pod-infra-container-image=602401143452.dkr.ecr.us-east-1.amazonaws.com/eks/pause-amd64:3.1
    variables(
      :dns => get_first_nameserver(),
      :node_ip => get_aws_metadata("meta-data/local-ipv4")
    )
    notifies :run, "execute[systemctl daemon-reload]", :immediately
    notifies :restart, "service[kubelet]", :delayed
  end

  directory "/root/.kube"

  remote_file "/usr/bin/aws-iam-authenticator" do
    source "https://amazon-eks.s3-us-west-2.amazonaws.com/1.10.3/2018-07-26/bin/linux/amd64/aws-iam-authenticator"
    mode 0755
    not_if "test -f /usr/bin/aws-iam-authenticator"
  end

  ["/var/lib/kubelet/kubeconfig", "/root/.kube/config"].each { |kubecfg|
    template kubecfg do
      source "kubeconfig.erb"
      variables(
        :endpoint => endpoint,
        :cluster => cluster,
        :cacert => ca,
        :rolearn => node['ec2']['iam_instance_profile']['arn'].sub(/:instance-profile\//, ":role/")
      )
    end
  }

  master_ips = get_mu_master_ips
  opento = master_ips.map { |x| "#{x}/32"}

  opento.uniq.each { |src|
    [:tcp, :udp, :icmp].each { |proto|
      execute "iptables -I INPUT -p #{proto} -s #{src}" do
        not_if "iptables -L -n | tr -s ' ' | grep -- '#{proto} -- #{src.sub(/\/32$/, "")}' > /dev/null"
      end
    }
  }

  execute "/usr/sbin/sysctl -w net.ipv4.ip_forward=1"

  execute "echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf" do
    not_if "grep ^net.ipv4.ip_forward /etc/sysctl.conf"
  end

  bash "Allow DockerD to forward traffic outside" do
    code <<EOH
    /sbin/iptables -A FORWARD -i docker0 -j ACCEPT
    /sbin/iptables -A INPUT -i docker0 -j ACCEPT
    /sbin/iptables -t nat -A POSTROUTING -o eth0 -s 172.17.0.0/16 -j MASQUERADE
EOH
  end

end
