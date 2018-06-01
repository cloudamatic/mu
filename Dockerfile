FROM centos:7

EXPOSE 80

RUN yum update -y
RUN yum install wget git ssh -y
RUN wget https://raw.githubusercontent.com/cloudamatic/mu/master/install/installer
RUN chmod +x installer
RUN ./installer -n -m docker@cloudamatic.com