FROM centos:7

WORKDIR /root

COPY ./cloud-mu-*.gem /root

EXPOSE 2260

RUN yum install -y make gcc zlib-devel git
RUN rpm -iv https://s3.amazonaws.com/cloudamatic/muby-2.5.3-1.el7.x86_64.rpm
ENV PATH "$PATH:/usr/local/ruby-current/bin"
RUN yum install -y centos-release-scl-rh
RUN yum install -y rh-ruby25-ruby-devel gcc-c++
RUN gem update --system
RUN gem install ./cloud-mu-*.gem thin -N
RUM mkdir -p /opt/mu/etc/
RUN mkdir -p /usr/local/ruby-current/lib/ruby/gems/2.5.0/gems/var/
RUN rm cloud-mu-*.gem
RUN yum remove -y centos-release-scl-rh make gcc gcc-c++ zlib-devel
CMD /usr/sbin/init
