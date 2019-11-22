FROM ruby:2.5-slim

WORKDIR /root

COPY ./cloud-mu-*.gem /root

EXPOSE 2260

RUN mkdir -p /opt/mu/etc/
RUN mkdir -p /usr/local/ruby-current/lib/ruby/gems/2.5.0/gems/var/
RUN apt-get install -y build-essential ruby2.5-dev g++ dnsutils ansible
RUN apt-get update
RUN gem install ./cloud-mu-*.gem thin -N
RUN rm cloud-mu-*.gem
RUN apt-get remove -y make g++ build-essential
CMD /usr/sbin/init
