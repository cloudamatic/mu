FROM ruby:2.5-slim

RUN mkdir -p /opt/mu/etc/ /home/mu /usr/local/ruby-current/lib/ruby/gems/2.5.0/gems/var/

WORKDIR /home/mu

RUN apt-get update

RUN apt-get install -y ruby2.5-dev dnsutils ansible build-essential

RUN apt-get upgrade -y

COPY ./cloud-mu-*.gem /home/mu

RUN gem install ./cloud-mu-*.gem thin -N

RUN rm cloud-mu-*.gem

RUN apt-get remove -y build-essential ruby2.5-dev

RUN apt-get autoremove -y

EXPOSE 2260

CMD /usr/sbin/init
