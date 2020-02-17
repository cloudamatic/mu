FROM ruby:2.5-slim

RUN mkdir -p /opt/mu/etc/ /home/mu /usr/local/ruby-current/lib/ruby/gems/2.5.0/gems/var/

WORKDIR /home/mu

RUN df -h

RUN apt-get update

RUN apt-get install -y ruby2.5-dev dnsutils ansible build-essential

RUN apt-get upgrade -y

RUN df -h

COPY ./cloud-mu-*.gem /home/mu

RUN gem install ./cloud-mu-*.gem -N

RUN df -h

RUN ls -la

#RUN rm --verbose -f cloud-mu-*.gem

RUN apt-get remove -y build-essential ruby2.5-dev

RUN apt-get autoremove -y

EXPOSE 2260

CMD /usr/sbin/init
