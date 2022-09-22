FROM ruby:2.6.0-alpine

RUN adduser -D prometheus

USER prometheus

WORKDIR /home/prometheus
RUN mkdir conf
RUN mkdir metrics
COPY --chown=prometheus exporter.rb ./
RUN gem install prometheus_exporter:2.0.3
RUN gem install net-ldap
CMD ["ruby","/home/prometheus/exporter.rb"]