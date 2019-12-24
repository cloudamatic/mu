- name: elb
  tags:
    - key: Env
      value: <%= env %>
    - key: Application
      value: <%= myAppName %>
  vpc:
    name: parsemess
    subnet_pref: all_public
  idle_timeout: 360
  connection_draining_timeout: 60
  cross_zone_unstickiness: false
  lb_cookie_stickiness_policy:
    name: <%= myAppName %>
    timeout: 86400
  healthcheck:
    target: <%= $healthcheck_target.nil? ? "HTTP:80/" : $healthcheck_target %>
    timeout: 40
    interval: 60
    unhealthy-threshold: 2
    healthy-threshold: 2
<% if $environment != "dev" %>
  access_log:
    enabled: true
    s3_bucket_name: dts-elb-logs
    emit_interval: 5
    s3_bucket_prefix: <%= myAppName %>
<% end %>
  listeners:
  - lb-port: 80
    lb-protocol: HTTP
    instance-port: 8081
    instance-protocol: HTTP
#  - lb-port: 443
#    lb-protocol: HTTPS
#    instance-port: <%= $https_backend_port.nil? ? 80 : $https_backend_port %>
#    instance-protocol: <%= $elb_backend_proto.nil? ? "HTTP" : $elb_backend_proto %>
#    ssl_certificate_name: "*.<%= dnsbase %>"
  ingress_rules:
  - port: 80
    hosts:
    - 0.0.0.0/0
  - port: 443
    hosts:
    - 0.0.0.0/0
  alarms:
  - comparison_operator: "GreaterThanThreshold"
    metric_name: "HTTPCode_ELB_5XX_Count"
    evaluation_periods: 1
    name: "HTTP_500_Count"
    period: 60
    statistic: "Sum"
    threshold: 10
    enable_notifications: true
    notification_endpoint: 'egt.gcp.sandbox@gmail.com'
<% if $environment == "prod" %>
    notification_group: 'slack-notifications'
<% end %>
    namespace: "AWS/ApplicationELB"
  - comparison_operator: "GreaterThanThreshold"
    metric_name: "HTTPCode_Target_5XX_Count"
    evaluation_periods: 1
    name: "HTTP_Target_500_Count"
    period: 60
    statistic: "Sum"
    threshold: 10
    enable_notifications: true
    notification_endpoint: 'egt.gcp.sandbox@gmail.com'
<% if $environment == "prod" %>
    notification_group: 'slack-notifications'
<% end %>
    namespace: "AWS/ApplicationELB"
