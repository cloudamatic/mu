<% if $environment == "prod" %>
  scale_in_protection: initial
  notifications:
    topic: <%= $topic %>
  scaling_policies:
  - name: ALBRequestCountPerTarget
    policy_type: TargetTrackingScaling
    estimated_instance_warmup: <%= $estimated_instance_warmup %>
    target_tracking_configuration:
      target_value: <%= $target_value %>
      preferred_target_group: elbhttps443
      predefined_metric_specification: ALBRequestCountPerTarget
<% end %>
