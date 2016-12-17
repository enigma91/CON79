coreo_aws_advisor_alert "get-security-groups" do
  action :define
  service :ec2
  display_name "List of security groups"
  description "Gets all security groups"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["security_groups"]
  audit_objects ["security_group_info.group_name"]
  operators ["=~"]
  alert_when [//]
end

coreo_aws_advisor_alert "get-active-security-groups" do
  action :define
  service :ec2
  display_name "List of active security groups"
  description "Gets all active security groups"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["spot_instance_requests"]
  audit_objects ["spot_instance_request_set.network_interface_set.security_group_id"]
  operators ["=~"]
  alert_when [//]
end

coreo_aws_advisor_ec2 "advise-ec2" do
  action :advise
  alerts ["get-security-groups", "get-active-security-groups"]
  regions ${AUDIT_AWS_ELB_REGIONS}
end


coreo_aws_advisor_alert "get-active-security-groups-from-elb" do
  action :define
  service :elb
  display_name "List of active security groups"
  description "Gets all active security groups"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["load_balancers"]
  audit_objects ["load_balancers.load_balancer_descriptions.security_groups"]
  operators ["=~"]
  alert_when [//]
end

coreo_aws_advisor_elb "advise-elb" do
  action :advise
  alerts ["get-active-security-groups-from-elb"]
  regions ${AUDIT_AWS_ELB_REGIONS}
end