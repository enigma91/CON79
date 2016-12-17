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

coreo_aws_advisor_alert "get-active-security-groups-for-instances" do
  action :define
  service :ec2
  display_name "List of active security groups for instances"
  description "Gets all active security groupsfor instances"
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
  alerts ["get-security-groups", "get-active-security-groups-for-instances"]
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
  audit_objects ["load_balancer_descriptions.security_groups"]
  operators ["=~"]
  alert_when [//]
end

coreo_aws_advisor_elb "advise-elb" do
  action :advise
  alerts ["get-active-security-groups-from-elb"]
  regions ${AUDIT_AWS_ELB_REGIONS}
end

coreo_uni_util_jsrunner "security-groups" do
  action :run
  json_input '{
      "security_groups_report":COMPOSITE::coreo_aws_advisor_ec2.advise-ec2.report,
      "active_groups_report":COMPOSITE::coreo_aws_advisor_elb.advise-elb.report
  }'
  function <<-EOH
const result = {};
const activeSecurityGroups = [];
const unusedSecGroups = [];

const groupIsActive = (groupId) => {
  for (let activeGroupId of activeSecurityGroups) {
      if (activeGroupId === groupId) return true;
  }
  return false;
};

const getActiveSecGroup = (violationId) => {
  const violation = json_input.active_groups_report[key].violations[violationId];
  if (!violation) return;
  violation.violating_object.forEach((obj) => {
      obj.object.forEach((secGroup) => {
          activeSecurityGroups.push(secGroup);
      })
  });
};

Object.keys(json_input.active_groups_report).forEach((key) => {
    getActiveSecGroup('get-active-security-groups-from-elb');
});
Object.keys(json_input.security_groups_report).forEach((key) => {
    getActiveSecGroup('get-active-security-groups-for-instances');
});

Object.keys(json_input.security_groups_report).forEach((key) => {
    const violations = json_input.security_groups_report[key].violations["get-security-groups"];
    if (!violations) return;
    const tags = json_input.security_groups_report[key].tags;
    violations.violating_object.forEach((item) => {
        const currectSecGroup = item.object;
        if (groupIsActive(currectSecGroup.group_id)) return;

        unusedSecGroups.push(currectSecGroup);
        const notUsedSecurityGroupAlert = {
            violations:
            { 'not-used-sequrity-groups':
            {
                'display_name': 'Security group is not used',
                'description': 'Security group is not used anywhere',
                'category': 'Audit',
                'suggested_action': 'Remove this security group',
                'level': 'Warning',
                'region': violations.region
            }
            },
            tags: tags
        };
        result[key] = notUsedSecurityGroupAlert;
    });
});

console.log(result);
callback(result);
  EOH
end