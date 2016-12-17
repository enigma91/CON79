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

coreo_aws_advisor_ec2 "advise-ec2" do
  action :advise
  alerts ["get-security-groups"]
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
  json_input '{
      "security_groups_report":"STACK::coreo_aws_advisor_ec2.advise-ec2.report",
      "active_groups_report": "STACK::coreo_aws_advisor_elb.advise-elb.report",
      "composite name":"PLAN::stack_name",
      "plan name":"PLAN::name",
      "number_of_checks":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2.number_checks"
  }'
  function <<-EOH
const result = {};
result['composite name'] = json_input['composite name'];
result['plan name'] = json_input['plan name'];
result['number_of_checks'] = json_input['number_of_checks'];
result['violations'] = {};

const activeSecurityGroups = [];
const unusedSecGroups = [];

const groupIsActive = (groupId) => {
    for (let activeGroupId of activeSecurityGroups) {
        if (activeGroupId === groupId) return true;
    }
    return false;
};


Object.keys(json_input.active_groups_report).forEach((key) => {
    const violation = json_input.active_groups_report[key].violations["get-active-security-groups-from-elb"];
    violation.violating_object.forEach((obj) => {
        obj.object.forEach((secGroup) => {
            activeSecurityGroups.push(secGroup);
        })
    });
});

Object.keys(json_input.security_groups_report).forEach((key) => {
    const violations = json_input.security_groups_report[key].violations["get-security-groups"];
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
            tags: []
        };
        result[key] = notUsedSecurityGroupAlert;
    });
});

console.log(unusedSecGroups);
console.log(result);
callback(result);
  EOH
end