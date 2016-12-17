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
  display_name "EC2 Instance Inventory"
  description "This rule performs an inventory on all EC2 instances in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Information"
  objectives ["instances"]
  audit_objects ["reservation_set.instances_set.group_set.group_id"]
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


const getActiveSecGroup = (violation) => {
  if (!violation) return;
  violation.violating_object.forEach((obj) => {
      obj.object.forEach((secGroup) => {
        if (secGroup.group_id) activeSecurityGroups.push(secGroup.group_id);
        else activeSecurityGroups.push(secGroup);
      })
  });
};

Object.keys(json_input.active_groups_report).forEach((key) => {
    getActiveSecGroup(json_input.active_groups_report[key].violations['get-active-security-groups-from-elb']);
});
Object.keys(json_input.security_groups_report).forEach((key) => {
    getActiveSecGroup(json_input.security_groups_report[key].violations['get-active-security-groups-for-instances']);
});



Object.keys(json_input.active_groups_report).forEach((key) => {
    const violation = json_input.active_groups_report[key].violations["get-active-security-groups-from-elb"];
    violation.violating_object.forEach((obj) => {
        obj.object.forEach((secGroup) => {
            activeSecurityGroups.push(secGroup);
        })
    });
});

Object.keys(json_input.security_groups_report).forEach((key) => {
    const tags = json_input.security_groups_report[key].tags;
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
            tags: tags
        };
        result[key] = notUsedSecurityGroupAlert;
    });
});

console.log(result);
callback(result);
  EOH
end