import re
conf_path = '/var/ossec/etc/ossec.conf'
with open(conf_path, 'r') as f:
    content = f.read()

block = '''
  <!-- ML Alert Classifier Integration -->
  <integration>
    <name>custom-ml-predict</name>
    <rule_id>31101,31103,31104,31105,31106,31151,100112,100113</rule_id>
    <alert_format>json</alert_format>
  </integration>
'''

if 'custom-ml-predict' not in content:
    content = content.replace('</ossec_config>', block + '\n</ossec_config>')
    with open(conf_path, 'w') as f:
        f.write(content)
    print('Integration block inserted.')
else:
    print('Integration block already exists.')
