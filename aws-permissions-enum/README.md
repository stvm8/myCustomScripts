# aws_api_pull.py
This script will run though AWS services that are defined in a text file, then collect all api commands that does not require parameters.
For example: In IAM, the "list-users" does not need any additional param for execution, but "list-user-policies" will need "--user-name" param.

**Script sample: python aws_api_pull.py run --profile myprofile --services-file targeted_services.txt**

If you want more services, just add it into the targeted_services.txt or create a new text file.
By default, the script will save the result into aws_operations.json file, which can be used for aws_enum_permissions.py script

# aws_enum_permissions.py
This script is inspired by https://github.com/shabarkin/aws-enumerator
The purpose of this script is for early AWS services enumeration with a valid AWS key.

**Script sample: python aws_enum_permissions.py run --profile myprofile --operations-file targeted_operations.json**
