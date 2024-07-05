# ec2_instances_list

This script list all ec2 instances in all of your aws organizations accounts you have access to

It Opens web browser and authorize to boto3 generate access_token, then reads all aws accounts you have access, call ecs api "describe_instances" and "describe_instance_information", then export result to a csv file

change global vars:
start_url = your SSO start URI  
region = AWS Region  
accepted_roles = SSO role names
