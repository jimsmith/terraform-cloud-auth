# terraform-cloud-auth

This script will look for secrets stored in AWS Secret Manger, and update 
a Terraform Cloud workspace environment variable. 

The AWS Secret is expected to contain the following keys:

AWS_ACCESS_KEY_ID

AWS_SECRET_ACCESS_KEY

TERRAFORM_WORKSPACE_PREFIX


TERRAFORM_WORKSPACE_PREFIX is a prefix string attached to the 
workspaces that share the same API keys for authentication. 
This is useful for workspaces that share the same account but serve
multiple regions.

The AWS Secret Name must be prefixed with a name, such as "terraform_auth"
The remainder of the key name is arbitrary but suggested to be the AWS
account number, e.g. 'terraform_auth/1234567890
