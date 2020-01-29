#!/usr/bin/env python3
#
# This script will look for secrets stored in AWS Secret Manger, 
# generate temporary STS credentials, and update a Terraform Cloud
# workspace environment variable. The AWS Secret is expected to contain
# the following keys:
#
# "AWS_ACCESS_KEY_ID"
# "AWS_SECRET_ACCESS_KEY"
# "TERRAFORM_WORKSPACE_PREFIX"
#
# TERRAFORM_WORKSPACE_PREFIX is a prefix string attached to the 
# workspaces that share the same API keys for authentication. 
# This is useful for workspaces that share the same account but serve
# multiple regions.
#
# The AWS Secret Name must be prefixed with a name, such as "terraform_auth"
# The remainder of the key name is arbitrary but suggested to be the AWS
# account number, e.g. 'terraform_auth/1234567890
#
# Set the region used by AWS Secrets Manager
region        = 'us-east-1'

# Set the prefix for all secrets to iterate over
secret_prefix = 'terraform_auth'

# Set the Terraform Cloud API Key secret name
tfc_key_name  = 'terraform_cloud_api'

# Set Terraform Cloud Organization Name 
tfc_organization = 'OrgName'

## End of Configuration ##

import boto3
import json
import requests
import sys
import logging


logger = logging.getLogger()
logger.setLevel(logging.INFO)

class TerraformOrganization:
    def __init__(self, organization_name, token):
        self.organization_name = organization_name
        self.token             = token
        self.headers           = { 'Authorization': f"Bearer {token}",
                                   'Content-Type': 'application/vnd.api+json'
                                }
        self.validate_org()

    # Validate the org to make sure it exists and the API key works for it. 
    def validate_org(self):
        logger.info(f"Verifying org {self.organization_name} is valid")
        response      = requests.get(
        f"https://app.terraform.io/api/v2/organizations/{self.organization_name}/",
        headers = self.headers
        )
            
        if response.status_code == 200:
            logger.info(f"Organization {self.organization_name} is valid")
        
        else:
            logger.error(f"Organization {self.organization_name} Not Found or API key invalid")
            sys.exit()

    # Return a list of workspaces for the given organization. 
    def get_workspaces(self):
        logger.info(f"Getting list of workspaces for {self.organization_name}")
        response      = requests.get(
        f"https://app.terraform.io/api/v2/organizations/{self.organization_name}/workspaces",
        headers = self.headers
        )
        workspaces = []
        if response.status_code == 200:
            for workspace in json.loads(response.content)['data']:
                workspaces.append(workspace['attributes']['name'])
            return workspaces
        
        else:
            logger.error(f"Unable to get workspaces for {self.organization_name}")
            sys.exit()

class TerraformWorkspace: 
    def __init__(self, workspace_name, organization_name, token): 
        self.workspace_name    = workspace_name
        self.organization_name = organization_name
        self.token             = token
        self.headers           = { 'Authorization': f"Bearer {token}",
                                    'Content-Type': 'application/vnd.api+json'
                                }
        self.workspace_id      = self.id()

    # Get workspace ID
    def id(self):
        logger.info(f"Getting workspace ID for {self.workspace_name}")
        response      = requests.get(
        f"https://app.terraform.io/api/v2/organizations/{self.organization_name}/workspaces/{self.workspace_name}",
        headers = self.headers
        )
            
        if response.status_code == 200:
            logger.info(f"Workspace ID is {json.loads(response.content)['data']['id']}")
            return(json.loads(response.content)['data']['id'])
        
        elif response.status_code == 404:
            logger.error(f"Workspace {self.workspace_name} Not Found")

    # Create environment variable
    def create_var(self, var_key, var_value):
        logger.info(f"Creating new variable {var_key}")
        payload =  {
            "data": {
                "type"      : "vars",
                "attributes": {
                    "key"      : var_key,
                    "value"    : var_value,
                    "category" : "env",
                    "hcl"      : "false",
                    "sensitive": "true"
                },
                "relationships": {
                    "workspace": {
                        "data": {
                            "id"  : self.workspace_id,
                            "type": "workspaces"
                        }
                    }
                }
            }
        }    

        # Try to create a new variable
        try:
            response = requests.post(
            'https://app.terraform.io/api/v2/vars',
            json    = payload,
            headers = self.headers
            )
            if response.status_code == 200:
                logger.info(f"New variable {var_key} created")
            response.raise_for_status()

        # If the variable exists, get the variable ID and then update in place
        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 422:
                logger.info("Variable exists, attempting to update in place")
                self.update_var(var_key, var_value, self.var_id(var_key))
        
    # Get variable ID
    def var_id(self, var_key): 
        params = {
            "filter[organization][name]": {self.organization_name},
            "filter[workspace][name]"   : {self.workspace_name}
        } 

        response = requests.get(
            'https://app.terraform.io/api/v2/vars',
            params  = params,
            headers = self.headers
        )

        # Find ID of variable by key name
        key = [var for var in response.json()['data'] if var['attributes']['key'] == var_key]
        logger.info(f"Variable {var_key} ID is {key[0]['id']}")
        return key[0]['id']

    # Update variable in place
    def update_var(self, var_key, var_value, var_id):
        payload = {
            "data": {
                "id"        : var_id,
                "attributes": {
                    "key"      : var_key,
                    "value"    : var_value,
                    "category" : "env",
                    "hcl"      : "false",
                    "sensitive": "true"
                },
                "type": "vars"
            }
        }

        response = requests.patch(
        f"https://app.terraform.io/api/v2/vars/{var_id}",
        json    = payload,
        headers = self.headers,
        )
        if response.status_code == 200:
            logger.info(f"Updated variable {var_key} in place")
        else:
            logger.error(response.status_code)


def list_secrets(region, prefix): 
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client  = session.client(
        service_name = 'secretsmanager',
        region_name  = region
    )
    # Get a list of all secrets in this region
    list_secrets_response = client.list_secrets()
    # Filter for a specific prefix in the secret. (i.e. prefix/secret_name)
    secrets_list = [secret for secret in list_secrets_response['SecretList'] if secret['Name'].startswith(prefix)]
    return secrets_list
       
def get_secret(name, region): 
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client  = session.client(
        service_name = 'secretsmanager',
        region_name  = region
    )

    get_secret_value_response = client.get_secret_value(
        SecretId = name
    )
    # AWS returns SecretString as a string literal, convert to json.
    return json.loads(get_secret_value_response['SecretString'])


def get_sts_credentials(region, key): 
    # Create an STS client
    session = boto3.session.Session()
    client  = session.client(
        service_name          = 'sts',
        region_name           = region,
        aws_access_key_id     = key['AWS_ACCESS_KEY_ID'],
        aws_secret_access_key = key['AWS_SECRET_ACCESS_KEY']
    )
    sts_token = client.get_session_token()
    logger.info(f"Fetching STS credentials using key ID {key['AWS_ACCESS_KEY_ID']}")
    return sts_token

def test_sts_credentials(region, key, secret, token): 
    # Create an STS client
    logger.info(f"Testing STS credentials")
    session = boto3.session.Session()
    client  = session.client(
        service_name          = 'sts',
        region_name           = region,
        aws_access_key_id     = key,
        aws_secret_access_key = secret,
        aws_session_token     = token
    )
    caller = client.get_caller_identity()
    logger.info(f"STS caller identity is {caller['Arn']}")
    return caller['ResponseMetadata']['HTTPStatusCode']

def main():
    # Instantiate organization
    organization = TerraformOrganization(
        tfc_organization,
        get_secret(
                tfc_key_name, 
                region)['api_key'])

    ws_list = organization.get_workspaces()

    # For every secret in AWS SM with the specified prefix...
    for secret in list_secrets(region, secret_prefix):
        # Get the workspaces the secret should be applied to
        logger.info(f" -- Processing secret {secret['Name']}")
        ws_prefix = get_secret(
            secret['Name'], 
            region)['TERRAFORM_WORKSPACE_PREFIX']
        logger.info(f"Workspace prefix is {ws_prefix}")

       # Set the workspaces which match the AWS SM prefix
        workspaces = [i for i in ws_list if i.startswith(ws_prefix)]
        logger.info(f"Attempting to update credentials for workspaces {workspaces}")

        # Instantiate workspace
        for workspace in workspaces:
            logger.info(f"Processing workspace {workspace}")
            workspace = TerraformWorkspace(
                workspace, 
                tfc_organization, 
                get_secret(
                    tfc_key_name, 
                    region)['api_key'])

            # Fetch STS Credentials
            sts_credentials = get_sts_credentials(
                region,
                get_secret(
                    secret['Name'],
                    region)
                    )['Credentials']

            # Test STS Credentials to ensure they work
            sts_test = test_sts_credentials(
                        region,
                        sts_credentials['AccessKeyId'],
                        sts_credentials['SecretAccessKey'],
                        sts_credentials['SessionToken'])
            
            if sts_test == 200:
                # Create variables
                workspace.create_var(
                    "AWS_ACCESS_KEY_ID", sts_credentials['AccessKeyId'])
                workspace.create_var(
                    "AWS_SECRET_ACCESS_KEY", sts_credentials['SecretAccessKey'])
                workspace.create_var(
                    "AWS_SESSION_TOKEN", sts_credentials['SessionToken'])
            else:
                logger.error(f"STS Credentials Invalid")


def lambda_handler(event, context):
    main()

if __name__ == '__main__':
    logging.basicConfig()
    main()
