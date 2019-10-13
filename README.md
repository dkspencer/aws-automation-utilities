# AWS Automation Utilities
## Automation tools designed to be ran in AWS Lambda.

These are a selection of AWS utilities I have written whilst in the workplace.
They were all designed for organisations with multiple AWS accounts, however,
they can probably be ran on single AWS accounts with a bit of tweaking (if any at all).

### Libraries
#### assume_role.py
Assumes a role in the given account using the account number and role name.

#### get_account_list.py
If accounts.py has been ran, there will exist a json file containing all account
ids, this will retrieve that list from an S3 bucket.

#### save_output.py
Saves the utility scripts output to a specified S3 bucket.

#### accounts.py
Gathers all of the accounts connected to an organisation and saves the list in S3.

#### credentials.py
Goes through all AWS accounts in the accounts list and downloads a generated credential report to S3.

#### elastic-ip.py
Gathers data related to Elastic IP addresses, security groups and network interfaces.

#### security-groups.py
Gathers ingress and egress rules for security groups in your accounts as well as
network acls.

NOTE: I'm not 100% sure these work, I don't have access to an AWS organisation with multiple accounts.
