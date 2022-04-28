# pihole-sentinel

A simple Python script and cron task to push Pi-Hole's FTL query log into Azure Sentinel.

It copies the FTL database to /tmp (otherwise Pi-Hole can stop writing while read operations are in progress), and transforms the queries to Azure Sentinel Information Model [(ASIM)](https://docs.microsoft.com/en-us/azure/sentinel/dns-normalization-schema). Processed logs appear in the `Normalized_CL` table in the Log Analytics workspace.

There's also an example Analytic rule, which creates an incident when Failures occur (for example, if you use Quad9, it'll return NXDOMAIN for blocked domains).



## Setup

You will need:

- To run the below as the pihole user (or whatever user pihole runs as)
- A working Sentinel instance
- the Workspace ID and Secret Key that your Sentinel instance is attached to

```bash

cd /opt
git clone https://github.com/jlaundry/pihole-sentinel.git
cd pihole-sentinel
python3 -m venv .env
source .env/bin/activate
pip install -r requirements.txt
echo 'AZURE_WORKSPACE_ID = "cb0af8dc-e731-4e0e-8578-a439aebcec18"' > local_settings.py
echo 'AZURE_SECRET_KEY = "Mjc1ZjFlNTYyjBiY2U5YjJjOTI3MzJkMjRkNTM4NmU2MmRkNWQwODAzYWQ0NzIyNzM3YzkyN2VmNmZiNDNkNA=="' >> local_settings.py

touch /var/log/pihole-sentinel.log
chown pihole:pihole /var/log/pihole-sentinel.log

echo '* * * * * pihole /opt/pihole-sentinel/cron.sh >> /var/log/pihole-sentinel.log 2>&1' > /etc/cron.d/pihole-sentinel

```

Deployment template for the Analytic rule: 

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw%2Egithubusercontent%2Ecom%2Fjlaundry%2Fpihole%2Dsentinel%2Fmain%2FAzure%5FSentinel%5Fanalytic%5Frule%2Ejson)
