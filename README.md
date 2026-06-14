# pihole-sentinel

A simple Python script and cron task to push Pi-Hole's FTL query log into Azure Sentinel.

The script originally used the old Data Collector API, writing to the `Normalized_CL` table, and has been rewritten to use the newer Log Ingestion API. It transforms the queries to Azure Sentinel Information Model [(ASIM)](https://docs.microsoft.com/en-us/azure/sentinel/dns-normalization-schema). Processed logs appear in the `ASimDnsActivityLogs` table in the Log Analytics workspace.

There's also an example Analytic rule, which creates an incident when Failures occur (for example, if you use Quad9, it'll return NXDOMAIN for blocked domains).

## Setup

First, you will need to configure the Azure environment:

1. The new Log Ingestion API requires using a service principal - workspace keys are no longer supported. Decide if you're going to use an App Registration with Client ID and Secret, or Managed Identity. I strongly recommend using Managed Identity, and the Azure Arc agent can be installed on arm64 devices.
2. Deploy the DCR template: [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw%2Egithubusercontent%2Ecom%2Fjlaundry%2Fpihole%2Dsentinel%2Fmain%2FData%5FCollection%5FRule%2Ejson)
3. Once the DCR has been deployed, copy the *Immutable ID* and *Data Collection Endpoint* values, and assign the **Monitoring Metrics Publisher** role to the service principal.
4. Install the script (below)
5. Configure the `DATA_COLLECTION_ENDPOINT` and `LOGS_DCR_RULE_ID` environment variables in the `cron.sh` script. If you are using a Managed Identity, no further configuration should be required; if using a Client ID and Secret, configure them here too.
6. (optionally) deploy the Analytic rule to alert on failures.

```bash
sudo mkdir /opt/pihole-sentinel
sudo chown pihole:pihole /opt/pihole-sentinel

# If you are using Azure Arc, add the pihole user to the HIMDS group:
sudo usermod -aG himds pihole

sudo su - pihole
cd /opt/pihole-sentinel
git clone https://github.com/jlaundry/pihole-sentinel.git .
python3 -m venv .env
source .env/bin/activate
pip install -r requirements.txt

touch /var/log/pihole-sentinel.log
chown pihole:pihole /var/log/pihole-sentinel.log

echo '* * * * * pihole /opt/pihole-sentinel/cron.sh >> /var/log/pihole-sentinel.log 2>&1' | sudo tee /etc/cron.d/pihole-sentinel
```

Deployment template for the Analytic rule: 

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw%2Egithubusercontent%2Ecom%2Fjlaundry%2Fpihole%2Dsentinel%2Fmain%2FAzure%5FSentinel%5Fanalytic%5Frule%2Ejson)
