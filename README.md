# pihole-sentinel

A simple Python script and cron task to push Pi-Hole's FTL query DB into Azure Sentinel.

## Setup

You will need:

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
echo 'AZURE_SHARED_KEY = "Mjc1ZjFlNTYyjBiY2U5YjJjOTI3MzJkMjRkNTM4NmU2MmRkNWQwODAzYWQ0NzIyNzM3YzkyN2VmNmZiNDNkNA=="' >> local_settings.py


```
