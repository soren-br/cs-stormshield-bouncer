# CS-STORMSHIELD-BOUNCER
## Requirements
To operate this bouncer, you must have:
- Python3
- A Stormshield firewall
- the following github repository in the same directory as the script : https://github.com/stormshield/python-SNS-API

## Step to be done on the firewall
- Create a group and report the name of the group in config.json
- Create a rule that blocks ip members of the previously created group 

## Run automatically
- Create this crontab : */5 * * * * /usr/bin/python3 /opt/cs-stormshield-bouncer/app.py >/dev/null 2>&1 for run every 5 minutes 
