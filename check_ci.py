import json
import urllib.request

with open('runs.json') as f:
    data = json.load(f)

for run in data.get('workflow_runs', []):
    if run['conclusion'] == 'failure':
        print(f"Failing Run: {run['name']} (ID: {run['id']})")
        jobs_url = run['jobs_url']
        req = urllib.request.Request(jobs_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            jobs_data = json.loads(response.read().decode())
            for job in jobs_data.get('jobs', []):
                if job['conclusion'] == 'failure':
                    print(f"  -> Failed Job: {job['name']} (ID: {job['id']})")
                    for step in job['steps']:
                        if step['conclusion'] == 'failure':
                            print(f"    -> Failed Step: {step['name']}")
