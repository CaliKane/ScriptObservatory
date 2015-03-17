import json
import requests

BASE_URL = "https://scriptobservatory.org"

new_data = {"url": "www.google.com", "sha256": "hash_value_here"}

r = requests.post(BASE_URL + "/api/script", data=json.dumps(new_data), headers={"content-type": "application/json"})

print r.status_code, r.content

i = json.loads(r.content)['id']

r = requests.get(BASE_URL + '/api/script/%s' % i, headers={'content-type': 'application/json'})
print r.status_code, r.content


r = requests.get(BASE_URL + '/api/script', headers={'content-type': 'application/json'})
print r.status_code, r.content
