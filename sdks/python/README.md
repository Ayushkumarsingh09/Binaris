# Binaris Python SDK

```python
from binaris import BinarisClient

client = BinarisClient.login("http://127.0.0.1:8080", "demo@binaris.dev", "demo-password-change-me")
projects = client.list_projects()
report = client.upload(projects[0]["id"], "sample.exe")
print(report["executive_summary"])
print(client.chat(report["id"], "Where is networking?")["message"]["content"])
```
