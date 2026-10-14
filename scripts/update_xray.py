"""Select the newest upstream release tag and let Go resolve its immutable commit."""
import json
import re
import subprocess
import urllib.request

request = urllib.request.Request("https://api.github.com/repos/XTLS/Xray-core/tags?per_page=100", headers={"User-Agent": "X-Node-updater"})
tags = json.load(urllib.request.urlopen(request))
tag = max((t for t in tags if re.fullmatch(r"v\d+\.\d+\.\d+", t["name"])), key=lambda t: tuple(map(int, t["name"][1:].split("."))))
subprocess.run(["go", "get", "github.com/xtls/xray-core@" + tag["commit"]["sha"]], check=True)
subprocess.run(["go", "mod", "tidy"], check=True)
print(f"Selected {tag['name']} at {tag['commit']['sha']}")
