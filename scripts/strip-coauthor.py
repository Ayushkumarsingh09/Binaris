import sys

text = sys.stdin.read()
out = []
for line in text.splitlines():
    lower = line.lower().strip()
    if lower.startswith("co-authored-by:"):
        continue
    if "cursoragent@cursor.com" in lower:
        continue
    out.append(line)
sys.stdout.write("\n".join(out).rstrip() + "\n")
