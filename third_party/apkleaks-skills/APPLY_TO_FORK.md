# Apply these changes to kingcobra-py/apkleaks-skills

This directory is a full snapshot of the fork with batch-scan enhancements.
The cloud agent could not push to `kingcobra-py/apkleaks-skills` (403), so the
work is shipped here for you to sync.

## What was added

1. `AWS_Secret_Access_Key` pattern in `config/regexes.json`
2. `tools/batch_scan.py` — threaded multi-APK scan + progress/status JSON
3. `tools/fdroid_download.py` — download N APKs from F-Droid (`-n 100`)
4. `tools/dashboard_server.py` — local status API on `:8787`
5. Website `/dashboard` page + preview image in `docs/dashboard-preview.png`

## Sync into your fork

```bash
git clone https://github.com/kingcobra-py/apkleaks-skills.git
cd apkleaks-skills
git checkout -b cursor/batch-scan-dashboard-93e0
# copy from this snapshot (adjust path)
rsync -a --exclude .git ../db/third_party/apkleaks-skills/ ./
git add -A
git commit -m "Add AWS secret detection, batch scan, F-Droid downloader, dashboard"
git push -u origin cursor/batch-scan-dashboard-93e0
```

## Quick start

```bash
cd third_party/apkleaks-skills
pip install -r requirements.txt
python3 tools/fdroid_download.py -n 100 -o apks
python3 tools/batch_scan.py -d apks -t 4 -o results
python3 tools/dashboard_server.py
# open website /dashboard (demo) or API http://127.0.0.1:8787/api/status
```
