# WebSET

Website Security Evaluation Tool. Desktop app for authorised lab targets.

The finding count below was recorded on this environment. Match it if you need the same result. A different DVWA image, Juice Shop commit, Node version, or Python version can change the count.

## Recorded test environment

| Piece | Exact version |
|---|---|
| WebSET Python | 3.12, from [python.org](https://www.python.org/downloads/). Not the Mac system Python. Not Anaconda / Miniconda. |
| DVWA | `ghcr.io/digininja/dvwa@sha256:ed35515e9111801e6e386a6fbb11165508cc7f72e0cb8da4dbb3df70182986c6` |
| DVWA database | `mariadb:10` |
| DVWA URL | `http://127.0.0.1:4280/` |
| DVWA security | Low, after **Create / Reset Database** |
| DVWA login | `admin` / `password` |
| Juice Shop | git `1618a611b173b4bf114028e6e02549950606e29d` ([commit](https://github.com/juice-shop/juice-shop/commit/1618a611b173b4bf114028e6e02549950606e29d)), `package.json` version 20.2.0. Not a Docker image. Not tag `v20.2.0`. |
| Juice Shop Node | `v24.20.0` |
| Juice Shop URL | `http://127.0.0.1:3000/` |
| Chrome | Current stable build. Required for Active Test and pages that need a browser. |

Recorded Start Scan counts on that environment: **21** findings for DVWA, **15** findings for Juice Shop.

## 1. Install Python, Node, and Chrome

- Python 3.12 from [python.org](https://www.python.org/downloads/). On Windows, tick **Add python.exe to PATH**.
- Node.js `v24.20.0` from [nodejs.org](https://nodejs.org/). Juice Shop was run with this version.
- Google Chrome, current stable build.
- Docker Desktop, for DVWA only. Leave it running.
- Git, for Juice Shop.

```bash
python3 --version
node -v
```

You want `Python 3.12` and `v24.20.0`. If `python3` is missing, try `python`.

## 2. Install WebSET

From the folder that contains `main.py`. Do this in a new virtual environment, not an existing Conda environment. Conda ships another Qt build, and mixing it with PyQt6 stops the window from opening.

**macOS / Linux**

```bash
cd /path/to/WebSET
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

**Windows (Command Prompt)**

```bat
cd C:\path\to\WebSET
py -3 -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The prompt should show `(.venv)`.

## 3. Start the local lab

The repo includes `lab_target`. It is a small site with known weaknesses, for **Start Scan** only. It listens on `127.0.0.1` and needs no extra packages. Do not deploy it, and do not scan anything you are not allowed to test.

From the WebSET folder:

```bash
cd lab_target
python app.py
```

On Windows, `py -3 app.py` works if `python` is not on PATH. Leave that window open. Open [http://127.0.0.1:5000/](http://127.0.0.1:5000/). You should see **Lab Target**.

In WebSET, Create Scan, set the URL to `http://127.0.0.1:5000/`, and press **Start Scan**. Do not press **Get Stack**. Stop the site with Ctrl+C.

These are the dynamic issues that page is built to show: missing security headers, a `session` cookie without `HttpOnly` and `SameSite`, reflected input and a SQL error on `/search?q=`, a sign-in form without an anti-CSRF token, a directory listing at `/files/`, a backup file linked from that listing, and an open redirect on `/redirect`. This target is separate from the DVWA and Juice Shop counts above.

**Static scan.** From the folder that contains `app.py`:

**macOS / Linux**

```bash
zip -r lab_target.zip app.py .env assets
```

**Windows (PowerShell)**

```powershell
Compress-Archive -Path app.py, .env, assets -DestinationPath lab_target.zip -Force
```

In WebSET, Create Scan, choose that ZIP, and press **Start Scan**. The ZIP must be made from this folder. `.env`, hard-coded secrets, `debug = True`, and the other planted lines in `app.py` and `assets/app.js` are there for the static scanner. The running pages do not call them.

Do not put `lab_target` under a path that contains `example`, `sample`, or `test`. The static scanner treats those paths as samples and lowers the result.

## 4. Start DVWA

In an empty folder, save this as `compose.yml`:

```yaml
volumes:
  dvwa:

networks:
  dvwa:

services:
  dvwa:
    image: ghcr.io/digininja/dvwa@sha256:ed35515e9111801e6e386a6fbb11165508cc7f72e0cb8da4dbb3df70182986c6
    environment:
      - DB_SERVER=db
    depends_on:
      - db
    networks:
      - dvwa
    ports:
      - 127.0.0.1:4280:80
    restart: unless-stopped

  db:
    image: docker.io/library/mariadb:10
    environment:
      - MYSQL_ROOT_PASSWORD=dvwa
      - MYSQL_DATABASE=dvwa
      - MYSQL_USER=dvwa
      - MYSQL_PASSWORD=p@ssw0rd
    volumes:
      - dvwa:/var/lib/mysql
    networks:
      - dvwa
    restart: unless-stopped
```

```bash
sudo docker compose up -d
```

Open [http://127.0.0.1:4280/setup.php](http://127.0.0.1:4280/setup.php) and click **Create / Reset Database**. Log in at [http://127.0.0.1:4280/login.php](http://127.0.0.1:4280/login.php) with `admin` / `password`. Open **DVWA Security**, set **Low**, and submit. Scan `http://127.0.0.1:4280/`.

After that scan, `admin` can log in with a blank password. DVWA at Low applies a password change when the two password fields are sent equal, including both empty. That is a vulnerability in the site, not a scanner fault. **Create / Reset Database** puts the password back to `password`.

## 5. Start Juice Shop

This checkout is source, not `bkimminich/juice-shop` on Docker Hub.

```bash
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop
git checkout 1618a611b173b4bf114028e6e02549950606e29d
```

On Node.js v24.20.0 this commit fails during `npm install` because the frontend SBOM step expects `dist/frontend/stats.json`. Change the production build so it does not run `npm run sbom`. The Juice Shop commit itself is not changed.

```bash
python3 - << 'PY'
from pathlib import Path
p = Path("frontend/package.json")
t = p.read_text()
for old in (
    "ng build --configuration production --stats-json && npm run sbom",
    "ng build --configuration production && npm run sbom",
):
    if old in t:
        p.write_text(t.replace(old, "ng build --configuration production", 1))
        print("patched", old)
        break
else:
    raise SystemExit("build script not found")
PY
npm install
npm start
```

Open [http://127.0.0.1:3000/](http://127.0.0.1:3000/) and scan that URL.

## 6. Start WebSET

From the WebSET folder, with the venv active:

```bash
python main.py
```

## If the finding count is short

The recorded counts are **21** for DVWA and **15** for Juice Shop. If you followed every step above and Start Scan still returns fewer findings, the machine is probably slower than the one used for that recording. Each probe has a short timeout, and each check stops when its time budget runs out, so later probes never run.

You do not need to change the code if the counts already match. If they do not, close WebSET and raise the numbers below. Leave the names as they are. Start WebSET again and scan the same URL.

`security_checks/injection_checks.py`

```python
_PROBE_TIMEOUT = 3.0
_INJECT_BUDGET_SEC = 20.0
```

`security_checks/dynamic_analyser.py`

```python
_SCAN_BUDGET_SEC = 25.0
```

`security_checks/generic_surface_checks.py`

```python
_PROBE_TIMEOUT = 3.0
_SURFACE_BUDGET_SEC = 12.0
```

Raise them and scan again. If the count is still short, raise the same numbers further. A slower machine needs a larger budget before the same findings appear.

## If setup fails

**`No module named PyQt6`:** the venv is not active. Run `source .venv/bin/activate` (Windows: `.venv\Scripts\activate`) and install `requirements.txt` again.

**macOS `Could not find the Qt platform plugin "cocoa"`:** you are on Conda or outside the venv. Run `conda deactivate` until the prompt is clean, delete `.venv`, and repeat section 2.

**Windows `python` is not recognised:** create the venv with `py -3 -m venv .venv`.

**Scan fails immediately:** the URL must start with `http://` or `https://` and must be able to open on this machine. `localhost` on another computer is not this machine.

**PDF export says ReportLab is missing:** `python -m pip install "reportlab>=4.0.9"`.
