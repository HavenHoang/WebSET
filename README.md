# WebSET

Website Security Evaluation Tool. Desktop app for authorised lab targets such as DVWA or OWASP Juice Shop.

Python 3.10, 3.11, or 3.12. Do not use the Mac system Python, and do not install these packages into an existing Anaconda / Miniconda environment. Conda already ships another Qt build, and mixing it with PyQt6 is the usual cause of a window that never opens.

## 1. Install Python and Chrome

- Python 3.10 or newer from [python.org](https://www.python.org/downloads/). During the Windows install, tick **Add python.exe to PATH**.
- Google Chrome, current stable build. Active Test and some script-heavy pages open Chrome through Selenium. The scan still runs with `requests` if Chrome is missing, but those pages will not render.

Check the interpreter before continuing:

```bash
python3 --version
```

You want `Python 3.10`, `3.11`, or `3.12`. If the command is missing, try `python --version`. Use whichever command prints 3.10 or newer in the steps below.

## 2. Install dependencies

From the folder that contains `main.py`:

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

The prompt should show `(.venv)`. If a later command says `No module named PyQt6`, the venv is not active. Run the `source` or `activate` line again.

## 3. Start the app

Still inside the project folder, with the venv active:

```bash
python main.py
```

The first launch creates `webset.db` in this folder. That file is local history. It is gitignored. Do not delete it if you want to keep cases.

On the login screen, choose a username and a password of at least 4 characters, click **Register**, then **Login**. There is no default account.

## 4. Start the same DVWA and Juice Shop

Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) and leave it running. Use these two labs, not an older DVWA image such as `vulnerables/web-dvwa`. A different image produces a different finding count.

**DVWA** is the official image pinned to the build this project was checked against:

`ghcr.io/digininja/dvwa@sha256:ed35515e9111801e6e386a6fbb11165508cc7f72e0cb8da4dbb3df70182986c6`

Source and package pages: [github.com/digininja/DVWA](https://github.com/digininja/DVWA), [ghcr.io/digininja/dvwa](https://github.com/digininja/DVWA/pkgs/container/dvwa).

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

From that folder:

```bash
docker compose up -d
```

Then open [http://127.0.0.1:4280/setup.php](http://127.0.0.1:4280/setup.php) and click **Create / Reset Database**. Log in at [http://127.0.0.1:4280/login.php](http://127.0.0.1:4280/login.php) with `admin` / `password`. Open **DVWA Security**, set it to **Low**, and submit. Scan `http://127.0.0.1:4280/`.

**Juice Shop** is the current official image:

```bash
docker pull bkimminich/juice-shop
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```

Open [http://127.0.0.1:3000/](http://127.0.0.1:3000/). Image page: [hub.docker.com/r/bkimminich/juice-shop](https://hub.docker.com/r/bkimminich/juice-shop). Scan `http://127.0.0.1:3000/`.

Stop them with:

```bash
docker compose down
docker stop juice-shop
```

`docker compose down` does not delete the DVWA database volume. Add `-v` only if you want a fresh database.

## 5. First scan

1. Open **Create Scan**.
2. Enter an application / case name.
3. Enter a full target URL, including `http://` or `https://`. Example: `http://127.0.0.1:4280/`.
4. **Get Stack** detects technologies. It does not fill Alerts.
5. **Start Scan** runs the security checks. Findings appear on **Alerts**.
6. On a finding that supports it, **Active Test** sends the checks for that parameter.
7. **Report** then **Export PDF** writes the assessment. PDF export needs the `reportlab` package from `requirements.txt`.

Only scan systems you are allowed to test.

## If it does not start

**`No module named PyQt6` / `requests` / `reportlab`**

The venv is not active, or pip installed into another Python. From the project folder:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

On Windows, activate with `.venv\Scripts\activate` instead of `source`.

**macOS: `Could not find the Qt platform plugin "cocoa"`**

You are not using the venv, or PyQt6 was installed into Conda. Close Conda (`conda deactivate` until the prompt is clean), delete `.venv`, and repeat section 2. Then:

```bash
python -c "from PyQt6.QtWidgets import QApplication; print('qt ok')"
python main.py
```

**Windows: `python` is not recognised**

Use `py -3` instead of `python3` when creating the venv. After activate, `python` is the venv interpreter.

**The window opens, then a scan fails immediately**

The URL must be reachable from this machine and must start with `http://` or `https://`. A lab app on another computer is not reachable as `localhost`.

**PDF export says ReportLab is missing**

```bash
python -m pip install "reportlab>=4.0.9"
```

**Chrome / Selenium errors during a scan**

Install or update Google Chrome, then:

```bash
python -m pip install "selenium>=4.15.0"
```

Selenium 4 downloads a matching driver on its own. You do not install ChromeDriver by hand.

**Broken history or a database error after an update**

Quit the app, rename `webset.db` to `webset.db.bak`, and start again. Register a new user. This drops local cases only.
