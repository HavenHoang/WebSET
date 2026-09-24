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

## 3. Start DVWA

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
docker compose up -d
```

Open [http://127.0.0.1:4280/setup.php](http://127.0.0.1:4280/setup.php) and click **Create / Reset Database**. Log in at [http://127.0.0.1:4280/login.php](http://127.0.0.1:4280/login.php) with `admin` / `password`. Open **DVWA Security**, set **Low**, and submit. Scan `http://127.0.0.1:4280/`.

## 4. Start Juice Shop

This checkout is source, not `bkimminich/juice-shop` on Docker Hub.

```bash
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop
git checkout 1618a611b173b4bf114028e6e02549950606e29d
npm install
npm start
```

`git status --short` must print nothing. Open [http://127.0.0.1:3000/](http://127.0.0.1:3000/) and scan that URL.

## 5. Start WebSET

From the WebSET folder, with the venv active:

```bash
python main.py
```

## If setup fails

**`No module named PyQt6`:** the venv is not active. Run `source .venv/bin/activate` (Windows: `.venv\Scripts\activate`) and install `requirements.txt` again.

**macOS `Could not find the Qt platform plugin "cocoa"`:** you are on Conda or outside the venv. Run `conda deactivate` until the prompt is clean, delete `.venv`, and repeat section 2.

**Windows `python` is not recognised:** create the venv with `py -3 -m venv .venv`.

**Scan fails immediately:** the URL must start with `http://` or `https://` and must be open on this machine. `localhost` on another computer is not this machine.

**PDF export says ReportLab is missing:** `python -m pip install "reportlab>=4.0.9"`.
