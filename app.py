import hmac
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from fractions import Fraction
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["DATABASE"] = os.environ.get(
    "DATABASE", os.path.join(app.root_path, "econ_sim.db")
)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def load_secret_key():
    """Use SECRET_KEY if set, otherwise create a random key once and keep it in a file.

    Sign-ins are signed with this key, so it must never be a value others could guess.
    """
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    path = os.path.join(app.root_path, "secret.key")
    try:
        with open(path) as f:
            return f.read().strip()
    except FileNotFoundError:
        pass
    key = secrets.token_hex(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key)
    except OSError:
        pass  # read-only folder: sign-ins last until the app restarts
    return key


app.config["SECRET_KEY"] = load_secret_key()

INDUSTRIES = {
    "automobile": "Automobile",
    "computer": "Computer",
}

# --------------------------------------------------------------------------
# Simulation settings: change the numbers here, nothing else needs to move.
# --------------------------------------------------------------------------
STARTING_BUDGET = 1_000_000          # cash every company starts year 1 with
NEW_LINE_COST = 100_000              # one-time cost to start a product line the company didn't make last year
INDUSTRY_SWITCH_FEE = 500_000        # one-time cost to move to the other industry

# Total fixed cost (TFC) for each product line a company produces, every year.
FIXED_COST_PER_LINE = {
    "automobile": 500_000,
    "computer": 300_000,
}

PRODUCTS = {
    "automobile": {
        "sedan": {"label": "Sedan", "unit_cost": 5_000},
        "minivan": {"label": "Mini-van", "unit_cost": 8_000},
        "suv": {"label": "SUV", "unit_cost": 10_000},
    },
    "computer": {
        "tablet": {"label": "Tablet", "unit_cost": 100},
        "desktop": {"label": "Desktop", "unit_cost": 200},
        "notebook": {"label": "Notebook", "unit_cost": 500},
    },
}
PRODUCT_LABELS = {
    key: info["label"] for group in PRODUCTS.values() for key, info in group.items()
}
ALL_PRODUCT_KEYS = list(PRODUCT_LABELS)
PRODUCT_ORDER = {key: i for i, key in enumerate(ALL_PRODUCT_KEYS)}

# Demand equations: price per unit P = base + slope / Q, where Q is the total
# number of units of that product produced by all companies combined.
# Each company earns P for every unit it produced.
DEMAND = {
    "sedan": (4_000, 20_000_000),
    "minivan": (7_000, 10_000_000),
    "suv": (9_000, 20_000_000),
    "tablet": (80, 10_000_000),
    "desktop": (120, 40_000_000),
    "notebook": (400, 20_000_000),
}

# Password the professor types to advance the year. Set a real one with the
# PROFESSOR_PASSWORD environment variable before using this in class.
PROFESSOR_PASSWORD = os.environ.get("PROFESSOR_PASSWORD", "password")

# Mergers: from this year on, companies in the top half of their industry (ranked
# by cash) must merge with a company in the bottom half.
MERGER_START_YEAR = 4

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
MAX_MEMBERS = 8
MAX_NAME_LENGTH = 80
MAX_DIGITS = 12

SCHEMA_VERSION = 3


@app.template_filter("money")
def money(value):
    return "${:,}".format(int(value))


@app.template_filter("dollars")
def dollars(cents):
    """Format an amount stored in cents, e.g. 204000 -> $2,040.00 (negatives get a minus sign)."""
    cents = int(cents)
    sign = "-" if cents < 0 else ""
    cents = abs(cents)
    return f"{sign}${cents // 100:,}.{cents % 100:02d}"


def other_industry(industry):
    return next(key for key in INDUSTRIES if key != industry)


# --------------------------------------------------------------------------
# Database helpers
# --------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@contextmanager
def write_txn(db):
    """Run a group of writes as one all-or-nothing step."""
    db.execute("BEGIN IMMEDIATE")
    try:
        yield
        db.commit()
    except Exception:
        db.rollback()
        raise


# --------------------------------------------------------------------------
# Signing in: one shared password per company, plus the professor
# --------------------------------------------------------------------------
def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = session["csrf_token"] = secrets.token_urlsafe(32)
    return token


def csrf_field():
    return Markup('<input type="hidden" name="csrf_token" value="{}">').format(get_csrf_token())


@app.before_request
def check_csrf():
    """Every form submission must carry the token from the page it came from."""
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
            abort(400, "This page is out of date. Go back, reload it, and try again.")


def get_active_company(db, company_id):
    """The company row, following merges to the company that now carries on."""
    row = db.execute("SELECT * FROM companies WHERE id = ?", (company_id,)).fetchone()
    hops = 0
    while row is not None and row["merged_into"] is not None and hops < 50:
        row = db.execute(
            "SELECT * FROM companies WHERE id = ?", (row["merged_into"],)
        ).fetchone()
        hops += 1
    return row


def current_company():
    if "_company" not in g:
        company_id = session.get("company_id")
        g._company = get_active_company(get_db(), company_id) if company_id else None
    return g._company


def is_professor():
    return bool(session.get("professor"))


@app.context_processor
def inject_account():
    return {
        "me": current_company(),
        "is_professor": is_professor(),
        "csrf_field": csrf_field,
        "merger_start_year": MERGER_START_YEAR,
    }


def sign_in(company_id=None, professor=False):
    session.clear()  # a fresh session also means a fresh form token
    if professor:
        session["professor"] = True
    else:
        session["company_id"] = company_id
    g.pop("_company", None)


def safe_next(value):
    """Only follow `next` links that stay on this site."""
    if (
        value
        and value.startswith("/")
        and not value.startswith("//")
        and "\\" not in value
        and "\n" not in value
        and "\r" not in value
    ):
        return value
    return None


def login_redirect():
    target = None
    if request.method == "GET":
        target = request.full_path if request.query_string else request.path
    return redirect(url_for("login", next=target))


def company_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if current_company() is None:
            flash("Sign in with your company to continue.")
            return login_redirect()
        return view(*args, **kwargs)

    return wrapper


def professor_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not is_professor():
            flash("Sign in as the professor to continue.")
            return login_redirect()
        return view(*args, **kwargs)

    return wrapper


def family_ids(db, company_id):
    """A company plus every company that has been merged into it, directly or not."""
    rows = db.execute(
        "WITH RECURSIVE fam(id) AS ("
        "  SELECT ? UNION ALL "
        "  SELECT c.id FROM companies c JOIN fam ON c.merged_into = fam.id"
        ") SELECT id FROM fam",
        (company_id,),
    )
    return [r[0] for r in rows]


def password_matches(db, company_id, password):
    """A merged company can be entered with the password of either original group."""
    ids = family_ids(db, company_id)
    hashes = db.execute(
        f"SELECT password_hash FROM companies WHERE id IN ({','.join('?' * len(ids))})", ids
    )
    return any(
        row["password_hash"] and check_password_hash(row["password_hash"], password)
        for row in hashes
    )


SCHEMA = """
CREATE TABLE IF NOT EXISTS companies (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT NOT NULL,
    -- industry at the start of the current year (changes only when a year ends)
    industry       TEXT NOT NULL CHECK (industry IN ('automobile', 'computer')),
    -- industry in this year's production plan (differs when switching)
    plan_industry  TEXT NOT NULL CHECK (plan_industry IN ('automobile', 'computer')),
    created_at     TEXT NOT NULL,
    joined_year    INTEGER NOT NULL,
    -- money the company can spend this year, in cents
    cash_cents     INTEGER NOT NULL,
    -- one-time industry switch fee in this year's plan, in whole dollars
    switch_fee     INTEGER NOT NULL DEFAULT 0,
    -- the group's sign-in password (hashed)
    password_hash  TEXT NOT NULL DEFAULT '',
    -- set when this company was absorbed in a merger (it no longer operates)
    merged_into    INTEGER REFERENCES companies (id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_company_name
    ON companies (name COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS members (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id  INTEGER NOT NULL REFERENCES companies (id) ON DELETE CASCADE,
    name        TEXT NOT NULL
);

-- Each company's production plan for the current year (whole dollars).
-- tc = tvc + tfc + onetime
CREATE TABLE IF NOT EXISTS products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id  INTEGER NOT NULL REFERENCES companies (id) ON DELETE CASCADE,
    product     TEXT NOT NULL,
    units       INTEGER NOT NULL,
    tvc         INTEGER NOT NULL,
    tfc         INTEGER NOT NULL,
    onetime     INTEGER NOT NULL DEFAULT 0,
    tc          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS simulation (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    current_year  INTEGER NOT NULL
);
INSERT OR IGNORE INTO simulation (id, current_year) VALUES (1, 1);

-- One row per company per product per finished year (money in cents).
CREATE TABLE IF NOT EXISTS results (
    year           INTEGER NOT NULL,
    company_id     INTEGER NOT NULL REFERENCES companies (id) ON DELETE CASCADE,
    product        TEXT NOT NULL,
    units          INTEGER NOT NULL,
    price_cents    INTEGER NOT NULL,
    revenue_cents  INTEGER NOT NULL,
    tc_cents       INTEGER NOT NULL,
    PRIMARY KEY (year, company_id, product)
);

-- One row per company per finished year (money in cents).
-- end_cents = start_cents - cost_cents + income_cents, and becomes next year's cash.
CREATE TABLE IF NOT EXISTS company_results (
    year          INTEGER NOT NULL,
    company_id    INTEGER NOT NULL REFERENCES companies (id) ON DELETE CASCADE,
    industry      TEXT NOT NULL,
    start_cents   INTEGER NOT NULL,
    income_cents  INTEGER NOT NULL,
    cost_cents    INTEGER NOT NULL,
    end_cents     INTEGER NOT NULL,
    PRIMARY KEY (year, company_id)
);

-- Merger proposals. survivor = the higher-ranked company (keeps its name),
-- absorbed = the lower-ranked company. An agreed merger takes effect when the year ends.
CREATE TABLE IF NOT EXISTS mergers (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    year         INTEGER NOT NULL,
    survivor_id  INTEGER NOT NULL REFERENCES companies (id),
    absorbed_id  INTEGER NOT NULL REFERENCES companies (id),
    proposed_by  INTEGER NOT NULL REFERENCES companies (id),
    status       TEXT NOT NULL CHECK (status IN
                     ('pending', 'agreed', 'declined', 'cancelled', 'completed')),
    created_at   TEXT NOT NULL
);
-- A company can only have one agreed merger at a time.
CREATE UNIQUE INDEX IF NOT EXISTS idx_agreed_survivor
    ON mergers (survivor_id) WHERE status = 'agreed';
CREATE UNIQUE INDEX IF NOT EXISTS idx_agreed_absorbed
    ON mergers (absorbed_id) WHERE status = 'agreed';

-- Market-wide supply and resulting price per product for each finished year.
CREATE TABLE IF NOT EXISTS market_prices (
    year         INTEGER NOT NULL,
    product      TEXT NOT NULL,
    total_units  INTEGER NOT NULL,
    price_cents  INTEGER NOT NULL,
    PRIMARY KEY (year, product)
);
"""


def init_db():
    path = app.config["DATABASE"]

    # An older layout can't be upgraded in place, so set it aside instead of deleting it.
    if os.path.exists(path):
        con = sqlite3.connect(path)
        version = con.execute("PRAGMA user_version").fetchone()[0]
        has_tables = con.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'"
        ).fetchone()[0]
        con.close()
        if has_tables and version < 2:
            backup = f"{path}.old-layout-backup"
            if os.path.exists(backup):
                backup += "-" + datetime.now().strftime("%Y%m%d%H%M%S")
            os.replace(path, backup)
            print(f"The database layout changed. Your old data was moved to {backup}")

    db = sqlite3.connect(path)
    db.executescript(SCHEMA)

    # Upgrade a version-2 database in place: companies gain a password and a merge link.
    # Existing companies start with no password; the professor sets one for them.
    columns = {row[1] for row in db.execute("PRAGMA table_info(companies)")}
    if "password_hash" not in columns:
        db.execute("ALTER TABLE companies ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''")
    if "merged_into" not in columns:
        db.execute("ALTER TABLE companies ADD COLUMN merged_into INTEGER REFERENCES companies (id)")

    db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    db.commit()
    db.close()


# --------------------------------------------------------------------------
# Form parsing and validation
# --------------------------------------------------------------------------
def parse_whole_number(raw):
    """Return an int, None for a blank field, or raise ValueError.

    Accepts things students naturally type, like "$1,200,000".
    """
    text = (raw or "").strip().replace("$", "").replace(",", "").replace(" ", "")
    if not text:
        return None
    if not re.fullmatch(r"[0-9]{1,%d}" % MAX_DIGITS, text):
        raise ValueError(raw)
    return int(text)


def blank_form():
    return {
        "company": "",
        "industry": "",
        "members": [""],
        "units": {k: "" for k in ALL_PRODUCT_KEYS},
        "tvc": {k: "" for k in ALL_PRODUCT_KEYS},
        "onetime": {k: "" for k in ALL_PRODUCT_KEYS},
        "tc": {k: "" for k in ALL_PRODUCT_KEYS},
        "total_tc": "",
        "switch": False,
        "switch_fee": "",
        "password": "",
        "password_confirm": "",
    }


def read_form(source):
    """Collect the raw submitted values so they can be shown again on error."""
    return {
        "company": source.get("company", "").strip(),
        "industry": source.get("industry", ""),
        "members": [m.strip() for m in source.getlist("member") if m.strip()] or [""],
        "units": {k: source.get(f"units_{k}", "") for k in ALL_PRODUCT_KEYS},
        "tvc": {k: source.get(f"tvc_{k}", "") for k in ALL_PRODUCT_KEYS},
        "onetime": {k: source.get(f"onetime_{k}", "") for k in ALL_PRODUCT_KEYS},
        "tc": {k: source.get(f"tc_{k}", "") for k in ALL_PRODUCT_KEYS},
        "total_tc": source.get("total_tc", ""),
        "switch": source.get("switch") == "1",
        "switch_fee": source.get("switch_fee", ""),
        "password": source.get("password", ""),
        "password_confirm": source.get("password_confirm", ""),
    }


def check_production(form, industry, budget_cents, budget_text, prior_products=None, switching=False):
    """Validate the products and costs, which registration and yearly plans share.

    prior_products is None at registration (no one-time costs apply). For a yearly
    plan it is the set of products the company made last year: any product not in
    it is a new line and carries NEW_LINE_COST.

    Returns (lines, errors). `lines` holds the verified numbers; the budget error,
    if any, comes first in `errors`.
    """
    planning = prior_products is not None
    errors = []
    lines = []
    units_problem = False
    tfc = FIXED_COST_PER_LINE[industry]

    for key, info in PRODUCTS[industry].items():
        label = info["label"]
        try:
            units = parse_whole_number(form["units"].get(key, ""))
        except ValueError:
            errors.append(f"{label}: units must be a whole number, 0 or more.")
            units_problem = True
            continue
        if not units:  # blank or 0 means the company isn't making this product
            continue

        one_time = NEW_LINE_COST if planning and key not in prior_products else 0
        true_tvc = units * info["unit_cost"]
        true_tc = true_tvc + tfc + one_time

        checks = [("tvc", true_tvc, "TVC", True)]
        if planning:
            # Only required when the product is new; blank means $0 otherwise.
            checks.append(("onetime", one_time, "one-time cost", one_time > 0))
        checks.append(("tc", true_tc, "TC", True))

        for field, expected, name, required in checks:
            try:
                entered = parse_whole_number(form[field].get(key, ""))
            except ValueError:
                errors.append(f"{label}: enter the {name} as a whole number of dollars.")
                continue
            if entered is None:
                if required:
                    errors.append(f"{label}: enter the {name}.")
            elif entered != expected:
                errors.append(
                    f"{label}: the {name} you entered isn't correct. Recheck your calculation."
                )

        lines.append(
            {
                "key": key,
                "units": units,
                "tvc": true_tvc,
                "tfc": tfc,
                "onetime": one_time,
                "tc": true_tc,
            }
        )

    if not lines and not units_problem:
        errors.append("Enter the number of units for at least one product.")

    switch_fee = INDUSTRY_SWITCH_FEE if switching else 0
    if switching:
        try:
            entered_fee = parse_whole_number(form["switch_fee"])
        except ValueError:
            errors.append("Enter the industry switch fee as a whole number of dollars.")
        else:
            if entered_fee is None:
                errors.append("Enter the industry switch fee.")
            elif entered_fee != switch_fee:
                errors.append("The industry switch fee you entered isn't correct.")

    true_total = sum(line["tc"] for line in lines) + switch_fee

    if lines:
        try:
            entered_total = parse_whole_number(form["total_tc"])
        except ValueError:
            errors.append("Enter the company's total cost (TC) as a whole number of dollars.")
        else:
            if entered_total is None:
                errors.append("Enter the company's total cost (TC).")
            elif entered_total != true_total:
                hint = "Add up the TC of each product line"
                if switching:
                    hint += " and include the industry switch fee"
                errors.append(
                    f"The company total cost (TC) you entered isn't correct. {hint}."
                )

    # The budget check uses what the plan actually costs, not what was typed in.
    if true_total * 100 > budget_cents:
        errors.insert(
            0,
            f"Your company spent too much. Total cost can't be more than {budget_text}. "
            "Reduce production and try again.",
        )

    return lines, errors


def validate_registration(form):
    errors = []
    members = [m for m in form["members"] if m]
    company = form["company"]
    industry = form["industry"]

    if not members:
        errors.append("Add at least one group member.")
    if len(members) > MAX_MEMBERS:
        errors.append(f"A group can have at most {MAX_MEMBERS} members.")
    if any(len(m) > MAX_NAME_LENGTH for m in members):
        errors.append(f"Member names must be {MAX_NAME_LENGTH} characters or fewer.")
    if len({m.lower() for m in members}) != len(members):
        errors.append("Each member should be listed only once.")
    if not company:
        errors.append("Enter a company name.")
    elif len(company) > MAX_NAME_LENGTH:
        errors.append(f"The company name must be {MAX_NAME_LENGTH} characters or fewer.")
    password = form["password"]
    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Choose a password of at least {MIN_PASSWORD_LENGTH} characters.")
    elif len(password) > MAX_PASSWORD_LENGTH:
        errors.append(f"The password can be at most {MAX_PASSWORD_LENGTH} characters.")
    elif password != form["password_confirm"]:
        errors.append("The two passwords don't match.")
    if industry not in INDUSTRIES:
        errors.append("Choose a starting industry.")
        return [], errors

    lines, product_errors = check_production(
        form,
        industry,
        STARTING_BUDGET * 100,
        f"the {money(STARTING_BUDGET)} starting budget",
    )
    return lines, errors + product_errors


def validate_plan(form, company, prior_products):
    """Validate a yearly production plan. Returns (industry, lines, errors)."""
    switching = form["switch"]
    industry = other_industry(company["industry"]) if switching else company["industry"]
    lines, errors = check_production(
        form,
        industry,
        company["cash_cents"],
        f"your starting amount of {dollars(company['cash_cents'])}",
        prior_products=prior_products,
        switching=switching,
    )
    return industry, lines, errors


# --------------------------------------------------------------------------
# Mergers
# --------------------------------------------------------------------------
def rankings(db):
    """Rank every active company by cash within its industry.

    The top half (rounded down) must merge with a company in the bottom half.
    Ties are broken in favor of the company that registered first.
    """
    groups = {}
    for r in db.execute(
        "SELECT id, name, industry, plan_industry, cash_cents FROM companies "
        "WHERE merged_into IS NULL"
    ):
        groups.setdefault(r["industry"], []).append(r)

    ranked = {}
    for industry, group in groups.items():
        group.sort(key=lambda r: (-r["cash_cents"], r["id"]))
        top = len(group) // 2
        for position, r in enumerate(group, 1):
            ranked[r["id"]] = {
                "id": r["id"],
                "name": r["name"],
                "industry": industry,
                "cash_cents": r["cash_cents"],
                "rank": position,
                "of": len(group),
                "side": "top" if position <= top else "bottom",
                "switching": r["plan_industry"] != industry,
            }
    return ranked


def agreed_merger(db, company_id):
    return db.execute(
        "SELECT * FROM mergers WHERE status = 'agreed' AND (survivor_id = ? OR absorbed_id = ?)",
        (company_id, company_id),
    ).fetchone()


def merge_blocker(db, ranking, a_id, b_id, year):
    """Why these two companies can't merge right now, or None if they can."""
    if year < MERGER_START_YEAR:
        return f"Mergers begin in year {MERGER_START_YEAR}."
    a, b = ranking.get(a_id), ranking.get(b_id)
    if a is None or b is None:
        return "That company isn't available to merge."
    if a_id == b_id:
        return "A company can't merge with itself."
    if a["industry"] != b["industry"]:
        return "Companies can only merge with a company in the same industry."
    if a["side"] == b["side"]:
        return (
            "A company in the top half can only merge with a company in the bottom half, "
            "and the other way around."
        )
    for company in (a, b):
        if company["switching"]:
            return f"{company['name']} is switching industries this year, so it can't merge."
    for company in (a, b):
        if agreed_merger(db, company["id"]):
            return f"{company['name']} has already agreed to a merger this year."
    return None


def merge_options(db, ranking, company_id, year):
    """Ids of companies this company could propose a merger to right now."""
    waiting = {
        frozenset((m["survivor_id"], m["absorbed_id"]))
        for m in db.execute(
            "SELECT survivor_id, absorbed_id FROM mergers WHERE status = 'pending' AND year = ?",
            (year,),
        )
    }
    return {
        other
        for other in ranking
        if frozenset((company_id, other)) not in waiting
        and merge_blocker(db, ranking, company_id, other, year) is None
    }


def load_mergers(db, where="", params=()):
    return db.execute(
        "SELECT m.*, s.name AS survivor_name, a.name AS absorbed_name "
        "FROM mergers m "
        "JOIN companies s ON s.id = m.survivor_id "
        "JOIN companies a ON a.id = m.absorbed_id "
        f"{where} ORDER BY m.id",
        params,
    ).fetchall()


def unmerged_top_half(db, year):
    """Top-half companies that haven't agreed to a merger yet (empty before the start year)."""
    if year < MERGER_START_YEAR:
        return []
    committed = set()
    for m in db.execute("SELECT survivor_id, absorbed_id FROM mergers WHERE status = 'agreed'"):
        committed.update((m[0], m[1]))
    return sorted(
        (r for r in rankings(db).values() if r["side"] == "top" and r["id"] not in committed),
        key=lambda r: r["name"].lower(),
    )


def complete_mergers(db):
    """Carry out every agreed merger. Runs right after a year's results are in.

    The higher-ranked company keeps its name and takes over the other's cash,
    members and production. Where both made the same product the units are added
    together and the product line's fixed cost is paid once.
    """
    for m in db.execute("SELECT * FROM mergers WHERE status = 'agreed' ORDER BY id").fetchall():
        s = db.execute("SELECT * FROM companies WHERE id = ?", (m["survivor_id"],)).fetchone()
        t = db.execute("SELECT * FROM companies WHERE id = ?", (m["absorbed_id"],)).fetchone()
        if (
            s["merged_into"] is not None
            or t["merged_into"] is not None
            or s["industry"] != t["industry"]
        ):
            db.execute("UPDATE mergers SET status = 'cancelled' WHERE id = ?", (m["id"],))
            continue

        industry = s["industry"]
        tfc = FIXED_COST_PER_LINE[industry]
        units = {}
        for row in db.execute(
            "SELECT product, units FROM products WHERE company_id IN (?, ?) ORDER BY id",
            (s["id"], t["id"]),
        ):
            units[row["product"]] = units.get(row["product"], 0) + row["units"]
        db.execute("DELETE FROM products WHERE company_id IN (?, ?)", (s["id"], t["id"]))

        combined_cash = s["cash_cents"] + t["cash_cents"]
        lines = []
        for product, count in units.items():
            tvc = count * PRODUCTS[industry][product]["unit_cost"]
            lines.append((s["id"], product, count, tvc, tfc, 0, tvc + tfc))
        repeat_cost = sum(line[3] + line[4] for line in lines) * 100
        if repeat_cost <= combined_cash:
            db.executemany(
                "INSERT INTO products (company_id, product, units, tvc, tfc, onetime, tc) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                lines,
            )

        db.execute("UPDATE members SET company_id = ? WHERE company_id = ?", (s["id"], t["id"]))
        db.execute("UPDATE companies SET cash_cents = ? WHERE id = ?", (combined_cash, s["id"]))
        db.execute(
            "UPDATE companies SET merged_into = ?, cash_cents = 0, switch_fee = 0 WHERE id = ?",
            (s["id"], t["id"]),
        )
        db.execute("UPDATE mergers SET status = 'completed' WHERE id = ?", (m["id"],))


# --------------------------------------------------------------------------
# Yearly results
# --------------------------------------------------------------------------
def get_current_year(db):
    return db.execute("SELECT current_year FROM simulation WHERE id = 1").fetchone()[0]


def to_cents(amount):
    """Round a Fraction of dollars to whole cents (halves round up)."""
    return int((amount * 100 + Fraction(1, 2)) // 1)


def close_year(db, year):
    """Work out market prices, every company's income, and next year's cash.

    Must be called inside a transaction; it only writes rows.
    """
    totals = {
        row["product"]: row["total"]
        for row in db.execute(
            "SELECT product, SUM(units) AS total FROM products GROUP BY product"
        )
    }

    prices = {}
    for product, quantity in totals.items():
        base, slope = DEMAND[product]
        prices[product] = Fraction(base) + Fraction(slope, quantity)
        db.execute(
            "INSERT INTO market_prices (year, product, total_units, price_cents) "
            "VALUES (?, ?, ?, ?)",
            (year, product, quantity, to_cents(prices[product])),
        )

    lines_by_company = {}
    for row in db.execute(
        "SELECT company_id, product, units, tvc, tfc, tc FROM products ORDER BY id"
    ):
        lines_by_company.setdefault(row["company_id"], []).append(row)

    for company in db.execute(
        "SELECT id, plan_industry, cash_cents, switch_fee FROM companies"
    ).fetchall():
        lines = lines_by_company.get(company["id"])
        if not lines:
            continue  # produced nothing this year, so cash doesn't change

        income = 0
        cost = company["switch_fee"] * 100
        for line in lines:
            price = prices[line["product"]]
            revenue = to_cents(line["units"] * price)
            income += revenue
            cost += line["tc"] * 100
            db.execute(
                "INSERT INTO results (year, company_id, product, units, price_cents, "
                "revenue_cents, tc_cents) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    year,
                    company["id"],
                    line["product"],
                    line["units"],
                    to_cents(price),
                    revenue,
                    line["tc"] * 100,
                ),
            )

        start = company["cash_cents"]
        end = start - cost + income
        db.execute(
            "INSERT INTO company_results (year, company_id, industry, start_cents, "
            "income_cents, cost_cents, end_cents) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (year, company["id"], company["plan_industry"], start, income, cost, end),
        )

        # Next year repeats this plan (without one-time costs) unless the company
        # changes it, but only if it can afford to. Otherwise it makes nothing
        # until it submits a new plan.
        repeat_cost = sum(line["tvc"] + line["tfc"] for line in lines) * 100
        if repeat_cost <= end:
            db.execute(
                "UPDATE products SET onetime = 0, tc = tvc + tfc WHERE company_id = ?",
                (company["id"],),
            )
        else:
            db.execute("DELETE FROM products WHERE company_id = ?", (company["id"],))

        db.execute(
            "UPDATE companies SET industry = plan_industry, cash_cents = ?, switch_fee = 0 "
            "WHERE id = ?",
            (end, company["id"]),
        )


def advance_year(db, year):
    """Finish `year` and start the next one. Returns False if it was already advanced."""
    try:
        db.execute("BEGIN IMMEDIATE")
        if get_current_year(db) != year:
            db.rollback()
            return False
        close_year(db, year)
        complete_mergers(db)
        # Rankings change with the new cash, so unanswered proposals start over.
        db.execute("UPDATE mergers SET status = 'cancelled' WHERE status = 'pending'")
        db.execute("UPDATE simulation SET current_year = ? WHERE id = 1", (year + 1,))
        db.commit()
        return True
    except Exception:
        db.rollback()
        raise


def save_plan(db, company_id, year, industry, lines, switching):
    """Replace a company's plan for `year`. Returns False if the year has moved on."""
    try:
        db.execute("BEGIN IMMEDIATE")
        if get_current_year(db) != year:
            db.rollback()
            return False
        db.execute("DELETE FROM products WHERE company_id = ?", (company_id,))
        db.executemany(
            "INSERT INTO products (company_id, product, units, tvc, tfc, onetime, tc) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (company_id, l["key"], l["units"], l["tvc"], l["tfc"], l["onetime"], l["tc"])
                for l in lines
            ],
        )
        db.execute(
            "UPDATE companies SET plan_industry = ?, switch_fee = ? WHERE id = ?",
            (industry, INDUSTRY_SWITCH_FEE if switching else 0, company_id),
        )
        db.commit()
        return True
    except Exception:
        db.rollback()
        raise


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def register():
    form = blank_form()
    errors = []

    if request.method == "POST":
        form = read_form(request.form)
        lines, errors = validate_registration(form)

        if not errors:
            db = get_db()
            password_hash = generate_password_hash(form["password"])
            try:
                db.execute("BEGIN IMMEDIATE")
                cur = db.execute(
                    "INSERT INTO companies (name, industry, plan_industry, created_at, "
                    "joined_year, cash_cents, password_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        form["company"],
                        form["industry"],
                        form["industry"],
                        datetime.now(timezone.utc).isoformat(),
                        get_current_year(db),
                        STARTING_BUDGET * 100,
                        password_hash,
                    ),
                )
                company_id = cur.lastrowid
                db.executemany(
                    "INSERT INTO members (company_id, name) VALUES (?, ?)",
                    [(company_id, m) for m in form["members"]],
                )
                db.executemany(
                    "INSERT INTO products (company_id, product, units, tvc, tfc, onetime, tc) "
                    "VALUES (?, ?, ?, ?, ?, 0, ?)",
                    [
                        (company_id, l["key"], l["units"], l["tvc"], l["tfc"], l["tc"])
                        for l in lines
                    ],
                )
                db.commit()
            except sqlite3.IntegrityError:
                db.rollback()
                errors.append(
                    f"A company named “{form['company']}” is already registered. "
                    "Pick a different name."
                )
            except Exception:
                db.rollback()
                raise
            else:
                sign_in(company_id=company_id)
                flash(f"{form['company']} is registered and signed in.")
                return redirect(url_for("companies", new=company_id))

    return render_template(
        "register.html",
        form=form,
        errors=errors,
        industries=INDUSTRIES,
        all_products=PRODUCTS,
        fixed_costs=FIXED_COST_PER_LINE,
        budget=STARTING_BUDGET,
        min_password=MIN_PASSWORD_LENGTH,
        max_members=MAX_MEMBERS,
        max_length=MAX_NAME_LENGTH,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    db = get_db()
    next_url = safe_next(request.values.get("next"))
    selected = request.form.get("who", "")
    error = None
    status = 200

    if request.method == "POST":
        password = request.form.get("password", "")[:MAX_PASSWORD_LENGTH]
        signed_in = False
        if selected == "professor":
            if hmac.compare_digest(password.encode(), PROFESSOR_PASSWORD.encode()):
                sign_in(professor=True)
                signed_in = True
        elif selected.isdigit():
            company = get_active_company(db, int(selected))
            if company is not None and password_matches(db, company["id"], password):
                sign_in(company_id=company["id"])
                signed_in = True
        if signed_in:
            flash("You're signed in.")
            return redirect(next_url or url_for("companies"))
        error = "That password isn't correct."
        status = 403

    choices = db.execute(
        "SELECT id, name FROM companies WHERE merged_into IS NULL ORDER BY name COLLATE NOCASE"
    ).fetchall()
    return (
        render_template("login.html", choices=choices, selected=selected, error=error, next_url=next_url),
        status,
    )


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You're signed out.")
    return redirect(url_for("companies"))


@app.route("/plan")
@company_required
def plan_index():
    """Send a signed-in company to its own plan page (or explain why it can't plan yet)."""
    db = get_db()
    year = get_current_year(db)
    me = current_company()
    if year > 1 and me["joined_year"] < year:
        return redirect(url_for("plan", company_id=me["id"]))
    return render_template("plan_index.html", year=year, company=me)


@app.route("/plan/<int:company_id>", methods=["GET", "POST"])
@company_required
def plan(company_id):
    db = get_db()
    year = get_current_year(db)
    company = current_company()
    if company["id"] != company_id:
        flash(f"You're signed in as {company['name']}, so you can only plan its production.")
        return redirect(url_for("plan", company_id=company["id"]))
    if company["joined_year"] >= year:
        flash(
            f"{company['name']} registered this year, so its production is already set. "
            "Planning opens next year."
        )
        return redirect(url_for("plan_index"))

    # What the company (including any company merged into it) made last year.
    family = family_ids(db, company_id)
    prior = [
        {"key": r["product"], "label": PRODUCT_LABELS[r["product"]], "units": r["units"]}
        for r in db.execute(
            "SELECT product, SUM(units) AS units FROM results "
            f"WHERE year = ? AND company_id IN ({','.join('?' * len(family))}) "
            "GROUP BY product ORDER BY MIN(rowid)",
            [year - 1, *family],
        )
    ]
    prior_products = {p["key"] for p in prior}

    form = blank_form()
    errors = []

    if request.method == "POST":
        form = read_form(request.form)
        if request.form.get("year", type=int) != year:
            flash("The year changed before you submitted. Check the new numbers and submit again.")
            return redirect(url_for("plan", company_id=company_id))

        industry, lines, errors = validate_plan(form, company, prior_products)
        if form["switch"] and agreed_merger(db, company_id):
            errors.insert(
                0, "You've agreed to a merger this year, so you can't switch industries."
            )
        if not errors:
            if save_plan(db, company_id, year, industry, lines, form["switch"]):
                flash(f"Year {year} plan saved for {company['name']}.")
            else:
                flash("The year changed before you submitted. Check the new numbers and submit again.")
            return redirect(url_for("companies"))

    current = [
        {"label": PRODUCT_LABELS[r["product"]], "units": r["units"]}
        for r in db.execute(
            "SELECT product, units FROM products WHERE company_id = ? ORDER BY id",
            (company_id,),
        )
    ]
    baseline = company["industry"]
    return render_template(
        "plan.html",
        year=year,
        company=company,
        form=form,
        errors=errors,
        prior=prior,
        current=current,
        industries=INDUSTRIES,
        baseline=baseline,
        other=other_industry(baseline),
        all_products=PRODUCTS,
        fixed_costs=FIXED_COST_PER_LINE,
        new_line_cost=NEW_LINE_COST,
        switch_fee=INDUSTRY_SWITCH_FEE,
    )


def incoming_proposals(db, company_id, year):
    return [
        m
        for m in load_mergers(db, "WHERE m.status = 'pending' AND m.year = ?", (year,))
        if company_id in (m["survivor_id"], m["absorbed_id"]) and m["proposed_by"] != company_id
    ]


@app.route("/companies")
def companies():
    db = get_db()
    year = get_current_year(db)
    last_year = year - 1 if year > 1 else None
    me = current_company()

    company_rows = db.execute(
        "SELECT id, name, industry, plan_industry, joined_year, switch_fee FROM companies "
        "WHERE merged_into IS NULL ORDER BY created_at DESC, id DESC"
    ).fetchall()

    members_by_company = {}
    for m in db.execute("SELECT company_id, name FROM members ORDER BY id"):
        members_by_company.setdefault(m["company_id"], []).append(m["name"])

    products_by_company = {}
    for p in db.execute(
        "SELECT company_id, product, units, tc FROM products ORDER BY id"
    ):
        products_by_company.setdefault(p["company_id"], []).append(
            {
                "label": PRODUCT_LABELS.get(p["product"], p["product"]),
                "units": p["units"],
                "tc": p["tc"],
            }
        )

    # Results for the most recently finished year, if there is one.
    results_by_company = {}
    merged_by_company = {}
    market = []
    if last_year:
        for r in db.execute(
            "SELECT company_id, start_cents, income_cents, cost_cents, end_cents "
            "FROM company_results WHERE year = ?",
            (last_year,),
        ):
            results_by_company[r["company_id"]] = {
                "start": r["start_cents"],
                "income": r["income_cents"],
                "cost": r["cost_cents"],
                "profit": r["income_cents"] - r["cost_cents"],
                "left": r["end_cents"],
            }
        for m in load_mergers(db, "WHERE m.status = 'completed' AND m.year = ?", (last_year,)):
            merged_by_company.setdefault(m["survivor_id"], []).append(m["absorbed_name"])
        market = sorted(
            (
                {
                    "key": m["product"],
                    "label": PRODUCT_LABELS.get(m["product"], m["product"]),
                    "units": m["total_units"],
                    "price_cents": m["price_cents"],
                }
                for m in db.execute(
                    "SELECT product, total_units, price_cents FROM market_prices WHERE year = ?",
                    (last_year,),
                )
            ),
            key=lambda m: PRODUCT_ORDER.get(m["key"], 99),
        )

    # Merger standing, once mergers have started.
    started = year >= MERGER_START_YEAR
    ranking = rankings(db) if started else {}
    options = merge_options(db, ranking, me["id"], year) if (started and me) else set()
    agreed_with = {}
    if started:
        for m in load_mergers(db, "WHERE m.status = 'agreed'"):
            agreed_with[m["survivor_id"]] = m["absorbed_name"]
            agreed_with[m["absorbed_id"]] = m["survivor_name"]
    waiting_for_me = len(incoming_proposals(db, me["id"], year)) if (started and me) else 0

    teams = []
    for r in company_rows:
        products = products_by_company.get(r["id"], [])
        standing = ranking.get(r["id"])
        is_me = me is not None and me["id"] == r["id"]
        teams.append(
            {
                "id": r["id"],
                "name": r["name"],
                "industry": r["plan_industry"],
                "industry_label": INDUSTRIES[r["plan_industry"]],
                "switching_from": (
                    INDUSTRIES[r["industry"]] if r["industry"] != r["plan_industry"] else None
                ),
                "members": members_by_company.get(r["id"], []),
                "products": products,
                "total_cost": sum(p["tc"] for p in products) + r["switch_fee"],
                "results": results_by_company.get(r["id"]),
                "merged_with": merged_by_company.get(r["id"], []),
                "standing": standing,
                "agreed_with": agreed_with.get(r["id"]),
                "can_propose": r["id"] in options,
                "is_me": is_me,
                "can_plan": is_me and r["joined_year"] < year,
            }
        )

    return render_template(
        "companies.html",
        teams=teams,
        year=year,
        last_year=last_year,
        market=market,
        started=started,
        waiting_for_me=waiting_for_me,
        new_id=request.args.get("new", type=int),
        counts={k: sum(1 for t in teams if t["industry"] == k) for k in INDUSTRIES},
    )


# ---- mergers ----
@app.route("/mergers")
def mergers():
    db = get_db()
    year = get_current_year(db)
    me = current_company()
    started = year >= MERGER_START_YEAR
    ranking = rankings(db) if started else {}

    open_mergers = load_mergers(
        db, "WHERE m.status IN ('pending', 'agreed') AND m.year = ?", (year,)
    )
    agreed_with = {}
    for m in open_mergers:
        if m["status"] == "agreed":
            agreed_with[m["survivor_id"]] = m["absorbed_name"]
            agreed_with[m["absorbed_id"]] = m["survivor_name"]

    tables = []
    for key, label in INDUSTRIES.items():
        entries = sorted(
            (r for r in ranking.values() if r["industry"] == key), key=lambda r: r["rank"]
        )
        if entries:
            tables.append({"label": label, "entries": entries})

    mine = None
    if me is not None and started:
        standing = ranking.get(me["id"])
        options = merge_options(db, ranking, me["id"], year)
        mine = {
            "standing": standing,
            "agreed": [m for m in open_mergers if m["status"] == "agreed"
                       and me["id"] in (m["survivor_id"], m["absorbed_id"])],
            "incoming": incoming_proposals(db, me["id"], year),
            "outgoing": [m for m in open_mergers if m["status"] == "pending"
                         and m["proposed_by"] == me["id"]],
            "candidates": sorted(
                (ranking[o] for o in options), key=lambda r: (r["industry"], r["rank"])
            ),
        }

    completed = list(reversed(load_mergers(db, "WHERE m.status = 'completed'")))
    return render_template(
        "mergers.html",
        year=year,
        started=started,
        start_year=MERGER_START_YEAR,
        mine=mine,
        tables=tables,
        agreed_with=agreed_with,
        completed=completed,
        industries=INDUSTRIES,
    )


@app.route("/mergers/propose", methods=["POST"])
@company_required
def propose_merger():
    db = get_db()
    me = current_company()
    other_id = request.form.get("other", type=int)
    with write_txn(db):
        year = get_current_year(db)
        ranking = rankings(db)
        error = merge_blocker(db, ranking, me["id"], other_id, year)
        if error is None:
            mine, theirs = ranking[me["id"]], ranking[other_id]
            survivor, absorbed = (mine, theirs) if mine["side"] == "top" else (theirs, mine)
            duplicate = db.execute(
                "SELECT 1 FROM mergers WHERE status = 'pending' AND year = ? "
                "AND survivor_id = ? AND absorbed_id = ?",
                (year, survivor["id"], absorbed["id"]),
            ).fetchone()
            if duplicate:
                error = f"A proposal between {me['name']} and {theirs['name']} is already waiting."
        if error is None:
            db.execute(
                "INSERT INTO mergers (year, survivor_id, absorbed_id, proposed_by, status, created_at) "
                "VALUES (?, ?, ?, ?, 'pending', ?)",
                (year, survivor["id"], absorbed["id"], me["id"],
                 datetime.now(timezone.utc).isoformat()),
            )
    if error:
        flash(error)
    else:
        flash(f"Proposal sent to {theirs['name']}. The merger happens only if they accept.")
    return redirect(url_for("mergers"))


@app.route("/mergers/<int:merger_id>/<action>", methods=["POST"])
@company_required
def answer_merger(merger_id, action):
    """accept / decline (by the company that received it) or withdraw (by the sender)."""
    if action not in ("accept", "decline", "withdraw"):
        abort(404)
    db = get_db()
    me = current_company()
    message = None
    with write_txn(db):
        year = get_current_year(db)
        m = db.execute("SELECT * FROM mergers WHERE id = ?", (merger_id,)).fetchone()
        if m is None or m["status"] != "pending" or m["year"] != year:
            message = "That proposal isn't open anymore."
        elif me["id"] not in (m["survivor_id"], m["absorbed_id"]):
            message = "That proposal isn't for your company."
        elif action == "withdraw":
            if m["proposed_by"] != me["id"]:
                message = "Only the company that sent a proposal can withdraw it."
            else:
                db.execute("UPDATE mergers SET status = 'cancelled' WHERE id = ?", (merger_id,))
                message = "Proposal withdrawn."
        elif m["proposed_by"] == me["id"]:
            message = "The other company has to answer your proposal."
        elif action == "decline":
            db.execute("UPDATE mergers SET status = 'declined' WHERE id = ?", (merger_id,))
            message = "Proposal declined."
        else:
            error = merge_blocker(db, rankings(db), m["survivor_id"], m["absorbed_id"], year)
            if error:
                message = error
            else:
                db.execute("UPDATE mergers SET status = 'agreed' WHERE id = ?", (merger_id,))
                # Both companies are now committed, so their other proposals are void.
                db.execute(
                    "UPDATE mergers SET status = 'cancelled' "
                    "WHERE status = 'pending' AND id != ? AND "
                    "(survivor_id IN (?, ?) OR absorbed_id IN (?, ?))",
                    (merger_id, m["survivor_id"], m["absorbed_id"],
                     m["survivor_id"], m["absorbed_id"]),
                )
                names = db.execute(
                    "SELECT s.name AS s, a.name AS a FROM companies s, companies a "
                    "WHERE s.id = ? AND a.id = ?",
                    (m["survivor_id"], m["absorbed_id"]),
                ).fetchone()
                message = (
                    f"Merger agreed. {names['a']} will merge into {names['s']} "
                    f"when year {year} ends."
                )
    flash(message)
    return redirect(url_for("mergers"))


# ---- professor ----
@app.route("/professor")
@professor_required
def professor():
    db = get_db()
    year = get_current_year(db)
    members = {}
    for m in db.execute("SELECT company_id, name FROM members ORDER BY id"):
        members.setdefault(m["company_id"], []).append(m["name"])
    rows = [
        {
            "id": r["id"],
            "name": r["name"],
            "industry": INDUSTRIES[r["industry"]],
            "cash_cents": r["cash_cents"],
            "has_password": bool(r["password_hash"]),
            "members": members.get(r["id"], []),
        }
        for r in db.execute(
            "SELECT id, name, industry, cash_cents, password_hash FROM companies "
            "WHERE merged_into IS NULL ORDER BY name COLLATE NOCASE"
        )
    ]
    return render_template(
        "professor.html",
        year=year,
        companies=rows,
        open_mergers=load_mergers(
            db, "WHERE m.status IN ('pending', 'agreed') AND m.year = ?", (year,)
        ),
        needs=unmerged_top_half(db, year),
        started=year >= MERGER_START_YEAR,
    )


@app.route("/professor/reset/<int:company_id>", methods=["POST"])
@professor_required
def reset_password(company_id):
    db = get_db()
    company = db.execute(
        "SELECT id, name FROM companies WHERE id = ? AND merged_into IS NULL", (company_id,)
    ).fetchone()
    if company is None:
        abort(404)
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no look-alike characters
    temporary = "".join(secrets.choice(alphabet) for _ in range(10))
    with write_txn(db):
        db.execute(
            "UPDATE companies SET password_hash = ? WHERE id = ?",
            (generate_password_hash(temporary), company_id),
        )
    flash(
        f"New password for {company['name']}: {temporary}  "
        "Give it to the group now. It won't be shown again."
    )
    return redirect(url_for("professor"))


@app.route("/professor/mergers/<int:merger_id>/cancel", methods=["POST"])
@professor_required
def cancel_merger(merger_id):
    db = get_db()
    with write_txn(db):
        changed = db.execute(
            "UPDATE mergers SET status = 'cancelled' "
            "WHERE id = ? AND status IN ('pending', 'agreed')",
            (merger_id,),
        ).rowcount
    flash("Merger cancelled." if changed else "That merger isn't open anymore.")
    return redirect(url_for("professor"))


@app.route("/next-year", methods=["GET", "POST"])
def next_year():
    """Professor-only: asks for the password, then finishes the current year."""
    db = get_db()
    year = get_current_year(db)
    error = None
    status = 200

    if request.method == "POST":
        if request.form.get("year", type=int) != year:
            flash("That year was already finished. Nothing was changed.")
            return redirect(url_for("companies"))

        entered = request.form.get("password", "")
        if hmac.compare_digest(entered.encode(), PROFESSOR_PASSWORD.encode()):
            if advance_year(db, year):
                flash(f"Year {year} is finished. Year {year + 1} has started.")
            else:
                flash("That year was already finished. Nothing was changed.")
            return redirect(url_for("companies"))

        error = "That password isn't correct. The year was not changed."
        status = 403

    return (
        render_template(
            "next_year.html", year=year, error=error, needs=unmerged_top_half(db, year)
        ),
        status,
    )


init_db()

if __name__ == "__main__":
    app.run(debug=True)
