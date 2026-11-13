# Market Simulation

A Flask app for a college economics simulation.

## Run it

    pip install -r requirements.txt
    PROFESSOR_PASSWORD=choose-something-else python app.py

On Windows PowerShell, set the password first: `$env:PROFESSOR_PASSWORD="choose-something-else"`.
Then open http://127.0.0.1:5000.

## Settings

Environment variables:

- `PROFESSOR_PASSWORD`: the professor's password (default: `password`, so change it).
- `SECRET_KEY`: signs sign-ins. If you don't set one, a random key is created once and saved in `secret.key`.
- `DATABASE`: path to the SQLite file (default: `econ_sim.db` next to `app.py`).

Simulation numbers (budget, product costs, fixed costs, demand equations, one-time costs,
merger start year, minimum password length) are all at the top of `app.py`.

## How a class runs

1. Each group registers a company and chooses a password. They're signed in afterwards.
2. The professor finishes each year with "Go to year N" on the companies page (asks for the professor password).
3. From year 2, groups sign in and plan production. From year 4, groups merge (see the Mergers page).
4. Professor sign-in (choose "Professor" on the sign-in page) opens the Professor page: reset a group's
   password and cancel mergers.

If you run it for real students, serve it over HTTPS and don't use `debug=True`.
