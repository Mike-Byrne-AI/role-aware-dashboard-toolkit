# Run your first dashboard

The starter is a small dashboard you can edit: an overview, grouped controls,
saved profiles and an audit history. It runs as a Python process and opens in
your browser. Opening `app.py` in an editor does not start it.

Use Python 3.11 or later and a downloaded or cloned toolkit source checkout.
The Streamlit UI requires this interpreter baseline; core/API remain usable on Python 3.10.
Open a terminal in the checkout, in the folder containing `pyproject.toml`.
Extract a downloaded source ZIP first. These instructions use the same Python
interpreter for installation and launch, without requiring shell activation.

## Windows PowerShell

Create the environment once. Reuse `.venv` only if it already uses Python 3.11+;
otherwise choose a new environment name and use that path throughout:

```powershell
python -m venv .venv
$dashboardPython = (Resolve-Path .\.venv\Scripts\python.exe).Path
& $dashboardPython -m pip install ".[workbench]"
& $dashboardPython -m pip check
& $dashboardPython -m role_aware_dashboard_toolkit init ..\my-dashboard --dry-run
& $dashboardPython -m role_aware_dashboard_toolkit init ..\my-dashboard
Set-Location ..\my-dashboard
& $dashboardPython -m streamlit run app.py --server.address 127.0.0.1
```

This Streamlit starter runs directly on Windows; WSL is not required.

## macOS or Linux

In bash or zsh, skip the first command if `.venv` already exists:

```bash
python3 -m venv .venv
dashboard_python="$PWD/.venv/bin/python"
"$dashboard_python" -m pip install ".[workbench]"
"$dashboard_python" -m pip check
"$dashboard_python" -m role_aware_dashboard_toolkit init ../my-dashboard --dry-run
"$dashboard_python" -m role_aware_dashboard_toolkit init ../my-dashboard
cd ../my-dashboard
"$dashboard_python" -m streamlit run app.py --server.address 127.0.0.1
```

`init` creates a sibling folder named `my-dashboard`. It refuses to overwrite
an existing destination. Choose a different new name if that folder already
exists; do not delete a project just to repeat setup.

## Open, try, and restart

Keep the terminal running. Open the **Local URL** printed by Streamlit in a
browser on the same computer. If you ran these commands on a remote development
machine, use that development tool's supported port forwarding; its local URL
does not point to your PC. The command is a local development launch, not public
hosting.

Try these interactions:

1. Start as Viewer, choose **Plan**, and check that protected controls cannot be edited.
2. Choose Admin in the demo role selector, change a control in Plan, then save a profile.
3. Change the control again, load the profile, and check that it is restored.
4. Freeze writes and check that edits and profile restoration are disabled.
5. Switch views and inspect the audit history. Try a narrow browser window too.

Stop the server with `Ctrl+C` in its terminal. Closing the browser tab alone
does not stop the server. To restart in the same terminal, run the last launch
command again. In a new terminal, open the `my-dashboard` folder and use the
absolute path to the toolkit environment's Python executable. For example, in
PowerShell, replacing the example path with your own:

```powershell
& 'C:\Projects\role-aware-dashboard-toolkit\.venv\Scripts\python.exe' -m streamlit run app.py --server.address 127.0.0.1
```

The role selector is a local demonstration: anyone using it can choose Admin.
Profiles, controls and audit history are session-local and reset with a new
browser session or server restart. Before inviting real users, start with
`init NEW-DIRECTORY --auth` and follow the
[authentication guide](../role_aware_dashboard_toolkit/resources/guides/authentication.md).
The host application supplies its identity provider, protected storage and
business operations.

## If it does not start

| What you see | What to check |
| --- | --- |
| `python` is not recognized | Install Python, reopen the terminal, and confirm `python --version` (or `python3 --version` on macOS/Linux). |
| `No module named streamlit` or toolkit import failure | Run installation and launch with the same environment's Python path shown above. Run its `-m pip check`. |
| `app.py` not found | Change into the generated `my-dashboard` directory before launching. |
| Theme looks different | Launch from `my-dashboard`, where `.streamlit/config.toml` lives; restart the server after changing the theme. |
| Port 8501 already in use | Stop the dashboard you previously started with `Ctrl+C`, or append `--server.port 8502` and use the new printed URL. |
| Browser says it cannot connect | Check that the terminal is still running and has no startup error; use the URL and port it printed. |

Use the starter's README to find its named editing functions. The installed
`python -m role_aware_dashboard_toolkit guide appearance` command explains theme
and layout options. See the [examples index](../examples/README.md) for other
workflows.
