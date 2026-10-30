# Start with the installed toolkit

Work in the user's project and follow its instructions. This handbook describes
the installed library; it does not grant permission to modify files or services.
The discovery commands use this Python environment's installed version and need
no checkout. `python` below means this environment's interpreter; without an
active environment, use its path (for example `.venv/bin/python` on macOS or
Linux, `.\.venv\Scripts\python.exe` on Windows).

```shell
python -m role_aware_dashboard_toolkit inspect
python -m role_aware_dashboard_toolkit guide controls
python -m role_aware_dashboard_toolkit example starter --format json
```

Before launching a dashboard, use Python 3.11 or later and install the toolkit's
`workbench` extra in that environment. Core/API remain usable on Python 3.10.
The extra applies the supported Streamlit and server dependency
requirements, including when the core toolkit is already installed. Replace the
example path with the absolute path to your reviewed toolkit source checkout. In
PowerShell on Windows:

```powershell
python -m pip install "C:\path\to\role-aware-dashboard-toolkit[workbench]"
python -m pip check
```

In bash or zsh on macOS or Linux:

```bash
python -m pip install "/path/to/role-aware-dashboard-toolkit[workbench]"
python -m pip check
```

Alternatively, pass the absolute filename of your reviewed local toolkit wheel
with `[workbench]` appended to the same `pip install` command. These explicit
paths work from your application directory. No toolkit package-index release
is assumed. The toolkit core itself has no mandatory runtime dependencies.

For a new project, preview then explicitly create a new directory. In PowerShell:

```powershell
python -m role_aware_dashboard_toolkit init my-dashboard --dry-run --format json
python -m role_aware_dashboard_toolkit init my-dashboard
Set-Location my-dashboard
python -m streamlit run app.py
```

In bash or zsh:

```bash
python -m role_aware_dashboard_toolkit init my-dashboard --dry-run --format json
python -m role_aware_dashboard_toolkit init my-dashboard
cd my-dashboard
python -m streamlit run app.py
```

`init` prints the exact launch command for the interpreter that ran it.

Keep the launch terminal running and open Streamlit's printed Local URL in a
browser on the same computer. Opening `app.py` as a file does not run the
dashboard. Stop it with `Ctrl+C`; closing a browser tab alone leaves the server
running. To restart, open a terminal in the generated project directory and
repeat the launch command using the same environment's Python executable.
If the port is occupied, append `--server.port 8502` and open the new printed
URL. A server started on a remote machine needs that tool's supported port
forwarding; its local URL does not point to your own computer.

`init` refuses existing destinations; it does not merge or replace an existing
AGENTS.md. For existing projects, read `example starter` and adapt the relevant
files under the host's instructions.

For shared use, choose `init my-dashboard --auth` and read `guide authentication`
for provider configuration and explicit role provisioning. Plain `init` is the
local role-selection demo, with no protection against choosing Admin.
Its records are in memory: a new browser session or server restart starts fresh.

Edit the starter's named functions: `build_controls`, `build_roles`,
`render_view_menu`, `render_project_panel`, `build_dashboard_config` and
`session_resources`. Theme settings live in `.streamlit/config.toml`.

Verify by changing a field, using the menu, switching roles, freezing controls,
and saving/loading a profile. Inspect the actual browser for appearance changes.
Imports and guide/inspect/example commands do not write project files.
