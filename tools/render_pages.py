"""Render every web page to HTML files, with no server and no session.

The page builders in frontend.web_server are pure functions of an Account, so
reviewing the UI needs neither a running server nor an authenticated browser.
That matters beyond convenience: the states worth looking at are the awkward
ones (unpaid, no Telegram linked, no voice profile, billing portal
unavailable), and manufacturing those in a live session means editing the
account manifest by hand.

    python -m tools.render_pages            # write to /tmp/letterlock-pages
    python -m tools.render_pages --open     # ...and open the index
    python -m tools.render_pages --out DIR

Absolute /static/ and route links are rewritten to relative filenames so the
dump is navigable straight from disk under file://.
"""

import os
import shutil
import sys
import webbrowser
from pathlib import Path

# The web modules read secrets at import time. Nothing here sends anything, so
# placeholders keep a bare checkout renderable. These are set before the imports
# below because load_dotenv() does not overwrite an existing variable -- which is
# also how the empty bot token sticks: the settings page asks Telegram for the
# bot's username, and a render must not make network calls with a real token.
os.environ.setdefault("DEEPSEEK_API_KEY", "render-placeholder")
os.environ.setdefault("SESSION_SECRET", "render-placeholder")
os.environ["TELEGRAM_BOT_TOKEN"] = ""

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend import paths                                    # noqa: E402
from backend.accounts import account, state                  # noqa: E402
from backend.integrations.telegram import TelegramTarget     # noqa: E402
from backend.masking import pseudonymizer                    # noqa: E402
from frontend import web_server as web                       # noqa: E402

OUT_DEFAULT = Path("/tmp/letterlock-pages")

# route -> output filename, used both to name files and to rewrite nav links.
ROUTES = {
    "/": "home.html",
    "/about": "about.html",
    "/faq": "faq.html",
    "/pricing": "pricing.html",
    "/contact": "contact.html",
    "/dashboard": "dashboard.html",
    "/voice": "voice.html",
    "/settings": "settings.html",
    "/billing": "billing.html",
    "/account": "account.html",
}


def _account(id, *, plan_status="active", telegram=True, polar=None,
             voice_file=None, auto_schedule=False):
    """A synthetic Account. Never touches the manifest: these are display
    fixtures, not registrations."""
    identity = pseudonymizer.UserIdentity(
        "Morgan", "Rivers", first_aliases=["Daniel"], emails=[id], account_id=id,
    )
    return account.Account(
        id=id,
        identity=identity,
        state=state.StateStore(Path("/nonexistent/state.json")),
        telegram=TelegramTarget("bot-token", "12345") if telegram else None,
        plan_status=plan_status,
        polar_customer_id=polar,
        voice_file=voice_file,
        auto_schedule=auto_schedule,
    )


def variants():
    """(filename, html) for every page worth eyeballing.

    Two accounts carry most of it: the box owner with everything wired up, and
    a fresh signup with nothing -- unpaid, no chat linked, no voice profile.
    The second is what a new user actually sees, and it is the one a live
    session never shows you."""
    owner = _account(
        "owner@example.com", polar="cus_123",
        voice_file=str(paths.CONFIG_DIR / "voice-dna-email.md"),
        auto_schedule=True,
    )
    fresh = _account("newuser@example.com", plan_status="inactive", telegram=False)

    pages = [
        ("home.html", web._page_home()),
        ("about.html", web._page_about()),
        ("faq.html", web._page_faq()),
        ("pricing.html", web._page_pricing()),
        ("contact.html", web._page_contact()),
        ("contact-sent.html", web._page_contact(msg="Message received.")),
        ("contact-error.html", web._page_contact(error="Please include a message.")),

        ("dashboard.html", web._page_dashboard(owner)),
        ("dashboard-inactive.html", web._page_dashboard(fresh)),
        ("voice.html", web._page_voice(owner)),
        ("voice-default.html", web._page_voice(fresh)),
        ("settings.html", web._page_settings(owner)),
        ("settings-saved.html", web._page_settings(owner, saved=True)),
        ("settings-unlinked.html", web._page_settings(fresh)),
        ("settings-linking.html", web._page_settings(fresh, link_code="AB12CD")),
        ("settings-error.html", web._page_settings(fresh, error="Could not reach Telegram.")),
        ("billing.html", web._page_billing(owner)),
        ("billing-inactive.html", web._page_billing(fresh)),
        ("billing-error.html", web._page_billing(owner, error="The billing portal is unavailable.")),
        ("account.html", web._page_account(owner)),
        ("account-error.html", web._page_account(owner, error="Email address did not match.")),
        ("deleted.html", web._page_deleted()),

        ("error-404.html", web._page_error(404, "Page not found.")),
        ("error-500.html", web._page_error(500, "Sign-in failed. Please try again.")),
    ]
    return [(name, html.decode() if isinstance(html, bytes) else html)
            for name, html in pages]


def relativise(html):
    """Absolute URLs assume a server at the root. Point them at siblings so the
    dump browses from disk."""
    html = html.replace('href="/static/', 'href="').replace('src="/static/', 'src="')
    for route, filename in ROUTES.items():
        html = html.replace(f'href="{route}"', f'href="{filename}"')
    return html


def index(names):
    links = "\n".join(f'<li><a href="{n}">{n[:-5]}</a></li>' for n in names)
    return f"""<!doctype html>
<meta charset="utf-8"><title>Letterlock pages</title>
<link rel="stylesheet" href="app.css">
<div id="page"><div id="content">
<h2>Rendered pages</h2>
<p>Static render of every page and state. Forms and sign-in do nothing here.</p>
<ul>{links}</ul>
</div></div>"""


def render(out):
    out.mkdir(parents=True, exist_ok=True)
    if paths.STATIC_DIR.is_dir():
        for asset in paths.STATIC_DIR.iterdir():
            if asset.is_file():
                shutil.copy2(asset, out / asset.name)
    else:
        print(f"warning: no static assets at {paths.STATIC_DIR}; pages will be unstyled")

    names = []
    for name, html in variants():
        (out / name).write_text(relativise(html))
        names.append(name)
    (out / "index.html").write_text(index(names))
    return names


def main(argv):
    out = OUT_DEFAULT
    if "--out" in argv:
        out = Path(argv[argv.index("--out") + 1])
    names = render(out)
    print(f"wrote {len(names)} pages to {out}")
    print(f"  {out / 'index.html'}")
    if "--open" in argv:
        webbrowser.open((out / "index.html").as_uri())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
