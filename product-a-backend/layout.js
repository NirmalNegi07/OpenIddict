// Shared page shell (nav + styles) so every route renders consistently instead of each
// handler inventing its own one-off HTML string.

const STYLES = `
  :root {
    --color-bg: #f6f7fb;
    --color-surface: #ffffff;
    --color-border: #e3e5ef;
    --color-text: #14141c;
    --color-text-muted: #6b6d80;
    --color-primary: #4338ca;
    --color-primary-dark: #362f9e;
    --color-primary-soft: #ecebfd;
    --color-success: #0f7a4d;
    --color-success-soft: #e4f6ee;
    --color-danger: #c0341f;
    --color-danger-soft: #fbe9e6;
    --shadow-card: 0 1px 2px rgba(20,20,28,0.04), 0 8px 24px rgba(20,20,28,0.06);
    --radius: 12px;
  }
  * { box-sizing: border-box; }
  html, body {
    margin: 0; padding: 0;
    background: var(--color-bg);
    color: var(--color-text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
    font-size: 15px;
    line-height: 1.5;
  }
  a { color: var(--color-primary); text-decoration: none; }
  a:hover { text-decoration: underline; }
  code, .mono { font-family: ui-monospace, "SF Mono", Menlo, monospace; }

  .shell { max-width: 880px; margin: 0 auto; padding: 0 24px; }

  .site-header { background: var(--color-surface); border-bottom: 1px solid var(--color-border); }
  .header-inner { display: flex; align-items: center; justify-content: space-between; height: 64px; gap: 16px; flex-wrap: wrap; }
  .brand { display: flex; align-items: center; gap: 8px; font-weight: 700; font-size: 1.05rem; color: var(--color-text); }
  .brand:hover { text-decoration: none; }
  .brand-mark {
    display: inline-flex; align-items: center; justify-content: center;
    width: 30px; height: 30px; border-radius: 8px;
    background: var(--color-primary-soft); color: var(--color-primary-dark);
    font-weight: 700; font-size: 0.85rem;
  }
  .header-nav { display: flex; gap: 18px; font-size: 0.87rem; align-items: center; flex-wrap: wrap; }
  .header-nav a { color: var(--color-text-muted); }
  .header-nav a.active { color: var(--color-primary); font-weight: 600; }
  .header-nav a:hover { color: var(--color-text); text-decoration: none; }
  .header-user { font-size: 0.82rem; color: var(--color-text-muted); }

  .page-main { padding: 40px 24px 64px; }
  .site-footer { border-top: 1px solid var(--color-border); color: var(--color-text-muted); font-size: 0.8rem; padding: 18px 0; margin-top: 40px; }

  .card {
    background: var(--color-surface); border: 1px solid var(--color-border);
    border-radius: var(--radius); box-shadow: var(--shadow-card); padding: 24px;
  }
  .card + .card { margin-top: 16px; }
  .card h2 { margin: 0 0 4px; font-size: 1.05rem; }
  .card .card-sub { color: var(--color-text-muted); font-size: 0.85rem; margin: 0 0 16px; }

  .hero { text-align: center; padding: 24px 0 8px; }
  .hero h1 { font-size: 1.9rem; margin: 0 0 10px; }
  .hero p { color: var(--color-text-muted); max-width: 480px; margin: 0 auto 24px; }

  .btn {
    display: inline-flex; align-items: center; justify-content: center; gap: 6px;
    padding: 10px 18px; border-radius: 8px; border: none; cursor: pointer;
    font-size: 0.9rem; font-weight: 600; text-decoration: none;
  }
  .btn:hover { text-decoration: none; }
  .btn-primary { background: var(--color-primary); color: #fff; }
  .btn-primary:hover { background: var(--color-primary-dark); }
  .btn-ghost { background: var(--color-surface); color: var(--color-text); border: 1px solid var(--color-border); }
  .btn-ghost:hover { background: #fafafe; }

  .tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 16px; }
  .tile { background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius); padding: 16px; }
  .tile .label { font-size: 0.76rem; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.03em; margin-bottom: 6px; }
  .tile .value { font-size: 1.15rem; font-weight: 700; }
  .tile .value.mono { font-size: 0.95rem; font-weight: 600; word-break: break-all; }

  .quick-links { display: flex; gap: 10px; flex-wrap: wrap; }

  table.kv { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  table.kv td { padding: 8px 4px; border-top: 1px solid var(--color-border); vertical-align: top; }
  table.kv td.k { color: var(--color-text-muted); width: 180px; white-space: nowrap; font-family: ui-monospace, monospace; font-size: 0.8rem; }
  table.kv td.v { word-break: break-all; font-family: ui-monospace, monospace; font-size: 0.8rem; }

  .badge { display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 0.76rem; font-weight: 600; }
  .badge-success { background: var(--color-success-soft); color: var(--color-success); }
  .badge-danger { background: var(--color-danger-soft); color: var(--color-danger); }
  .badge-neutral { background: var(--color-primary-soft); color: var(--color-primary-dark); }

  .scope-tags { display: flex; flex-wrap: wrap; gap: 6px; }
  .scope-tag { background: var(--color-primary-soft); color: var(--color-primary-dark); padding: 4px 10px; border-radius: 6px; font-size: 0.78rem; font-family: ui-monospace, monospace; }

  details.raw { margin-top: 10px; }
  details.raw summary { cursor: pointer; font-size: 0.85rem; color: var(--color-text-muted); }
  details.raw pre {
    background: #14141c; color: #d7d8e6; padding: 14px; border-radius: 8px; overflow-x: auto;
    font-size: 0.78rem; margin-top: 8px;
  }

  .flow-entry { border: 1px solid var(--color-border); border-radius: var(--radius); margin-bottom: 12px; overflow: hidden; }
  .flow-entry-head { display: flex; align-items: center; gap: 8px; background: #fafafe; padding: 10px 14px; }
  .step-num {
    background: var(--color-primary); color: white; border-radius: 50%; width: 22px; height: 22px;
    display: inline-flex; align-items: center; justify-content: center; font-size: 12px; flex-shrink: 0;
  }
  .flow-entry .title { font-weight: 600; font-size: 0.9rem; flex: 1; }
  .flow-entry .time { color: var(--color-text-muted); font-size: 0.78rem; }

  .empty-state { text-align: center; padding: 40px 20px; color: var(--color-text-muted); }
`;

const NAV_ITEMS = [
  { key: 'dashboard', label: 'Dashboard', href: '/dashboard', authOnly: true },
  { key: 'profile', label: 'Profile', href: '/profile', authOnly: true },
  { key: 'session', label: 'Session', href: '/session', authOnly: true },
  { key: 'logs', label: 'Flow Log', href: '/logs', authOnly: false },
];

function renderPage({ title, active, user, body }) {
  const navLinks = NAV_ITEMS.filter((item) => !item.authOnly || user)
    .map((item) => `<a href="${item.href}" class="${item.key === active ? 'active' : ''}">${item.label}</a>`)
    .join('');

  const authAction = user
    ? `<a href="/logout" class="header-user">Logout (${escapeHtml(user.email || user.sub)})</a>`
    : `<a href="/login">Login</a>`;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${escapeHtml(title)} - Product A</title>
  <style>${STYLES}</style>
</head>
<body>
  <header class="site-header">
    <div class="shell header-inner">
      <a class="brand" href="/">
        <span class="brand-mark">A</span>
        Product A
      </a>
      <nav class="header-nav">
        ${navLinks}
        ${authAction}
      </nav>
    </div>
  </header>

  <main class="shell page-main">
    ${body}
  </main>

  <footer class="site-footer">
    <div class="shell">Product A &middot; OAuth2/OIDC client of Lighthouse &middot; local experiment</div>
  </footer>
</body>
</html>`;
}

function escapeHtml(str) {
  return String(str).replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
  );
}

module.exports = { renderPage, escapeHtml };
