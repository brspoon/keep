"""Table-based email layouts with inline light fallback and optional system dark mode."""
from datetime import datetime
from html import escape

FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif"
LOGO_CID = 'keep-logo@keep'
# Inline styles are the fallback for clients that strip style blocks/media queries.
STYLES = {
    'canvas': 'background:#f7f8fa;color:#20242b;',
    'surface': 'background:#ffffff;color:#20242b;border:1px solid #d3d9e1;border-radius:16px;',
    'text': 'color:#20242b;',
    'muted': 'color:#566171;',
    'accent': 'color:#805000;',
    'badge': 'background:#fff0d4;color:#805000;border:1px solid #a87926;border-radius:999px;',
    'urgent': 'background:#fff0ef;color:#962f30;border:1px solid #d69896;border-radius:999px;',
    'count': 'background:#f0f2f5;color:#566171;border-radius:999px;',
    'fallback': 'background:#f0f2f5;color:#566171;border-radius:6px;',
}
DARK = {
    'canvas': 'background:#0b0d10!important;color:#f1f2f4!important;',
    'surface': 'background:#17191e!important;color:#f1f2f4!important;border-color:#333740!important;',
    'text': 'color:#f1f2f4!important;',
    'muted': 'color:#a8adb8!important;',
    'accent': 'color:#efb34f!important;',
    'badge': 'background:#352919!important;color:#f4c679!important;border-color:#806039!important;',
    'urgent': 'background:#391e23!important;color:#ffabb3!important;border-color:#85434c!important;',
    'count': 'background:#272b33!important;color:#c4c8d0!important;',
    'fallback': 'background:#272b33!important;color:#c4c8d0!important;',
}


def style(name, extra=''):
    return f'class="mail-{name}" style="{STYLES[name]}{extra}"'


def action(url, label):
    return (f'<a href="{escape(url, quote=True)}" style="display:inline-block;'
            'padding:14px 22px;background:#efb34f;color:#17120a;border:1px solid #c0872d;'
            f'border-radius:10px;text-decoration:none;font-weight:700">{escape(label)}</a>')


def layout(title, content, preheader=''):
    dark_rules = ''.join(f'.mail-{name}{{{value}}}' for name, value in DARK.items())
    return f'''<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><meta name="supported-color-schemes" content="light dark">
<title>{escape(title)}</title><style>
:root{{color-scheme:light dark;supported-color-schemes:light dark}}
@media(prefers-color-scheme:dark){{{dark_rules}}}
@media(max-width:480px){{.mail-pad{{padding:22px 12px!important}}.mail-hero,.mail-brand-pad{{padding:20px!important}}}}
</style></head><body {style('canvas', f'margin:0;padding:0;font-family:{FONT};')}>
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">{escape(preheader)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" {style('canvas')}>
<tr><td align="center" class="mail-pad" style="padding:32px 18px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:620px;font-family:{FONT}">
<tr><td style="padding-bottom:24px"><table role="presentation" class="mail-brand mail-surface" width="100%" cellpadding="0" cellspacing="0" bgcolor="#ffffff" style="{STYLES['surface']}"><tr><td class="mail-brand-pad" style="padding:24px">
<table role="presentation" cellpadding="0" cellspacing="0"><tr>
<td width="64" height="64" align="center" valign="middle"><img src="cid:{LOGO_CID}" alt="" width="64" height="64" style="display:block;width:64px;height:64px;border:0"></td>
<td valign="middle" style="padding-left:16px"><div class="mail-brand-name mail-text" style="{STYLES['text']}font-size:36px;line-height:40px;font-weight:750;letter-spacing:-1px">Keep</div>
<div class="mail-brand-tagline mail-accent" style="{STYLES['accent']}font-size:13px;line-height:20px;font-weight:600">Keep what you love.</div></td></tr></table></td></tr></table></td></tr>
<tr><td>{content}</td></tr></table></td></tr></table></body></html>'''


def account_email(name, setup_url, reset=False):
    subject = 'Reset your Keep password' if reset else 'Set up your Keep account'
    intro = ('A password reset was requested for your Keep account.' if reset
             else 'The Keep owner created a local account for you.')
    content = f'''<table role="presentation" width="100%" cellpadding="0" cellspacing="0" {style('surface')}>
<tr><td class="mail-hero" style="padding:26px">
<h1 {style('text', 'margin:0 0 16px;font-size:26px;line-height:34px;')}>{escape(subject)}</h1>
<p {style('muted', 'margin:0;line-height:1.6;font-size:15px;')}>Hi {escape(name)}, {escape(intro)} This link expires in 24 hours and can be used once.</p>
<p style="margin:24px 0">{action(setup_url, subject)}</p>
<p {style('muted', 'margin:0;font-size:12px;line-height:18px;')}>If you were not expecting this, you can ignore this email.</p>
</td></tr></table>'''
    plain = f'Hi {name},\n\n{intro} This link expires in 24 hours and can be used once.\n\n{setup_url}\n\nIf you were not expecting this, you can ignore this email.'
    return subject, layout(subject, content, intro), plain


def date_label(value):
    if not value:
        return ''
    try:
        if isinstance(value, str):
            value = datetime.fromisoformat(value).date()
        return value.strftime('%B %d, %Y').replace(' 0', ' ')
    except (ValueError, AttributeError):
        return ''


def digest_email(items, keep_url):
    count = len(items)
    subject = f"Keep: {count} {'title needs' if count == 1 else 'titles need'} your attention"
    intro = 'These titles are scheduled to leave Plex. Keep your favorites before their deadlines.'
    categories = list(dict.fromkeys(item['collection'] for item in items))
    days = [item['days'] for item in items if item.get('days') is not None]
    earliest = min(days) if days else None
    earliest_label = 'Check Keep' if earliest is None else ('Today' if earliest == 0 else f"{earliest} {'day' if earliest == 1 else 'days'}")
    plain = [subject, '', intro, '']
    sections = []
    for category in categories:
        group = [item for item in items if item['collection'] == category]
        plain.append(f'{category} ({len(group)})')
        sections.append(f'<h2 {style("text", "margin:28px 0 12px;font-size:20px;line-height:26px;")}>{escape(category)} '
                        f'<span {style("count", "padding:3px 9px;font-size:12px;")}>{len(group)}</span></h2>')
        for item in group:
            title = str(item['title'])
            remaining = item.get('days')
            detail = ('Check Keep for timing' if remaining is None else 'Due today' if remaining == 0
                      else f"{remaining} {'day' if remaining == 1 else 'days'} left")
            if item.get('urgent'):
                detail = 'Last chance · ' + detail
            date = date_label(item.get('removal_date'))
            schedule = f'Scheduled for removal {date}' if date else ''
            year = str(item.get('year') or '')
            plain.append(f'- {title}' + (f' ({year})' if year else '') + f' — {detail}' + (f' · {schedule}' if schedule else ''))
            poster_url = item.get('poster_url') or ''
            if poster_url.startswith(('https://', 'http://')):
                poster = f'<img src="{escape(poster_url, quote=True)}" alt="{escape(title, quote=True)} poster" width="72" height="108" style="display:block;border:0;border-radius:6px;object-fit:cover">'
            else:
                poster = f'<table role="presentation" width="72" height="108" cellpadding="0" cellspacing="0" {style("fallback", "font-size:11px;line-height:16px;")}><tr><td align="center">No poster<br>available</td></tr></table>'
            badge = 'urgent' if remaining is not None and remaining <= 3 else 'badge'
            sections.append(f'''<table role="presentation" width="100%" cellpadding="0" cellspacing="0" {style('surface', 'table-layout:fixed;')}><tr><td style="padding:12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="table-layout:fixed"><tr>
<td width="72" valign="top">{poster}</td><td valign="middle" style="padding-left:14px;overflow-wrap:anywhere;word-wrap:break-word">
<div {style('text', 'font-size:16px;line-height:22px;font-weight:700;')}>{escape(title)}</div>
<div {style('muted', 'font-size:13px;line-height:20px;margin-top:3px;')}>{escape(year)}</div>
<div style="margin-top:9px"><span {style(badge, 'display:inline-block;padding:5px 9px;font-size:12px;line-height:16px;font-weight:700;')}>{escape(detail)}</span></div>
<div {style('muted', 'font-size:12px;line-height:18px;margin-top:7px;')}>{escape(schedule)}</div>
</td></tr></table></td></tr></table><div style="height:10px;line-height:10px">&nbsp;</div>''')
        plain.append('')
    summary = ''.join(f'<td width="33%" valign="top"><div {style("muted", "font-size:11px;line-height:17px;")}>{label}</div><div {style("text", "font-size:18px;line-height:25px;font-weight:700;")}>{escape(str(value))}</div></td>'
                      for label, value in [('Titles', count), ('Collections', len(categories)), ('Earliest deadline', earliest_label)])
    content = f'''<table role="presentation" width="100%" cellpadding="0" cellspacing="0" {style('surface')}><tr><td class="mail-hero" style="padding:26px">
<div {style('accent', 'font-size:11px;line-height:18px;letter-spacing:1px;font-weight:700;text-transform:uppercase;')}>Action needed</div>
<h1 {style('text', 'margin:8px 0;font-size:26px;line-height:34px;')}>{count} {'title is' if count == 1 else 'titles are'} leaving Plex</h1>
<p {style('muted', 'margin:0;font-size:14px;line-height:22px;')}>{intro}</p>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:20px"><tr>{summary}</tr></table>
</td></tr></table>{''.join(sections)}
<p style="margin:22px 0 0">{action(keep_url, 'Review titles in Keep')}</p>
<p {style('muted', 'margin:18px 0 0;font-size:12px;line-height:18px;')}>Opening Keep lets you protect a title before it leaves Plex. Manage email notifications in Preferences.</p>'''
    plain.append(f'Review and keep your favorites: {keep_url}')
    return subject, layout(subject, content, f'{count} titles scheduled to leave Plex. Earliest deadline: {earliest_label}.'), '\n'.join(plain)
