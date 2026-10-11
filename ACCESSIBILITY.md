# Accessibility in Keep

Keep aims to make browsing media, managing Keeps, and administering an
installation usable by people with different abilities and input methods.
[WCAG 2.2 Level AA](https://www.w3.org/TR/WCAG22/) guides accessibility work.
Keep has not completed a formal accessibility audit and does not claim WCAG
conformance.

## Design priorities

Accessibility work should preserve:

- Keyboard access, visible focus, and a sensible focus order.
- Clear labels, headings, landmarks, validation, and status messages for people
  using assistive technology.
- Readable text and controls in light and dark mode, without relying on color
  alone to communicate a state or action.
- Layouts that remain usable on narrow screens and with browser zoom.
- Respect for the system's reduced-motion preference.

Keep already includes skip links, keyboard handling for custom controls and
dialogs, and reduced-motion styles. These features do not establish that every
page or workflow is accessible.

## Browser environments

Keep targets current versions of Safari, Chrome, Firefox, and Edge on desktop,
and Safari on iOS and Chrome on Android. JavaScript must be enabled for
interactive features. The interface is designed for both desktop and narrow
mobile layouts.

These are intended browser environments, not a verified browser or assistive
technology compatibility matrix. Automated interaction checks use simulated
browser elements. A narrow desktop viewport does not establish physical-device
accessibility. See [development and testing](docs/DEVELOPMENT_TESTING.md) for the
current validation scope.

## Known limitations and gaps

- The API endpoint listing, title-details dialogs, and some administrator
  controls depend on JavaScript.
- Custom selection controls, dialogs, and dynamically updated content need
  further testing with real screen readers and other assistive technology.
- Keyboard, zoom, contrast, and mobile behavior have not been comprehensively
  audited across all pages and account roles.
- Plex sign-in and linked external services have their own interfaces. Barriers
  in Keep's handoff to those services can still be reported to this project.

## Report an accessibility barrier

Open a [GitHub bug report](https://github.com/brspoon/keep/issues/new?template=bug_report.yml)
and identify it as an accessibility issue. Describe the task that was blocked
and include, when available:

- The Keep version and affected page or control.
- Your browser and operating system, including their versions.
- Your input method, browser zoom, and assistive technology, if relevant.
- Steps to reproduce the barrier, what you expected, and what happened instead.

You do not need to disclose a disability or provide a screenshot. If you include
screenshots or logs, remove personal information, credentials, private media
details, and service addresses. Reports are public, so use only information you
are comfortable sharing.

Conduct concerns should go to the private contact in the
[Code of Conduct](CODE_OF_CONDUCT.md). Suspected vulnerabilities should use the
private reporting channel in [SECURITY.md](SECURITY.md).

## Contributing improvements

Include the affected workflow and how you checked the improvement. For interface
changes, check keyboard navigation, focus, labels and status messages, zoom,
light and dark mode, reduced motion, and narrow layouts as relevant. Record the
actual browsers, devices, and assistive technology used; distinguish simulated
checks from real-device observations. See [contributing](CONTRIBUTING.md) and
[development and testing](docs/DEVELOPMENT_TESTING.md).
