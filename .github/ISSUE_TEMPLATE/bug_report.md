---
name: Bug report
about: Report a bug in the adblock-fast service
title: "[adblock-fast] "
labels: bug
assignees: stangri

---

**Before opening this issue**

If you're using the LuCI web UI, please decide first whether the bug is in the UI or the service:

- The setting saves correctly but `adblock-fast` still misbehaves → file here.
- Service-level commands (e.g. `service adblock-fast status`) reproduce the bug without the UI → file here.
- Only the UI looks broken / a control does nothing / Save & Apply produces a JS error → file at [stangri/luci-app-adblock-fast](https://github.com/stangri/luci-app-adblock-fast/issues) instead.

**Describe the bug**

A clear and concise description of what the bug is.

**To reproduce**

1.
2.

**Expected behavior**

A clear and concise description of what you expected to happen.

**Diagnostic info**

Please run the following and paste the output (you can mask sensitive parts):

```sh
ubus call system board
service adblock-fast version
uci export dhcp
uci export adblock-fast
service adblock-fast status
service adblock-fast sizes
```

If the issue is about a specific domain not being blocked or being blocked unexpectedly, please also include:

```sh
service adblock-fast check <domain>
service adblock-fast check_lists <domain>
```
