export interface InstallCommandOptions {
  /** Breeze API origin, e.g. https://eu.2breeze.app */
  apiUrl: string;
  /** Base URL for direct Windows binary downloads (GitHub releases) */
  ghBase: string;
  /** Enrollment token from the Add Device / setup flow */
  token: string;
  /** Optional org enrollment secret */
  enrollmentSecret?: string;
  /**
   * Optional URL to a code-signing certificate (.cer) to install into the
   * Windows machine's Trusted Root store before running the agent — for a
   * self-signed build (no CA-chained reputation) that would otherwise trip
   * SmartScreen on a fresh machine. No-op on macOS/Linux.
   */
  trustCertUrl?: string;
  /**
   * Optional URL for a standalone breeze-user-helper.exe to place directly at
   * C:\Program Files\Breeze\breeze-user-helper.exe after service install. A
   * normal release-versioned agent self-heals a missing companion helper via
   * server-side reconciliation, but that 404s for a build version that was
   * never registered in the API's binary catalog (e.g. a custom/self-signed
   * build) — sessionbroker then falls back to spawning the (admin-manifested)
   * main exe as the per-user helper, which fails with ELEVATION_REQUIRED and
   * leaves desktop capture broken. No-op on macOS/Linux.
   */
  userHelperUrl?: string;
  /**
   * Optional URL for a standalone breeze-watchdog.exe, downloaded as a SIBLING
   * next to breeze-agent.exe before `service install`. The agent prefers a
   * sibling watchdog over its GitHub-download fallback (locateSiblingWatchdog
   * in watchdog_bootstrap.go), so providing this keeps a self-signed/custom
   * build from pulling the stock watchdog from LanternOps' release (pinned to
   * the build's hardcoded version, e.g. v0.5.0) — self-hosted + consistent
   * branding. No-op on macOS/Linux.
   */
  watchdogUrl?: string;
  /**
   * Optional URL to a prebuilt Linux agent binary (breeze-agent-linux-amd64).
   * When set, the Linux install command downloads THIS binary directly and
   * installs it as a per-user systemd service (systemd --user) under whoever
   * runs the command — instead of routing through the server-generated
   * install.sh (which pre-flights an agent-versions catalog this self-hosted
   * fork leaves empty, and which installs a root system service using the
   * upstream binary). No-op on Windows/macOS. When unset, Linux falls back to
   * the install.sh flow.
   */
  linuxBinaryUrl?: string;
}

export interface InstallCommands {
  windows: string;
  macos: string;
  linux: string;
}

/**
 * Builds the copy-paste agent install commands shown in the Add Device modal
 * and the setup wizard.
 *
 * macOS/Linux route through the server-generated install.sh, which pre-flights
 * connectivity to the server (distinguishing "unreachable" from "intercepted
 * by a captive portal/router"), verifies the download, and surfaces enrollment
 * failures — instead of letting `installer`/`bash` die with a cryptic OS error
 * (see PR #1271 for the original field report). The one-liner itself only
 * trusts the fetched file after a shebang check, so an intercepting device
 * serving HTML is reported as a connectivity problem rather than executed.
 */
export function buildInstallCommands(opts: InstallCommandOptions): InstallCommands {
  const apiUrl = opts.apiUrl.replace(/\/+$/, '');
  const ghBase = opts.ghBase.replace(/\/+$/, '');
  const { token, enrollmentSecret, trustCertUrl, userHelperUrl, watchdogUrl, linuxBinaryUrl } = opts;

  // The connectivity message is scoped to the fetch + shebang check only —
  // once install.sh runs it reports its own failures precisely, and appending
  // a "could not reach" hint after e.g. an enrollment error would mislead.
  const unixSecretFlag = enrollmentSecret ? ` --enrollment-secret "${enrollmentSecret}"` : '';
  const unixCmd =
    `f="$(mktemp)" && ` +
    `{ curl -fsSL --connect-timeout 10 -o "$f" "${apiUrl}/api/v1/agents/install.sh" && head -n1 "$f" | grep -q '^#!' || ` +
    `{ echo "[ERROR] Could not fetch the Breeze installer from ${apiUrl} — verify this machine has network access to your Breeze server." >&2; false; }; } && ` +
    `sudo bash "$f" --server "${apiUrl}" --token "${token}"${unixSecretFlag}`;

  // Direct-download, per-user Linux install (used when linuxBinaryUrl is set).
  // Runs entirely as the invoking desktop user — no username is baked in, so
  // the same command installs under whoever pastes it (e.g. the kiosk user).
  // The only privileged step is `loginctl enable-linger`, which lets the user
  // service survive logout/reboot; it is best-effort (|| true). The ELF-magic
  // check is the Linux analog of the Windows MZ check — a captive portal's HTML
  // saved as the binary is blamed on the network, not run.
  const linuxUserCmd = [
    `set -e`,
    `[ "$(id -u)" = 0 ] && { echo "[ERROR] Run this as the desktop user (e.g. icool), NOT with sudo/root — the agent installs as a per-user service." >&2; exit 1; }`,
    `BIN="$HOME/.local/bin/breeze-agent"`,
    `mkdir -p "$HOME/.local/bin" "$HOME/.config/breeze" "$HOME/.config/systemd/user"`,
    `curl -fsSL --connect-timeout 10 -o "$BIN" "${linuxBinaryUrl}" || { echo "[ERROR] Could not fetch the Breeze agent from ${linuxBinaryUrl} — check this machine's network access." >&2; exit 1; }`,
    `magic=$(od -An -tx1 -N4 "$BIN" | tr -d ' \\n'); [ "$magic" = "7f454c46" ] || { echo "[ERROR] Downloaded file is not a Linux binary — a captive portal or web filter may be intercepting this network." >&2; exit 1; }`,
    `chmod 0755 "$BIN"`,
    `"$BIN" --config "$HOME/.config/breeze/agent.yaml" enroll "${token}" --server "${apiUrl}"${unixSecretFlag}`,
    `printf '[Unit]\\nDescription=Breeze RMM Agent (user)\\nAfter=graphical-session.target\\n\\n[Service]\\nType=simple\\nExecStart=%s --config %%h/.config/breeze/agent.yaml run\\nRestart=always\\nRestartSec=10\\n\\n[Install]\\nWantedBy=default.target\\n' "$BIN" > "$HOME/.config/systemd/user/breeze-agent.service"`,
    // `systemctl --user` needs XDG_RUNTIME_DIR (and a D-Bus address derived from
    // it) to reach the user manager. A plain `su -`/SSH shell that isn't a full
    // login session leaves them unset — "Failed to connect to user scope bus".
    // Default them to the logged-in user's runtime dir (present because the
    // desktop user has an active graphical session).
    `export XDG_RUNTIME_DIR="\${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"`,
    `export DBUS_SESSION_BUS_ADDRESS="\${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}"`,
    `systemctl --user daemon-reload`,
    `systemctl --user enable --now breeze-agent`,
    `sudo loginctl enable-linger "$(id -un)" 2>/dev/null || true`,
    `echo "Breeze agent installed under $(id -un). Status: systemctl --user status breeze-agent"`,
  ].join('\n');

  // The MZ-magic check is the Windows analog of the unix shebang check: a
  // captive portal's 200 HTML saved as breeze-agent.exe would otherwise stop
  // the chain with PowerShell's raw "not a valid application" exception
  // (which never sets $LASTEXITCODE — the process fails to start). The
  // $LASTEXITCODE throws cover agent steps that DO run but fail, since
  // native exe exit codes do not trip $ErrorActionPreference.
  const winSecretFlag = enrollmentSecret ? ` --enrollment-secret "${enrollmentSecret}"` : '';
  const winThrow = (step: string) => `if($LASTEXITCODE){throw "Breeze: ${step} failed (exit code $LASTEXITCODE)"}`;
  const winMzCheck =
    `$b=[IO.File]::ReadAllBytes("$pwd\\breeze-agent.exe"); ` +
    `if($b.Length -lt 2 -or $b[0] -ne 0x4D -or $b[1] -ne 0x5A)` +
    `{throw "Breeze: downloaded file is not a Windows executable - a captive portal or web filter may be intercepting this network"}`;
  // certutil -addstore requires Administrator, same as `service install`
  // below — no separate elevation prompt beyond what the script already needs.
  const winTrustCert = trustCertUrl
    ? `Invoke-WebRequest -Uri "${trustCertUrl}" -OutFile breeze-trust.cer; ` +
      `certutil -addstore Root breeze-trust.cer; ` +
      `if($LASTEXITCODE){throw "Breeze: installing the trust certificate failed (exit code $LASTEXITCODE)"}; `
    : '';
  // Downloaded as a sibling next to breeze-agent.exe BEFORE `service install`,
  // so the agent's locateSiblingWatchdog finds it and skips its LanternOps
  // GitHub-download fallback entirely.
  const winWatchdog = watchdogUrl
    ? `Invoke-WebRequest -Uri "${watchdogUrl}" -OutFile breeze-watchdog.exe; ` +
      `if($LASTEXITCODE){throw "Breeze: downloading the watchdog failed (exit code $LASTEXITCODE)"}; `
    : '';
  // Placed after `service install` succeeds, since that's what creates
  // C:\Program Files\Breeze\ in the first place.
  const winUserHelper = userHelperUrl
    ? `Invoke-WebRequest -Uri "${userHelperUrl}" -OutFile "$env:ProgramFiles\\Breeze\\breeze-user-helper.exe"; ` +
      `if($LASTEXITCODE){throw "Breeze: installing the user helper failed (exit code $LASTEXITCODE)"}; `
    : '';
  const windows =
    `$ErrorActionPreference='Stop'; ` +
    `Invoke-WebRequest -Uri "${ghBase}/breeze-agent-windows-amd64.exe" -OutFile breeze-agent.exe; ` +
    `${winMzCheck}; ` +
    `${winTrustCert}` +
    `${winWatchdog}` +
    `.\\breeze-agent.exe service install; ${winThrow('service install')}; ` +
    `${winUserHelper}` +
    `.\\breeze-agent.exe enroll "${token}" --server "${apiUrl}"${winSecretFlag}; ${winThrow('enrollment')}; ` +
    `.\\breeze-agent.exe service start; ${winThrow('service start')}`;

  return { windows, macos: unixCmd, linux: linuxBinaryUrl ? linuxUserCmd : unixCmd };
}
