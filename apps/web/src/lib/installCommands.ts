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
  const { token, enrollmentSecret, trustCertUrl } = opts;

  // The connectivity message is scoped to the fetch + shebang check only —
  // once install.sh runs it reports its own failures precisely, and appending
  // a "could not reach" hint after e.g. an enrollment error would mislead.
  const unixSecretFlag = enrollmentSecret ? ` --enrollment-secret "${enrollmentSecret}"` : '';
  const unixCmd =
    `f="$(mktemp)" && ` +
    `{ curl -fsSL --connect-timeout 10 -o "$f" "${apiUrl}/api/v1/agents/install.sh" && head -n1 "$f" | grep -q '^#!' || ` +
    `{ echo "[ERROR] Could not fetch the Breeze installer from ${apiUrl} — verify this machine has network access to your Breeze server." >&2; false; }; } && ` +
    `sudo bash "$f" --server "${apiUrl}" --token "${token}"${unixSecretFlag}`;

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
  const windows =
    `$ErrorActionPreference='Stop'; ` +
    `Invoke-WebRequest -Uri "${ghBase}/breeze-agent-windows-amd64.exe" -OutFile breeze-agent.exe; ` +
    `${winMzCheck}; ` +
    `${winTrustCert}` +
    `.\\breeze-agent.exe service install; ${winThrow('service install')}; ` +
    `.\\breeze-agent.exe enroll "${token}" --server "${apiUrl}"${winSecretFlag}; ${winThrow('enrollment')}; ` +
    `.\\breeze-agent.exe service start; ${winThrow('service start')}`;

  return { windows, macos: unixCmd, linux: unixCmd };
}
