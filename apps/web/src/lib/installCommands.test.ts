import { describe, expect, it } from 'vitest';
import { buildInstallCommands } from './installCommands';

const base = {
  apiUrl: 'https://rmm.example.com',
  ghBase: 'https://github.com/lanternops/breeze/releases/latest/download',
  token: 'enroll_abc123',
};

describe('buildInstallCommands', () => {
  describe('macOS / Linux (install.sh based)', () => {
    it('routes through the server-generated install.sh for both platforms', () => {
      const cmds = buildInstallCommands(base);
      for (const cmd of [cmds.macos, cmds.linux]) {
        expect(cmd).toContain('https://rmm.example.com/api/v1/agents/install.sh');
        expect(cmd).toContain('--server "https://rmm.example.com"');
        expect(cmd).toContain('--token "enroll_abc123"');
      }
      // The script auto-detects the OS; both platforms get the same command.
      expect(cmds.macos).toBe(cmds.linux);
    });

    it('downloads to a mktemp path and verifies the shebang before sudo bash', () => {
      const { macos } = buildInstallCommands(base);
      // Guards against an intercepting device serving HTML where the script
      // should be: never pipe straight into bash, check for #! first.
      expect(macos).toContain('mktemp');
      expect(macos).toContain("grep -q '^#!'");
      expect(macos).not.toContain('| sudo bash');
    });

    it('scopes the connectivity error to the fetch + shebang check', () => {
      const { macos } = buildInstallCommands(base);
      expect(macos).toContain('Could not fetch the Breeze installer from https://rmm.example.com');
      // The fallback must wrap only the fetch/verify group: install.sh prints
      // its own precise errors, so a failure inside `sudo bash` must NOT
      // trigger the "could not fetch" message.
      expect(macos.indexOf('Could not fetch')).toBeLessThan(macos.indexOf('sudo bash'));
      // Must surface a failing exit code without closing the user's shell.
      expect(macos).toContain('false; }');
      expect(macos).not.toContain('exit 1');
    });

    it('sends the error to stderr and bounds the bootstrap fetch', () => {
      const { macos } = buildInstallCommands(base);
      // MDM/RMM log collectors split streams — the actionable message must
      // land on stderr like install.sh's own errors do.
      expect(macos).toContain('>&2');
      // Against a DROP-style firewall the user should not stare at a silent
      // prompt for curl's ~2min default connect timeout.
      expect(macos).toContain('--connect-timeout 10');
    });

    it('appends --enrollment-secret only when a secret is provided', () => {
      const withSecret = buildInstallCommands({ ...base, enrollmentSecret: 's3cret' });
      expect(withSecret.macos).toContain('--enrollment-secret "s3cret"');
      expect(buildInstallCommands(base).macos).not.toContain('--enrollment-secret');
    });
  });

  describe('Windows (PowerShell)', () => {
    it('stops on download failure via $ErrorActionPreference', () => {
      const { windows } = buildInstallCommands(base);
      expect(windows.startsWith("$ErrorActionPreference='Stop';")).toBe(true);
      expect(windows).toContain('Invoke-WebRequest');
      expect(windows).toContain('breeze-agent-windows-amd64.exe');
    });

    it('checks $LASTEXITCODE after every agent invocation', () => {
      const { windows } = buildInstallCommands(base);
      // Native exe failures do not throw in PowerShell — each of the three
      // agent steps (service install, enroll, service start) needs a check.
      expect(windows.match(/if\(\$LASTEXITCODE\)\{throw/g)).toHaveLength(3);
      expect(windows).toContain('enroll "enroll_abc123" --server "https://rmm.example.com"');
    });

    it('verifies the download is a real PE executable before running it', () => {
      const { windows } = buildInstallCommands(base);
      // The Windows analog of the unix shebang check: a captive portal's 200
      // HTML saved as breeze-agent.exe must be blamed on the network, not
      // surface as PowerShell's raw "not a valid application" exception.
      expect(windows).toContain('0x4D');
      expect(windows).toContain('0x5A');
      expect(windows).toContain('captive portal or web filter');
      // The MZ check must run before the first agent invocation.
      expect(windows.indexOf('0x4D')).toBeLessThan(windows.indexOf('service install'));
    });

    it('appends --enrollment-secret only when a secret is provided', () => {
      const withSecret = buildInstallCommands({ ...base, enrollmentSecret: 's3cret' });
      expect(withSecret.windows).toContain('--enrollment-secret "s3cret"');
      expect(buildInstallCommands(base).windows).not.toContain('--enrollment-secret');
    });

    it('installs a trust cert only when trustCertUrl is provided, before service install', () => {
      const withCert = buildInstallCommands({
        ...base,
        trustCertUrl: 'https://gh.example.com/dl/trust.cer',
      });
      expect(withCert.windows).toContain('https://gh.example.com/dl/trust.cer');
      expect(withCert.windows).toContain('certutil -addstore Root breeze-trust.cer');
      expect(withCert.windows.indexOf('certutil')).toBeLessThan(withCert.windows.indexOf('service install'));
      expect(buildInstallCommands(base).windows).not.toContain('certutil');
      // macOS/Linux path is untouched by this Windows-only option.
      expect(withCert.macos).toBe(buildInstallCommands(base).macos);
    });

    it('installs the user helper only when userHelperUrl is provided, after service install', () => {
      const withHelper = buildInstallCommands({
        ...base,
        userHelperUrl: 'https://gh.example.com/dl/breeze-user-helper-windows-amd64.exe',
      });
      expect(withHelper.windows).toContain('https://gh.example.com/dl/breeze-user-helper-windows-amd64.exe');
      expect(withHelper.windows).toContain('$env:ProgramFiles\\Breeze\\breeze-user-helper.exe');
      expect(withHelper.windows.indexOf('service install')).toBeLessThan(
        withHelper.windows.indexOf('breeze-user-helper.exe')
      );
      expect(buildInstallCommands(base).windows).not.toContain('breeze-user-helper.exe');
      // macOS/Linux path is untouched by this Windows-only option.
      expect(withHelper.macos).toBe(buildInstallCommands(base).macos);
    });

    it('downloads the watchdog as a sibling only when watchdogUrl is provided, before service install', () => {
      const withWatchdog = buildInstallCommands({
        ...base,
        watchdogUrl: 'https://gh.example.com/dl/breeze-watchdog-windows-amd64.exe',
      });
      expect(withWatchdog.windows).toContain('https://gh.example.com/dl/breeze-watchdog-windows-amd64.exe');
      expect(withWatchdog.windows).toContain('-OutFile breeze-watchdog.exe');
      // Must land next to breeze-agent.exe BEFORE service install so the agent's
      // sibling-watchdog lookup finds it and skips the LanternOps download.
      expect(withWatchdog.windows.indexOf('breeze-watchdog.exe')).toBeLessThan(
        withWatchdog.windows.indexOf('service install')
      );
      expect(buildInstallCommands(base).windows).not.toContain('breeze-watchdog.exe');
      // macOS/Linux path is untouched by this Windows-only option.
      expect(withWatchdog.macos).toBe(buildInstallCommands(base).macos);
    });
  });

  describe('Linux per-user install (linuxBinaryUrl)', () => {
    it('keeps the install.sh flow when linuxBinaryUrl is not provided', () => {
      const { linux, macos } = buildInstallCommands(base);
      expect(linux).toBe(macos);
      expect(linux).toContain('/api/v1/agents/install.sh');
      expect(linux).not.toContain('systemctl --user');
    });

    it('switches Linux to a direct-download per-user systemd service when linuxBinaryUrl is set', () => {
      const cmds = buildInstallCommands({
        ...base,
        linuxBinaryUrl: 'https://gh.example.com/dl/breeze-agent-linux-amd64',
      });
      // Downloads the provided binary directly, not install.sh.
      expect(cmds.linux).toContain('https://gh.example.com/dl/breeze-agent-linux-amd64');
      expect(cmds.linux).not.toContain('/api/v1/agents/install.sh');
      // Per-user systemd, not a root system service.
      expect(cmds.linux).toContain('systemctl --user enable --now breeze-agent');
      expect(cmds.linux).toContain('.config/systemd/user/breeze-agent.service');
      // Refuses to run as root (would target root's user manager).
      expect(cmds.linux).toContain('"$(id -u)" = 0');
      // ELF-magic guard against intercepted downloads.
      expect(cmds.linux).toContain('7f454c46');
      // Sets XDG_RUNTIME_DIR so `systemctl --user` works from a su/SSH shell
      // that isn't a full login session (else "cannot connect to user bus").
      expect(cmds.linux).toContain('export XDG_RUNTIME_DIR=');
      expect(cmds.linux.indexOf('XDG_RUNTIME_DIR')).toBeLessThan(
        cmds.linux.indexOf('systemctl --user daemon-reload')
      );
      expect(cmds.linux).toContain('enroll "enroll_abc123" --server "https://rmm.example.com"');
      // Windows and macOS are unaffected.
      expect(cmds.macos).toBe(buildInstallCommands(base).macos);
      expect(cmds.windows).toBe(buildInstallCommands(base).windows);
    });

    it('fetches the OpenH264 lib next to the binary only when openh264Url is set', () => {
      const withLib = buildInstallCommands({
        ...base,
        linuxBinaryUrl: 'https://gh.example.com/dl/breeze-agent-linux-amd64',
        openh264Url: 'https://gh.example.com/dl/libopenh264-2.4.1-linux64.7.so',
      });
      expect(withLib.linux).toContain('https://gh.example.com/dl/libopenh264-2.4.1-linux64.7.so');
      expect(withLib.linux).toContain('.local/bin/libopenh264-2.4.1-linux64.7.so');
      // Must be placed before enroll/service start so the encoder is ready.
      expect(withLib.linux.indexOf('libopenh264')).toBeLessThan(withLib.linux.indexOf('enroll'));
      // Not present when the URL is omitted.
      const noLib = buildInstallCommands({
        ...base,
        linuxBinaryUrl: 'https://gh.example.com/dl/breeze-agent-linux-amd64',
      });
      expect(noLib.linux).not.toContain('libopenh264');
    });

    it('appends --enrollment-secret to the Linux per-user enroll only when provided', () => {
      const withSecret = buildInstallCommands({
        ...base,
        linuxBinaryUrl: 'https://gh.example.com/dl/breeze-agent-linux-amd64',
        enrollmentSecret: 's3cret',
      });
      expect(withSecret.linux).toContain('--enrollment-secret "s3cret"');
      const noSecret = buildInstallCommands({
        ...base,
        linuxBinaryUrl: 'https://gh.example.com/dl/breeze-agent-linux-amd64',
      });
      expect(noSecret.linux).not.toContain('--enrollment-secret');
    });
  });

  it('strips trailing slashes from apiUrl and ghBase', () => {
    const cmds = buildInstallCommands({
      ...base,
      apiUrl: 'https://rmm.example.com/',
      ghBase: 'https://gh.example.com/dl/',
    });
    expect(cmds.macos).toContain('https://rmm.example.com/api/v1/agents/install.sh');
    expect(cmds.macos).not.toContain('com//');
    expect(cmds.windows).toContain('https://gh.example.com/dl/breeze-agent-windows-amd64.exe');
  });
});
