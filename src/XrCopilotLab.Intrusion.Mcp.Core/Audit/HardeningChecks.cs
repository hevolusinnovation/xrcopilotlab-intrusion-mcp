using XrCopilotLab.Intrusion.Mcp.Core.Guard;
using XrCopilotLab.Intrusion.Mcp.Core.Models;

namespace XrCopilotLab.Intrusion.Mcp.Core.Audit;

/// <summary>
/// What is wrong with how the host is kept, read from the audit's <see cref="HardeningFacts"/>: security updates that
/// wait, a firewall that is on and lets everything in, a port Docker opens behind the firewall's back, a container
/// that can take over the host, a certificate about to expire. Nothing here needs an attack to be true, and nothing
/// goes quiet with <c>xrc-audit accept</c>: it ends when the host is fixed. Pure.
/// </summary>
public static class HardeningChecks
{
    public const string Area = "hardening";

    /// <summary>Apt looks for updates every day on a host that is looked after: silent this long, nobody is told about new fixes.</summary>
    public const int UncheckedDays = 14;

    /// <summary>Let's Encrypt renews a certificate with 30 days left: closer than this, the renewal is failing.</summary>
    public const int CertificateWarningDays = 21;
    public const int CertificateUrgentDays = 7;

    /// <summary>Every finding here reads the configuration alone: fixed, it stops firing, so advice on it can be verified.</summary>
    public static readonly IReadOnlyList<string> VerifiableIds =
    [
        "updates-security-pending", "updates-not-checked", "updates-auto-off", "reboot-required", "firewall-default-allow", "firewall-unused-rules",
        "docker-bypasses-firewall", "docker-host-access", "docker-group-root", "tls-cert-expiring", "tls-old-protocols",
    ];

    private const int Shown = 8;

    /// <summary><paramref name="listening"/>: the host's TCP ports, when known; without them the firewall's unused rules are not judged.</summary>
    public static IReadOnlyList<PostureFinding> Evaluate(HardeningFacts facts, DateTimeOffset now, IReadOnlyList<ListeningPort>? listening = null)
    {
        var findings = new List<PostureFinding>();
        static string Safe(string text) => AuditChecks.Safe(text);

        // ---- Updates ----
        if (facts.Updates is { } updates)
        {
            if (updates.Security > 0)
            {
                var exposed = updates.Packages.Where(HardeningParsers.FacesNetwork).ToList();
                findings.Add(new("updates-security-pending", (exposed.Count > 0 ? Severity.High : Severity.Medium).ToString(), Area,
                    "Security updates are waiting",
                    $"{updates.Security} installed package(s) have a security fix that is not installed: {List(updates.Packages.Select(Safe), updates.Security)}."
                    + (exposed.Count > 0 ? $" Among them, what answers the network or gives root: {List(exposed.Select(Safe), exposed.Count)}." : ""),
                    "A hole is public from the day its fix comes out, and scanners look for the hosts that did not install it. Install the updates, "
                    + "then restart the services they touch (or the host, if it asks).",
                    "sudo apt-get update && sudo apt-get upgrade"));
            }
            var silent = updates.Checked is { } at ? now - at : (TimeSpan?)null;
            if (silent is null || silent > TimeSpan.FromDays(UncheckedDays))
                findings.Add(new("updates-not-checked", nameof(Severity.Medium), Area, "The host has not looked for updates",
                    (updates.Checked is { } last ? $"The package lists were last downloaded at {last:u}, {(int)silent!.Value.TotalDays} day(s) ago"
                                                  : "The package lists were never downloaded, as far as apt's files say")
                    + ": the host does not know which fixes came out since, so the count of waiting updates says little.",
                    "Download the lists and see what waits. If it happens again, apt's daily timer is off or the host cannot reach its archives.",
                    "sudo apt-get update"));
            if (!updates.Automatic)
                findings.Add(new("updates-auto-off", nameof(Severity.Low), Area, "Security updates are not installed by themselves",
                    "unattended-upgrades is not installed or not switched on: every security fix waits for someone to log in and install it.",
                    "Let the host install the distribution's security fixes every night: it is what Debian and Ubuntu do by default, "
                    + "and it touches only the security archive.",
                    "sudo apt-get install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades"));
            if (updates.RebootRequired)
                findings.Add(new("reboot-required", nameof(Severity.Medium), Area, "An update waits for a restart",
                    "/run/reboot-required is there: a kernel or a system library was updated, and the old one, with its holes, is the one still running.",
                    "Restart the host in a quiet hour. Until then the fix is on the disk, not in memory.", null));
        }

        // ---- The firewall's own rules ----
        var firewall = facts.Firewall is { Enabled: true } ? facts.Firewall : null;
        if (firewall is { Incoming: "allow" })
            findings.Add(new("firewall-default-allow", nameof(Severity.High), Area, "The firewall is on and lets everything in",
                "UFW is enabled, but a connection no rule names is accepted (DEFAULT_INPUT_POLICY=ACCEPT): it protects nothing.",
                "Allow what must be reachable first (SSH above all), then make the default deny.",
                "sudo ufw allow OpenSSH && sudo ufw default deny incoming"));
        if (firewall is { RulesRead: true, Incoming: not "allow" })
        {
            if (listening is not null)
            {
                var used = listening.Select(p => p.Port).ToHashSet();
                var unused = firewall.Rules.Where(r => r.Action is "allow" or "limit" && r.From is "0.0.0.0/0" or "::/0" && r.Protocol is "tcp")
                    .SelectMany(HardeningParsers.SinglePorts).Distinct().Where(p => !used.Contains(p)).Order().ToList();
                if (unused.Count > 0)
                    findings.Add(new("firewall-unused-rules", nameof(Severity.Low), Area, "The firewall lets in ports nothing listens on",
                        $"UFW allows anyone on TCP port(s) {List(unused.Select(p => p.ToString(System.Globalization.CultureInfo.InvariantCulture)), unused.Count)}, "
                        + "and no program listens there now.",
                        "A rule left from a service that is gone is a door already open for the next program that takes the port. "
                        + "Remove the ones you do not need (sudo ufw status numbered, then sudo ufw delete <number>).", null));
            }
            // Docker writes its own rules before UFW's: a published port is reachable whatever UFW says.
            var behind = facts.Containers.Where(c => !c.HostNetwork)
                .Select(c => (c.Name, Ports: c.Ports.Where(p => !firewall.Rules.Any(r => HardeningParsers.AllowsAnyone(r, p))).ToList()))
                .Where(c => c.Ports.Count > 0).ToList();
            if (behind.Count > 0)
                findings.Add(new("docker-bypasses-firewall", nameof(Severity.High), Area, "Docker opens ports the firewall does not allow",
                    List(behind.Select(c => $"{Safe(c.Name)}: {string.Join(", ", c.Ports)}"), behind.Count)
                    + ". UFW is on and has no rule that lets these ports in, but Docker publishes a port with its own rules, which come before UFW's: "
                    + "they are reachable from outside all the same.",
                    "Publish the port on the host only (-p 127.0.0.1:8080:80, or 127.0.0.1:8080:80 in compose) and put nginx or the VPN in front; "
                    + "or, if it must be public, say so in UFW too, so the firewall's rules tell the truth.", null));
        }

        // ---- Containers ----
        var powerful = facts.Containers.Select(c => (Container: c, Why: Powers(c))).Where(c => c.Why.Count > 0).ToList();
        if (powerful.Count > 0)
        {
            var reachable = powerful.Any(c => c.Container.HostNetwork || c.Container.Ports.Count > 0);
            findings.Add(new("docker-host-access", (reachable ? Severity.High : Severity.Medium).ToString(), Area, "A container can take over the host",
                List(powerful.Select(c => $"{Safe(c.Container.Name)} ({Safe(c.Container.Image)}): {string.Join(", ", c.Why)}"), powerful.Count) + "."
                + (reachable ? " At least one of them answers the network." : ""),
                "Whoever breaks into such a container is root on the host: the container's walls are gone. Keep it only for what truly needs it "
                + "(a monitoring agent, this toolkit's own Docker install), never for a site or an application that answers the internet.", null));
        }
        if (facts.DockerGroup.Count > 0)
            findings.Add(new("docker-group-root", nameof(Severity.Low), Area, "Accounts that become root through Docker",
                $"{List(facts.DockerGroup.Select(Safe), facts.DockerGroup.Count)}: in the group docker, without sudo rights.",
                "Whoever may talk to Docker starts a container with the host's disk inside it, and is root with no password asked. "
                + "Keep in the group only who would be given sudo anyway.",
                facts.DockerGroup.Count == 1 ? $"sudo gpasswd -d {Safe(facts.DockerGroup[0])} docker" : null));

        // ---- TLS ----
        var expiring = facts.Certificates.Where(c => c.Expires - now < TimeSpan.FromDays(CertificateWarningDays)).OrderBy(c => c.Expires).ToList();
        if (expiring.Count > 0)
        {
            var left = expiring[0].Expires - now;
            findings.Add(new("tls-cert-expiring", (left < TimeSpan.FromDays(CertificateUrgentDays) ? Severity.High : Severity.Medium).ToString(), Area,
                left <= TimeSpan.Zero ? "A certificate has expired" : "A certificate is about to expire",
                List(expiring.Select(c => $"{Safe(c.Names)} ({Safe(c.File)}): "
                    + (c.Expires <= now ? $"expired at {c.Expires:u}" : $"expires at {c.Expires:u}, in {(int)(c.Expires - now).TotalDays} day(s)")), expiring.Count) + ".",
                "Once it expires every browser shows a warning instead of the site, and people learn to click through warnings. Let's Encrypt renews "
                + "with 30 days left: this close, the renewal is failing (sudo certbot renew --dry-run says why).",
                expiring.All(c => c.File.StartsWith("/etc/letsencrypt/", StringComparison.Ordinal)) ? "sudo certbot renew && sudo systemctl reload nginx" : null));
        }
        if (facts.OldTlsProtocols.Count > 0)
            findings.Add(new("tls-old-protocols", nameof(Severity.Medium), Area, "The web server still accepts old TLS versions",
                $"{List(facts.OldTlsProtocols.Select(Safe), facts.OldTlsProtocols.Count)}. "
                + "SSLv3, TLS 1.0 and 1.1 have known attacks and no browser needs them any more.",
                "Accept only TLS 1.2 and 1.3 (ssl_protocols TLSv1.2 TLSv1.3;), then reload nginx.", null));

        return findings;
    }

    private static List<string> Powers(AuditContainer c)
    {
        var why = new List<string>();
        if (c.Privileged) why.Add("privileged");
        if (c.DockerSocket) why.Add("Docker's socket inside it");
        if (c.HostDisk) why.Add("the host's whole disk inside it");
        if (c.HostPid) why.Add("it sees the host's processes");
        return why;
    }

    private static string List(IEnumerable<string> items, int total)
    {
        var shown = items.Take(Shown).ToList();
        return string.Join("; ", shown) + (total > shown.Count ? $"; and {total - shown.Count} more" : "");
    }
}
