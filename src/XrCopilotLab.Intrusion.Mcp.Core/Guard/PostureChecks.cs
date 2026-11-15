using XrCopilotLab.Intrusion.Mcp.Core.Analysis;
using XrCopilotLab.Intrusion.Mcp.Core.Audit;
using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Queries;

namespace XrCopilotLab.Intrusion.Mcp.Core.Guard;

/// <summary>
/// One thing to fix or to know about the host's protection. <c>Id</c> is stable (an agent or a page can key on it);
/// <c>Evidence</c> says what in the configuration or in the attacks of the period made the check fire; <c>Fix</c> is the
/// command that solves it with this package, when there is one. Nothing here is applied: it is advice.
/// </summary>
public sealed record PostureFinding(string Id, string Severity, string Area, string Title, string Evidence, string Recommendation, string? Fix);

/// <summary>
/// The checks behind <c>intrusion_posture</c>: the host's configuration (<see cref="HostFacts"/>) read against what
/// attacked it in the period (<see cref="SummaryResult"/>). A check speaks only when it has something to say, and its
/// severity grows with the evidence: SSH with passwords is Medium on a quiet host, High under brute force, Critical
/// once someone got in. Pure.
/// </summary>
public static class PostureChecks
{
    /// <summary>Services nobody should reach from the internet: no password, a known worm target, or a database.</summary>
    public static readonly IReadOnlyDictionary<int, string> RiskyPorts = new Dictionary<int, string>
    {
        [23] = "Telnet", [445] = "SMB", [3389] = "RDP", [5900] = "VNC", [3306] = "MySQL", [5432] = "PostgreSQL",
        [1433] = "SQL Server", [6379] = "Redis", [27017] = "MongoDB", [9200] = "Elasticsearch", [11211] = "Memcached",
        [2375] = "Docker API", [1883] = "MQTT",
    };

    public const int StaleRulesDays = 3;

    /// <summary>A VPN user silent this long is probably a device nobody uses any more, and its key still opens the network.</summary>
    public const int UnusedVpnDays = 60;

    // The findings that fire on the host's configuration alone. The others (incidents, probes, a slow brute force, what
    // the web firewall would have blocked, a VPN user abroad) need the attacks of the period: when they stop firing, the
    // attacks ended, nobody fixed anything.
    private static readonly HashSet<string> ConfigurationIds = new(StringComparer.Ordinal)
    {
        "lab-image", "ssh-password-auth", "ssh-root-login", "fail2ban-missing", "waf-missing", "ids-rules-stale", "ids-missing",
        "host-monitor-missing", "firewall-off", "vpn-unused-users", "vpn-endpoint-missing", "connection-temporary", "connection-tunnel-open",
    };
    private static readonly string[] ConfigurationPrefixes =
        ["exposed-industrial-", "exposed-service-", "exposed-ai-", "guardian-stopped-", "log-unreadable-"];

    /// <summary>True when the finding with this id fires on the configuration alone: once it is fixed it stops firing,
    /// so advice that came from it can be verified (<see cref="Advice.AdviceVerifier"/>).</summary>
    public static bool ReadsConfiguration(string id) =>
        ConfigurationIds.Contains(id) || AuditChecks.VerifiableIds.Contains(id) || ConfigurationPrefixes.Any(p => id.StartsWith(p, StringComparison.Ordinal));

    public static IReadOnlyList<PostureFinding> Evaluate(HostFacts facts, SummaryResult attacks, ConnectionInfo? connection = null, VpnResult? vpn = null)
    {
        var findings = new List<PostureFinding>();
        var g = facts.Guardians.ToDictionary(x => x.Name, StringComparer.Ordinal);
        bool Active(string name) => g.TryGetValue(name, out var x) && x.Installed && x.Running != false;
        bool Has(string type) => attacks.ByAttackType.Any(t => t.Type == type);
        int Addresses(string type) => attacks.ByAttackType.FirstOrDefault(t => t.Type == type)?.Addresses ?? 0;
        var hours = (int)Math.Round((attacks.Period.To - attacks.Period.From).TotalHours);
        var period = hours % 24 == 0 ? $"{hours / 24} day(s)" : $"{hours} hour(s)";

        // ---- The lab's test server first: built to be attacked, it must never carry a real network. Only its marker says so. ----
        if (facts.Lab is { } lab)
        {
            var demoUsers = lab.DemoVpnUsers.Where(u => facts.Vpn?.Peers.Any(p => p.Name == u) == true).ToList();
            var evidence = new List<string> { $"Lab marker present ({lab.Name})." };
            if (lab.Note.Length > 0) evidence.Add(lab.Note.TrimEnd('.') + ".");
            if (demoUsers.Count > 0) evidence.Add($"VPN users added by the lab, whose keys the attacker has on purpose: {string.Join(", ", demoUsers)}.");
            evidence.AddRange(lab.Demo.Select(d => d.TrimEnd('.') + "."));
            findings.Add(new("lab-image", nameof(Severity.Critical), "lab", "This is the Docker lab's test server, built to be attacked",
                string.Join(" ", evidence),
                "Do not connect a real network, real users or a real site to it. For a real server (a VPS, a mini PC, a container) "
                + "install the package with install.sh, or build a container without the lab's files: same toolkit, same guardians, "
                + "no demo users and no keys given away.",
                demoUsers.Count > 0 ? string.Join(" && ", demoUsers.Select(u => $"sudo xrc-vpn revoke {u}")) : null));
        }

        // ---- Incidents first: someone is or was inside. One finding per way in, with the addresses. ----
        void Incident(string id, string title, IReadOnlyList<IpReport> who, string recommendation)
        {
            if (who.Count == 0) return;
            var list = string.Join("; ", who.OrderByDescending(r => r.LastSeen).Take(5)
                .Select(r => $"{r.Ip} ({r.Location.City}, {r.Location.Country}), last seen {r.LastSeen:u}"));
            findings.Add(new(id, nameof(Severity.Critical), "incident", title, (who.Count > 5 ? $"{who.Count} addresses, the latest: " : "") + list + ".",
                recommendation, null));
        }
        Incident("incident-ssh-login", "Someone got in over SSH after guessing the password",
            attacks.TopAttackers.Where(r => r.AttackTypes.Contains(nameof(AttackType.LoginAfterFailures))
                                         || r.HostActivity.Any(h => h.LinkedBy == "ssh-session")).ToList(),
            "Treat the host as compromised: change the password of the account it used, remove SSH keys you do not know, "
            + "look for programs started from /tmp or /dev/shm, and ban the address.");
        Incident("incident-web-exploit", "A web attack ran commands on the host",
            attacks.TopAttackers.Where(r => r.HostActivity.Any(h => h.LinkedBy == "web-exploit")).ToList(),
            "The web application has a hole that runs commands: update it or take the page offline, and check what the web server's user (www-data) can reach.");
        Incident("incident-c2", "The host is calling a malware controller",
            attacks.TopAttackers.Where(r => r.AttackTypes.Contains(nameof(AttackType.CommandAndControl))).ToList(),
            "Disconnect it from the internet, keep its disk for analysis, and rebuild it from a clean backup: a host that calls a controller obeys someone else.");

        // ---- SSH ----
        if (facts.Ssh is { } ssh && facts.Listening.Any(p => p.Port == ssh.Port && p.Public))
        {
            var brute = Addresses(nameof(AttackType.SshBruteForce)) + Addresses(nameof(AttackType.DistributedSshBruteForce));
            if (ssh.PasswordAuthentication)
            {
                var severity = Has(nameof(AttackType.LoginAfterFailures)) ? Severity.Critical : brute > 0 ? Severity.High : Severity.Medium;
                findings.Add(new("ssh-password-auth", severity.ToString(), "ssh", "SSH accepts passwords from the internet",
                    $"PasswordAuthentication yes on port {ssh.Port}; {brute} address(es) tried passwords in the last {period}." + (ssh.Note is null ? "" : $" ({ssh.Note})"),
                    "Log in with SSH keys and set PasswordAuthentication no; or let SSH answer only from the office or a VPN.",
                    "printf 'PasswordAuthentication no\\n' | sudo tee /etc/ssh/sshd_config.d/10-no-passwords.conf && sudo systemctl reload ssh"));
            }
            if (ssh.PermitRootLogin is "yes")
                findings.Add(new("ssh-root-login", nameof(Severity.Medium), "ssh", "root can log in over SSH",
                    "PermitRootLogin yes: root is the first account every brute force tries.",
                    "Log in as a named user and use sudo; set PermitRootLogin no.",
                    "printf 'PermitRootLogin no\\n' | sudo tee /etc/ssh/sshd_config.d/10-no-root.conf && sudo systemctl reload ssh"));
            if (!Active("fail2ban"))
                findings.Add(new("fail2ban-missing", (brute > 0 ? Severity.High : Severity.Medium).ToString(), "ssh", "Nothing bans SSH brute force",
                    $"fail2ban is {(g.TryGetValue("fail2ban", out var f) && f.Installed ? "installed but not running" : "not installed")}; {brute} address(es) tried passwords.",
                    "Install fail2ban with its sshd jail: an address that fails five times is kept out for a while.",
                    "sudo ./install.sh --with fail2ban"));
        }

        // A slow brute force stays under fail2ban's threshold; CrowdSec saw it but, with no bouncer, nothing acted on it.
        var unbannedBrute = attacks.TopAttackers.Where(r => r.AttackTypes.Contains(nameof(AttackType.SshBruteForce)) && r.Bans == 0
                                                          && r.CrowdsecScenarios.Any(s => s.Contains("slow", StringComparison.Ordinal))).ToList();
        if (unbannedBrute.Count > 0)
            findings.Add(new("slow-brute-force-unbanned", nameof(Severity.High), "ssh", "A slow brute force was never banned",
                $"{string.Join(", ", unbannedBrute.Select(r => r.Ip))}: CrowdSec recognised it ({string.Join(", ", unbannedBrute.SelectMany(r => r.CrowdsecScenarios).Distinct())}), fail2ban never banned it.",
                "A try every few minutes stays under fail2ban's findtime. Let CrowdSec act on what it sees (its firewall bouncer), or raise fail2ban's findtime for sshd to a few hours.",
                null));

        // ---- Exposed services: the VPN is the way to keep reaching them from outside ----
        var vpnOn = Active("wireguard") && vpn is { Up: true };
        var behindVpn = vpnOn ? " The VPN is already here: close the port to the internet and let the people who need it connect through the VPN."
                              : " A VPN lets the people who need it keep reaching it from outside.";
        // When the VPN is up AND UFW is on, the concrete fix closes the port to the internet and allows it only from the
        // VPN's own network and the on-site LANs it joins — so remote staff (via the VPN) and people in the office keep
        // reaching it, nobody else does. Only when UFW is "blocking": this package never enables UFW, so otherwise the
        // rules would not take effect. (UFW also does not cover ports Docker publishes with -p: bind-to-internal still applies.)
        var ufwBlocking = g.TryGetValue("ufw", out var ufwG) && ufwG.Mode == "blocking";
        var allowFrom = new List<string>();
        if (vpn is not null)
        {
            allowFrom.Add(string.IsNullOrWhiteSpace(vpn.Subnet) ? "10.88.0.0/24" : vpn.Subnet);
            allowFrom.AddRange(vpn.Lan);
        }
        if (vpnOn && !ufwBlocking)
            behindVpn += " Turn UFW on first (this package never does it for you), then close the port and allow the VPN.";
        string? VpnFix(int port)
        {
            if (!vpnOn) return "sudo ./install.sh --with wireguard";
            if (!ufwBlocking) return null;  // the rules would not take effect until UFW is enabled, and we never enable it
            var allows = string.Join(" && ", allowFrom.Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => $"sudo ufw allow from {n} to any port {port}"));
            return $"{allows} && sudo ufw deny {port}";
        }
        foreach (var p in facts.Listening.Where(p => p.Public && AttackCatalog.IndustrialPorts.ContainsKey(p.Port)).DistinctBy(p => p.Port))
            findings.Add(new($"exposed-industrial-{p.Port}", nameof(Severity.Critical), "industrial", $"{AttackCatalog.IndustrialPorts[p.Port]} is open to the network",
                $"Port {p.Port} listens on {p.Address}. Industrial protocols have no password: whoever reaches the port can send commands to the plant.",
                "Never publish it on the internet: reach it only through a VPN, from the plant's own network." + behindVpn, VpnFix(p.Port)));
        foreach (var p in facts.Listening.Where(p => p.Public && RiskyPorts.ContainsKey(p.Port)).DistinctBy(p => p.Port))
            findings.Add(new($"exposed-service-{p.Port}", nameof(Severity.High), "network", $"{RiskyPorts[p.Port]} is open to the network",
                $"Port {p.Port} listens on {p.Address}.",
                "Bind it to 127.0.0.1 or to the internal network only." + behindVpn, VpnFix(p.Port)));
        if (Has(nameof(AttackType.IndustrialProtocolProbe)))
            findings.Add(new("industrial-probes", nameof(Severity.Medium), "industrial", "Someone is looking for plant systems",
                $"{Addresses(nameof(AttackType.IndustrialProtocolProbe))} address(es) tried industrial ports (Modbus, S7, IEC 104…) in the last {period}.",
                "Check that no PLC or SCADA port is reachable from the internet, here or on other hosts of the network.", null));

        // ---- AI services ----
        // Ollama, LM Studio, Gradio, ComfyUI and the vector databases answer without a password by default: whoever reaches
        // the port uses the models (and the GPU), reads the documents indexed, downloads or deletes models.
        foreach (var p in facts.Listening.Where(p => p.Public && AttackCatalog.AiServicePorts.ContainsKey(p.Port)).DistinctBy(p => p.Port))
            findings.Add(new($"exposed-ai-{p.Port}", nameof(Severity.High), "ai", $"{AttackCatalog.AiServicePorts[p.Port]} is open to the network",
                $"Port {p.Port} listens on {p.Address}. It has no password by default: anyone who reaches it can use the models, read what is " +
                (Has(nameof(AttackType.AiServiceProbe)) ? $"indexed, or replace a model. {Addresses(nameof(AttackType.AiServiceProbe))} address(es) looked for AI services in the last {period}."
                    : "indexed, or replace a model."),
                (p.Port == 11434 ? "Let Ollama listen on 127.0.0.1 only (OLLAMA_HOST=127.0.0.1 in its service) and put the applications that use it on the same host or behind an authenticated proxy."
                    : "Bind it to 127.0.0.1 and reach it through the application that uses it, or through an authenticated proxy.") + behindVpn,
                VpnFix(p.Port)));
        if (Has(nameof(AttackType.AiServiceProbe)))
            findings.Add(new("ai-probes", nameof(Severity.Low), "ai", "Someone is looking for AI services",
                $"{Addresses(nameof(AttackType.AiServiceProbe))} address(es) looked for Ollama, OpenAI-compatible APIs, MCP servers or vector databases in the last {period}.",
                "Check that no model, MCP server or vector database is reachable without a password, here or on other hosts of the network.", null));
        if (Has(nameof(AttackType.AiPromptInjection)))
            findings.Add(new("ai-prompt-injection", nameof(Severity.Medium), "ai", "Someone wrote instructions for an AI",
                $"{Addresses(nameof(AttackType.AiPromptInjection))} address(es) wrote text meant for an AI in the last {period}: in page addresses, " +
                "SSH account names, commands, or the messages sent to a chatbot. It may target the assistant that reads these logs, or a chatbot of yours.",
                "The assistant reports that text as evidence and does not follow it. If you run a chatbot or an agent that reads what visitors send " +
                "(forms, emails, tickets), treat that input as untrusted: never let it trigger an action without a person's approval.", null));

        // ---- Web ----
        if (g.TryGetValue("nginx", out var nginx) && nginx.Installed)
        {
            var web = Addresses(nameof(AttackType.WebExploitAttempt)) + Addresses(nameof(AttackType.WebVulnerabilityScan));
            if (!(g.TryGetValue("modsecurity", out var waf) && waf.Installed && waf.Mode is not null))
                findings.Add(new("waf-missing", (Has(nameof(AttackType.WebExploitAttempt)) ? Severity.Medium : Severity.Low).ToString(), "web",
                    "No web application firewall reads the requests",
                    $"{web} address(es) scanned or attacked the site in the last {period}; the access log does not show request bodies, where many attacks travel.",
                    "Install ModSecurity with the OWASP Core Rule Set in detection mode: it sees SQL injection, XSS and command injection in every request, POST bodies included, and blocks nothing.",
                    "sudo ./install.sh --with modsecurity"));
            else if (waf.Mode == "detection" && attacks.Totals.WafAlerts > 0)
                findings.Add(new("waf-detection-only", nameof(Severity.Low), "web", "The web firewall only watches",
                    $"ModSecurity is in detection mode: in the last {period} it would have blocked {attacks.Totals.WafAlerts} request(s).",
                    "Keep watching for a couple of weeks; if what it would have blocked contains no request of your own users, it can be switched to blocking.",
                    null));
        }

        // ---- The guardians themselves ----
        foreach (var x in facts.Guardians.Where(x => x.Installed && x.Running == false))
        {
            var unit = x.Name == "wireguard" ? "wg-quick@wgxrc" : x.Name;
            findings.Add(new($"guardian-stopped-{x.Name}", nameof(Severity.High), "guardians", $"{x.Name} is installed but not running",
                x.Name == "wireguard" ? "The VPN's interface is down: nobody can connect." : "Its service is not active: it sees nothing.",
                $"Start it and check why it stopped (journalctl -u {unit}).", $"sudo systemctl enable --now {unit}"));
        }
        foreach (var x in facts.Guardians.Where(x => x.Installed && x.LogExists && !x.LogReadable))
            findings.Add(new($"log-unreadable-{x.Name}", nameof(Severity.Medium), "guardians", $"The toolkit cannot read {x.Name}'s log",
                $"{x.Log} exists but is not readable by the toolkit's service (group adm).",
                "Make the log readable by the group adm, as install.sh --with does.", $"sudo ./install.sh --with {x.Name}"));
        if (g.TryGetValue("suricata", out var ids) && ids.Installed && ids.RulesUpdated is { } updated && facts.Time - updated > TimeSpan.FromDays(StaleRulesDays))
            findings.Add(new("ids-rules-stale", nameof(Severity.Medium), "network", "Suricata's rules are old",
                $"Last update {updated:u}: new attacks are published every day.",
                "Check the nightly update (xrcopilotlab-suricata-update.timer) and the host's internet access.", "sudo suricata-update && sudo suricatasc -c reload-rules"));
        if (!Active("suricata"))
            findings.Add(new("ids-missing", nameof(Severity.Low), "network", "No network IDS",
                "Suricata is not running: nobody would notice the host calling a malware controller.",
                "Install Suricata (needs about 1.5 GB of RAM).", "sudo ./install.sh --with suricata"));
        if (!Active("falco"))
            findings.Add(new("host-monitor-missing", nameof(Severity.Low), "host", "Nothing watches what happens inside the host",
                "Falco is not running: after a break-in, keys read, accounts added or a miner started would go unseen.",
                "Install Falco (about 230 MB of RAM, kernel 5.8+).", "sudo ./install.sh --with falco"));
        if (g.TryGetValue("ufw", out var ufw) && ufw.Mode != "blocking")
            findings.Add(new("firewall-off", nameof(Severity.Low), "network", "The host firewall is off",
                $"UFW is {(ufw.Installed ? "installed but not enabled" : "not installed")}: every listening service is reachable.",
                "Allow SSH first, then enable it (ufw allow OpenSSH; ufw enable). This package never enables it for you: a mistake locks everyone out.", null));
        var unlinked = attacks.HostAlerts.Count(a => a.Ip is null && a.Severity is nameof(Severity.Critical));
        if (unlinked > 0)
            findings.Add(new("host-alerts-unlinked", nameof(Severity.High), "host", "Critical activity on the host with no known origin",
                $"{unlinked} critical Falco alert(s) could not be tied to a login or a web attack.",
                "Look at them (intrusion_host_activity unlinkedOnly=true): a cron job you know, or an intruder who came in a way the logs do not show.", null));

        // ---- The host itself: what changed on it since the customer last said "this is how it should be" ----
        if (facts.Audit is { } audit)
            findings.AddRange(AuditChecks.Evaluate(audit, facts.Time,
                findings.Any(f => f.Id is "incident-ssh-login" or "incident-web-exploit") ? attacks.Period.From : null));
        else
            findings.Add(new("audit-missing", nameof(Severity.Low), AuditChecks.Area, "Nothing checks the host itself for signs of a break-in",
                "The logs show who knocked and who was let in. They do not show an SSH key added, a new account, a job that starts by itself "
                + "or a program running from /tmp: what an intruder leaves to come back, also after cleaning the logs.",
                "Install the audit: every 15 minutes it reads accounts, SSH keys, scheduled jobs, services and running programs, as root and "
                + "without changing anything, and says what is different from the day you accepted the host as it was.",
                "sudo ./install.sh --with audit"));

        // ---- The VPN: who holds a key is the customer's decision; these say when a key looks out of place ----
        if (vpn is { Installed: true })
        {
            var away = vpn.Peers.Where(p => !p.ExpectedCountry && p.LastHandshake >= attacks.Period.From).ToList();
            if (away.Count > 0)
                findings.Add(new("vpn-unexpected-country", nameof(Severity.High), "vpn", "A VPN user connected from an unexpected country",
                    string.Join("; ", away.Select(p => $"{p.Name} from {p.RemoteIp} ({p.Location?.City}, {p.Location?.Country}), last {p.LastHandshake:u}")) + ".",
                    "Ask the person if they are travelling. If not, the device or its configuration was taken: revoke it now, the key stops working at once, "
                    + "and give the person a new one.",
                    away.Count == 1 ? $"sudo xrc-vpn revoke {away[0].Name}" : null));
            var unused = vpn.Peers.Where(p => p.LastHandshake is { } at ? facts.Time - at > TimeSpan.FromDays(UnusedVpnDays)
                                                                      : facts.Time - p.Created > TimeSpan.FromDays(30)).ToList();
            if (unused.Count > 0)
                findings.Add(new("vpn-unused-users", nameof(Severity.Low), "vpn", "VPN users nobody uses",
                    string.Join("; ", unused.Select(p => p.LastHandshake is { } at ? $"{p.Name}: last connected {at:u}" : $"{p.Name}: never connected, added {p.Created:u}")) + ".",
                    $"A key that has not been used for {UnusedVpnDays} days is often an old phone or someone who left, and it still opens the network: revoke it.",
                    unused.Count == 1 ? $"sudo xrc-vpn revoke {unused[0].Name}" : null));
            if (vpn.Up && vpn.Endpoint is null)
                findings.Add(new("vpn-endpoint-missing", nameof(Severity.Low), "vpn", "The VPN has no public address yet",
                    "Nobody can be given a configuration until it is set.",
                    "Set the public IP or name of the office (the router must forward the VPN's UDP port to this server).",
                    "sudo xrc-vpn endpoint <the office's public IP or name>"));
        }

        // ---- How XRCopilotLab reaches the server ----
        if (connection?.Mode == "tunnel")
            findings.Add(new("connection-temporary", nameof(Severity.Low), "connection", "XRCopilotLab uses a temporary test address",
                $"{connection.Url}: a Dev Tunnels address, which changes if the tunnel is recreated.",
                "Fine for a trial. For production publish the API on the customer's domain (nginx with TLS) and set Connection:PublicUrl.", null));
        else if (connection is { Mode: "domain", TunnelUrl: not null })
            findings.Add(new("connection-tunnel-open", nameof(Severity.Medium), "connection", "A test tunnel is still open beside the domain",
                $"Domain {connection.Url}; tunnel {connection.TunnelUrl}: a second way in to the API that nobody needs any more.",
                "Close the test tunnel: XRCopilotLab must use the domain only.", null));

        // The lab's own finding leads: whatever else is wrong, this host must not carry a real network.
        return findings
            .OrderByDescending(f => f.Area == "lab")
            .ThenByDescending(f => Enum.Parse<Severity>(f.Severity))
            .ThenBy(f => f.Area, StringComparer.Ordinal)
            .ThenBy(f => f.Id, StringComparer.Ordinal)
            .ToList();
    }
}
