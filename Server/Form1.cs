using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

// BouncyCastle — AES-256-GCM
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace ChatServerGUI
{
    // ═══════════════════════════════════════════════════════
    //  Modèles
    // ═══════════════════════════════════════════════════════

    public class UserAccount
    {
        public string Username { get; set; }
        public string PasswordHash { get; set; }
        public string PasswordSalt { get; set; }
        public int FailedLogins { get; set; } = 0;
        public DateTime? LockedUntil { get; set; } = null;
        /// <summary>Clé publique X25519 persistante (Base64) pour le E2E.</summary>
        public string PublicKey { get; set; }
    }

    public class ConnectedClient
    {
        public TcpClient TcpClient { get; set; }
        public SslStream SslStream { get; set; }
        public string Username { get; set; }
        public string IP { get; set; }
        public string CurrentRoom { get; set; } = "général";
        public bool IsAuthenticated { get; set; } = false;
        public DateTime ConnectedAt { get; set; } = DateTime.Now;
        public byte[] SessionKey { get; set; }
        public DateTime LastPong { get; set; } = DateTime.Now;
        /// <summary>Clé publique E2E persistante (Base64) annoncée par le client à la connexion.</summary>
        public string E2EPublicKey { get; set; }

        // ═══════════════════════════════════════════════════════
        //  Déconnexion idempotente (atomique)
        // ═══════════════════════════════════════════════════════
        private int _disconnected = 0;

        public bool TryMarkDisconnected()
        {
            return Interlocked.CompareExchange(ref _disconnected, 1, 0) == 0;
        }

        public bool IsDisconnected => Volatile.Read(ref _disconnected) == 1;

        // ═══════════════════════════════════════════════════════
        //  Verrou d'écriture dédié par client
        // ═══════════════════════════════════════════════════════
        public readonly SemaphoreSlim WriteLock = new SemaphoreSlim(1, 1);

        // ═══════════════════════════════════════════════════════
        //  Rate-limiting par client
        // ═══════════════════════════════════════════════════════
        private readonly object _rateLock = new object();
        private readonly Queue<DateTime> _messageTimestamps = new Queue<DateTime>();

        public bool TryConsumeRateLimit(int maxPerWindow, double windowSeconds)
        {
            lock (_rateLock)
            {
                DateTime now = DateTime.UtcNow;
                DateTime cutoff = now.AddSeconds(-windowSeconds);
                while (_messageTimestamps.Count > 0 && _messageTimestamps.Peek() < cutoff)
                    _messageTimestamps.Dequeue();
                if (_messageTimestamps.Count >= maxPerWindow)
                    return false;
                _messageTimestamps.Enqueue(now);
                return true;
            }
        }

        public int CurrentRateCount
        {
            get { lock (_rateLock) return _messageTimestamps.Count; }
        }
    }

    public class ChatRoom
    {
        public string Name { get; set; }
        public List<string> History { get; set; } = new List<string>();
        public const int MaxHistory = 100;
        public void AddMessage(string msg)
        {
            History.Add(msg);
            if (History.Count > MaxHistory) History.RemoveAt(0);
        }
    }

    /// <summary>
    /// Transfert de fichier en cours — le serveur relaie les chunks entre expéditeur et destinataire(s).
    /// </summary>
    public class FileTransfer
    {
        public string TransferId { get; set; }
        public string SenderUsername { get; set; }
        public string TargetRoom { get; set; }
        public string TargetUsername { get; set; }
        public string FileName { get; set; }
        public long FileSize { get; set; }
        public string MimeType { get; set; }
        public int TotalChunks { get; set; }
        public int ReceivedChunks { get; set; }
        public DateTime StartedAt { get; set; } = DateTime.Now;
    }

    public enum BanType { Pseudo, IP, Temp }

    public class BanEntry
    {
        public BanType Type { get; set; }
        public string Value { get; set; }
        public string LinkedIP { get; set; }
        public string LinkedPseudo { get; set; }
        public DateTime Expiry { get; set; }

        public override string ToString()
        {
            switch (Type)
            {
                case BanType.Pseudo: return "👤  " + Value + (LinkedIP != null ? "  →  " + LinkedIP : "");
                case BanType.IP: return "🌐  " + Value + (LinkedPseudo != null ? "  (" + LinkedPseudo + ")" : "");
                case BanType.Temp: return "⏱  " + Value + "  (expire " + Expiry.ToString("HH:mm:ss") + ")";
                default: return Value;
            }
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Logging structuré vers fichier avec rotation
    // ═══════════════════════════════════════════════════════

    public class FileLogger : IDisposable
    {
        public enum LogLevel { DEBUG, INFO, WARN, ERROR, SECURITY }

        private readonly string _logDirectory;
        private readonly long _maxFileSize;
        private readonly int _maxFiles;
        private readonly object _lock = new object();
        private StreamWriter _writer;
        private string _currentFilePath;
        private DateTime _currentFileDate;
        private long _currentFileSize;
        private bool _disposed = false;

        public FileLogger(string logDirectory = null, long maxFileSizeMB = 10, int maxFiles = 30)
        {
            _logDirectory = logDirectory ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
            _maxFileSize = maxFileSizeMB * 1024 * 1024;
            _maxFiles = maxFiles;
            try
            {
                if (!Directory.Exists(_logDirectory))
                    Directory.CreateDirectory(_logDirectory);
            }
            catch { }
            OpenNewFile();
        }

        private void OpenNewFile()
        {
            try
            {
                _writer?.Flush();
                _writer?.Dispose();
                _currentFileDate = DateTime.Now.Date;
                string timestamp = DateTime.Now.ToString("yyyy-MM-dd_HHmmss");
                _currentFilePath = Path.Combine(_logDirectory, $"nexus_server_{timestamp}.log");
                _writer = new StreamWriter(_currentFilePath, append: true, encoding: Encoding.UTF8) { AutoFlush = true };
                _currentFileSize = new FileInfo(_currentFilePath).Length;
                string header = $"═══ NexusChat Server Log — Démarré le {DateTime.Now:yyyy-MM-dd HH:mm:ss} ═══";
                _writer.WriteLine(header);
                _currentFileSize += Encoding.UTF8.GetByteCount(header) + 2;
                CleanupOldFiles();
            }
            catch { _writer = null; }
        }

        private void CleanupOldFiles()
        {
            try
            {
                var logFiles = Directory.GetFiles(_logDirectory, "nexus_server_*.log")
                    .OrderByDescending(f => f).Skip(_maxFiles).ToList();
                foreach (var old in logFiles)
                    try { File.Delete(old); } catch { }
            }
            catch { }
        }

        private bool NeedsRotation()
        {
            return _currentFileSize >= _maxFileSize || DateTime.Now.Date != _currentFileDate;
        }

        public void Log(LogLevel level, string category, string message)
        {
            if (_disposed) return;
            string line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [{level,-8}] [{category,-12}] {message}";
            lock (_lock)
            {
                try
                {
                    if (_writer == null || NeedsRotation()) OpenNewFile();
                    if (_writer != null)
                    {
                        _writer.WriteLine(line);
                        _currentFileSize += Encoding.UTF8.GetByteCount(line) + 2;
                    }
                }
                catch { }
            }
        }

        public void Info(string category, string message) => Log(LogLevel.INFO, category, message);
        public void Warn(string category, string message) => Log(LogLevel.WARN, category, message);
        public void Error(string category, string message) => Log(LogLevel.ERROR, category, message);
        public void Security(string category, string message) => Log(LogLevel.SECURITY, category, message);
        public void Debug(string category, string message) => Log(LogLevel.DEBUG, category, message);

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            lock (_lock)
            {
                try
                {
                    _writer?.WriteLine($"═══ Log fermé le {DateTime.Now:yyyy-MM-dd HH:mm:ss} ═══");
                    _writer?.Flush();
                    _writer?.Dispose();
                }
                catch { }
            }
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Backup/rotation des JSON
    // ═══════════════════════════════════════════════════════

    public static class JsonBackupManager
    {
        private const int MaxBackupsPerFile = 5;

        public static void SaveWithBackup(string filePath, string content, FileLogger logger = null)
        {
            string backupDir = Path.Combine(Path.GetDirectoryName(filePath), "backups");
            try
            {
                if (!Directory.Exists(backupDir))
                    Directory.CreateDirectory(backupDir);
                if (File.Exists(filePath))
                {
                    string baseName = Path.GetFileNameWithoutExtension(filePath);
                    string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                    string backupPath = Path.Combine(backupDir, $"{baseName}_{timestamp}.json.bak");
                    try { File.Copy(filePath, backupPath, overwrite: true); }
                    catch (Exception ex) { logger?.Warn("BACKUP", $"Impossible de créer le backup de {Path.GetFileName(filePath)} : {ex.Message}"); }
                    CleanupBackups(backupDir, baseName, MaxBackupsPerFile, logger);
                }
                string tmpPath = filePath + ".tmp";
                File.WriteAllText(tmpPath, content, Encoding.UTF8);
                var tmpInfo = new FileInfo(tmpPath);
                if (tmpInfo.Length == 0)
                {
                    logger?.Error("BACKUP", $"Fichier temporaire vide — annulation de la sauvegarde de {Path.GetFileName(filePath)}");
                    try { File.Delete(tmpPath); } catch { }
                    return;
                }
                try
                {
                    File.Replace(tmpPath, filePath, filePath + ".old");
                    try { File.Delete(filePath + ".old"); } catch { }
                }
                catch
                {
                    if (File.Exists(tmpPath))
                    {
                        if (File.Exists(filePath)) File.Delete(filePath);
                        File.Move(tmpPath, filePath);
                    }
                }
            }
            catch (Exception ex) { logger?.Error("BACKUP", $"Erreur de sauvegarde {Path.GetFileName(filePath)} : {ex.Message}"); }
        }

        public static string LoadWithRecovery(string filePath, FileLogger logger = null)
        {
            if (File.Exists(filePath))
            {
                try
                {
                    string content = File.ReadAllText(filePath, Encoding.UTF8);
                    if (!string.IsNullOrWhiteSpace(content) && (content.TrimStart().StartsWith("[") || content.TrimStart().StartsWith("{")))
                        return content;
                    logger?.Warn("RECOVERY", $"{Path.GetFileName(filePath)} semble corrompu — tentative de récupération…");
                }
                catch (Exception ex) { logger?.Error("RECOVERY", $"Impossible de lire {Path.GetFileName(filePath)} : {ex.Message}"); }
            }
            string backupDir = Path.Combine(Path.GetDirectoryName(filePath), "backups");
            string baseName = Path.GetFileNameWithoutExtension(filePath);
            if (Directory.Exists(backupDir))
            {
                var backups = Directory.GetFiles(backupDir, $"{baseName}_*.json.bak").OrderByDescending(f => f).ToList();
                foreach (var backup in backups)
                {
                    try
                    {
                        string content = File.ReadAllText(backup, Encoding.UTF8);
                        if (!string.IsNullOrWhiteSpace(content) && (content.TrimStart().StartsWith("[") || content.TrimStart().StartsWith("{")))
                        {
                            logger?.Warn("RECOVERY", $"Récupération réussie depuis {Path.GetFileName(backup)}");
                            try { File.Copy(backup, filePath, overwrite: true); } catch { }
                            return content;
                        }
                    }
                    catch { continue; }
                }
            }
            logger?.Error("RECOVERY", $"Aucun backup valide trouvé pour {Path.GetFileName(filePath)}");
            return null;
        }

        private static void CleanupBackups(string backupDir, string baseName, int maxKeep, FileLogger logger)
        {
            try
            {
                var files = Directory.GetFiles(backupDir, $"{baseName}_*.json.bak").OrderByDescending(f => f).Skip(maxKeep).ToList();
                foreach (var old in files)
                    try { File.Delete(old); } catch { }
                if (files.Count > 0)
                    logger?.Debug("BACKUP", $"Nettoyage : {files.Count} ancien(s) backup(s) supprimé(s) pour {baseName}");
            }
            catch { }
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Validation des entrées utilisateur
    // ═══════════════════════════════════════════════════════

    public static class InputValidator
    {
        private static readonly Regex RoomNameRegex = new Regex(@"^[\p{L}\p{N}_\-]{1,20}$", RegexOptions.Compiled);
        private static readonly Regex UsernameRegex = new Regex(@"^[\p{L}\p{N}_\-]{2,20}$", RegexOptions.Compiled);
        private static readonly Regex Base64Regex = new Regex(@"^[A-Za-z0-9+/=]{1,500}$", RegexOptions.Compiled);
        private static readonly Regex TransferIdRegex = new Regex(@"^[\w\-]{1,64}$", RegexOptions.Compiled);
        private static readonly Regex FileNameRegex = new Regex(@"^[^<>:""/\\|?*\x00-\x1f]{1,255}$", RegexOptions.Compiled);

        public static string ValidateRoomName(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return null;
            name = name.Trim();
            return RoomNameRegex.IsMatch(name) ? name : null;
        }

        public static string ValidateUsername(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return null;
            name = name.Trim();
            return UsernameRegex.IsMatch(name) ? name : null;
        }

        public static bool IsValidE2EPublicKey(string key)
        {
            if (string.IsNullOrWhiteSpace(key)) return false;
            return Base64Regex.IsMatch(key);
        }

        public static bool IsValidTransferId(string id)
        {
            if (string.IsNullOrWhiteSpace(id)) return false;
            return TransferIdRegex.IsMatch(id);
        }

        public static bool IsValidFileName(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return false;
            return FileNameRegex.IsMatch(name);
        }

        public static bool IsValidMessage(string text, int maxLength)
        {
            return !string.IsNullOrWhiteSpace(text) && text.Length <= maxLength;
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Formulaire principal
    // ═══════════════════════════════════════════════════════

    public partial class ServerForm : Form
    {
        // ── Réseau ──
        private TcpListener tcpListener;
        private Thread listenThread;
        private volatile bool isRunning = false;
        private int port = 8888;

        // ── AES-256-GCM constantes ──
        private const int GCM_NONCE_SIZE = 12;
        private const int GCM_TAG_BITS = 128;
        private const int GCM_TAG_SIZE = GCM_TAG_BITS / 8;

        // ── File Transfer ──
        private readonly Dictionary<string, FileTransfer> _activeTransfers = new Dictionary<string, FileTransfer>();
        private readonly object _transfersLock = new object();
        private const long MaxFileSize = 100L * 1024 * 1024;
        private const int FileChunkSize = 48 * 1024;
        private const int MaxPacketSize = 128 * 1024;

        // ── Heartbeat ──
        private System.Windows.Forms.Timer _heartbeatTimer;
        private const int PingIntervalSec = 30;
        private const int PongTimeoutSec = 45;

        // ── Rate-limiting ──
        private const int RateLimitMaxMessages = 10;
        private const double RateLimitWindowSec = 5.0;
        private const int RateLimitMaxWarnings = 3;
        private readonly Dictionary<string, int> _rateLimitWarnings = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        private readonly object _rateLimitWarningsLock = new object();

        // ── RSA ──
        private static RSACryptoServiceProvider _serverRsa;
        private static string _serverRsaPublicXml;

        // ── Logging structuré ──
        private FileLogger _fileLogger;

        private static void EnsureRsaKeys()
        {
            if (_serverRsa != null) return;
            _serverRsa = new RSACryptoServiceProvider(2048);
            _serverRsaPublicXml = _serverRsa.ToXmlString(false);
        }

        // ═══════════════════════════════════════════════════════
        //  PFX password from config file
        // ═══════════════════════════════════════════════════════

        private static readonly string PfxPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "nexuschat_server.pfx");
        private static readonly string PfxConfigFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "tls_config.json");
        private static string _pfxPasswordCached = null;

        private static string PfxPassword
        {
            get
            {
                if (_pfxPasswordCached != null) return _pfxPasswordCached;
                _pfxPasswordCached = LoadPfxPassword();
                return _pfxPasswordCached;
            }
        }

        private static string LoadPfxPassword()
        {
            try
            {
                if (File.Exists(PfxConfigFile))
                {
                    string json = File.ReadAllText(PfxConfigFile, Encoding.UTF8);
                    string pwd = JsonGetString(json, "PfxPassword");
                    if (!string.IsNullOrWhiteSpace(pwd)) return pwd;
                }
            }
            catch { }
            string envPwd = Environment.GetEnvironmentVariable("NEXUSCHAT_PFX_PASSWORD");
            if (!string.IsNullOrWhiteSpace(envPwd)) return envPwd;
            string generated;
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] bytes = new byte[32];
                rng.GetBytes(bytes);
                generated = Convert.ToBase64String(bytes);
            }
            try
            {
                string configJson = "{\"PfxPassword\":\"" + JsonEscape(generated) + "\"}";
                File.WriteAllText(PfxConfigFile, configJson, Encoding.UTF8);
            }
            catch { }
            return generated;
        }

        private void EnsureTlsCertificate()
        {
            if (_serverCert != null) return;
            try
            {
                if (File.Exists(PfxPath))
                {
                    bool loaded = false;
                    try
                    {
                        _serverCert = new X509Certificate2(PfxPath, PfxPassword,
                            X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
                        if (_serverCert.HasPrivateKey) loaded = true;
                    }
                    catch { _serverCert = null; }
                    if (loaded && _serverCert != null && _serverCert.HasPrivateKey)
                    {
                        LogMessage("[TLS] Certificat chargé depuis " + PfxPath);
                        return;
                    }
                    LogMessage("[TLS] PFX existant illisible — régénération...");
                    _fileLogger?.Warn("TLS", "PFX illisible avec le mot de passe actuel — régénération du certificat.");
                    try { File.Delete(PfxPath); } catch { }
                    _serverCert = null;
                }
                LogMessage("[TLS] Génération du certificat auto-signé via PowerShell...");
                string tmpScript = Path.Combine(Path.GetTempPath(), "nexuschat_gencert.ps1");
                string escapedPfxPath = PfxPath.Replace("\\", "\\\\").Replace("'", "''");
                string[] lines = {
                    "$ErrorActionPreference = 'Stop'",
                    "$cert = New-SelfSignedCertificate -DnsName 'NexusChat-Server' -CertStoreLocation 'Cert:\\CurrentUser\\My' -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(10) -FriendlyName 'NexusChat Server TLS'",
                    "$pwd = ConvertTo-SecureString -String '" + PfxPassword + "' -Force -AsPlainText",
                    "Export-PfxCertificate -Cert $cert -FilePath '" + escapedPfxPath + "' -Password $pwd | Out-Null",
                    "Remove-Item -Path ('Cert:\\CurrentUser\\My\\' + $cert.Thumbprint) -Force",
                    "Write-Output 'OK'"
                };
                File.WriteAllLines(tmpScript, lines, new UTF8Encoding(false));
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + tmpScript + "\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };
                string psOut, psErr;
                using (var ps = Process.Start(psi)) { psOut = ps.StandardOutput.ReadToEnd().Trim(); psErr = ps.StandardError.ReadToEnd().Trim(); ps.WaitForExit(); }
                try { File.Delete(tmpScript); } catch { }
                if (!File.Exists(PfxPath))
                    throw new Exception("PowerShell n'a pas créé le PFX." + (string.IsNullOrEmpty(psErr) ? "" : " Détail : " + psErr));
                _serverCert = new X509Certificate2(PfxPath, PfxPassword, X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
                if (!_serverCert.HasPrivateKey) throw new Exception("PFX chargé mais clé privée introuvable.");
                LogMessage("[TLS] Certificat généré → " + Path.GetFileName(PfxPath));
                LogMessage("[TLS] RSA-2048 / SHA-256 / valide 10 ans.");
            }
            catch (Exception ex)
            {
                LogMessage("[TLS] ⚠ Échec : " + ex.Message);
                LogMessage("[TLS] TLS désactivé — chiffrement AES-256-GCM applicatif actif.");
                _serverCert = null;
            }
        }

        // ── Debounce SaveRooms ──
        private void InitSaveRoomsDebounce()
        {
            if (_saveRoomsTimer != null) return;
            _saveRoomsTimer = new System.Windows.Forms.Timer { Interval = 5000 };
            _saveRoomsTimer.Tick += (s, e) =>
            {
                _saveRoomsTimer.Stop();
                if (_saveRoomsPending) { _saveRoomsPending = false; SaveRooms(); }
            };
        }

        private void ScheduleSaveRooms()
        {
            _saveRoomsPending = true;
            if (_saveRoomsTimer == null) return;
            if (lstUsers != null && lstUsers.InvokeRequired)
                lstUsers.BeginInvoke(new Action(() => { _saveRoomsTimer.Stop(); _saveRoomsTimer.Start(); }));
            else { _saveRoomsTimer.Stop(); _saveRoomsTimer.Start(); }
        }

        // ── Heartbeat ──
        private void StartHeartbeat()
        {
            _heartbeatTimer = new System.Windows.Forms.Timer { Interval = PingIntervalSec * 1000 };
            _heartbeatTimer.Tick += (s, e) =>
            {
                List<ConnectedClient> snapshot;
                lock (clientsLock) snapshot = connectedClients.Where(c => c.IsAuthenticated && !c.IsDisconnected).ToList();
                foreach (var cc in snapshot)
                {
                    if ((DateTime.Now - cc.LastPong).TotalSeconds > PongTimeoutSec)
                    {
                        _fileLogger?.Warn("HEARTBEAT", $"{cc.Username} ({cc.IP}) — timeout PONG");
                        LogMessage($"[HEARTBEAT] {cc.Username} ({cc.IP}) — timeout PONG, déconnexion.");
                        DisconnectClient(cc, cc.Username + " inactif (heartbeat timeout)");
                        continue;
                    }
                    try { SendEncrypted(cc, "PING"); } catch { }
                }
            };
            _heartbeatTimer.Start();
        }

        private void StopHeartbeat() { _heartbeatTimer?.Stop(); _heartbeatTimer?.Dispose(); _heartbeatTimer = null; }

        // ── Données ──
        private readonly Dictionary<string, UserAccount> registeredUsers = new Dictionary<string, UserAccount>(StringComparer.OrdinalIgnoreCase);
        private readonly object _usersLock = new object();
        private readonly List<ConnectedClient> connectedClients = new List<ConnectedClient>();
        private readonly object clientsLock = new object();
        private readonly Dictionary<string, ChatRoom> rooms = new Dictionary<string, ChatRoom>(StringComparer.OrdinalIgnoreCase);
        private readonly object roomsLock = new object();
        private readonly HashSet<string> bannedIPs = new HashSet<string>();
        private readonly HashSet<string> bannedUsernames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> bannedUsernameToIP = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly object _bansLock = new object();
        private readonly Dictionary<string, int> ipConnCount = new Dictionary<string, int>();
        private readonly Dictionary<string, int> ipAuthFails = new Dictionary<string, int>();
        private readonly Dictionary<string, DateTime> ipBanExpiry = new Dictionary<string, DateTime>();
        private readonly object _authLock = new object();

        private int maxConnPerIP = 5;
        private const int MaxAuthFailsPerIP = 10;
        private const int AuthBanMinutes = 5;
        private const int MaxPasswordLength = 64;
        private const int MaxMessageLength = 2000;

        private X509Certificate2 _serverCert;
        private volatile bool _saveRoomsPending = false;
        private System.Windows.Forms.Timer _saveRoomsTimer;

        private long _totalBytesIn = 0;
        private long _totalBytesOut = 0;
        private readonly object _trafficLock = new object();
        private DateTime _trafficResetTime = DateTime.Now;

        private PerformanceCounter _cpuCounter;
        private bool _cpuCounterAvailable = false;

        // ── UI ──
        private Label lblStatus, lblStats, lblUsers, lblRooms, lblBanned, lblPort, lblMaxConn;
        private Label lblSysInfo, lblTraffic;
        private Button btnStartServer, btnBan, btnUnban, btnAddRoom, btnBroadcast;
        private TextBox txtPort, txtLog, txtNewRoom, txtBroadcastMsg;
        private NumericUpDown numMaxConn;
        private ListBox lstUsers, lstRooms, lstBanned;
        private TabControl tabMain;
        private TabPage tabLog, tabUsers, tabSecurity, tabSettings;
        private System.Windows.Forms.Timer _uiRefreshTimer;
        private System.Windows.Forms.Timer _sysMonitorTimer;

        // ── Fichiers ──
        private static readonly string UsersFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "users.json");
        private static readonly string RoomsFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rooms.json");
        private static readonly string BansFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "bans.json");

        // ═══════════════════════════════════════════════════════
        //  Constructeur
        // ═══════════════════════════════════════════════════════

        public ServerForm()
        {
            InitializeComponent();
            this.Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            _fileLogger = new FileLogger();
            _fileLogger.Info("SERVER", "NexusChat Server démarré");
            InitPerformanceCounters();
            LoadRooms(); LoadUsers(); LoadBans();
        }

        private void InitPerformanceCounters()
        {
            try
            {
                _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                _cpuCounter.NextValue();
                _cpuCounterAvailable = true;
            }
            catch
            {
                _cpuCounterAvailable = false;
                _fileLogger?.Warn("MONITOR", "PerformanceCounter CPU indisponible — monitoring CPU désactivé.");
            }
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return bytes + " B";
            if (bytes < 1024 * 1024) return (bytes / 1024.0).ToString("0.0") + " KB";
            if (bytes < 1024L * 1024 * 1024) return (bytes / (1024.0 * 1024)).ToString("0.0") + " MB";
            return (bytes / (1024.0 * 1024 * 1024)).ToString("0.00") + " GB";
        }

        private void UpdateSysMonitor(object sender, EventArgs e)
        {
            try
            {
                string time = DateTime.Now.ToString("HH:mm:ss");
                string cpuStr = "N/A";
                if (_cpuCounterAvailable)
                {
                    try { cpuStr = _cpuCounter.NextValue().ToString("0.0") + "%"; }
                    catch { _cpuCounterAvailable = false; cpuStr = "N/A"; }
                }
                var proc = Process.GetCurrentProcess();
                long ramMb = proc.WorkingSet64 / (1024 * 1024);
                string ramStr = ramMb + " MB";
                long bIn, bOut; DateTime resetAt;
                lock (_trafficLock) { bIn = _totalBytesIn; bOut = _totalBytesOut; resetAt = _trafficResetTime; }
                string sessionDur = (DateTime.Now - resetAt).ToString(@"hh\:mm\:ss");
                Action update = () =>
                {
                    lblSysInfo.Text = $"🕐 {time}    CPU {cpuStr}    RAM {ramStr}";
                    lblTraffic.Text = $"⬇ RX  {FormatBytes(bIn)}    ⬆ TX  {FormatBytes(bOut)}    ∑ {FormatBytes(bIn + bOut)}    ⏱ {sessionDur}";
                };
                if (lblSysInfo.InvokeRequired) lblSysInfo.BeginInvoke(update); else update();
            }
            catch { }
        }

        private void AddBytesIn(int count) { lock (_trafficLock) _totalBytesIn += count; }
        private void AddBytesOut(int count) { lock (_trafficLock) _totalBytesOut += count; }

        // ═══════════════════════════════════════════════════════
        //  Salons — Load / Save
        // ═══════════════════════════════════════════════════════

        private void LoadRooms()
        {
            lock (roomsLock)
            {
                if (!rooms.ContainsKey("général")) rooms["général"] = new ChatRoom { Name = "général" };
                if (!rooms.ContainsKey("tech")) rooms["tech"] = new ChatRoom { Name = "tech" };
                if (!rooms.ContainsKey("blabla")) rooms["blabla"] = new ChatRoom { Name = "blabla" };
            }
            string json = JsonBackupManager.LoadWithRecovery(RoomsFilePath, _fileLogger);
            if (json == null) return;
            try
            {
                var objects = JsonSplitObjects(json);
                lock (roomsLock)
                {
                    foreach (string obj in objects)
                    {
                        string name = JsonGetString(obj, "Name");
                        if (string.IsNullOrWhiteSpace(name)) continue;
                        if (!rooms.ContainsKey(name)) rooms[name] = new ChatRoom { Name = name };
                        var hist = JsonGetStringArray(obj, "History");
                        rooms[name].History.Clear();
                        foreach (string line in hist) rooms[name].History.Add(line);
                    }
                }
                _fileLogger?.Info("JSON", $"{rooms.Count} salon(s) chargé(s)");
            }
            catch (Exception ex)
            {
                _fileLogger?.Error("JSON", "Erreur LoadRooms : " + ex.Message);
                LogMessage("[ERREUR] LoadRooms : " + ex.Message);
            }
        }

        private void SaveRooms()
        {
            try
            {
                var sb = new StringBuilder();
                sb.AppendLine("[");
                List<ChatRoom> list;
                lock (roomsLock) list = rooms.Values.ToList();
                for (int i = 0; i < list.Count; i++)
                {
                    var r = list[i];
                    sb.Append("  {\"Name\":\"" + JsonEscape(r.Name) + "\",\"History\":[");
                    var hist = r.History.ToList();
                    for (int h = 0; h < hist.Count; h++)
                    {
                        sb.Append("\"" + JsonEscape(hist[h]) + "\"");
                        if (h < hist.Count - 1) sb.Append(",");
                    }
                    sb.Append("]}");
                    if (i < list.Count - 1) sb.Append(",");
                    sb.AppendLine();
                }
                sb.AppendLine("]");
                JsonBackupManager.SaveWithBackup(RoomsFilePath, sb.ToString(), _fileLogger);
            }
            catch (Exception ex)
            {
                _fileLogger?.Error("JSON", "Sauvegarde rooms.json : " + ex.Message);
                LogMessage("[ERREUR] Sauvegarde rooms.json : " + ex.Message);
            }
        }

        // ═══════════════════════════════════════════════════════
        //  Utilisateurs — Load / Save
        // ═══════════════════════════════════════════════════════

        private void LoadUsers()
        {
            string json = JsonBackupManager.LoadWithRecovery(UsersFilePath, _fileLogger);
            if (json == null) return;
            try
            {
                var objects = JsonSplitObjects(json);
                lock (_usersLock)
                {
                    foreach (string obj in objects)
                    {
                        string username = JsonGetString(obj, "Username");
                        string hash = JsonGetString(obj, "PasswordHash");
                        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(hash)) continue;
                        var u = new UserAccount
                        {
                            Username = username,
                            PasswordHash = hash,
                            PasswordSalt = JsonGetString(obj, "PasswordSalt"),
                            FailedLogins = JsonGetInt(obj, "FailedLogins"),
                            PublicKey = JsonGetString(obj, "PublicKey")
                        };
                        string lockedStr = JsonGetString(obj, "LockedUntil");
                        if (!string.IsNullOrEmpty(lockedStr) && lockedStr != "null")
                            if (DateTime.TryParse(lockedStr, out DateTime dt)) u.LockedUntil = dt;
                        registeredUsers[u.Username] = u;
                    }
                }
                _fileLogger?.Info("JSON", $"{registeredUsers.Count} compte(s) chargé(s)");
                LogMessage("[JSON] " + registeredUsers.Count + " compte(s) chargé(s)");
            }
            catch (Exception ex)
            {
                _fileLogger?.Error("JSON", "Chargement users.json : " + ex.Message);
                LogMessage("[ERREUR] Chargement users.json : " + ex.Message);
            }
        }

        private void SaveUsers()
        {
            try
            {
                List<UserAccount> list;
                lock (_usersLock) list = registeredUsers.Values.ToList();
                var sb = new StringBuilder();
                sb.AppendLine("[");
                for (int i = 0; i < list.Count; i++)
                {
                    var u = list[i];
                    string locked = u.LockedUntil.HasValue ? "\"" + u.LockedUntil.Value.ToString("o") + "\"" : "null";
                    sb.Append("  {");
                    sb.Append("\"Username\":\"" + JsonEscape(u.Username) + "\",");
                    sb.Append("\"PasswordHash\":\"" + u.PasswordHash + "\",");
                    sb.Append("\"PasswordSalt\":\"" + (u.PasswordSalt ?? "") + "\",");
                    sb.Append("\"FailedLogins\":" + u.FailedLogins + ",");
                    sb.Append("\"LockedUntil\":" + locked + ",");
                    sb.Append("\"PublicKey\":\"" + JsonEscape(u.PublicKey ?? "") + "\"");
                    sb.Append(i < list.Count - 1 ? "}," : "}");
                    sb.AppendLine();
                }
                sb.AppendLine("]");
                JsonBackupManager.SaveWithBackup(UsersFilePath, sb.ToString(), _fileLogger);
            }
            catch (Exception ex)
            {
                _fileLogger?.Error("JSON", "Sauvegarde users.json : " + ex.Message);
                LogMessage("[ERREUR] Sauvegarde users.json : " + ex.Message);
            }
        }

        // ═══════════════════════════════════════════════════════
        //  Bans — Load / Save
        // ═══════════════════════════════════════════════════════

        private void LoadBans()
        {
            string json = JsonBackupManager.LoadWithRecovery(BansFilePath, _fileLogger);
            if (json == null) return;
            try
            {
                if (!json.Contains("\"Mappings\""))
                {
                    _fileLogger?.Warn("JSON", "bans.json ancien format — réinitialisation.");
                    lock (_bansLock) { bannedIPs.Clear(); bannedUsernames.Clear(); bannedUsernameToIP.Clear(); }
                    SaveBans(); return;
                }
                lock (_bansLock)
                {
                    foreach (string ip in JsonGetStringArray(json, "IPs"))
                        if (!string.IsNullOrWhiteSpace(ip)) bannedIPs.Add(ip);
                    foreach (string u in JsonGetStringArray(json, "Usernames"))
                        if (!string.IsNullOrWhiteSpace(u)) bannedUsernames.Add(u);
                    int mIdx = json.IndexOf("\"Mappings\":[", StringComparison.Ordinal);
                    if (mIdx >= 0)
                    {
                        int arrStart = json.IndexOf('[', mIdx) + 1;
                        int depth = 1, pos = arrStart;
                        while (pos < json.Length && depth > 0) { if (json[pos] == '[') depth++; else if (json[pos] == ']') depth--; pos++; }
                        string arrContent = json.Substring(arrStart, pos - arrStart - 1);
                        foreach (string obj in JsonSplitObjects(arrContent))
                        {
                            string u2 = JsonGetString(obj, "u"); string ip2 = JsonGetString(obj, "ip");
                            if (!string.IsNullOrWhiteSpace(u2) && !string.IsNullOrWhiteSpace(ip2)) bannedUsernameToIP[u2] = ip2;
                        }
                    }
                }
                _fileLogger?.Info("JSON", $"Bans : {bannedIPs.Count} IP, {bannedUsernames.Count} pseudo(s)");
            }
            catch (Exception ex)
            {
                _fileLogger?.Error("JSON", "Chargement bans.json : " + ex.Message);
                LogMessage("[ERREUR] Chargement bans.json : " + ex.Message);
            }
        }

        private void SaveBans()
        {
            try
            {
                List<string> ips, uns; List<KeyValuePair<string, string>> maps;
                lock (_bansLock) { ips = bannedIPs.ToList(); uns = bannedUsernames.ToList(); maps = bannedUsernameToIP.ToList(); }
                var sb = new StringBuilder();
                sb.Append("{\"IPs\":[");
                for (int i = 0; i < ips.Count; i++) sb.Append("\"" + JsonEscape(ips[i]) + "\"" + (i < ips.Count - 1 ? "," : ""));
                sb.Append("],\"Usernames\":[");
                for (int i = 0; i < uns.Count; i++) sb.Append("\"" + JsonEscape(uns[i]) + "\"" + (i < uns.Count - 1 ? "," : ""));
                sb.Append("],\"Mappings\":[");
                for (int i = 0; i < maps.Count; i++)
                    sb.Append("{\"u\":\"" + JsonEscape(maps[i].Key) + "\",\"ip\":\"" + JsonEscape(maps[i].Value) + "\"}" + (i < maps.Count - 1 ? "," : ""));
                sb.Append("]}");
                JsonBackupManager.SaveWithBackup(BansFilePath, sb.ToString(), _fileLogger);
            }
            catch (Exception ex)
            {
                _fileLogger?.Error("JSON", "Sauvegarde bans.json : " + ex.Message);
            }
        }

        // ═══════════════════════════════════════════════════════
        //  Helpers JSON
        // ═══════════════════════════════════════════════════════

        private static string JsonEscape(string s)
        {
            if (s == null) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r");
        }

        private static string JsonGetString(string obj, string key)
        {
            string search = "\"" + key + "\":\"";
            int idx = obj.IndexOf(search, StringComparison.Ordinal);
            if (idx < 0) return null;
            idx += search.Length;
            var sb = new StringBuilder(); bool esc = false;
            for (int i = idx; i < obj.Length; i++)
            {
                char ch = obj[i];
                if (esc) { sb.Append(ch == 'n' ? '\n' : ch == 'r' ? '\r' : ch); esc = false; }
                else if (ch == '\\') esc = true;
                else if (ch == '"') break;
                else sb.Append(ch);
            }
            return sb.ToString();
        }

        private static bool JsonGetBool(string obj, string key)
        {
            string search = "\"" + key + "\":"; int idx = obj.IndexOf(search, StringComparison.Ordinal);
            if (idx < 0) return false;
            return obj.Substring(idx + search.Length).TrimStart().StartsWith("true");
        }

        private static int JsonGetInt(string obj, string key)
        {
            string search = "\"" + key + "\":"; int idx = obj.IndexOf(search, StringComparison.Ordinal);
            if (idx < 0) return 0;
            string rest = obj.Substring(idx + search.Length).TrimStart();
            var num = new StringBuilder();
            foreach (char ch in rest) { if (char.IsDigit(ch)) num.Append(ch); else break; }
            return num.Length > 0 ? int.Parse(num.ToString()) : 0;
        }

        private static List<string> JsonGetStringArray(string obj, string key)
        {
            var result = new List<string>();
            string search = "\"" + key + "\":["; int idx = obj.IndexOf(search, StringComparison.Ordinal);
            if (idx < 0) return result;
            int arrStart = obj.IndexOf('[', idx) + 1; int arrEnd = obj.IndexOf(']', arrStart);
            if (arrEnd <= arrStart) return result;
            string content = obj.Substring(arrStart, arrEnd - arrStart);
            bool inStr = false; bool esc = false; var cur = new StringBuilder();
            foreach (char ch in content)
            {
                if (esc) { cur.Append(ch == 'n' ? '\n' : ch == 'r' ? '\r' : ch); esc = false; }
                else if (ch == '\\') esc = true;
                else if (ch == '"') { if (inStr) { result.Add(cur.ToString()); cur.Clear(); } inStr = !inStr; }
                else if (inStr) cur.Append(ch);
            }
            return result;
        }

        private static List<string> JsonSplitObjects(string json)
        {
            var result = new List<string>(); int depth = 0, start = -1;
            bool inString = false; bool escaped = false;
            for (int i = 0; i < json.Length; i++)
            {
                char ch = json[i];
                if (escaped) { escaped = false; continue; }
                if (ch == '\\' && inString) { escaped = true; continue; }
                if (ch == '"') { inString = !inString; continue; }
                if (inString) continue;
                if (ch == '{') { if (depth++ == 0) start = i; }
                else if (ch == '}') if (--depth == 0 && start >= 0) { result.Add(json.Substring(start, i - start + 1)); start = -1; }
            }
            return result;
        }

        // ═══════════════════════════════════════════════════════
        //  Démarrage / Arrêt
        // ═══════════════════════════════════════════════════════

        private void btnStartServer_Click(object sender, EventArgs e)
        { if (!isRunning) StartServer(); else StopServer(); }

        private void StartServer()
        {
            if (!int.TryParse(txtPort.Text, out port) || port < 1 || port > 65535) { port = 8888; txtPort.Text = "8888"; }
            try
            {
                EnsureRsaKeys(); EnsureTlsCertificate(); InitSaveRoomsDebounce();
                tcpListener = new TcpListener(IPAddress.Any, port);
                tcpListener.Start();
                isRunning = true;
                listenThread = new Thread(ListenForClients) { IsBackground = true };
                listenThread.Start();
                StartHeartbeat();
                btnStartServer.Text = "⏹  Arrêter le serveur";
                btnStartServer.BackColor = Color.FromArgb(192, 57, 43);
                lblStatus.Text = "🟢  Actif  —  port " + port;
                lblStatus.ForeColor = Color.FromArgb(46, 213, 115);
                txtPort.Enabled = false; numMaxConn.Enabled = false;
                btnBroadcast.Enabled = true; btnAddRoom.Enabled = true;
                int roomCount; lock (roomsLock) roomCount = rooms.Count;
                int banCount; lock (_bansLock) banCount = bannedIPs.Count + bannedUsernames.Count;

                _fileLogger?.Info("SERVER", $"Serveur démarré sur le port {port}");
                _fileLogger?.Info("CRYPTO", "AES-256-GCM (BouncyCastle) — nonce 96 bits, tag 128 bits");
                _fileLogger?.Info("E2E", "Relai X25519 + Sender Keys activé (zero-knowledge)");
                _fileLogger?.Info("SECURITY", "Le serveur est un relai opaque — il ne peut pas lire les messages E2E");

                LogMessage("Serveur démarré sur le port " + port);
                LogMessage("[CRYPTO] AES-256-GCM (BouncyCastle) — nonce 96 bits, tag 128 bits");
                LogMessage("[E2E] Relai X25519 + Sender Keys — zero-knowledge E2E");
                LogMessage("[FILE] Transfert fichiers — max " + (MaxFileSize / 1024 / 1024) + " MB, chunks " + (FileChunkSize / 1024) + " KB");
                LogMessage("[RATELIMIT] " + RateLimitMaxMessages + " msg / " + RateLimitWindowSec + "s — " + RateLimitMaxWarnings + " avertissements avant déconnexion");
                LogMessage("[JSON] " + roomCount + " salon(s), " + banCount + " ban(s) chargés");
                LogMessage("[LOG] Logging fichier actif → dossier logs/");
                UpdateStats();
            }
            catch (Exception ex)
            {
                isRunning = false;
                try { tcpListener?.Stop(); } catch { }
                tcpListener = null;
                string msg = ex.Message;
                if (msg.Contains("adresse de socket") || msg.Contains("address already") || msg.Contains("Only one usage"))
                    msg = "Le port " + port + " est déjà utilisé. Choisissez un autre port.";
                _fileLogger?.Error("SERVER", "Impossible de démarrer : " + msg);
                LogMessage("[ERREUR] Impossible de démarrer : " + msg);
                MessageBox.Show("Impossible de démarrer le serveur.\n\n" + msg, "Erreur de démarrage", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void StopServer()
        {
            isRunning = false; StopHeartbeat();
            try { tcpListener?.Stop(); } catch { }
            lock (clientsLock)
            {
                foreach (var cc in connectedClients)
                {
                    try { SendEncrypted(cc, "SERVER:SHUTDOWN"); } catch { }
                    try { cc.TcpClient.Close(); } catch { }
                }
                connectedClients.Clear();
            }
            btnStartServer.Text = "▶  Démarrer le serveur";
            btnStartServer.BackColor = Color.FromArgb(39, 174, 96);
            lblStatus.Text = "🔴  Arrêté";
            lblStatus.ForeColor = Color.FromArgb(231, 76, 60);
            txtPort.Enabled = true; numMaxConn.Enabled = true;
            btnBroadcast.Enabled = false; btnAddRoom.Enabled = false;
            SaveRooms();
            _fileLogger?.Info("SERVER", "Serveur arrêté");
            LogMessage("Serveur arrêté.");
            RefreshUserList(); UpdateStats();
        }

        // ═══════════════════════════════════════════════════════
        //  Écoute
        // ═══════════════════════════════════════════════════════

        private void ListenForClients()
        {
            try
            {
                while (isRunning)
                {
                    TcpClient tcp = tcpListener.AcceptTcpClient();
                    string ip = ((IPEndPoint)tcp.Client.RemoteEndPoint).Address.ToString();

                    bool ipBanned; lock (_bansLock) ipBanned = bannedIPs.Contains(ip);
                    if (ipBanned)
                    {
                        _fileLogger?.Security("CONNECT", $"Refus IP bannie : {ip}");
                        SendRawFramedBeforeTls(tcp, "ERR:BANNED_IP"); tcp.Close(); continue;
                    }

                    bool tempBanned; int remaining2 = 0;
                    lock (_authLock) { tempBanned = ipBanExpiry.TryGetValue(ip, out DateTime expiry2) && DateTime.Now < expiry2; if (tempBanned) remaining2 = (int)(expiry2 - DateTime.Now).TotalSeconds; }
                    if (tempBanned)
                    {
                        _fileLogger?.Security("CONNECT", $"Refus IP temp bannie ({remaining2}s) : {ip}");
                        SendRawFramedBeforeTls(tcp, "ERR:TEMP_BANNED:" + remaining2); tcp.Close(); continue;
                    }

                    lock (clientsLock)
                    {
                        int count = connectedClients.Count(c => c.IP == ip);
                        if (count >= maxConnPerIP)
                        {
                            _fileLogger?.Security("CONNECT", $"Limite connexions ({maxConnPerIP}) atteinte : {ip}");
                            SendRawFramedBeforeTls(tcp, "ERR:TOO_MANY_CONNECTIONS"); tcp.Close(); continue;
                        }
                    }

                    _fileLogger?.Info("CONNECT", $"Connexion entrante : {ip}");
                    LogMessage("Connexion entrante : " + ip);
                    var cc = new ConnectedClient { TcpClient = tcp, IP = ip };
                    new Thread(() => HandleClientComm(cc)) { IsBackground = true }.Start();
                }
            }
            catch (Exception ex)
            {
                if (isRunning)
                {
                    _fileLogger?.Error("LISTEN", ex.Message);
                    LogMessage("[ERREUR] Thread écoute : " + ex.Message);
                }
            }
        }

        // ═══════════════════════════════════════════════════════
        //  Gestion client
        // ═══════════════════════════════════════════════════════

        private void HandleClientComm(ConnectedClient cc)
        {
            Stream stream;
            if (_serverCert != null)
            {
                try
                {
                    var ssl = new SslStream(cc.TcpClient.GetStream(), false);
                    ssl.AuthenticateAsServer(_serverCert, clientCertificateRequired: false,
                        enabledSslProtocols: System.Security.Authentication.SslProtocols.Tls12, checkCertificateRevocation: false);
                    cc.SslStream = ssl; stream = ssl;
                }
                catch (Exception ex)
                {
                    _fileLogger?.Error("TLS", $"Handshake TLS échoué ({cc.IP}) : {ex.Message}");
                    DisconnectClient(cc, null); return;
                }
            }
            else { stream = cc.TcpClient.GetStream(); }

            try
            {
                if (!PerformServerHandshake(cc))
                {
                    _fileLogger?.Security("AUTH", $"Handshake RSA échoué : {cc.IP}");
                    DisconnectClient(cc, null); return;
                }

                string authMsg = ReadFramedPacket(stream, cc.SessionKey);
                if (authMsg == null) { DisconnectClient(cc, null); return; }
                if (!authMsg.StartsWith("AUTH:") || authMsg.Split(':').Length < 4)
                { SendEncrypted(cc, "ERR:INVALID_AUTH_FORMAT"); DisconnectClient(cc, null); return; }

                string[] parts = authMsg.Split(new[] { ':' }, 4);
                string action = parts[1]; string username = parts[2].Trim(); string password = parts[3];

                if (InputValidator.ValidateUsername(username) == null)
                {
                    _fileLogger?.Security("AUTH", $"Username invalide refusé : '{username}' depuis {cc.IP}");
                    SendEncrypted(cc, "ERR:INVALID_USERNAME"); DisconnectClient(cc, null); return;
                }

                if (password.Length < 4 || password.Length > MaxPasswordLength)
                { SendEncrypted(cc, "ERR:INVALID_PASSWORD"); DisconnectClient(cc, null); return; }

                bool userBanned; lock (_bansLock) userBanned = bannedUsernames.Contains(username);
                if (userBanned) { SendEncrypted(cc, "ERR:BANNED_USERNAME"); DisconnectClient(cc, null); return; }

                lock (clientsLock)
                {
                    if (connectedClients.Any(c => c.Username != null && c.Username.Equals(username, StringComparison.OrdinalIgnoreCase)))
                    { SendEncrypted(cc, "ERR:ALREADY_CONNECTED"); DisconnectClient(cc, null); return; }
                }

                if (action == "REGISTER")
                {
                    lock (_usersLock)
                    {
                        if (registeredUsers.ContainsKey(username))
                        { SendEncrypted(cc, "ERR:USERNAME_TAKEN"); DisconnectClient(cc, null); return; }
                        var (hash, salt) = HashPasswordNew(password);
                        registeredUsers[username] = new UserAccount { Username = username, PasswordHash = hash, PasswordSalt = salt };
                    }
                    SaveUsers();
                    _fileLogger?.Info("AUTH", $"Nouveau compte : {username} ({cc.IP})");
                    LogMessage("Nouveau compte : " + username + " (" + cc.IP + ")");
                    SendEncrypted(cc, "OK:REGISTERED");
                    cc.Username = username; cc.IsAuthenticated = true;
                }
                else if (action == "LOGIN")
                {
                    UserAccount account;
                    lock (_usersLock) registeredUsers.TryGetValue(username, out account);
                    if (account == null)
                    {
                        RecordAuthFail(cc.IP);
                        SendEncrypted(cc, "ERR:USER_NOT_FOUND"); DisconnectClient(cc, null); return;
                    }
                    if (account.LockedUntil.HasValue && DateTime.Now < account.LockedUntil.Value)
                    { int sec = (int)(account.LockedUntil.Value - DateTime.Now).TotalSeconds; SendEncrypted(cc, "ERR:ACCOUNT_LOCKED:" + sec); DisconnectClient(cc, null); return; }
                    if (string.IsNullOrEmpty(account.PasswordSalt))
                    { SendEncrypted(cc, "ERR:ACCOUNT_MIGRATION_REQUIRED"); DisconnectClient(cc, null); return; }
                    string expectedHash = HashPassword(password, account.PasswordSalt);
                    if (account.PasswordHash != expectedHash)
                    {
                        account.FailedLogins++; RecordAuthFail(cc.IP);
                        if (account.FailedLogins >= 5)
                        {
                            account.LockedUntil = DateTime.Now.AddMinutes(AuthBanMinutes); account.FailedLogins = 0;
                            _fileLogger?.Security("AUTH", $"Compte verrouillé {AuthBanMinutes}min : {username}");
                        }
                        lock (_usersLock) registeredUsers[username] = account;
                        SaveUsers(); SendEncrypted(cc, "ERR:WRONG_PASSWORD"); DisconnectClient(cc, null); return;
                    }
                    account.FailedLogins = 0; account.LockedUntil = null;
                    lock (_usersLock) registeredUsers[username] = account;
                    SaveUsers();
                    cc.Username = username; cc.IsAuthenticated = true;
                    SendEncrypted(cc, "OK:LOGIN:USER");
                    _fileLogger?.Info("AUTH", $"Login réussi : {username} ({cc.IP})");
                }
                else { SendEncrypted(cc, "ERR:INVALID_AUTH_FORMAT"); DisconnectClient(cc, null); return; }

                lock (_authLock) { ipAuthFails.Remove(cc.IP); ipBanExpiry.Remove(cc.IP); }
                lock (clientsLock) connectedClients.Add(cc);
                cc.LastPong = DateTime.Now;
                LogMessage("✅ " + cc.Username + " connecté (" + cc.IP + ")");
                RefreshUserList(); UpdateStats();

                string roomList; lock (roomsLock) roomList = string.Join(",", rooms.Keys);
                SendEncrypted(cc, "ROOMS:" + roomList);
                JoinRoom(cc, "général", sendHistory: true);
                BroadcastToRoom("SYSTEM:" + cc.Username + " a rejoint le chat.", "général", null);

                // ═══════════════════════════════════════════════
                //  E2E Key Bundle — relai opaque des clés publiques
                //  Le serveur ne fait que relayer, la vérification
                //  se fait côté client via KeyTrustStore (TOFU)
                // ═══════════════════════════════════════════════
                BroadcastE2EKeyBundle(cc);

                while (isRunning && !cc.IsDisconnected)
                {
                    string raw;
                    try { raw = ReadFramedPacket(stream, cc.SessionKey); }
                    catch (Exception ex)
                    {
                        if (isRunning && !cc.IsDisconnected)
                            _fileLogger?.Error("READ", $"{cc.Username ?? cc.IP} : {ex.Message}");
                        break;
                    }
                    if (raw == null) break;
                    ProcessMessage(cc, raw);
                }
            }
            catch (Exception ex)
            {
                if (isRunning && !cc.IsDisconnected)
                    _fileLogger?.Error("CLIENT", $"{cc.Username ?? cc.IP} : {ex.Message}");
            }
            finally { DisconnectClient(cc, null); }
        }

        private void RecordAuthFail(string ip)
        {
            lock (_authLock)
            {
                if (!ipAuthFails.ContainsKey(ip)) ipAuthFails[ip] = 0;
                ipAuthFails[ip]++;
                if (ipAuthFails[ip] >= MaxAuthFailsPerIP)
                {
                    ipBanExpiry[ip] = DateTime.Now.AddMinutes(AuthBanMinutes); ipAuthFails[ip] = 0;
                    _fileLogger?.Security("AUTH", $"IP bannie {AuthBanMinutes}min (trop d'échecs) : {ip}");
                    LogMessage("[SÉCURITÉ] IP bannie " + AuthBanMinutes + "min (trop d'échecs) : " + ip);
                }
            }
        }

        // ═══════════════════════════════════════════════════════
        //  E2E Key Exchange — le serveur est un relai opaque
        // ═══════════════════════════════════════════════════════

        private void BroadcastE2EKeyBundle(ConnectedClient newClient)
        {
            List<ConnectedClient> others;
            lock (clientsLock) others = connectedClients.Where(c => c != newClient && c.IsAuthenticated && !c.IsDisconnected && !string.IsNullOrEmpty(c.E2EPublicKey)).ToList();

            foreach (var other in others)
                SendEncrypted(newClient, "E2E_PUBKEY:" + other.Username + ":" + other.E2EPublicKey);

            if (!string.IsNullOrEmpty(newClient.E2EPublicKey))
                foreach (var other in others)
                    SendEncrypted(other, "E2E_PUBKEY:" + newClient.Username + ":" + newClient.E2EPublicKey);
        }

        // ═══════════════════════════════════════════════════════
        //  Rate-limiting helper
        // ═══════════════════════════════════════════════════════

        private bool CheckRateLimit(ConnectedClient sender)
        {
            if (sender.TryConsumeRateLimit(RateLimitMaxMessages, RateLimitWindowSec))
                return true;

            int warnings;
            lock (_rateLimitWarningsLock)
            {
                if (!_rateLimitWarnings.TryGetValue(sender.Username, out warnings)) warnings = 0;
                warnings++;
                _rateLimitWarnings[sender.Username] = warnings;
            }

            if (warnings >= RateLimitMaxWarnings)
            {
                _fileLogger?.Security("RATELIMIT", $"{sender.Username} ({sender.IP}) déconnecté pour flood ({warnings} avertissements)");
                LogMessage($"[RATELIMIT] {sender.Username} ({sender.IP}) déconnecté pour flood répété.");
                SendEncrypted(sender, "ERR:RATE_LIMITED:DISCONNECTED");
                DisconnectClient(sender, sender.Username + " déconnecté (flood)");
                return false;
            }

            _fileLogger?.Warn("RATELIMIT", $"{sender.Username} ({sender.IP}) — avertissement flood ({warnings}/{RateLimitMaxWarnings})");
            SendEncrypted(sender, $"ERR:RATE_LIMITED:{RateLimitMaxMessages}:{(int)RateLimitWindowSec}");
            return false;
        }

        // ═══════════════════════════════════════════════════════
        //  Traitement messages
        // ═══════════════════════════════════════════════════════

        private void ProcessMessage(ConnectedClient sender, string raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return;
            if (raw == "PING") { try { SendEncrypted(sender, "PONG"); } catch { } return; }
            if (raw == "PONG") { sender.LastPong = DateTime.Now; return; }

            // ── E2E : Annonce de clé publique ──
            if (raw.StartsWith("E2E_ANNOUNCE:"))
            {
                string pubKey = raw.Substring(13);
                if (!InputValidator.IsValidE2EPublicKey(pubKey))
                {
                    _fileLogger?.Security("E2E", $"Clé publique invalide rejetée de {sender.Username}");
                    SendEncrypted(sender, "ERR:INVALID_E2E_KEY");
                    return;
                }
                sender.E2EPublicKey = pubKey;
                lock (_usersLock)
                {
                    if (registeredUsers.TryGetValue(sender.Username, out var acct))
                    {
                        acct.PublicKey = pubKey;
                        registeredUsers[sender.Username] = acct;
                    }
                }
                SaveUsers();
                _fileLogger?.Info("E2E", $"Clé publique reçue de {sender.Username}");
                LogMessage("[E2E] Clé publique reçue de " + sender.Username);
                List<ConnectedClient> others;
                lock (clientsLock) others = connectedClients.Where(c => c != sender && c.IsAuthenticated && !c.IsDisconnected).ToList();
                foreach (var c in others)
                    SendEncrypted(c, "E2E_PUBKEY:" + sender.Username + ":" + pubKey);
                return;
            }

            // ── E2E Sender Key relay ──
            if (raw.StartsWith("E2E_SENDER_KEY:"))
            {
                string[] p = raw.Split(new[] { ':' }, 3);
                if (p.Length < 3) return;
                string targetUser = p[1];
                if (InputValidator.ValidateUsername(targetUser) == null)
                {
                    SendEncrypted(sender, "ERR:INVALID_USERNAME"); return;
                }
                string encPayload = p[2];
                ConnectedClient target;
                lock (clientsLock)
                    target = connectedClients.FirstOrDefault(c =>
                        c.Username.Equals(targetUser, StringComparison.OrdinalIgnoreCase) && !c.IsDisconnected);
                if (target == null) { SendEncrypted(sender, "ERR:USER_NOT_FOUND:" + targetUser); return; }
                SendEncrypted(target, "E2E_SENDER_KEY:" + sender.Username + ":" + encPayload);
                _fileLogger?.Debug("E2E-SK", $"Sender key relayée {sender.Username} → {targetUser}");
                return;
            }

            // ── E2E : Message chiffré end-to-end (PM) — le serveur ne voit qu'un blob ──
            if (raw.StartsWith("E2E_MSG:"))
            {
                if (!CheckRateLimit(sender)) return;
                string[] p = raw.Split(new[] { ':' }, 3);
                if (p.Length < 3) return;
                string targetUser = p[1];
                if (InputValidator.ValidateUsername(targetUser) == null)
                {
                    SendEncrypted(sender, "ERR:INVALID_USERNAME"); return;
                }
                string encPayload = p[2];
                ConnectedClient target;
                lock (clientsLock) target = connectedClients.FirstOrDefault(c => c.Username.Equals(targetUser, StringComparison.OrdinalIgnoreCase) && !c.IsDisconnected);
                if (target == null) { SendEncrypted(sender, "ERR:USER_NOT_FOUND:" + targetUser); return; }
                SendEncrypted(target, "E2E_MSG:" + sender.Username + ":" + encPayload);
                _fileLogger?.Debug("E2E", $"PM relayé {sender.Username} → {targetUser} ({encPayload.Length} chars)");
                return;
            }

            // ── E2E : Message room chiffré (Sender Keys) — le serveur ne voit qu'un blob ──
            if (raw.StartsWith("E2E_ROOM_MSG:"))
            {
                if (!CheckRateLimit(sender)) return;
                string[] p = raw.Split(new[] { ':' }, 3);
                if (p.Length < 3) return;
                string room = p[1]; string encPayload = p[2];
                if (InputValidator.ValidateRoomName(room) == null)
                {
                    SendEncrypted(sender, "ERR:INVALID_ROOM_NAME"); return;
                }
                lock (roomsLock) { if (!rooms.ContainsKey(room)) { SendEncrypted(sender, "ERR:ROOM_NOT_FOUND:" + room); return; } }
                lock (roomsLock)
                {
                    if (rooms.TryGetValue(room, out ChatRoom r))
                        r.AddMessage("[" + DateTime.Now.ToString("HH:mm") + "] " + sender.Username + ": [E2E chiffré — Sender Keys]");
                }
                ScheduleSaveRooms();
                BroadcastToRoom("E2E_ROOM_MSG:" + sender.Username + ":" + room + ":" + encPayload, room, sender);
                _fileLogger?.Debug("E2E", $"Room #{room} — {sender.Username} (Sender Key, {encPayload.Length} chars)");
                return;
            }

            // ── File Transfer ──
            if (raw.StartsWith("FILE_INIT:")) { HandleFileInit(sender, raw); return; }
            if (raw.StartsWith("FILE_CHUNK:")) { HandleFileChunk(sender, raw); return; }
            if (raw.StartsWith("FILE_COMPLETE:")) { HandleFileComplete(sender, raw); return; }

            // ── Link Preview ──
            if (raw.StartsWith("LINK_PREVIEW:"))
            {
                if (!CheckRateLimit(sender)) return;
                string url = raw.Substring(13);
                if (!string.IsNullOrWhiteSpace(url) && url.Length <= 2000)
                {
                    string fmt = "LINK:" + sender.Username + ":" + sender.CurrentRoom + ":" + url;
                    lock (roomsLock)
                    {
                        if (rooms.TryGetValue(sender.CurrentRoom, out ChatRoom room))
                            room.AddMessage("[" + DateTime.Now.ToString("HH:mm") + "] " + sender.Username + ": " + url);
                    }
                    ScheduleSaveRooms();
                    BroadcastToRoom(fmt, sender.CurrentRoom, sender);
                }
                return;
            }

            // ── Messages classiques ──
            if (raw.StartsWith("MSG:"))
            {
                if (!CheckRateLimit(sender)) return;
                string text = raw.Substring(4);
                if (!InputValidator.IsValidMessage(text, MaxMessageLength)) return;
                string fmt = "MSG:" + sender.Username + ":" + sender.CurrentRoom + ":" + text;
                lock (roomsLock)
                {
                    if (rooms.TryGetValue(sender.CurrentRoom, out ChatRoom room))
                        room.AddMessage("[" + DateTime.Now.ToString("HH:mm") + "] " + sender.Username + ": " + text);
                }
                ScheduleSaveRooms();
                _fileLogger?.Info("MSG", $"[#{sender.CurrentRoom}] {sender.Username}: {(text.Length > 100 ? text.Substring(0, 100) + "…" : text)}");
                LogMessage("[#" + sender.CurrentRoom + "] " + sender.Username + ": " + text);
                BroadcastToRoom(fmt, sender.CurrentRoom, sender);
            }
            else if (raw.StartsWith("PM:"))
            {
                if (!CheckRateLimit(sender)) return;
                string[] p = raw.Split(new[] { ':' }, 3);
                if (p.Length < 3) return;
                string targetPm = InputValidator.ValidateUsername(p[1]);
                if (targetPm == null) { SendEncrypted(sender, "ERR:INVALID_USERNAME"); return; }
                ConnectedClient target;
                lock (clientsLock) target = connectedClients.FirstOrDefault(c => c.Username.Equals(targetPm, StringComparison.OrdinalIgnoreCase) && !c.IsDisconnected);
                if (target == null) { SendEncrypted(sender, "ERR:USER_NOT_FOUND:" + targetPm); return; }
                SendEncrypted(target, "PM:" + sender.Username + ":" + p[2]);
                SendEncrypted(sender, "PM_SENT:" + targetPm + ":" + p[2]);
                _fileLogger?.Info("PM", $"{sender.Username} → {targetPm}");
            }
            else if (raw.StartsWith("JOIN:"))
            {
                string roomName = raw.Substring(5).Trim();
                if (InputValidator.ValidateRoomName(roomName) == null)
                {
                    SendEncrypted(sender, "ERR:INVALID_ROOM_NAME"); return;
                }
                JoinRoom(sender, roomName, sendHistory: true);
            }
            else if (raw.StartsWith("MKROOM:")) { SendEncrypted(sender, "ERR:NOT_ALLOWED"); }
            else if (raw == "CMD:delete_account")
            {
                string uname = sender.Username;
                lock (_usersLock) registeredUsers.Remove(uname);
                SaveUsers();
                _fileLogger?.Info("ACCOUNT", $"Compte supprimé : {uname}");
                LogMessage("[COMPTE] Compte supprimé : " + uname);
                SendEncrypted(sender, "SERVER:ACCOUNT_DELETED");
                DisconnectClient(sender, uname + " a supprimé son compte");
            }
            else if (raw.StartsWith("CMD:")) { SendEncrypted(sender, "ERR:NOT_ALLOWED"); }
            else if (raw == "LIST_USERS")
            {
                var sb = new StringBuilder("USERS_E2E:");
                List<ConnectedClient> all;
                lock (clientsLock) all = connectedClients.Where(c => !c.IsDisconnected).ToList();
                for (int i = 0; i < all.Count; i++)
                {
                    sb.Append(all[i].Username + "|" + (all[i].E2EPublicKey ?? ""));
                    if (i < all.Count - 1) sb.Append(",");
                }
                SendEncrypted(sender, sb.ToString());
                string list; lock (clientsLock) list = string.Join(",", connectedClients.Where(c => !c.IsDisconnected).Select(c => c.Username));
                SendEncrypted(sender, "USERS:" + list);
            }
        }

        // ═══════════════════════════════════════════════════════
        //  File Transfer Handlers
        // ═══════════════════════════════════════════════════════

        private void HandleFileInit(ConnectedClient sender, string raw)
        {
            string[] p = raw.Split(new[] { ':' }, 9);
            if (p.Length < 8) { SendEncrypted(sender, "FILE_ERR:INVALID_FORMAT"); return; }

            string transferId = p[1]; string targetType = p[2]; string targetName = p[3];
            string fileName = p[4];
            if (!long.TryParse(p[5], out long fileSize)) { SendEncrypted(sender, "FILE_ERR:INVALID_SIZE"); return; }
            string mimeType = p[6];
            if (!int.TryParse(p[7], out int totalChunks)) { SendEncrypted(sender, "FILE_ERR:INVALID_CHUNKS"); return; }
            string e2eFlag = p.Length >= 9 ? p[8] : "PLAIN";

            if (!InputValidator.IsValidTransferId(transferId)) { SendEncrypted(sender, "FILE_ERR:INVALID_FORMAT"); return; }
            if (!InputValidator.IsValidFileName(fileName)) { SendEncrypted(sender, "FILE_ERR:INVALID_PARAMS"); return; }
            if (targetType == "room" && InputValidator.ValidateRoomName(targetName) == null) { SendEncrypted(sender, "FILE_ERR:INVALID_PARAMS"); return; }
            if (targetType == "pm" && InputValidator.ValidateUsername(targetName) == null) { SendEncrypted(sender, "FILE_ERR:INVALID_PARAMS"); return; }
            if (fileSize > MaxFileSize) { SendEncrypted(sender, "FILE_ERR:TOO_LARGE:" + (MaxFileSize / 1024 / 1024)); return; }
            if (totalChunks > 10000) { SendEncrypted(sender, "FILE_ERR:INVALID_PARAMS"); return; }

            var transfer = new FileTransfer
            {
                TransferId = transferId,
                SenderUsername = sender.Username,
                TargetRoom = targetType == "room" ? targetName : null,
                TargetUsername = targetType == "pm" ? targetName : null,
                FileName = fileName,
                FileSize = fileSize,
                MimeType = mimeType,
                TotalChunks = totalChunks
            };
            lock (_transfersLock) _activeTransfers[transferId] = transfer;

            string initMsg = "FILE_INIT:" + transferId + ":" + sender.Username + ":" + fileName + ":" + fileSize + ":" + mimeType + ":" + totalChunks + ":" + e2eFlag;

            if (targetType == "pm")
            {
                ConnectedClient target;
                lock (clientsLock) target = connectedClients.FirstOrDefault(c => c.Username.Equals(targetName, StringComparison.OrdinalIgnoreCase) && !c.IsDisconnected);
                if (target == null) { SendEncrypted(sender, "FILE_ERR:USER_NOT_FOUND"); lock (_transfersLock) _activeTransfers.Remove(transferId); return; }
                SendEncrypted(target, initMsg);
            }
            else { BroadcastToRoom(initMsg, targetName, sender); }

            SendEncrypted(sender, "FILE_ACK:" + transferId);
            _fileLogger?.Info("FILE", $"Init {sender.Username} → {targetType}:{targetName} — {fileName} ({FormatBytes(fileSize)}) [{e2eFlag}]");
        }

        private void HandleFileChunk(ConnectedClient sender, string raw)
        {
            int c1 = raw.IndexOf(':', 0), c2 = raw.IndexOf(':', c1 + 1), c3 = raw.IndexOf(':', c2 + 1);
            if (c3 < 0) return;
            string transferId = raw.Substring(c1 + 1, c2 - c1 - 1);
            string chunkIdxStr = raw.Substring(c2 + 1, c3 - c2 - 1);
            string base64Data = raw.Substring(c3 + 1);

            FileTransfer transfer;
            lock (_transfersLock) { if (!_activeTransfers.TryGetValue(transferId, out transfer)) return; }
            if (transfer.SenderUsername != sender.Username) return;

            string chunkMsg = "FILE_CHUNK:" + transferId + ":" + chunkIdxStr + ":" + base64Data;

            if (transfer.TargetUsername != null)
            {
                ConnectedClient target;
                lock (clientsLock) target = connectedClients.FirstOrDefault(c => c.Username.Equals(transfer.TargetUsername, StringComparison.OrdinalIgnoreCase) && !c.IsDisconnected);
                if (target != null) SendEncrypted(target, chunkMsg);
            }
            else if (transfer.TargetRoom != null) { BroadcastToRoom(chunkMsg, transfer.TargetRoom, sender); }
            transfer.ReceivedChunks++;
        }

        private void HandleFileComplete(ConnectedClient sender, string raw)
        {
            string transferId = raw.Substring(14);
            FileTransfer transfer;
            lock (_transfersLock)
            {
                if (!_activeTransfers.TryGetValue(transferId, out transfer)) return;
                _activeTransfers.Remove(transferId);
            }
            string completeMsg = "FILE_COMPLETE:" + transferId + ":" + transfer.SenderUsername + ":" + transfer.FileName;
            if (transfer.TargetUsername != null)
            {
                ConnectedClient target;
                lock (clientsLock) target = connectedClients.FirstOrDefault(c => c.Username.Equals(transfer.TargetUsername, StringComparison.OrdinalIgnoreCase) && !c.IsDisconnected);
                if (target != null) SendEncrypted(target, completeMsg);
            }
            else if (transfer.TargetRoom != null)
            {
                BroadcastToRoom(completeMsg, transfer.TargetRoom, sender);
                lock (roomsLock)
                {
                    if (rooms.TryGetValue(transfer.TargetRoom, out ChatRoom room))
                        room.AddMessage("[" + DateTime.Now.ToString("HH:mm") + "] " + sender.Username + " a envoyé : " + transfer.FileName + " (" + FormatBytes(transfer.FileSize) + ")");
                }
                ScheduleSaveRooms();
            }
            _fileLogger?.Info("FILE", $"Terminé {transfer.SenderUsername} → {transfer.TargetUsername ?? "#" + transfer.TargetRoom} — {transfer.FileName}");
        }

        // ═══════════════════════════════════════════════════════
        //  Salons
        // ═══════════════════════════════════════════════════════

        private void JoinRoom(ConnectedClient cc, string roomName, bool sendHistory)
        {
            if (InputValidator.ValidateRoomName(roomName) == null)
            {
                SendEncrypted(cc, "ERR:INVALID_ROOM_NAME"); return;
            }
            lock (roomsLock) { if (!rooms.ContainsKey(roomName)) { SendEncrypted(cc, "ERR:ROOM_NOT_FOUND:" + roomName); return; } }
            string old = cc.CurrentRoom;
            if (!string.IsNullOrEmpty(old) && old != roomName)
                BroadcastToRoom("SYSTEM:" + cc.Username + " a quitté le salon.", old, null);
            cc.CurrentRoom = roomName;
            SendEncrypted(cc, "JOINED:" + roomName);
            BroadcastToRoom("SYSTEM:" + cc.Username + " a rejoint le salon.", roomName, cc);
            if (sendHistory)
            {
                List<string> hist; lock (roomsLock) hist = new List<string>(rooms[roomName].History);
                foreach (string line in hist) SendEncrypted(cc, "HISTORY:" + roomName + ":" + line);
                SendEncrypted(cc, "HISTORY_END:" + roomName);
            }
            RefreshUserList();
        }

        private void CreateRoom(ConnectedClient cc, string name)
        {
            if (InputValidator.ValidateRoomName(name) == null) { SendEncrypted(cc, "ERR:INVALID_ROOM_NAME"); return; }
            lock (roomsLock)
            {
                if (rooms.ContainsKey(name)) { SendEncrypted(cc, "ERR:ROOM_EXISTS:" + name); return; }
                rooms[name] = new ChatRoom { Name = name };
            }
            SaveRooms();
            _fileLogger?.Info("ROOM", $"Salon [{name}] créé par {cc.Username}");
            string list; lock (roomsLock) list = string.Join(",", rooms.Keys);
            lock (clientsLock) foreach (var c in connectedClients.Where(c2 => !c2.IsDisconnected)) SendEncrypted(c, "ROOMS:" + list);
            RefreshRoomList();
        }

        private void KickUser(string username, string by)
        {
            ConnectedClient t;
            lock (clientsLock) t = connectedClients.FirstOrDefault(c => c.Username.Equals(username, StringComparison.OrdinalIgnoreCase) && !c.IsDisconnected);
            if (t == null) { LogMessage("[ADMIN] Kick échoué : " + username + " introuvable"); return; }
            SendEncrypted(t, "SERVER:KICKED");
            DisconnectClient(t, "Expulsé par " + by);
            BroadcastToAll("SYSTEM:" + username + " a été expulsé.", null);
            _fileLogger?.Info("ADMIN", $"{username} expulsé par {by}");
        }

        private void BanUser(string username, string by)
        {
            lock (_bansLock) bannedUsernames.Add(username);
            ConnectedClient t;
            lock (clientsLock) t = connectedClients.FirstOrDefault(c => c.Username.Equals(username, StringComparison.OrdinalIgnoreCase) && !c.IsDisconnected);
            if (t != null)
            {
                string ip = t.IP == "::1" ? "127.0.0.1" : t.IP;
                lock (_bansLock) { bannedIPs.Add(ip); if (ip == "127.0.0.1") bannedIPs.Add("::1"); bannedUsernameToIP[username] = ip; }
                SendEncrypted(t, "SERVER:BANNED"); DisconnectClient(t, "Banni par " + by);
            }
            SaveBans(); BroadcastToAll("SYSTEM:" + username + " a été banni.", null);
            _fileLogger?.Security("ADMIN", $"{username} banni par {by}");
            RefreshBannedList();
        }

        private void UnbanUser(string username, string by)
        {
            lock (_bansLock)
            {
                bannedUsernames.Remove(username);
                if (bannedUsernameToIP.TryGetValue(username, out string ip))
                { bannedIPs.Remove(ip); if (ip == "127.0.0.1") bannedIPs.Remove("::1"); if (ip == "::1") bannedIPs.Remove("127.0.0.1"); bannedUsernameToIP.Remove(username); }
            }
            lock (_authLock) { var keys = ipBanExpiry.Keys.Where(k => k.Equals(username, StringComparison.OrdinalIgnoreCase)).ToList(); foreach (var k in keys) { ipBanExpiry.Remove(k); ipAuthFails.Remove(k); } }
            SaveBans();
            _fileLogger?.Info("ADMIN", $"{username} débanni par {by}");
            RefreshBannedList();
        }

        // ═══════════════════════════════════════════════════════
        //  Broadcast
        // ═══════════════════════════════════════════════════════

        private void BroadcastToRoom(string msg, string room, ConnectedClient exclude)
        {
            List<ConnectedClient> targets;
            lock (clientsLock) targets = connectedClients.Where(c => c.CurrentRoom == room && c != exclude && !c.IsDisconnected).ToList();
            foreach (var c in targets) try { SendEncrypted(c, msg); } catch { }
        }

        private void BroadcastToAll(string msg, ConnectedClient exclude)
        {
            List<ConnectedClient> targets;
            lock (clientsLock) targets = connectedClients.Where(c => c != exclude && !c.IsDisconnected).ToList();
            foreach (var c in targets) try { SendEncrypted(c, msg); } catch { }
        }

        // ═══════════════════════════════════════════════════════
        //  Déconnexion — IDEMPOTENTE
        // ═══════════════════════════════════════════════════════

        private void DisconnectClient(ConnectedClient cc, string reason)
        {
            if (!cc.TryMarkDisconnected()) return;
            bool was;
            lock (clientsLock) { was = connectedClients.Remove(cc); }
            if (cc.Username != null)
                lock (_rateLimitWarningsLock)
                    _rateLimitWarnings.Remove(cc.Username);
            try { cc.SslStream?.Close(); } catch { }
            try { cc.TcpClient?.Close(); } catch { }
            try { cc.WriteLock?.Dispose(); } catch { }
            if (was && cc.IsAuthenticated)
            {
                string logReason = reason ?? (cc.Username + " déconnecté");
                _fileLogger?.Info("DISCONNECT", logReason);
                LogMessage(logReason);
                BroadcastToRoom("SYSTEM:" + cc.Username + " a quitté le chat.", cc.CurrentRoom ?? "général", null);
                BroadcastToAll("E2E_DISCONNECTED:" + cc.Username, null);
                RefreshUserList(); UpdateStats();
            }
            lock (_transfersLock)
            {
                var toRemove = _activeTransfers.Where(t => t.Value.SenderUsername == cc.Username).Select(t => t.Key).ToList();
                foreach (var id in toRemove) _activeTransfers.Remove(id);
            }
        }

        // ═══════════════════════════════════════════════════════
        //  Réseau — framing
        // ═══════════════════════════════════════════════════════

        private byte[] ReadExact(Stream stream, int count)
        {
            byte[] buf = new byte[count]; int recv = 0;
            while (recv < count) { int n = stream.Read(buf, recv, count - recv); if (n == 0) return null; recv += n; }
            return buf;
        }

        private void SendRaw(Stream ns, byte[] data)
        {
            byte[] prefix = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(data.Length));
            ns.Write(prefix, 0, 4); ns.Write(data, 0, data.Length); ns.Flush();
        }

        private byte[] ReadRawPacket(Stream ns, int maxSize = 8192)
        {
            byte[] lenBuf = ReadExact(ns, 4); if (lenBuf == null) return null;
            int length = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(lenBuf, 0));
            if (length <= 0 || length > maxSize) return null;
            return ReadExact(ns, length);
        }

        private void SendRawFramedBeforeTls(TcpClient tcp, string message)
        {
            try
            {
                byte[] raw = Encoding.UTF8.GetBytes(message);
                byte[] prefix = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(raw.Length));
                var ns = tcp.GetStream();
                ns.Write(prefix, 0, 4); ns.Write(raw, 0, raw.Length); ns.Flush();
                AddBytesOut(4 + raw.Length);
            }
            catch (Exception ex) { _fileLogger?.Error("NET", "SendRawFramedBeforeTls : " + ex.Message); }
        }

        private bool PerformServerHandshake(ConnectedClient cc)
        {
            try
            {
                Stream ns = (Stream)cc.SslStream ?? cc.TcpClient.GetStream();
                byte[] pubKeyBytes = Encoding.UTF8.GetBytes(_serverRsaPublicXml);
                SendRaw(ns, pubKeyBytes);
                byte[] encAesKey = ReadRawPacket(ns, 512);
                if (encAesKey == null) return false;
                byte[] sessionKey = _serverRsa.Decrypt(encAesKey, true);
                if (sessionKey.Length != 32) return false;
                cc.SessionKey = sessionKey;
                return true;
            }
            catch (Exception ex)
            {
                _fileLogger?.Security("AUTH", "Handshake exception : " + ex.Message);
                return false;
            }
        }

        // ═══════════════════════════════════════════════════════
        //  AES-256-GCM (BouncyCastle)
        // ═══════════════════════════════════════════════════════

        private string ReadFramedPacket(Stream stream, byte[] sessionKey = null)
        {
            byte[] lenBuf = ReadExact(stream, 4);
            if (lenBuf == null) return null;
            int length = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(lenBuf, 0));
            int minSize = GCM_NONCE_SIZE + GCM_TAG_SIZE + 1;
            if (length < minSize || length > MaxPacketSize + GCM_NONCE_SIZE + GCM_TAG_SIZE) return null;
            byte[] data = ReadExact(stream, length);
            if (data == null) return null;
            AddBytesIn(4 + length);
            byte[] nonce = new byte[GCM_NONCE_SIZE];
            byte[] tag = new byte[GCM_TAG_SIZE];
            int cipherLen = length - GCM_NONCE_SIZE - GCM_TAG_SIZE;
            byte[] cipher = new byte[cipherLen];
            Buffer.BlockCopy(data, 0, nonce, 0, GCM_NONCE_SIZE);
            Buffer.BlockCopy(data, GCM_NONCE_SIZE, tag, 0, GCM_TAG_SIZE);
            Buffer.BlockCopy(data, GCM_NONCE_SIZE + GCM_TAG_SIZE, cipher, 0, cipherLen);
            try { return DecryptMessage(cipher, sessionKey, nonce, tag); }
            catch (CryptographicException)
            {
                _fileLogger?.Security("CRYPTO", "Paquet GCM invalide — rejeté.");
                return null;
            }
        }

        private void SendEncrypted(ConnectedClient cc, string message)
        {
            try
            {
                if (cc.SessionKey == null || cc.IsDisconnected) return;
                byte[] nonce, tag;
                byte[] cipher = EncryptMessage(message, cc.SessionKey, out nonce, out tag);
                int packetLen = GCM_NONCE_SIZE + GCM_TAG_SIZE + cipher.Length;
                byte[] packet = new byte[packetLen];
                Buffer.BlockCopy(nonce, 0, packet, 0, GCM_NONCE_SIZE);
                Buffer.BlockCopy(tag, 0, packet, GCM_NONCE_SIZE, GCM_TAG_SIZE);
                Buffer.BlockCopy(cipher, 0, packet, GCM_NONCE_SIZE + GCM_TAG_SIZE, cipher.Length);
                byte[] prefix = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(packetLen));
                Stream s = (Stream)cc.SslStream ?? cc.TcpClient.GetStream();
                if (!cc.WriteLock.Wait(5000))
                {
                    _fileLogger?.Warn("NET", $"WriteLock timeout pour {cc.Username ?? cc.IP}");
                    return;
                }
                try { s.Write(prefix, 0, 4); s.Write(packet, 0, packet.Length); s.Flush(); }
                finally { cc.WriteLock.Release(); }
                AddBytesOut(4 + packetLen);
            }
            catch (ObjectDisposedException) { }
            catch (Exception ex) { _fileLogger?.Error("NET", $"SendEncrypted [{cc.Username ?? cc.IP}]: {ex.Message}"); }
        }

        private byte[] EncryptMessage(string plainText, byte[] key, out byte[] nonce, out byte[] tag)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            nonce = new byte[GCM_NONCE_SIZE];
            using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(nonce);
            var gcm = new GcmBlockCipher(new AesEngine());
            gcm.Init(true, new AeadParameters(new KeyParameter(key), GCM_TAG_BITS, nonce));
            byte[] output = new byte[gcm.GetOutputSize(plainBytes.Length)];
            int len = gcm.ProcessBytes(plainBytes, 0, plainBytes.Length, output, 0);
            len += gcm.DoFinal(output, len);
            int cipherLen = len - GCM_TAG_SIZE;
            byte[] cipher = new byte[cipherLen]; tag = new byte[GCM_TAG_SIZE];
            Buffer.BlockCopy(output, 0, cipher, 0, cipherLen);
            Buffer.BlockCopy(output, cipherLen, tag, 0, GCM_TAG_SIZE);
            return cipher;
        }

        private string DecryptMessage(byte[] cipher, byte[] key, byte[] nonce, byte[] tag)
        {
            var gcm = new GcmBlockCipher(new AesEngine());
            gcm.Init(false, new AeadParameters(new KeyParameter(key), GCM_TAG_BITS, nonce));
            byte[] input = new byte[cipher.Length + GCM_TAG_SIZE];
            Buffer.BlockCopy(cipher, 0, input, 0, cipher.Length);
            Buffer.BlockCopy(tag, 0, input, cipher.Length, GCM_TAG_SIZE);
            byte[] plainBytes = new byte[gcm.GetOutputSize(input.Length)];
            int len = gcm.ProcessBytes(input, 0, input.Length, plainBytes, 0);
            len += gcm.DoFinal(plainBytes, len);
            return Encoding.UTF8.GetString(plainBytes, 0, len);
        }

        // ═══════════════════════════════════════════════════════
        //  PBKDF2-SHA256
        // ═══════════════════════════════════════════════════════

        private const int Pbkdf2Iterations = 100_000;
        private const int Pbkdf2HashBytes = 32;

        private static string GenerateSalt()
        {
            byte[] salt = new byte[32];
            using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(salt);
            return BitConverter.ToString(salt).Replace("-", "").ToLowerInvariant();
        }

        private static string HashPassword(string password, string saltHex)
        {
            byte[] saltBytes = HexToBytes(saltHex);
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, saltBytes, Pbkdf2Iterations, HashAlgorithmName.SHA256))
            { byte[] hash = pbkdf2.GetBytes(Pbkdf2HashBytes); return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant(); }
        }

        private static (string hash, string salt) HashPasswordNew(string password)
        { string salt = GenerateSalt(); return (HashPassword(password, salt), salt); }

        private static byte[] HexToBytes(string hex)
        { byte[] b = new byte[hex.Length / 2]; for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16); return b; }

        // ═══════════════════════════════════════════════════════
        //  UI Refresh
        // ═══════════════════════════════════════════════════════

        private void RefreshUserList()
        {
            if (lstUsers.InvokeRequired) { lstUsers.BeginInvoke(new Action(RefreshUserList)); return; }
            lstUsers.Items.Clear();
            List<ConnectedClient> online; lock (clientsLock) online = connectedClients.Where(c => !c.IsDisconnected).ToList();
            foreach (var cc in online)
                lstUsers.Items.Add("● [EN LIGNE]  " + cc.Username + "   room:" + cc.CurrentRoom
                    + "   " + cc.IP + "   " + (DateTime.Now - cc.ConnectedAt).ToString(@"hh\:mm\:ss")
                    + (string.IsNullOrEmpty(cc.E2EPublicKey) ? "" : "  🔐E2E"));
            HashSet<string> onlineNames;
            lock (clientsLock) onlineNames = new HashSet<string>(connectedClients.Where(c => !c.IsDisconnected).Select(c => c.Username), StringComparer.OrdinalIgnoreCase);
            List<UserAccount> allUsers; lock (_usersLock) allUsers = registeredUsers.Values.ToList();
            foreach (var kv in allUsers)
            {
                if (onlineNames.Contains(kv.Username)) continue;
                bool banned; lock (_bansLock) banned = bannedUsernames.Contains(kv.Username);
                lstUsers.Items.Add("○ [HORS LIGNE]  " + kv.Username + (banned ? "   ⛔ BANNI" : ""));
            }
        }

        private void RefreshRoomList()
        {
            if (lstRooms.InvokeRequired) { lstRooms.BeginInvoke(new Action(RefreshRoomList)); return; }
            lstRooms.Items.Clear();
            lock (roomsLock)
            {
                foreach (var kv in rooms)
                {
                    int n; lock (clientsLock) n = connectedClients.Count(c => c.CurrentRoom == kv.Key && !c.IsDisconnected);
                    lstRooms.Items.Add("#" + kv.Key + "   (" + n + " connecté(s))");
                }
            }
        }

        private void RefreshBannedList()
        {
            if (lstBanned.InvokeRequired) { lstBanned.BeginInvoke(new Action(RefreshBannedList)); return; }
            lstBanned.Items.Clear();
            List<string> unames, ips; Dictionary<string, string> maps;
            lock (_bansLock) { unames = bannedUsernames.ToList(); ips = bannedIPs.ToList(); maps = new Dictionary<string, string>(bannedUsernameToIP); }
            foreach (var u in unames)
            { string linkedIp = maps.TryGetValue(u, out string ip2) ? ip2 : null; lstBanned.Items.Add(new BanEntry { Type = BanType.Pseudo, Value = u, LinkedIP = linkedIp }); }
            foreach (var ip in ips)
            {
                if (ip == "::1" && ips.Contains("127.0.0.1")) continue;
                string linkedPseudo = maps.FirstOrDefault(kv => kv.Value == ip).Key;
                lstBanned.Items.Add(new BanEntry { Type = BanType.IP, Value = ip, LinkedPseudo = linkedPseudo });
            }
            List<KeyValuePair<string, DateTime>> tempBans; lock (_authLock) tempBans = ipBanExpiry.ToList();
            foreach (var kv in tempBans)
                if (DateTime.Now < kv.Value) lstBanned.Items.Add(new BanEntry { Type = BanType.Temp, Value = kv.Key, Expiry = kv.Value });
        }

        private void UpdateStats()
        {
            if (lblStats.InvokeRequired) { lblStats.BeginInvoke(new Action(UpdateStats)); return; }
            int u; lock (clientsLock) u = connectedClients.Count(c => !c.IsDisconnected);
            int r; lock (roomsLock) r = rooms.Count;
            int b; lock (_bansLock) b = bannedUsernames.Count + bannedIPs.Count;
            int ft; lock (_transfersLock) ft = _activeTransfers.Count;
            lblStats.Text = "👥 " + u + " connecté(s)   🚪 " + r + " salon(s)   🔒 " + b + " ban(s)   📎 " + ft + " transfert(s)";
        }

        private void LogMessage(string msg)
        {
            _fileLogger?.Info("UI", msg);
            if (txtLog.InvokeRequired) { txtLog.BeginInvoke(new Action<string>(LogMessage), msg); return; }
            txtLog.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "]  " + msg + Environment.NewLine);
            txtLog.ScrollToCaret();
        }

        private string GetSelectedUsername()
        {
            if (lstUsers.SelectedItem == null) return null;
            string entry = lstUsers.SelectedItem.ToString();
            int idx = entry.IndexOf(']'); if (idx < 0) return null;
            string rest = entry.Substring(idx + 1).TrimStart();
            string[] parts = rest.Split(new[] { "   " }, StringSplitOptions.RemoveEmptyEntries);
            return parts.Length > 0 ? parts[0].Trim() : null;
        }

        private bool IsSelectedUserOnline()
        {
            string name = GetSelectedUsername(); if (name == null) return false;
            lock (clientsLock) return connectedClients.Any(c => c.Username != null && c.Username.Equals(name, StringComparison.OrdinalIgnoreCase) && !c.IsDisconnected);
        }

        // ═══════════════════════════════════════════════════════
        //  UI Event Handlers
        // ═══════════════════════════════════════════════════════

        private void btnBan_Click(object sender, EventArgs e)
        {
            string sel = GetSelectedUsername(); if (sel == null) return;
            bool online = IsSelectedUserOnline();
            string msg = online ? "Bannir \"" + sel + "\" ? (connecté — sera déconnecté)" : "Bannir \"" + sel + "\" ? (hors ligne)";
            if (MessageBox.Show(msg, "Confirmer le ban", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes) BanUser(sel, "CONSOLE");
        }

        private void btnUnban_Click(object sender, EventArgs e)
        {
            if (lstBanned.SelectedItem == null) return;
            if (!(lstBanned.SelectedItem is BanEntry entry)) return;
            switch (entry.Type)
            {
                case BanType.Pseudo:
                    lock (_bansLock) { bannedUsernames.Remove(entry.Value); if (entry.LinkedIP != null) { bannedIPs.Remove(entry.LinkedIP); bannedIPs.Remove(entry.LinkedIP == "127.0.0.1" ? "::1" : "127.0.0.1"); } bannedUsernameToIP.Remove(entry.Value); }
                    LogMessage("[ADMIN] Débanni : " + entry.Value); break;
                case BanType.IP:
                    lock (_bansLock) { bannedIPs.Remove(entry.Value); bannedIPs.Remove(entry.Value == "127.0.0.1" ? "::1" : "127.0.0.1"); if (entry.LinkedPseudo != null) { bannedUsernames.Remove(entry.LinkedPseudo); bannedUsernameToIP.Remove(entry.LinkedPseudo); } }
                    LogMessage("[ADMIN] IP débannie : " + entry.Value); break;
                case BanType.Temp:
                    lock (_authLock) { ipBanExpiry.Remove(entry.Value); ipAuthFails.Remove(entry.Value); }
                    LogMessage("[ADMIN] Ban temporaire levé : " + entry.Value); break;
            }
            SaveBans(); RefreshBannedList(); UpdateStats();
        }

        private void btnAddRoom_Click(object sender, EventArgs e)
        {
            string name = txtNewRoom.Text.Trim();
            if (string.IsNullOrWhiteSpace(name) || name == "Nom du salon...") return;
            if (InputValidator.ValidateRoomName(name) == null) { LogMessage("[ERREUR] Nom de salon invalide : '" + name + "'"); return; }
            lock (roomsLock) { if (rooms.ContainsKey(name)) { LogMessage("Salon '" + name + "' existe déjà."); return; } rooms[name] = new ChatRoom { Name = name }; }
            string list; lock (roomsLock) list = string.Join(",", rooms.Keys);
            lock (clientsLock) foreach (var c in connectedClients.Where(c2 => !c2.IsDisconnected)) SendEncrypted(c, "ROOMS:" + list);
            SaveRooms(); txtNewRoom.Text = ""; RefreshRoomList();
            _fileLogger?.Info("ROOM", $"Salon [{name}] créé depuis la console.");
        }

        private void btnBroadcast_Click(object sender, EventArgs e)
        {
            string msg = txtBroadcastMsg.Text.Trim();
            if (string.IsNullOrWhiteSpace(msg) || msg == "Diffuser un message à tous...") return;
            BroadcastToAll("SYSTEM:[SERVEUR] " + msg, null);
            _fileLogger?.Info("BROADCAST", msg);
            LogMessage("[BROADCAST] " + msg); txtBroadcastMsg.Text = "";
        }

        private void numMaxConn_ValueChanged(object sender, EventArgs e) { maxConnPerIP = (int)numMaxConn.Value; }

        private void ServerForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (isRunning) StopServer(); else SaveRooms();
            _fileLogger?.Info("SERVER", "Application fermée");
            _fileLogger?.Dispose();
        }

        // ═══════════════════════════════════════════════════════
        //  InitializeComponent (UI)
        // ═══════════════════════════════════════════════════════

        private static readonly Color C_BG = Color.FromArgb(240, 242, 245);
        private static readonly Color C_PANEL = Color.White;
        private static readonly Color C_TOPBAR = Color.FromArgb(30, 35, 50);
        private static readonly Color C_ACCENT = Color.FromArgb(41, 128, 185);
        private static readonly Color C_ACCENT2 = Color.FromArgb(39, 174, 96);
        private static readonly Color C_DANGER = Color.FromArgb(192, 57, 43);
        private static readonly Color C_TEXT = Color.FromArgb(30, 30, 40);
        private static readonly Color C_TEXTLIGHT = Color.FromArgb(100, 110, 130);
        private static readonly Color C_BORDER = Color.FromArgb(210, 215, 225);
        private static readonly Color C_INPUT = Color.FromArgb(248, 249, 251);
        private static readonly Color C_LISTBG = Color.FromArgb(252, 253, 254);
        private static readonly Color C_PURPLE = Color.FromArgb(142, 68, 173);

        private void InitializeComponent()
        {
            this.Text = "Nexus  –  Serveur  E2E";
            this.ClientSize = new Size(920, 640);
            this.MinimumSize = new Size(920, 640);
            this.BackColor = C_BG; this.ForeColor = C_TEXT; this.Font = new Font("Segoe UI", 9f);
            this.SuspendLayout();

            // ── TOP BAR ──
            Panel topBar = new Panel { Dock = DockStyle.Top, Height = 54, BackColor = C_TOPBAR };
            Panel topAccent = new Panel { Dock = DockStyle.Bottom, Height = 3, BackColor = C_ACCENT };
            topBar.Controls.Add(topAccent);
            Label lblTitle = new Label { Text = "Serveur Nexus  🔐", Font = new Font("Segoe UI", 11f, FontStyle.Bold), ForeColor = Color.White, AutoSize = true, Location = new Point(14, 16) };
            lblPort = new Label { Text = "Port", ForeColor = Color.FromArgb(160, 170, 190), AutoSize = true, Location = new Point(222, 10) };
            txtPort = new TextBox { Text = "8888", Location = new Point(222, 28), Size = new Size(58, 22), BackColor = Color.FromArgb(50, 56, 75), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Font = new Font("Consolas", 9f) };
            btnStartServer = new Button { Text = "▶  Démarrer", Location = new Point(292, 20), Size = new Size(100, 26), BackColor = C_ACCENT2, ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Cursor = Cursors.Hand };
            btnStartServer.FlatAppearance.BorderSize = 0; btnStartServer.Click += btnStartServer_Click;
            lblStatus = new Label { Text = "● Arrêté", ForeColor = Color.FromArgb(231, 76, 60), Font = new Font("Segoe UI", 8.5f, FontStyle.Bold), AutoSize = true, Location = new Point(404, 22) };
            lblSysInfo = new Label { Text = "--:--:--  |  CPU --%  |  RAM -- Mo", Font = new Font("Consolas", 8f), ForeColor = Color.FromArgb(140, 160, 185), AutoSize = true, Location = new Point(560, 10) };
            lblStats = new Label { Text = "Connectés: 0   Salons: 0   Bans: 0", Font = new Font("Segoe UI", 8f), ForeColor = Color.FromArgb(140, 160, 185), AutoSize = true, Location = new Point(560, 30) };
            topBar.Controls.AddRange(new Control[] { topAccent, lblTitle, lblPort, txtPort, btnStartServer, lblStatus, lblSysInfo, lblStats });

            // ── STATUS BAR ──
            Panel bottomBar = new Panel { Dock = DockStyle.Bottom, Height = 24, BackColor = C_TOPBAR };
            Panel bottomAccent = new Panel { Dock = DockStyle.Top, Height = 1, BackColor = C_ACCENT };
            lblTraffic = new Label { Text = "↓ RX  0 o    ↑ TX  0 o", AutoSize = true, ForeColor = Color.FromArgb(140, 160, 185), Font = new Font("Consolas", 8f), Location = new Point(10, 4) };
            bottomBar.Controls.AddRange(new Control[] { bottomAccent, lblTraffic });

            // ── TABCONTROL ──
            tabMain = new TabControl { Dock = DockStyle.Fill, DrawMode = TabDrawMode.OwnerDrawFixed, ItemSize = new Size(130, 30), Padding = new Point(12, 6) };
            tabMain.DrawItem += (s, ev) =>
            {
                TabPage tp = tabMain.TabPages[ev.Index]; bool sel = tabMain.SelectedIndex == ev.Index;
                Color bgTab = sel ? C_PANEL : Color.FromArgb(228, 231, 236);
                ev.Graphics.FillRectangle(new SolidBrush(bgTab), ev.Bounds);
                if (sel) ev.Graphics.FillRectangle(new SolidBrush(C_ACCENT), new Rectangle(ev.Bounds.X, ev.Bounds.Y, ev.Bounds.Width, 3));
                TextRenderer.DrawText(ev.Graphics, tp.Text, new Font("Segoe UI", 8.5f, sel ? FontStyle.Bold : FontStyle.Regular), ev.Bounds, sel ? C_ACCENT : C_TEXTLIGHT, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
            };

            // ── TAB: Journal ──
            tabLog = new TabPage { Text = "  Journal  ", BackColor = C_PANEL };
            txtLog = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, BackColor = Color.FromArgb(248, 249, 251), ForeColor = Color.FromArgb(30, 120, 60), Font = new Font("Consolas", 8.5f), BorderStyle = BorderStyle.None };
            Panel broadcastRow = new Panel { Dock = DockStyle.Bottom, Height = 40, BackColor = Color.FromArgb(235, 238, 242) };
            Panel brBorder = new Panel { Dock = DockStyle.Top, Height = 1, BackColor = C_BORDER };
            txtBroadcastMsg = new TextBox { Location = new Point(8, 9), Size = new Size(680, 22), BackColor = C_INPUT, ForeColor = Color.Gray, BorderStyle = BorderStyle.FixedSingle, Text = "Diffuser un message à tous..." };
            txtBroadcastMsg.GotFocus += (s, ev) => { if (txtBroadcastMsg.Text == "Diffuser un message à tous...") { txtBroadcastMsg.Text = ""; txtBroadcastMsg.ForeColor = C_TEXT; } };
            txtBroadcastMsg.LostFocus += (s, ev) => { if (string.IsNullOrWhiteSpace(txtBroadcastMsg.Text)) { txtBroadcastMsg.Text = "Diffuser un message à tous..."; txtBroadcastMsg.ForeColor = Color.Gray; } };
            btnBroadcast = MakeButton("Diffuser", new Point(700, 8), new Size(100, 24), C_ACCENT);
            btnBroadcast.Enabled = false; btnBroadcast.Click += btnBroadcast_Click;
            broadcastRow.Controls.AddRange(new Control[] { brBorder, txtBroadcastMsg, btnBroadcast });
            tabLog.Controls.Add(txtLog); tabLog.Controls.Add(broadcastRow);

            // ── TAB: Utilisateurs ──
            tabUsers = new TabPage { Text = "  Utilisateurs  ", BackColor = C_PANEL };
            Panel usersPanel = new Panel { Dock = DockStyle.Fill, BackColor = C_PANEL, Padding = new Padding(10) };
            lblUsers = MakeSectionLabel("Utilisateurs  (● connecté  /  ○ hors ligne  /  🔐 E2E)", new Point(10, 10));
            lstUsers = new ListBox { Location = new Point(10, 32), Size = new Size(530, 440), BackColor = C_LISTBG, ForeColor = C_TEXT, Font = new Font("Consolas", 8.5f), BorderStyle = BorderStyle.FixedSingle };
            lstUsers.DrawMode = DrawMode.OwnerDrawFixed; lstUsers.ItemHeight = 18;
            lstUsers.DrawItem += (s, ev) =>
            {
                if (ev.Index < 0) return; string item = lstUsers.Items[ev.Index].ToString();
                bool online = item.Contains("[EN LIGNE]"); bool banned = item.Contains("⛔"); bool e2e = item.Contains("🔐");
                bool sel = (ev.State & DrawItemState.Selected) != 0;
                Color bg = sel ? C_ACCENT : C_LISTBG;
                Color fg = sel ? Color.White : banned ? C_DANGER : e2e ? C_PURPLE : online ? C_ACCENT2 : C_TEXTLIGHT;
                ev.Graphics.FillRectangle(new SolidBrush(bg), ev.Bounds);
                TextRenderer.DrawText(ev.Graphics, item, lstUsers.Font, new Point(ev.Bounds.X + 4, ev.Bounds.Y + 1), fg);
            };
            btnBan = MakeButton("⛔  Bannir", new Point(10, 480), new Size(110, 28), C_DANGER);
            btnBan.Click += btnBan_Click; btnBan.Enabled = false;
            Button btnKick = MakeButton("✖  Expulser", new Point(130, 480), new Size(110, 28), Color.FromArgb(180, 100, 20));
            btnKick.Enabled = false;
            btnKick.Click += (s, ev) => { string sel = GetSelectedUsername(); if (sel == null) return; if (MessageBox.Show("Expulser \"" + sel + "\" ?", "Confirmation", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes) KickUser(sel, "CONSOLE"); };
            lstUsers.SelectedIndexChanged += (s, ev) => { bool hasSel = lstUsers.SelectedIndex >= 0; btnBan.Enabled = hasSel; btnKick.Enabled = hasSel && IsSelectedUserOnline(); };
            Button btnRefreshUsers = MakeButton("↻  Actualiser", new Point(250, 480), new Size(100, 28), Color.FromArgb(100, 110, 130));
            btnRefreshUsers.Click += (s, ev) => RefreshUserList();
            lblRooms = MakeSectionLabel("Salons de discussion", new Point(558, 10));
            lstRooms = new ListBox { Location = new Point(558, 32), Size = new Size(330, 380), BackColor = C_LISTBG, ForeColor = C_TEXT, Font = new Font("Consolas", 9f), BorderStyle = BorderStyle.FixedSingle };
            txtNewRoom = new TextBox { Location = new Point(558, 422), Size = new Size(214, 22), BackColor = C_INPUT, ForeColor = Color.Gray, BorderStyle = BorderStyle.FixedSingle, Text = "Nom du salon..." };
            txtNewRoom.GotFocus += (s, ev) => { if (txtNewRoom.Text == "Nom du salon...") { txtNewRoom.Text = ""; txtNewRoom.ForeColor = C_TEXT; } };
            txtNewRoom.LostFocus += (s, ev) => { if (string.IsNullOrWhiteSpace(txtNewRoom.Text)) { txtNewRoom.Text = "Nom du salon..."; txtNewRoom.ForeColor = Color.Gray; } };
            btnAddRoom = MakeButton("+ Créer", new Point(780, 421), new Size(108, 24), C_ACCENT);
            btnAddRoom.Enabled = false; btnAddRoom.Click += btnAddRoom_Click;
            usersPanel.Controls.AddRange(new Control[] { lblUsers, lstUsers, btnBan, btnKick, btnRefreshUsers, lblRooms, lstRooms, txtNewRoom, btnAddRoom });
            tabUsers.Controls.Add(usersPanel);

            // ── TAB: Sécurité ──
            tabSecurity = new TabPage { Text = "  Sécurité  ", BackColor = C_BG };
            Panel secPanel = new Panel { Dock = DockStyle.Fill, BackColor = C_BG };
            lblBanned = MakeSectionLabel("Bans actifs", new Point(8, 8));
            lstBanned = new ListBox { Location = new Point(8, 28), Size = new Size(270, 430), BackColor = C_LISTBG, ForeColor = C_DANGER, Font = new Font("Consolas", 8.5f), BorderStyle = BorderStyle.FixedSingle };
            btnUnban = MakeButton("✔  Débannir", new Point(8, 466), new Size(128, 26), C_ACCENT2);
            btnUnban.Click += btnUnban_Click;
            Button btnUnbanAll = MakeButton("✕  Tout effacer", new Point(144, 466), new Size(134, 26), C_DANGER);
            btnUnbanAll.Click += (s, ev) =>
            {
                if (MessageBox.Show("Supprimer TOUS les bans ?", "Confirmation", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
                lock (_bansLock) { bannedUsernames.Clear(); bannedIPs.Clear(); bannedUsernameToIP.Clear(); }
                lock (_authLock) { ipBanExpiry.Clear(); ipAuthFails.Clear(); }
                SaveBans(); RefreshBannedList(); UpdateStats(); LogMessage("[ADMIN] All bans cleared.");
            };

            int cx = 290, cw = 295, cy = 8;
            Panel encCard = MakeSecCard(new Point(cx, cy), new Size(cw, 208), "Chiffrement & Transport");
            {
                int ry = 30;
                encCard.Controls.Add(MakeSecRow("RSA-2048 (OAEP) + AES-256-GCM", "Transport chiffré client ↔ serveur", true, ry)); ry += 42;
                encCard.Controls.Add(MakeSecRow("E2E PM : X25519 + HKDF + AES-256-GCM", "Le serveur relaie sans pouvoir lire", true, ry)); ry += 42;
                encCard.Controls.Add(MakeSecRow("E2E Room : Sender Keys + AES-256-GCM", "Clé par utilisateur/salon, distribuée via X25519", true, ry)); ry += 42;
                encCard.Controls.Add(MakeSecRow("TLS 1.2 + TOFU Certificate Pinning", "Certificat épinglé à la 1ère connexion", true, ry));
            }
            cy += 216;
            Panel pwdCard = MakeSecCard(new Point(cx, cy), new Size(cw, 114), "Stockage des mots de passe");
            { int ry = 30; pwdCard.Controls.Add(MakeSecRow("PBKDF2-SHA256 — 100 000 itérations", "Lent par conception", true, ry)); ry += 42; pwdCard.Controls.Add(MakeSecRow("Sel aléatoire 32 octets / utilisateur", "Empêche les attaques par dictionnaire", true, ry)); }
            cy += 122;
            Panel bfCard = MakeSecCard(new Point(cx, cy), new Size(cw, 208), "Protection anti-bruteforce & anti-flood");
            {
                int ry = 30;
                bfCard.Controls.Add(MakeSecRow("Verrouillage compte — 5 mauvais mdp", "Locked " + AuthBanMinutes + " min", true, ry)); ry += 42;
                bfCard.Controls.Add(MakeSecRow("Ban IP temporaire — 10 échecs d'auth", "IP banned " + AuthBanMinutes + " min", true, ry)); ry += 42;
                bfCard.Controls.Add(MakeSecRow("Max " + maxConnPerIP + " connexions / IP", "Configurable", true, ry)); ry += 42;
                bfCard.Controls.Add(MakeSecRow($"Rate-limit : {RateLimitMaxMessages} msg / {(int)RateLimitWindowSec}s", $"{RateLimitMaxWarnings} avertissements puis déconnexion", true, ry));
            }

            int dx = 597, dy = 8;
            Panel acCard = MakeSecCard(new Point(dx, dy), new Size(cw, 114), "Contrôle d'accès");
            { int ry = 30; acCard.Controls.Add(MakeSecRow("Ban/kick depuis l'interface serveur", "Les clients ne peuvent pas émettre de cmd admin", true, ry)); ry += 42; acCard.Controls.Add(MakeSecRow("Ban IP + pseudo (persistant)", "Sauvegardés dans bans.json", true, ry)); }
            dy += 122;
            Panel limCard = MakeSecCard(new Point(dx, dy), new Size(cw, 250), "Sécurité renforcée");
            {
                int ry = 30;
                limCard.Controls.Add(MakeSecRow("TLS 1.2 + certificat auto-signé", "SslStream sur chaque connexion", true, ry)); ry += 42;
                limCard.Controls.Add(MakeSecRow("PFX password depuis tls_config.json", "Plus de mot de passe en dur", true, ry)); ry += 42;
                limCard.Controls.Add(MakeSecRow("AES-GCM : protection padding oracle", "Tag 128 bits vérifié avant déchiffrement", true, ry)); ry += 42;
                limCard.Controls.Add(MakeSecRow("Zero-knowledge E2E (PM, salons, fichiers)", "Le serveur ne voit que des blobs chiffrés", true, ry)); ry += 42;
                limCard.Controls.Add(MakeSecRow("Validation des entrées + logging fichier", "Rotation logs 10 MB, backup JSON auto", true, ry));
            }
            secPanel.Controls.AddRange(new Control[] { lblBanned, lstBanned, btnUnban, btnUnbanAll, encCard, pwdCard, bfCard, acCard, limCard });
            tabSecurity.Controls.Add(secPanel);

            // ── TAB: Paramètres ──
            tabSettings = new TabPage { Text = "  Paramètres  ", BackColor = C_PANEL };
            Panel settingsPanel = new Panel { Dock = DockStyle.Fill, BackColor = C_PANEL };
            Panel connCard = new Panel { Location = new Point(16, 16), Size = new Size(380, 100), BackColor = C_INPUT, BorderStyle = BorderStyle.FixedSingle };
            Label lblConnSection = MakeSectionLabel("Limites de connexion", new Point(10, 10)); lblConnSection.ForeColor = C_ACCENT;
            lblMaxConn = new Label { Text = "Max connexions / IP :", ForeColor = C_TEXTLIGHT, Location = new Point(10, 38), AutoSize = true };
            numMaxConn = new NumericUpDown { Location = new Point(180, 35), Size = new Size(70, 24), Minimum = 1, Maximum = 20, Value = maxConnPerIP, BackColor = C_PANEL, ForeColor = C_TEXT };
            numMaxConn.ValueChanged += numMaxConn_ValueChanged;
            connCard.Controls.AddRange(new Control[] { lblConnSection, lblMaxConn, numMaxConn });

            Panel filesCard = new Panel { Location = new Point(16, 130), Size = new Size(380, 180), BackColor = C_INPUT, BorderStyle = BorderStyle.FixedSingle };
            Label lblFilesTitle = MakeSectionLabel("Fichiers de données", new Point(10, 10)); lblFilesTitle.ForeColor = C_ACCENT;
            Label lblFilesInfo = new Label
            {
                Text = "users.json    – comptes, hashes, clés E2E publiques\n"
                     + "rooms.json   – salons & historique\n"
                     + "bans.json     – IP and username bans\n"
                     + "tls_config.json – mot de passe PFX (auto-généré)\n"
                     + "logs/         – logs structurés (rotation 10 MB, 30 fichiers)\n"
                     + "backups/      – backups JSON automatiques (5 par fichier)\n"
                     + "\nTransferts fichiers : max " + (MaxFileSize / 1024 / 1024) + " MB, chunks " + (FileChunkSize / 1024) + " KB\n"
                     + "Rate-limit : " + RateLimitMaxMessages + " msg / " + (int)RateLimitWindowSec + "s",
                ForeColor = C_TEXTLIGHT,
                Font = new Font("Segoe UI", 8.5f),
                Location = new Point(10, 34),
                AutoSize = true
            };
            filesCard.Controls.AddRange(new Control[] { lblFilesTitle, lblFilesInfo });

            Button btnResetTraffic = MakeButton("Réinitialiser le trafic", new Point(16, 330), new Size(200, 28), Color.FromArgb(100, 110, 130));
            btnResetTraffic.Click += (s, ev) =>
            {
                long snapIn, snapOut; DateTime snapReset;
                lock (_trafficLock) { snapIn = _totalBytesIn; snapOut = _totalBytesOut; snapReset = _trafficResetTime; }
                string dur = (DateTime.Now - snapReset).ToString(@"hh\:mm\:ss");
                LogMessage($"[TRAFIC] Session {dur} — RX {FormatBytes(snapIn)}  TX {FormatBytes(snapOut)}  Total {FormatBytes(snapIn + snapOut)} — remis à zéro.");
                lock (_trafficLock) { _totalBytesIn = 0; _totalBytesOut = 0; _trafficResetTime = DateTime.Now; }
            };

            Button btnOpenLogs = MakeButton("📂  Ouvrir les logs", new Point(230, 330), new Size(166, 28), C_ACCENT);
            btnOpenLogs.Click += (s, ev) =>
            {
                string logDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
                if (Directory.Exists(logDir)) Process.Start("explorer.exe", logDir);
                else LogMessage("[INFO] Dossier logs/ pas encore créé.");
            };

            settingsPanel.Controls.AddRange(new Control[] { connCard, filesCard, btnResetTraffic, btnOpenLogs });
            tabSettings.Controls.Add(settingsPanel);

            // ── Assemblage ──
            tabMain.TabPages.AddRange(new TabPage[] { tabLog, tabUsers, tabSecurity, tabSettings });
            this.Controls.Add(tabMain); this.Controls.Add(topBar); this.Controls.Add(bottomBar);
            this.FormClosing += ServerForm_FormClosing;

            _uiRefreshTimer = new System.Windows.Forms.Timer { Interval = 4000 };
            _uiRefreshTimer.Tick += (s, ev) => { RefreshUserList(); RefreshRoomList(); UpdateStats(); RefreshBannedList(); };
            _uiRefreshTimer.Start();
            _sysMonitorTimer = new System.Windows.Forms.Timer { Interval = 1000 };
            _sysMonitorTimer.Tick += UpdateSysMonitor;
            _sysMonitorTimer.Start();

            this.ResumeLayout(false);
        }

        // ── Helpers UI ──
        private Label MakeSectionLabel(string text, Point loc) => new Label { Text = text, Location = loc, AutoSize = true, ForeColor = C_TEXT, Font = new Font("Segoe UI", 9f, FontStyle.Bold) };
        private Button MakeButton(string text, Point loc, Size size, Color bg) { var b = new Button { Text = text, Location = loc, Size = size, BackColor = bg, ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand }; b.FlatAppearance.BorderSize = 0; return b; }
        private Panel MakeSecCard(Point loc, Size size, string title)
        {
            var card = new Panel { Location = loc, Size = size, BackColor = C_PANEL, BorderStyle = BorderStyle.FixedSingle };
            card.Controls.Add(new Panel { Dock = DockStyle.Top, Height = 4, BackColor = C_ACCENT });
            card.Controls.Add(new Label { Text = title, Location = new Point(10, 10), AutoSize = true, ForeColor = C_TEXT, Font = new Font("Segoe UI", 8.5f, FontStyle.Bold) });
            return card;
        }
        private Panel MakeSecRow(string title, string detail, bool ok, int y)
        {
            Color dot = ok ? C_ACCENT2 : C_DANGER;
            var row = new Panel { Location = new Point(8, y), Size = new Size(355, 38), BackColor = Color.Transparent };
            row.Controls.Add(new Panel { Location = new Point(0, 4), Size = new Size(4, 30), BackColor = dot });
            row.Controls.Add(new Label { Text = title, Location = new Point(12, 2), Size = new Size(335, 16), ForeColor = ok ? C_TEXT : C_DANGER, Font = new Font("Segoe UI", 8.5f, FontStyle.Bold) });
            row.Controls.Add(new Label { Text = detail, Location = new Point(12, 20), Size = new Size(335, 14), ForeColor = C_TEXTLIGHT, Font = new Font("Segoe UI", 7.5f) });
            return row;
        }
    }
}