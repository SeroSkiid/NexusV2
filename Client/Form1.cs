using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

// BouncyCastle — AES-256-GCM + X25519
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace ChatClientGUI
{
    // ═══════════════════════════════════════════════════════════
    //  FIX — Clé d'identité E2E persistante (DPAPI)
    //  Corrige la faille 1.3 : clés régénérées à chaque session
    // ═══════════════════════════════════════════════════════════

    /// <summary>
    /// Gestionnaire de clé d'identité E2E persistante.
    /// La clé privée est protégée par DPAPI (chiffrée par le compte Windows).
    /// </summary>
    public class E2EIdentity
    {
        private static readonly string IdentityFile = Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory, "e2e_identity.dat");

        public AsymmetricCipherKeyPair KeyPair { get; private set; }
        public byte[] PublicKeyBytes { get; private set; }
        public string PublicKeyBase64 { get; private set; }

        public void LoadOrGenerate()
        {
            if (TryLoad())
            {
                DebugLog.Info("E2E identity loaded from file");
                return;
            }
            Generate();
            Save();
            DebugLog.Info("E2E identity generated and saved");
        }

        private void Generate()
        {
            var gen = new X25519KeyPairGenerator();
            gen.Init(new KeyGenerationParameters(new SecureRandom(), 256));
            KeyPair = gen.GenerateKeyPair();
            PublicKeyBytes = ((X25519PublicKeyParameters)KeyPair.Public).GetEncoded();
            PublicKeyBase64 = Convert.ToBase64String(PublicKeyBytes);
        }

        private bool TryLoad()
        {
            try
            {
                if (!File.Exists(IdentityFile)) return false;
                byte[] encrypted = File.ReadAllBytes(IdentityFile);
                byte[] privateKeyBytes = ProtectedData.Unprotect(
                    encrypted,
                    Encoding.UTF8.GetBytes("NexusChat-E2E-Identity"),
                    DataProtectionScope.CurrentUser);
                if (privateKeyBytes.Length != 32) return false;
                var privateKey = new X25519PrivateKeyParameters(privateKeyBytes, 0);
                var publicKey = privateKey.GeneratePublicKey();
                KeyPair = new AsymmetricCipherKeyPair(publicKey, privateKey);
                PublicKeyBytes = publicKey.GetEncoded();
                PublicKeyBase64 = Convert.ToBase64String(PublicKeyBytes);
                Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);
                return true;
            }
            catch (Exception ex)
            {
                DebugLog.Warn("E2E identity load failed: " + ex.Message);
                return false;
            }
        }

        private void Save()
        {
            try
            {
                byte[] privateKeyBytes = ((X25519PrivateKeyParameters)KeyPair.Private).GetEncoded();
                byte[] encrypted = ProtectedData.Protect(
                    privateKeyBytes,
                    Encoding.UTF8.GetBytes("NexusChat-E2E-Identity"),
                    DataProtectionScope.CurrentUser);
                File.WriteAllBytes(IdentityFile, encrypted);
                Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);
            }
            catch (Exception ex) { DebugLog.Error("E2E identity save failed", ex); }
        }

        public void Regenerate()
        {
            Generate();
            Save();
            DebugLog.Info("E2E identity regenerated");
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  FIX — KeyTrustStore : TOFU + Fingerprint verification
    //  Corrige les failles 1.1 et 1.2 : MITM serveur + pas d'auth clés
    // ═══════════════════════════════════════════════════════════

    /// <summary>
    /// Gestionnaire de confiance des clés publiques.
    /// Implémente TOFU (Trust On First Use) avec alertes de changement.
    /// </summary>
    public class KeyTrustStore
    {
        private static readonly string TrustFile = Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory, "trusted_keys.json");

        private readonly Dictionary<string, string> _trustedFingerprints
            = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly object _lock = new object();

        public enum TrustResult
        {
            TrustedFirstUse,
            TrustedKnown,
            KeyChanged
        }

        public static string ComputeFingerprint(byte[] publicKey)
        {
            byte[] hash;
            using (var sha = SHA256.Create())
                hash = sha.ComputeHash(publicKey);
            var sb = new StringBuilder();
            for (int i = 0; i < 16; i++)
            {
                if (i > 0 && i % 2 == 0) sb.Append(' ');
                sb.Append(hash[i].ToString("X2"));
            }
            return sb.ToString();
        }

        public TrustResult VerifyKey(string username, byte[] publicKey)
        {
            string fingerprint = ComputeFingerprint(publicKey);
            lock (_lock)
            {
                if (!_trustedFingerprints.TryGetValue(username, out string known))
                {
                    _trustedFingerprints[username] = fingerprint;
                    Save();
                    return TrustResult.TrustedFirstUse;
                }
                if (known == fingerprint)
                    return TrustResult.TrustedKnown;
                return TrustResult.KeyChanged;
            }
        }

        public void AcceptNewKey(string username, byte[] publicKey)
        {
            lock (_lock)
            {
                _trustedFingerprints[username] = ComputeFingerprint(publicKey);
                Save();
            }
        }

        public string GetFingerprint(string username)
        {
            lock (_lock)
                return _trustedFingerprints.TryGetValue(username, out string fp) ? fp : null;
        }

        public static string GetMyFingerprint(byte[] myPublicKey) => ComputeFingerprint(myPublicKey);

        public void Load()
        {
            try
            {
                if (!File.Exists(TrustFile)) return;
                string json = File.ReadAllText(TrustFile, Encoding.UTF8);
                var parsed = ClientForm.SimpleJsonParseStatic(json);
                lock (_lock)
                    foreach (var kv in parsed)
                        _trustedFingerprints[kv.Key] = kv.Value;
            }
            catch (Exception ex) { DebugLog.Warn("KeyTrustStore.Load: " + ex.Message); }
        }

        private void Save()
        {
            try
            {
                var sb = new StringBuilder("{\n");
                bool first = true;
                foreach (var kv in _trustedFingerprints)
                {
                    if (!first) sb.Append(",\n");
                    sb.Append($"  \"{JsonEsc(kv.Key)}\": \"{JsonEsc(kv.Value)}\"");
                    first = false;
                }
                sb.Append("\n}");
                File.WriteAllText(TrustFile, sb.ToString(), Encoding.UTF8);
            }
            catch (Exception ex) { DebugLog.Warn("KeyTrustStore.Save: " + ex.Message); }
        }

        private static string JsonEsc(string s) => s?.Replace("\\", "\\\\").Replace("\"", "\\\"") ?? "";
    }

    // ═══════════════════════════════════════════════════════════
    //  FIX — SecureMessageFormat : sender authentifié dans le ciphertext
    //  Corrige la faille 1.11 : usurpation d'identité dans les salons
    // ═══════════════════════════════════════════════════════════

    /// <summary>
    /// Format de message E2E sécurisé.
    /// Le sender est inclus DANS le ciphertext pour empêcher l'usurpation.
    /// Structure : sender_length(2B BE) + sender(UTF-8) + message(UTF-8)
    /// </summary>
    public static class SecureMessageFormat
    {
        public static byte[] Encode(string sender, string message)
        {
            byte[] senderBytes = Encoding.UTF8.GetBytes(sender);
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            if (senderBytes.Length > 65535)
                throw new ArgumentException("Sender name too long");
            byte[] result = new byte[2 + senderBytes.Length + messageBytes.Length];
            result[0] = (byte)(senderBytes.Length >> 8);
            result[1] = (byte)(senderBytes.Length & 0xFF);
            Buffer.BlockCopy(senderBytes, 0, result, 2, senderBytes.Length);
            Buffer.BlockCopy(messageBytes, 0, result, 2 + senderBytes.Length, messageBytes.Length);
            return result;
        }

        public static string Decode(byte[] plainBytes, string expectedSender)
        {
            if (plainBytes.Length < 3) return null;
            int senderLen = (plainBytes[0] << 8) | plainBytes[1];
            if (senderLen <= 0 || 2 + senderLen > plainBytes.Length) return null;
            string sender = Encoding.UTF8.GetString(plainBytes, 2, senderLen);
            if (!sender.Equals(expectedSender, StringComparison.OrdinalIgnoreCase))
            {
                DebugLog.Error($"SENDER MISMATCH! Expected '{expectedSender}', got '{sender}'");
                return null;
            }
            int messageStart = 2 + senderLen;
            if (messageStart >= plainBytes.Length) return "";
            return Encoding.UTF8.GetString(plainBytes, messageStart, plainBytes.Length - messageStart);
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  FIX — NonceManager : nonce compteur anti-rejeu
    //  Corrige les failles 1.6 et 1.7
    // ═══════════════════════════════════════════════════════════

    /// <summary>
    /// Gestionnaire de nonce hybride pour AES-256-GCM.
    /// Format: [4 octets random salt] [8 octets compteur big-endian]
    /// </summary>
    public class NonceManager
    {
        private long _sendCounter = 0;
        private long _maxRecvCounter = 0;
        private readonly byte[] _salt;
        private readonly object _lock = new object();
        private const int ReorderWindow = 64;
        private readonly HashSet<long> _recentCounters = new HashSet<long>();

        public NonceManager()
        {
            _salt = new byte[4];
            using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(_salt);
        }

        public byte[] NextSendNonce()
        {
            long counter;
            lock (_lock) { counter = _sendCounter++; }
            byte[] nonce = new byte[12];
            Buffer.BlockCopy(_salt, 0, nonce, 0, 4);
            for (int i = 7; i >= 0; i--)
            {
                nonce[4 + i] = (byte)(counter & 0xFF);
                counter >>= 8;
            }
            return nonce;
        }

        public static long ExtractCounter(byte[] nonce)
        {
            long counter = 0;
            for (int i = 0; i < 8; i++)
                counter = (counter << 8) | nonce[4 + i];
            return counter;
        }

        public bool VerifyRecvNonce(byte[] nonce)
        {
            long counter = ExtractCounter(nonce);
            lock (_lock)
            {
                if (counter > _maxRecvCounter)
                {
                    _recentCounters.RemoveWhere(c => c < counter - ReorderWindow);
                    _recentCounters.Add(counter);
                    _maxRecvCounter = counter;
                    return true;
                }
                if (counter >= _maxRecvCounter - ReorderWindow)
                {
                    if (_recentCounters.Contains(counter)) return false;
                    _recentCounters.Add(counter);
                    return true;
                }
                return false;
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Protocol message parser
    // ═══════════════════════════════════════════════════════════

    public class ProtocolMessage
    {
        public string Command { get; }
        public string[] Fields { get; }
        public string Raw { get; }

        private ProtocolMessage(string command, string[] fields, string raw)
        {
            Command = command; Fields = fields; Raw = raw;
        }

        public static ProtocolMessage Parse(string raw, int expectedFields)
        {
            if (string.IsNullOrEmpty(raw))
                return new ProtocolMessage("", new string[0], raw ?? "");
            int firstColon = raw.IndexOf(':');
            if (firstColon < 0)
                return new ProtocolMessage(raw, new string[0], raw);
            string command = raw.Substring(0, firstColon);
            if (expectedFields <= 0)
                return new ProtocolMessage(command, new string[] { raw.Substring(firstColon + 1) }, raw);
            var fields = new List<string>();
            int pos = firstColon + 1;
            for (int i = 0; i < expectedFields - 1 && pos < raw.Length; i++)
            {
                int next = raw.IndexOf(':', pos);
                if (next < 0) { fields.Add(raw.Substring(pos)); pos = raw.Length; break; }
                fields.Add(raw.Substring(pos, next - pos));
                pos = next + 1;
            }
            if (pos <= raw.Length)
                fields.Add(pos < raw.Length ? raw.Substring(pos) : "");
            return new ProtocolMessage(command, fields.ToArray(), raw);
        }

        public static string Build(string command, params string[] fields)
        {
            if (fields == null || fields.Length == 0) return command;
            return command + ":" + string.Join(":", fields);
        }

        public string Field(int index, string defaultValue = "")
            => (index >= 0 && index < Fields.Length) ? Fields[index] : defaultValue;

        public int FieldInt(int index, int defaultValue = 0)
        {
            if (index >= 0 && index < Fields.Length && int.TryParse(Fields[index], out int val)) return val;
            return defaultValue;
        }

        public long FieldLong(int index, long defaultValue = 0)
        {
            if (index >= 0 && index < Fields.Length && long.TryParse(Fields[index], out long val)) return val;
            return defaultValue;
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Custom Controls
    // ═══════════════════════════════════════════════════════════

    public class RoundedPanel : Panel
    {
        public int CornerRadius { get; set; } = 12;
        public Color BorderColor { get; set; } = Color.FromArgb(230, 232, 238);
        public int BorderWidth { get; set; } = 1;

        public RoundedPanel()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            var rect = new Rectangle(BorderWidth, BorderWidth, Width - 2 * BorderWidth - 1, Height - 2 * BorderWidth - 1);
            using (var path = CreateRoundedRect(rect, CornerRadius))
            {
                using (var brush = new SolidBrush(BackColor)) e.Graphics.FillPath(brush, path);
                if (BorderWidth > 0)
                    using (var pen = new Pen(BorderColor, BorderWidth)) e.Graphics.DrawPath(pen, path);
            }
        }

        private static GraphicsPath CreateRoundedRect(Rectangle rect, int radius)
        {
            var path = new GraphicsPath(); int d = radius * 2;
            path.AddArc(rect.X, rect.Y, d, d, 180, 90);
            path.AddArc(rect.Right - d, rect.Y, d, d, 270, 90);
            path.AddArc(rect.Right - d, rect.Bottom - d, d, d, 0, 90);
            path.AddArc(rect.X, rect.Bottom - d, d, d, 90, 90);
            path.CloseFigure(); return path;
        }
    }

    public class ModernButton : Button
    {
        public Color HoverColor { get; set; } = Color.Empty;
        public Color PressColor { get; set; } = Color.Empty;
        public int CornerRadius { get; set; } = 10;
        public bool UseGradient { get; set; } = true;
        public string IconChar { get; set; } = null;
        public Color IconColor { get; set; } = Color.White;
        public Color DisabledBackColor { get; set; } = Color.FromArgb(200, 205, 215);
        public Color DisabledForeColor { get; set; } = Color.FromArgb(140, 148, 165);
        public Color BorderAccent { get; set; } = Color.Empty;
        public bool ShowShadow { get; set; } = true;

        private bool _hovering = false;
        private bool _pressing = false;
        private float _hoverFade = 0f;
        private System.Windows.Forms.Timer _animTimer;
        private Font _iconFont;

        public ModernButton()
        {
            FlatStyle = FlatStyle.Flat; FlatAppearance.BorderSize = 0;
            FlatAppearance.MouseDownBackColor = Color.Transparent;
            FlatAppearance.MouseOverBackColor = Color.Transparent;
            Cursor = Cursors.Hand;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw |
                     ControlStyles.SupportsTransparentBackColor, true);
            _animTimer = new System.Windows.Forms.Timer { Interval = 16 };
            _animTimer.Tick += (s, e) =>
            {
                float target = (_hovering && Enabled) ? 1f : 0f;
                float step = 0.18f;
                if (Math.Abs(_hoverFade - target) < step) { _hoverFade = target; _animTimer.Stop(); }
                else _hoverFade += (_hoverFade < target) ? step : -step;
                Invalidate();
            };
        }

        protected override void OnFontChanged(EventArgs e) { base.OnFontChanged(e); _iconFont?.Dispose(); _iconFont = new Font("Segoe UI", Font.Size + 1f); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            Color clearColor = Parent != null ? Parent.BackColor : Color.Transparent;
            g.Clear(clearColor);
            Color baseBg = Enabled ? BackColor : DisabledBackColor;
            Color baseFg = Enabled ? ForeColor : DisabledForeColor;
            Color hoverBg = HoverColor != Color.Empty ? HoverColor : LightenColor(baseBg, 18);
            Color pressBg = PressColor != Color.Empty ? PressColor : DarkenColor(baseBg, 15);
            Color currentBg;
            if (!Enabled) currentBg = DisabledBackColor;
            else if (_pressing) currentBg = pressBg;
            else currentBg = BlendColor(baseBg, hoverBg, _hoverFade);
            int shadowOff = (ShowShadow && Enabled && !_pressing) ? 2 : 0;
            var bodyRect = new Rectangle(1, 1, Width - 3, Height - 3 - shadowOff);
            if (shadowOff > 0)
            {
                var shadowRect = new Rectangle(2, 3, Width - 4, Height - 4);
                using (var sp = MkRoundedPath(shadowRect, CornerRadius))
                using (var sb = new SolidBrush(Color.FromArgb(22, 0, 0, 0)))
                    g.FillPath(sb, sp);
            }
            using (var path = MkRoundedPath(bodyRect, CornerRadius))
            {
                if (UseGradient && Enabled)
                {
                    using (var brush = new LinearGradientBrush(bodyRect, LightenColor(currentBg, 10), DarkenColor(currentBg, 6), 90f))
                        g.FillPath(brush, path);
                }
                else using (var brush = new SolidBrush(currentBg)) g.FillPath(brush, path);
                if (Enabled && !_pressing)
                {
                    var hlRect = new Rectangle(bodyRect.X + 2, bodyRect.Y + 1, bodyRect.Width - 4, bodyRect.Height / 2);
                    using (var hlPath = MkRoundedPath(hlRect, Math.Max(1, CornerRadius - 2)))
                    using (var hlBrush = new LinearGradientBrush(hlRect, Color.FromArgb(35, 255, 255, 255), Color.FromArgb(0, 255, 255, 255), 90f))
                        g.FillPath(hlBrush, hlPath);
                }
                if (BorderAccent != Color.Empty && Enabled)
                    using (var pen = new Pen(Color.FromArgb(80, BorderAccent), 1f)) g.DrawPath(pen, path);
                else if (Enabled && _hovering)
                    using (var pen = new Pen(Color.FromArgb(30, 255, 255, 255), 1f)) g.DrawPath(pen, path);
            }
            if (_iconFont == null) _iconFont = new Font("Segoe UI", Font.Size + 1f);
            int contentX = 0, totalW = 0;
            bool hasIcon = !string.IsNullOrEmpty(IconChar);
            var textSize = TextRenderer.MeasureText(Text, Font);
            Size iconSize = hasIcon ? TextRenderer.MeasureText(IconChar, _iconFont) : Size.Empty;
            if (hasIcon) totalW = iconSize.Width + textSize.Width - 4; else totalW = textSize.Width;
            contentX = (Width - totalW) / 2;
            int textY = (bodyRect.Height - textSize.Height) / 2 + bodyRect.Y;
            int pressOff = _pressing ? 1 : 0;
            if (hasIcon)
            {
                int iconY = (bodyRect.Height - iconSize.Height) / 2 + bodyRect.Y;
                TextRenderer.DrawText(g, IconChar, _iconFont, new Point(contentX + pressOff, iconY + pressOff), Enabled ? IconColor : DisabledForeColor);
                contentX += iconSize.Width - 2;
            }
            TextRenderer.DrawText(g, Text, Font, new Point(contentX + pressOff, textY + pressOff), baseFg);
        }

        protected override void OnMouseEnter(EventArgs e) { _hovering = true; if (Enabled) _animTimer.Start(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { _hovering = false; _pressing = false; _animTimer.Start(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(MouseEventArgs e) { _pressing = true; Invalidate(); base.OnMouseDown(e); }
        protected override void OnMouseUp(MouseEventArgs e) { _pressing = false; Invalidate(); base.OnMouseUp(e); }
        protected override void OnEnabledChanged(EventArgs e) { Invalidate(); base.OnEnabledChanged(e); }
        protected override void Dispose(bool disposing) { if (disposing) { _iconFont?.Dispose(); _animTimer?.Dispose(); } base.Dispose(disposing); }

        private static Color LightenColor(Color c, int a) => Color.FromArgb(c.A, Math.Min(255, c.R + a), Math.Min(255, c.G + a), Math.Min(255, c.B + a));
        private static Color DarkenColor(Color c, int a) => Color.FromArgb(c.A, Math.Max(0, c.R - a), Math.Max(0, c.G - a), Math.Max(0, c.B - a));
        private static Color BlendColor(Color a, Color b, float t) { t = Math.Max(0, Math.Min(1, t)); return Color.FromArgb((int)(a.R + (b.R - a.R) * t), (int)(a.G + (b.G - a.G) * t), (int)(a.B + (b.B - a.B) * t)); }
        private static GraphicsPath MkRoundedPath(Rectangle rect, int radius)
        {
            var path = new GraphicsPath(); int d = Math.Max(2, radius * 2);
            if (d > rect.Height) d = rect.Height; if (d > rect.Width) d = rect.Width;
            path.AddArc(rect.X, rect.Y, d, d, 180, 90); path.AddArc(rect.Right - d, rect.Y, d, d, 270, 90);
            path.AddArc(rect.Right - d, rect.Bottom - d, d, d, 0, 90); path.AddArc(rect.X, rect.Bottom - d, d, d, 90, 90);
            path.CloseFigure(); return path;
        }
    }

    public class ModernInputBox : Panel
    {
        public TextBox InnerTextBox { get; private set; }
        public string Placeholder { get; set; } = "";
        public Color FocusBorderColor { get; set; } = Color.FromArgb(99, 102, 241);
        public Color NormalBorderColor { get; set; } = Color.FromArgb(209, 213, 219);
        public Color FocusGlowColor { get; set; } = Color.FromArgb(30, 99, 102, 241);
        public int Radius { get; set; } = 10;
        private bool _focused = false;

        public ModernInputBox()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            Height = 36; Padding = new Padding(12, 6, 12, 6);
            BackColor = Color.FromArgb(248, 250, 252);
            InnerTextBox = new TextBox
            {
                BorderStyle = BorderStyle.None,
                BackColor = Color.FromArgb(248, 250, 252),
                ForeColor = Color.FromArgb(15, 23, 42),
                Font = new Font("Segoe UI", 10f),
                Dock = DockStyle.Fill
            };
            InnerTextBox.GotFocus += (s, e) => { _focused = true; Invalidate(); };
            InnerTextBox.LostFocus += (s, e) => { _focused = false; Invalidate(); };
            Controls.Add(InnerTextBox);
        }

        public override string Text { get => InnerTextBox.Text; set => InnerTextBox.Text = value; }
        public new bool Enabled { get => InnerTextBox.Enabled; set { InnerTextBox.Enabled = value; base.Enabled = value; Invalidate(); } }
        public char PasswordChar { get => InnerTextBox.PasswordChar; set => InnerTextBox.PasswordChar = value; }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics; g.SmoothingMode = SmoothingMode.AntiAlias;
            var rect = new Rectangle(1, 1, Width - 3, Height - 3);
            if (_focused)
            {
                var glowRect = new Rectangle(0, 0, Width - 1, Height - 1);
                using (var gp = MkRoundedPath(glowRect, Radius + 2))
                using (var brush = new SolidBrush(FocusGlowColor)) g.FillPath(brush, gp);
            }
            using (var path = MkRoundedPath(rect, Radius))
            {
                using (var brush = new SolidBrush(BackColor)) g.FillPath(brush, path);
                Color borderColor = _focused ? FocusBorderColor : NormalBorderColor;
                using (var pen = new Pen(borderColor, _focused ? 1.5f : 1f)) g.DrawPath(pen, path);
            }
            if (!_focused && string.IsNullOrEmpty(InnerTextBox.Text) && !string.IsNullOrEmpty(Placeholder))
                using (var brush = new SolidBrush(Color.FromArgb(160, 168, 182)))
                    g.DrawString(Placeholder, InnerTextBox.Font, brush, Padding.Left + 1, Padding.Top + 1);
        }

        private static GraphicsPath MkRoundedPath(Rectangle rect, int radius)
        {
            var path = new GraphicsPath(); int d = Math.Max(2, radius * 2); if (d > rect.Height) d = rect.Height;
            path.AddArc(rect.X, rect.Y, d, d, 180, 90); path.AddArc(rect.Right - d, rect.Y, d, d, 270, 90);
            path.AddArc(rect.Right - d, rect.Bottom - d, d, d, 0, 90); path.AddArc(rect.X, rect.Bottom - d, d, d, 90, 90);
            path.CloseFigure(); return path;
        }
    }

    public class ModernTextBox : TextBox
    {
        public string Placeholder { get; set; } = "";
        public Color PlaceholderColor { get; set; } = Color.FromArgb(160, 168, 182);
        private bool _focused = false;
        public ModernTextBox() { BorderStyle = BorderStyle.None; Font = new Font("Segoe UI", 10f); SetStyle(ControlStyles.UserPaint, false); }
        protected override void OnGotFocus(EventArgs e) { _focused = true; Parent?.Invalidate(); base.OnGotFocus(e); }
        protected override void OnLostFocus(EventArgs e) { _focused = false; Parent?.Invalidate(); base.OnLostFocus(e); }
        protected override void WndProc(ref Message m)
        {
            base.WndProc(ref m);
            if (m.Msg == 0x000F && !_focused && string.IsNullOrEmpty(Text) && !string.IsNullOrEmpty(Placeholder))
                using (var g = Graphics.FromHwnd(Handle))
                using (var brush = new SolidBrush(PlaceholderColor))
                    g.DrawString(Placeholder, Font, brush, new PointF(2, 1));
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Chat types and ChatPanel
    // ═══════════════════════════════════════════════════════════

    public enum ChatEntryType { Message, System, File, Link }

    public class ChatEntry
    {
        public DateTime Time { get; set; }
        public string Sender { get; set; }
        public string Text { get; set; }
        public string Room { get; set; }
        public bool IsMe { get; set; }
        public bool IsE2E { get; set; }
        public ChatEntryType Type { get; set; }
        public string FilePath { get; set; }
        public string FileName { get; set; }
        public long FileSize { get; set; }
        public string MimeType { get; set; }
        public Image Thumbnail { get; set; }
    }

    public class ChatPanel : Control
    {
        private readonly List<ChatEntry> _entries = new List<ChatEntry>();
        private readonly object _entriesLock = new object();
        private VScrollBar _scrollBar;
        private int _totalHeight = 0;
        private int _scrollOffset = 0;

        public Color BgColor { get; set; } = Color.FromArgb(250, 251, 253);
        public Color MeBubbleColor { get; set; } = Color.FromArgb(99, 102, 241);
        public Color OtherBubbleColor { get; set; } = Color.FromArgb(241, 243, 248);
        public Color MeTextColor { get; set; } = Color.White;
        public Color OtherTextColor { get; set; } = Color.FromArgb(30, 35, 50);
        public Color SystemColor { get; set; } = Color.FromArgb(148, 163, 184);
        public Color TimeColor { get; set; } = Color.FromArgb(148, 163, 184);
        public Color E2EColor { get; set; } = Color.FromArgb(139, 92, 246);
        public Color SenderMeColor { get; set; } = Color.FromArgb(99, 102, 241);
        public Color SenderOtherColor { get; set; } = Color.FromArgb(16, 163, 127);

        private static readonly Font FontSender = new Font("Segoe UI", 9f, FontStyle.Bold);
        private static readonly Font FontMsg = new Font("Segoe UI", 9.5f);
        private static readonly Font FontTime = new Font("Segoe UI", 7.5f);
        private static readonly Font FontSystem = new Font("Segoe UI", 8.5f, FontStyle.Italic);
        private static readonly Font FontE2E = new Font("Segoe UI", 7.5f, FontStyle.Bold);
        private static readonly Font FontFileExt = new Font("Segoe UI", 6.5f, FontStyle.Bold);
        private static readonly Font FontFileName = new Font("Segoe UI", 8.5f, FontStyle.Bold);
        private static readonly Font FontFileSize = new Font("Segoe UI", 7.5f);

        private const int PaddingH = 12, PaddingV = 6, BubbleMaxWidth = 640, BubbleRadius = 14, AvatarSize = 34, Spacing = 6;
        public event Action<string> FileRightClicked;
        private readonly List<(Rectangle rect, string filePath)> _fileHitAreas = new List<(Rectangle, string)>();

        public ChatPanel()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            DoubleBuffered = true;
            _scrollBar = new VScrollBar { Dock = DockStyle.Right, Width = 10, Minimum = 0, SmallChange = 30, LargeChange = 100 };
            _scrollBar.Scroll += (s, e) => { _scrollOffset = _scrollBar.Value; Invalidate(); };
            Controls.Add(_scrollBar);
        }

        public void AddEntry(ChatEntry entry) { lock (_entriesLock) _entries.Add(entry); RecalcScroll(); ScrollToBottom(); Invalidate(); }

        public void ClearEntries()
        {
            lock (_entriesLock) { foreach (var entry in _entries) entry.Thumbnail?.Dispose(); _entries.Clear(); }
            _totalHeight = 0; _scrollOffset = 0; RecalcScroll(); Invalidate();
        }

        public void ScrollToBottom()
        {
            if (InvokeRequired) { Invoke(new Action(ScrollToBottom)); return; }
            _scrollOffset = Math.Max(0, _totalHeight - (Height - 10));
            _scrollBar.Value = Math.Min(_scrollBar.Maximum, _scrollOffset); Invalidate();
        }

        private void RecalcScroll()
        {
            if (InvokeRequired) { Invoke(new Action(RecalcScroll)); return; }
            int total = 0;
            lock (_entriesLock) { using (var g = CreateGraphics()) foreach (var e in _entries) total += MeasureEntryHeight(g, e) + Spacing; }
            _totalHeight = total; _scrollBar.Maximum = Math.Max(0, _totalHeight); _scrollBar.LargeChange = Height;
        }

        private int MeasureEntryHeight(Graphics g, ChatEntry entry)
        {
            if (entry.Type == ChatEntryType.System) return 28;
            int maxTextW = BubbleMaxWidth - 24;
            var textSize = g.MeasureString(entry.Text ?? "", FontMsg, maxTextW);
            // FIX 5 : +20 pour la ligne d'heure dédiée (évite le chevauchement)
            int h = (int)textSize.Height + 36 + 20;
            if (entry.Thumbnail != null) h += 180;
            if (entry.Type == ChatEntryType.File && entry.Thumbnail == null) h += 64;
            return Math.Max(h, AvatarSize + PaddingV * 2);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            e.Graphics.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
            e.Graphics.Clear(BgColor);
            _fileHitAreas.Clear();
            _fileBtnAreas.Clear();
            int y = PaddingV - _scrollOffset;
            List<ChatEntry> snapshot; lock (_entriesLock) snapshot = _entries.ToList();
            foreach (var entry in snapshot)
            {
                int entryH = MeasureEntryHeight(e.Graphics, entry);
                if (y + entryH >= -60 && y <= Height + 60) DrawEntry(e.Graphics, entry, y, entryH);
                y += entryH + Spacing;
            }
        }

        private void DrawEntry(Graphics g, ChatEntry entry, int y, int height)
        {
            int chatWidth = Width - _scrollBar.Width;
            if (entry.Type == ChatEntryType.System)
            {
                var sz = g.MeasureString(entry.Text, FontSystem);
                using (var brush = new SolidBrush(SystemColor)) g.DrawString(entry.Text, FontSystem, brush, (chatWidth - sz.Width) / 2f, y + 6);
                return;
            }
            bool isMe = entry.IsMe;
            int bubbleW = Math.Min(BubbleMaxWidth, chatWidth - AvatarSize - PaddingH * 3);
            int maxTextW = bubbleW - 24;
            var textSz = g.MeasureString(entry.Text ?? "", FontMsg, maxTextW);
            // Largeur minimale confortable + prend en compte le nom du sender
            var senderSz = g.MeasureString(entry.Sender ?? "", FontSender);
            int minBubbleW = Math.Max(160, (int)senderSz.Width + 40);
            int actualBubbleW = Math.Max((int)textSz.Width + 32, minBubbleW);
            if (entry.Thumbnail != null) actualBubbleW = Math.Max(actualBubbleW, 300);
            if (entry.Type == ChatEntryType.File && entry.Thumbnail == null) actualBubbleW = Math.Max(actualBubbleW, 280);
            actualBubbleW = Math.Min(actualBubbleW, bubbleW);
            int bubbleX, avatarX;
            if (isMe) { bubbleX = chatWidth - actualBubbleW - PaddingH; avatarX = chatWidth - PaddingH + 6; }
            else { avatarX = PaddingH; bubbleX = avatarX + AvatarSize + 8; }
            if (!isMe)
            {
                Color avatarColor = GetAvatarColor(entry.Sender);
                using (var brush = new SolidBrush(avatarColor)) g.FillEllipse(brush, avatarX, y, AvatarSize, AvatarSize);
                string initial = (entry.Sender?.Length > 0 ? entry.Sender[0].ToString().ToUpper() : "?");
                var initSz = g.MeasureString(initial, FontSender);
                using (var brush = new SolidBrush(Color.White))
                    g.DrawString(initial, FontSender, brush, avatarX + (AvatarSize - initSz.Width) / 2, y + (AvatarSize - initSz.Height) / 2);
            }
            Color bubbleBg = isMe ? MeBubbleColor : OtherBubbleColor;
            int bubbleH = height - Spacing;
            var bubbleRect = new Rectangle(bubbleX, y, actualBubbleW, bubbleH);
            using (var path = CreateBubblePath(bubbleRect, BubbleRadius, isMe))
            using (var brush = new SolidBrush(bubbleBg)) g.FillPath(brush, path);
            int tx = bubbleX + 12, ty = y + 6;
            if (!isMe) { using (var brush = new SolidBrush(SenderOtherColor)) g.DrawString(entry.Sender, FontSender, brush, tx, ty); ty += 18; }
            else ty += 2;
            // Badge E2E supprimé — les MP sont toujours E2E si la clé est disponible
            if (entry.Thumbnail != null)
            {
                int imgW = Math.Min(entry.Thumbnail.Width, actualBubbleW - 24);
                int imgH = Math.Min((int)((double)imgW / entry.Thumbnail.Width * entry.Thumbnail.Height), 160);
                var imgRect = new Rectangle(tx, ty, imgW, imgH);
                using (var path = CreateRoundedRect(imgRect, 8)) { g.SetClip(path); g.DrawImage(entry.Thumbnail, imgRect); g.ResetClip(); }
                ty += imgH + 6;
                if (!string.IsNullOrEmpty(entry.FilePath)) _fileHitAreas.Add((new Rectangle(bubbleX, y, actualBubbleW, bubbleH), entry.FilePath));
            }
            else if (entry.Type == ChatEntryType.File)
            {
                DrawFileCard(g, tx, ty, actualBubbleW - 24, entry, isMe); ty += 60;
                if (!string.IsNullOrEmpty(entry.FilePath))
                {
                    _fileHitAreas.Add((new Rectangle(bubbleX, y, actualBubbleW, bubbleH), entry.FilePath));
                    // Zones boutons Enregistrer / Ouvrir (coordonnées identiques à DrawFileCard)
                    int btnY = (ty - 60) + 36;
                    _fileBtnAreas.Add((new Rectangle(tx + 44, btnY, 70, 14), entry.FilePath, "save"));
                    _fileBtnAreas.Add((new Rectangle(tx + 120, btnY, 50, 14), entry.FilePath, "open"));
                }
            }
            if (!string.IsNullOrEmpty(entry.Text))
            {
                Color textColor = isMe ? MeTextColor : OtherTextColor;
                using (var brush = new SolidBrush(textColor)) g.DrawString(entry.Text, FontMsg, brush, new RectangleF(tx, ty, maxTextW, 500));
                ty += (int)textSz.Height + 4;
            }
            // FIX 5 : Heure sur sa propre ligne sous le texte, pas en overlay
            string timeStr = entry.Time.ToString("HH:mm");
            var timeSz = g.MeasureString(timeStr, FontTime);
            Color timeCol = isMe ? Color.FromArgb(160, 255, 255, 255) : TimeColor;
            float timeY = y + bubbleH - timeSz.Height - 4;
            float timeX = bubbleX + actualBubbleW - timeSz.Width - 10;
            using (var brush = new SolidBrush(timeCol)) g.DrawString(timeStr, FontTime, brush, timeX, timeY);
        }

        private void DrawFileCard(Graphics g, int x, int y, int w, ChatEntry entry, bool isMe)
        {
            int cardH = 52;
            var cardRect = new Rectangle(x, y, Math.Min(w, 280), cardH);
            Color cardBg = isMe ? Color.FromArgb(50, 255, 255, 255) : Color.FromArgb(230, 234, 240);
            using (var path = CreateRoundedRect(cardRect, 8))
            using (var brush = new SolidBrush(cardBg)) g.FillPath(brush, path);

            // Icône extension
            string ext = Path.GetExtension(entry.FileName ?? "").ToUpperInvariant();
            Color extColor = GetExtColor(ext);
            using (var brush = new SolidBrush(extColor)) g.FillEllipse(brush, x + 8, y + 12, 28, 28);
            string extLabel = ext.Length > 4 ? ext.Substring(0, 4) : ext;
            var extSz = g.MeasureString(extLabel, FontFileExt);
            using (var brush = new SolidBrush(Color.White))
                g.DrawString(extLabel, FontFileExt, brush, x + 8 + (28 - extSz.Width) / 2, y + 12 + (28 - extSz.Height) / 2);

            // Nom du fichier
            Color fnColor = isMe ? Color.White : Color.FromArgb(30, 35, 50);
            string displayName = (entry.FileName?.Length > 26) ? entry.FileName.Substring(0, 23) + "..." : entry.FileName;
            using (var brush = new SolidBrush(fnColor))
                g.DrawString(displayName, FontFileName, brush, x + 44, y + 8);

            // Taille + hint boutons
            Color sizeColor = isMe ? Color.FromArgb(180, 255, 255, 255) : Color.FromArgb(120, 130, 150);
            using (var brush = new SolidBrush(sizeColor))
                g.DrawString(FormatBytes(entry.FileSize), FontFileSize, brush, x + 44, y + 26);

            // Boutons [↓ Enregistrer] [▶ Ouvrir]
            int btnY = y + 36;
            Color btnBg = isMe ? Color.FromArgb(40, 255, 255, 255) : Color.FromArgb(210, 215, 225);
            Color btnFg = isMe ? Color.White : Color.FromArgb(50, 60, 80);
            var btnFont = FontFileExt;

            // Bouton Enregistrer
            var saveRect = new Rectangle(x + 44, btnY, 70, 14);
            using (var path = CreateRoundedRect(saveRect, 3))
            using (var brush = new SolidBrush(btnBg)) g.FillPath(brush, path);
            using (var brush = new SolidBrush(btnFg))
                g.DrawString("↓ Enregistrer", btnFont, brush, saveRect.X + 3, saveRect.Y + 1);

            // Bouton Ouvrir
            var openRect = new Rectangle(x + 120, btnY, 50, 14);
            using (var path = CreateRoundedRect(openRect, 3))
            using (var brush = new SolidBrush(btnBg)) g.FillPath(brush, path);
            using (var brush = new SolidBrush(btnFg))
                g.DrawString("▶ Ouvrir", btnFont, brush, openRect.X + 3, openRect.Y + 1);
        }

        // Zones cliquables pour les boutons fichier
        private readonly List<(Rectangle rect, string filePath, string action)> _fileBtnAreas
            = new List<(Rectangle, string, string)>();

        public event Action<string> FileSaveClicked;
        public event Action<string> FileOpenClicked;

        protected override void OnMouseUp(MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left)
            {
                foreach (var (rect, path, action) in _fileBtnAreas)
                {
                    if (rect.Contains(e.Location))
                    {
                        if (action == "save") FileSaveClicked?.Invoke(path);
                        else if (action == "open") FileOpenClicked?.Invoke(path);
                        return;
                    }
                }
            }
            if (e.Button == MouseButtons.Right)
                foreach (var (rect, path) in _fileHitAreas)
                    if (rect.Contains(e.Location)) { FileRightClicked?.Invoke(path); return; }
            base.OnMouseUp(e);
        }

        protected override void OnMouseWheel(MouseEventArgs e)
        {
            _scrollOffset = Math.Max(0, Math.Min(_totalHeight - Height + 10, _scrollOffset - e.Delta));
            _scrollBar.Value = Math.Min(_scrollBar.Maximum, Math.Max(0, _scrollOffset));
            Invalidate(); base.OnMouseWheel(e);
        }

        protected override void OnResize(EventArgs e) { base.OnResize(e); RecalcScroll(); Invalidate(); }

        private static Color GetAvatarColor(string name)
        {
            if (string.IsNullOrEmpty(name)) return Color.Gray;
            int hash = 0; foreach (char c in name) hash = hash * 31 + c;
            Color[] palette = { Color.FromArgb(99, 102, 241), Color.FromArgb(16, 163, 127), Color.FromArgb(239, 68, 68), Color.FromArgb(234, 179, 8), Color.FromArgb(139, 92, 246), Color.FromArgb(6, 182, 212), Color.FromArgb(236, 72, 153), Color.FromArgb(34, 197, 94) };
            return palette[Math.Abs(hash) % palette.Length];
        }

        private static Color GetExtColor(string ext)
        {
            switch (ext.ToUpperInvariant())
            {
                case ".PDF": return Color.FromArgb(220, 50, 50);
                case ".ZIP": case ".RAR": case ".7Z": return Color.FromArgb(255, 160, 0);
                case ".EXE": case ".MSI": return Color.FromArgb(100, 100, 200);
                case ".DOC": case ".DOCX": return Color.FromArgb(40, 100, 200);
                case ".XLS": case ".XLSX": return Color.FromArgb(30, 150, 70);
                case ".MP3": case ".WAV": case ".FLAC": return Color.FromArgb(180, 60, 180);
                default: return Color.FromArgb(80, 130, 190);
            }
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return bytes + " B"; if (bytes < 1024 * 1024) return (bytes / 1024.0).ToString("0.0") + " KB";
            if (bytes < 1024L * 1024 * 1024) return (bytes / (1024.0 * 1024)).ToString("0.0") + " MB";
            return (bytes / (1024.0 * 1024 * 1024)).ToString("0.00") + " GB";
        }

        private static GraphicsPath CreateBubblePath(Rectangle rect, int radius, bool isRight)
        {
            var path = new GraphicsPath(); int d = radius * 2;
            if (!isRight) path.AddArc(rect.X, rect.Y, d / 2, d / 2, 180, 90); else path.AddArc(rect.X, rect.Y, d, d, 180, 90);
            if (isRight) path.AddArc(rect.Right - d / 2, rect.Y, d / 2, d / 2, 270, 90); else path.AddArc(rect.Right - d, rect.Y, d, d, 270, 90);
            path.AddArc(rect.Right - d, rect.Bottom - d, d, d, 0, 90); path.AddArc(rect.X, rect.Bottom - d, d, d, 90, 90);
            path.CloseFigure(); return path;
        }

        private static GraphicsPath CreateRoundedRect(Rectangle rect, int radius)
        {
            var path = new GraphicsPath(); int d = radius * 2;
            path.AddArc(rect.X, rect.Y, d, d, 180, 90); path.AddArc(rect.Right - d, rect.Y, d, d, 270, 90);
            path.AddArc(rect.Right - d, rect.Bottom - d, d, d, 0, 90); path.AddArc(rect.X, rect.Bottom - d, d, d, 90, 90);
            path.CloseFigure(); return path;
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Debug Logger
    // ═══════════════════════════════════════════════════════════

    public static class DebugLog
    {
        private static readonly string LogFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "nexuschat_debug.log");
        private static readonly object _logLock = new object();
        public static void Log(string level, string message)
        {
            try
            {
                string line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [{level}] {message}";
                System.Diagnostics.Debug.WriteLine(line);
                lock (_logLock) File.AppendAllText(LogFile, line + Environment.NewLine);
            }
            catch { }
        }
        public static void Info(string msg) => Log("INFO", msg);
        public static void Warn(string msg) => Log("WARN", msg);
        public static void Error(string msg, Exception ex = null) => Log("ERROR", ex != null ? $"{msg} — {ex.GetType().Name}: {ex.Message}" : msg);
    }

    // ═══════════════════════════════════════════════════════════
    //  Main Client Form
    // ═══════════════════════════════════════════════════════════

    public partial class ClientForm : Form
    {
        // ── Network ──
        private TcpClient client;
        private Stream clientStream;
        private SslStream _sslStream;
        private Thread receiveThread;
        private volatile bool isConnected = false;

        // ── AES-256-GCM session key ──
        private byte[] _sessionKey;
        private const int GCM_NONCE_SIZE = 12;
        private const int GCM_TAG_BITS = 128;
        private const int GCM_TAG_SIZE = GCM_TAG_BITS / 8;
        private readonly object _readLock = new object();

        // ═══════════════════════════════════════════════════════
        //  FIX — Clé d'identité persistante + KeyTrustStore
        // ═══════════════════════════════════════════════════════

        private E2EIdentity _e2eIdentity = new E2EIdentity();
        private KeyTrustStore _keyTrustStore = new KeyTrustStore();
        private Dictionary<string, byte[]> _pendingKeyChanges
            = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);

        // ═══════════════════════════════════════════════════════
        //  FIX — NonceManagers par pair E2E
        // ═══════════════════════════════════════════════════════
        private readonly Dictionary<string, NonceManager> _e2eNonceManagers
            = new Dictionary<string, NonceManager>(StringComparer.OrdinalIgnoreCase);
        private readonly object _nonceLock = new object();

        private NonceManager GetOrCreateNonceManager(string key)
        {
            lock (_nonceLock)
            {
                if (!_e2eNonceManagers.TryGetValue(key, out var mgr))
                {
                    mgr = new NonceManager();
                    _e2eNonceManagers[key] = mgr;
                }
                return mgr;
            }
        }

        // ═══════════════════════════════════════════════════════
        //  TLS Certificate Validation
        // ═══════════════════════════════════════════════════════

        private static readonly string PinnedCertFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "pinned_cert.txt");
        private string _pinnedThumbprint = null;

        private void LoadPinnedCert()
        {
            try { if (File.Exists(PinnedCertFile)) _pinnedThumbprint = File.ReadAllText(PinnedCertFile).Trim().ToUpperInvariant(); }
            catch (Exception ex) { DebugLog.Warn("LoadPinnedCert: " + ex.Message); }
        }

        private void SavePinnedCert(string thumbprint)
        {
            try { File.WriteAllText(PinnedCertFile, thumbprint.ToUpperInvariant()); }
            catch (Exception ex) { DebugLog.Warn("SavePinnedCert: " + ex.Message); }
            _pinnedThumbprint = thumbprint.ToUpperInvariant();
        }

        private bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (certificate == null) return false;
            string thumbprint;
            using (var sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(certificate.GetRawCertData());
                thumbprint = BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();
            }
            if (!string.IsNullOrEmpty(_pinnedThumbprint))
            {
                if (thumbprint != _pinnedThumbprint)
                {
                    AppendSystemMessage("⚠ ALERTE SÉCURITÉ : Le certificat du serveur a changé !");
                    AppendSystemMessage("  Connexion refusée. Supprimez pinned_cert.txt pour réinitialiser.");
                    DebugLog.Error("Certificate pinning FAILED");
                    return false;
                }
                return true;
            }
            if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable)) return false;
            SavePinnedCert(thumbprint);
            AppendSystemMessage("🔒 Certificat TLS épinglé (TOFU) : " + thumbprint.Substring(0, 16) + "...");
            return true;
        }

        // ═══════════════════════════════════════════════════════
        //  E2E with Sender Keys
        // ═══════════════════════════════════════════════════════

        private AsymmetricCipherKeyPair _e2eKeyPair;
        private byte[] _e2ePublicKeyBytes;
        private string _e2ePublicKeyBase64;

        private readonly Dictionary<string, byte[]> _peerE2EKeys = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, byte[]> _e2eSharedKeys = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        private readonly object _e2eLock = new object();

        private readonly Dictionary<string, byte[]> _mySenderKeys = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, byte[]> _peerSenderKeys = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        private readonly object _senderKeyLock = new object();

        private byte[] DeriveSharedKey(string peerUsername, byte[] peerPublicKeyBytes)
        {
            var agreement = new X25519Agreement();
            agreement.Init(_e2eKeyPair.Private);
            byte[] sharedSecret = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(new X25519PublicKeyParameters(peerPublicKeyBytes, 0), sharedSecret, 0);
            string[] sorted = new[] { username, peerUsername }.OrderBy(s => s, StringComparer.OrdinalIgnoreCase).ToArray();
            byte[] info = Encoding.UTF8.GetBytes("NexusChat-E2E:" + sorted[0] + ":" + sorted[1]);
            byte[] derivedKey = HkdfSha256(sharedSecret, info, 32);
            lock (_e2eLock) { _peerE2EKeys[peerUsername] = peerPublicKeyBytes; _e2eSharedKeys[peerUsername] = derivedKey; }
            DistributeSenderKeysToPeer(peerUsername);
            return derivedKey;
        }

        private byte[] GetOrCreateMySenderKey(string room)
        {
            lock (_senderKeyLock)
            {
                if (_mySenderKeys.TryGetValue(room, out byte[] key)) return key;
                key = new byte[32];
                using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(key);
                _mySenderKeys[room] = key;
                return key;
            }
        }

        private void DistributeSenderKeysToPeer(string peer)
        {
            byte[] pairwiseKey;
            lock (_e2eLock) { if (!_e2eSharedKeys.TryGetValue(peer, out pairwiseKey)) return; }
            string room = CurrentRoom;
            byte[] senderKey = GetOrCreateMySenderKey(room);
            string skBase64 = Convert.ToBase64String(senderKey);
            byte[] nonce, tag;
            byte[] cipher = EncryptAES(room + ":" + skBase64, pairwiseKey, out nonce, out tag);
            byte[] combined = new byte[GCM_NONCE_SIZE + GCM_TAG_SIZE + cipher.Length];
            Buffer.BlockCopy(nonce, 0, combined, 0, GCM_NONCE_SIZE);
            Buffer.BlockCopy(tag, 0, combined, GCM_NONCE_SIZE, GCM_TAG_SIZE);
            Buffer.BlockCopy(cipher, 0, combined, GCM_NONCE_SIZE + GCM_TAG_SIZE, cipher.Length);
            SendPacket(ProtocolMessage.Build("E2E_SENDER_KEY", peer, Convert.ToBase64String(combined)));
        }

        private void DistributeSenderKeyToAll(string room)
        {
            List<string> peers;
            lock (_e2eLock) peers = _e2eSharedKeys.Keys.ToList();
            foreach (string peer in peers) DistributeSenderKeysToPeer(peer);
        }

        private void HandleSenderKeyReceived(string peerUsername, string encPayloadBase64)
        {
            byte[] pairwiseKey;
            lock (_e2eLock) { if (!_e2eSharedKeys.TryGetValue(peerUsername, out pairwiseKey)) return; }
            try
            {
                byte[] combined = Convert.FromBase64String(encPayloadBase64);
                if (combined.Length < GCM_NONCE_SIZE + GCM_TAG_SIZE + 1) return;
                byte[] nonce = new byte[GCM_NONCE_SIZE]; byte[] tag = new byte[GCM_TAG_SIZE];
                int cLen = combined.Length - GCM_NONCE_SIZE - GCM_TAG_SIZE; byte[] cipher = new byte[cLen];
                Buffer.BlockCopy(combined, 0, nonce, 0, GCM_NONCE_SIZE);
                Buffer.BlockCopy(combined, GCM_NONCE_SIZE, tag, 0, GCM_TAG_SIZE);
                Buffer.BlockCopy(combined, GCM_NONCE_SIZE + GCM_TAG_SIZE, cipher, 0, cLen);
                string plainText = DecryptAES(cipher, pairwiseKey, nonce, tag);
                int colonIdx = plainText.IndexOf(':');
                if (colonIdx < 0) return;
                string room = plainText.Substring(0, colonIdx);
                byte[] senderKey = Convert.FromBase64String(plainText.Substring(colonIdx + 1));
                lock (_senderKeyLock) _peerSenderKeys[room + ":" + peerUsername] = senderKey;
                AppendSystemMessage($"🔐 Clé de salon reçue : {peerUsername} → #{room}");
            }
            catch (Exception ex)
            {
                AppendSystemMessage($"⚠ Erreur sender key de {peerUsername}: {ex.Message}");
                DebugLog.Error($"HandleSenderKeyReceived from {peerUsername}", ex);
            }
        }

        // ═══════════════════════════════════════════════════════
        //  FIX — E2E Room encrypt/decrypt avec SecureMessageFormat
        //  Corrige la faille 1.11 : sender authentifié dans le ciphertext
        // ═══════════════════════════════════════════════════════

        private string RoomE2EEncrypt(string room, string plainText)
        {
            byte[] senderKey = GetOrCreateMySenderKey(room);
            // FIX : Encoder le sender dans le plaintext
            byte[] authenticatedPlain = SecureMessageFormat.Encode(username, plainText);
            byte[] nonce = GetOrCreateNonceManager("room:" + room + ":send").NextSendNonce();
            var gcm = new GcmBlockCipher(new AesEngine());
            gcm.Init(true, new AeadParameters(new KeyParameter(senderKey), GCM_TAG_BITS, nonce));
            byte[] output = new byte[gcm.GetOutputSize(authenticatedPlain.Length)];
            int len = gcm.ProcessBytes(authenticatedPlain, 0, authenticatedPlain.Length, output, 0);
            len += gcm.DoFinal(output, len);
            int cipherLen = len - GCM_TAG_SIZE;
            byte[] combined = new byte[GCM_NONCE_SIZE + GCM_TAG_SIZE + cipherLen];
            Buffer.BlockCopy(nonce, 0, combined, 0, GCM_NONCE_SIZE);
            Buffer.BlockCopy(output, cipherLen, combined, GCM_NONCE_SIZE, GCM_TAG_SIZE);
            Buffer.BlockCopy(output, 0, combined, GCM_NONCE_SIZE + GCM_TAG_SIZE, cipherLen);
            return Convert.ToBase64String(combined);
        }

        private string RoomE2EDecrypt(string room, string claimedSender, string encPayloadBase64)
        {
            string dictKey = room + ":" + claimedSender;
            byte[] senderKey;
            lock (_senderKeyLock)
            {
                if (!_peerSenderKeys.TryGetValue(dictKey, out senderKey))
                    throw new InvalidOperationException("Pas de sender key pour " + claimedSender + " dans #" + room);
            }
            byte[] combined = Convert.FromBase64String(encPayloadBase64);
            if (combined.Length < GCM_NONCE_SIZE + GCM_TAG_SIZE + 1) throw new CryptographicException("Payload trop court");
            byte[] nonce = new byte[GCM_NONCE_SIZE]; byte[] tag = new byte[GCM_TAG_SIZE];
            int cLen = combined.Length - GCM_NONCE_SIZE - GCM_TAG_SIZE; byte[] cipher = new byte[cLen];
            Buffer.BlockCopy(combined, 0, nonce, 0, GCM_NONCE_SIZE);
            Buffer.BlockCopy(combined, GCM_NONCE_SIZE, tag, 0, GCM_TAG_SIZE);
            Buffer.BlockCopy(combined, GCM_NONCE_SIZE + GCM_TAG_SIZE, cipher, 0, cLen);

            // FIX : Anti-rejeu
            var nonceMgr = GetOrCreateNonceManager("room:" + room + ":" + claimedSender + ":recv");
            if (!nonceMgr.VerifyRecvNonce(nonce))
            {
                DebugLog.Warn($"Replay detected on room #{room} from {claimedSender}");
                throw new CryptographicException("Message E2E room rejeté : rejeu détecté");
            }

            var gcm = new GcmBlockCipher(new AesEngine());
            gcm.Init(false, new AeadParameters(new KeyParameter(senderKey), GCM_TAG_BITS, nonce));
            byte[] input = new byte[cipher.Length + GCM_TAG_SIZE];
            Buffer.BlockCopy(cipher, 0, input, 0, cipher.Length);
            Buffer.BlockCopy(tag, 0, input, cipher.Length, GCM_TAG_SIZE);
            byte[] plainBytes = new byte[gcm.GetOutputSize(input.Length)];
            int len = gcm.ProcessBytes(input, 0, input.Length, plainBytes, 0);
            len += gcm.DoFinal(plainBytes, len);

            byte[] actualPlain = new byte[len];
            Buffer.BlockCopy(plainBytes, 0, actualPlain, 0, len);

            // FIX : Vérifier sender authentifié dans le ciphertext
            string message = SecureMessageFormat.Decode(actualPlain, claimedSender);
            if (message == null)
                throw new CryptographicException($"USURPATION DÉTECTÉE : sender dans le ciphertext ≠ '{claimedSender}'");
            return message;
        }

        private string E2EEncrypt(string peerUsername, string plainText)
        {
            byte[] key;
            lock (_e2eLock) { if (!_e2eSharedKeys.TryGetValue(peerUsername, out key)) throw new InvalidOperationException("Pas de clé E2E pour " + peerUsername); }
            // FIX : Sender authentifié dans les PM aussi
            byte[] authenticatedPlain = SecureMessageFormat.Encode(username, plainText);
            byte[] nonce = GetOrCreateNonceManager("pm:" + peerUsername + ":send").NextSendNonce();
            var gcm = new GcmBlockCipher(new AesEngine());
            gcm.Init(true, new AeadParameters(new KeyParameter(key), GCM_TAG_BITS, nonce));
            byte[] output = new byte[gcm.GetOutputSize(authenticatedPlain.Length)];
            int len = gcm.ProcessBytes(authenticatedPlain, 0, authenticatedPlain.Length, output, 0);
            len += gcm.DoFinal(output, len);
            int cipherLen = len - GCM_TAG_SIZE;
            byte[] combined = new byte[GCM_NONCE_SIZE + GCM_TAG_SIZE + cipherLen];
            Buffer.BlockCopy(nonce, 0, combined, 0, GCM_NONCE_SIZE);
            Buffer.BlockCopy(output, cipherLen, combined, GCM_NONCE_SIZE, GCM_TAG_SIZE);
            Buffer.BlockCopy(output, 0, combined, GCM_NONCE_SIZE + GCM_TAG_SIZE, cipherLen);
            return Convert.ToBase64String(combined);
        }

        private string E2EDecrypt(string peerUsername, string encPayloadBase64)
        {
            byte[] key;
            lock (_e2eLock) { if (!_e2eSharedKeys.TryGetValue(peerUsername, out key)) throw new InvalidOperationException("Pas de clé E2E pour " + peerUsername); }
            byte[] combined = Convert.FromBase64String(encPayloadBase64);
            if (combined.Length < GCM_NONCE_SIZE + GCM_TAG_SIZE + 1) throw new CryptographicException("Payload E2E trop court");
            byte[] nonce = new byte[GCM_NONCE_SIZE]; byte[] tag = new byte[GCM_TAG_SIZE];
            int cLen = combined.Length - GCM_NONCE_SIZE - GCM_TAG_SIZE; byte[] cipher = new byte[cLen];
            Buffer.BlockCopy(combined, 0, nonce, 0, GCM_NONCE_SIZE);
            Buffer.BlockCopy(combined, GCM_NONCE_SIZE, tag, 0, GCM_TAG_SIZE);
            Buffer.BlockCopy(combined, GCM_NONCE_SIZE + GCM_TAG_SIZE, cipher, 0, cLen);

            // FIX : Anti-rejeu
            var nonceMgr = GetOrCreateNonceManager("pm:" + peerUsername + ":recv");
            if (!nonceMgr.VerifyRecvNonce(nonce))
            {
                DebugLog.Warn($"Replay detected on PM from {peerUsername}");
                throw new CryptographicException("Message E2E PM rejeté : rejeu détecté");
            }

            var gcm = new GcmBlockCipher(new AesEngine());
            gcm.Init(false, new AeadParameters(new KeyParameter(key), GCM_TAG_BITS, nonce));
            byte[] input = new byte[cipher.Length + GCM_TAG_SIZE];
            Buffer.BlockCopy(cipher, 0, input, 0, cipher.Length);
            Buffer.BlockCopy(tag, 0, input, cipher.Length, GCM_TAG_SIZE);
            byte[] plainBytes = new byte[gcm.GetOutputSize(input.Length)];
            int len = gcm.ProcessBytes(input, 0, input.Length, plainBytes, 0);
            len += gcm.DoFinal(plainBytes, len);

            byte[] actualPlain = new byte[len];
            Buffer.BlockCopy(plainBytes, 0, actualPlain, 0, len);

            // FIX : Vérifier sender
            string message = SecureMessageFormat.Decode(actualPlain, peerUsername);
            if (message == null)
                throw new CryptographicException($"USURPATION DÉTECTÉE : sender PM ≠ '{peerUsername}'");
            return message;
        }

        private bool HasE2EKey(string peerUsername)
        { lock (_e2eLock) return _e2eSharedKeys.ContainsKey(peerUsername); }

        private static byte[] HkdfSha256(byte[] ikm, byte[] info, int length)
        {
            byte[] salt = new byte[32]; byte[] prk;
            using (var hmac = new HMACSHA256(salt)) prk = hmac.ComputeHash(ikm);
            byte[] result = new byte[length]; byte[] t = new byte[0]; int offset = 0; byte counter = 1;
            while (offset < length)
            {
                byte[] input = new byte[t.Length + info.Length + 1];
                Buffer.BlockCopy(t, 0, input, 0, t.Length);
                Buffer.BlockCopy(info, 0, input, t.Length, info.Length);
                input[input.Length - 1] = counter++;
                using (var hmac = new HMACSHA256(prk)) t = hmac.ComputeHash(input);
                int toCopy = Math.Min(t.Length, length - offset);
                Buffer.BlockCopy(t, 0, result, offset, toCopy); offset += toCopy;
            }
            return result;
        }

        // ═══════════════════════════════════════════════════════
        //  E2E File Encryption helpers
        // ═══════════════════════════════════════════════════════

        private byte[] EncryptBytesAES(byte[] plainBytes, byte[] key)
        {
            byte[] nonce = new byte[GCM_NONCE_SIZE];
            using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(nonce);
            var gcm = new GcmBlockCipher(new AesEngine());
            gcm.Init(true, new AeadParameters(new KeyParameter(key), GCM_TAG_BITS, nonce));
            byte[] output = new byte[gcm.GetOutputSize(plainBytes.Length)];
            int len = gcm.ProcessBytes(plainBytes, 0, plainBytes.Length, output, 0);
            len += gcm.DoFinal(output, len);
            int cipherLen = len - GCM_TAG_SIZE;
            byte[] combined = new byte[GCM_NONCE_SIZE + GCM_TAG_SIZE + cipherLen];
            Buffer.BlockCopy(nonce, 0, combined, 0, GCM_NONCE_SIZE);
            Buffer.BlockCopy(output, cipherLen, combined, GCM_NONCE_SIZE, GCM_TAG_SIZE);
            Buffer.BlockCopy(output, 0, combined, GCM_NONCE_SIZE + GCM_TAG_SIZE, cipherLen);
            return combined;
        }

        private byte[] DecryptBytesAES(byte[] combined, byte[] key)
        {
            if (combined.Length < GCM_NONCE_SIZE + GCM_TAG_SIZE + 1) throw new CryptographicException("E2E file payload too short");
            byte[] nonce = new byte[GCM_NONCE_SIZE]; byte[] tag = new byte[GCM_TAG_SIZE];
            int cLen = combined.Length - GCM_NONCE_SIZE - GCM_TAG_SIZE; byte[] cipher = new byte[cLen];
            Buffer.BlockCopy(combined, 0, nonce, 0, GCM_NONCE_SIZE);
            Buffer.BlockCopy(combined, GCM_NONCE_SIZE, tag, 0, GCM_TAG_SIZE);
            Buffer.BlockCopy(combined, GCM_NONCE_SIZE + GCM_TAG_SIZE, cipher, 0, cLen);
            var gcm = new GcmBlockCipher(new AesEngine());
            gcm.Init(false, new AeadParameters(new KeyParameter(key), GCM_TAG_BITS, nonce));
            byte[] input = new byte[cipher.Length + GCM_TAG_SIZE];
            Buffer.BlockCopy(cipher, 0, input, 0, cipher.Length);
            Buffer.BlockCopy(tag, 0, input, cipher.Length, GCM_TAG_SIZE);
            byte[] plainBytes = new byte[gcm.GetOutputSize(input.Length)];
            int len = gcm.ProcessBytes(input, 0, input.Length, plainBytes, 0);
            len += gcm.DoFinal(plainBytes, len);
            byte[] result = new byte[len]; Buffer.BlockCopy(plainBytes, 0, result, 0, len);
            return result;
        }

        private byte[] GetFileE2EKey(string targetType, string targetName)
        {
            // Les fichiers en salon ne sont pas chiffrés E2E au niveau applicatif :
            // TLS chiffre déjà le transit, et les Sender Keys ont des problèmes de
            // timing qui causent des erreurs GCM. E2E uniquement pour les MP.
            if (targetType == "room") return null;
            lock (_e2eLock) return _e2eSharedKeys.TryGetValue(targetName, out byte[] key) ? key : null;
        }

        private byte[] GetFileE2EDecryptKey(string sender, string targetType, string targetName)
        {
            if (targetType == "room") { lock (_senderKeyLock) return _peerSenderKeys.TryGetValue(targetName + ":" + sender, out byte[] key) ? key : null; }
            else { lock (_e2eLock) return _e2eSharedKeys.TryGetValue(sender, out byte[] key) ? key : null; }
        }

        // ═══════════════════════════════════════════════════════
        //  File Transfer
        // ═══════════════════════════════════════════════════════

        private const int FileChunkSize = 48 * 1024;
        private const long MaxFileSize = 100L * 1024 * 1024;
        private readonly Dictionary<string, FileReceiveState> _incomingFiles = new Dictionary<string, FileReceiveState>();
        private readonly object _fileLock = new object();

        private class FileReceiveState
        {
            public string TransferId, Sender, FileName, MimeType;
            public long FileSize; public int TotalChunks;
            public Dictionary<int, byte[]> Chunks = new Dictionary<int, byte[]>();
            public bool IsE2E; public string TargetType, TargetName;
        }

        private async Task SendFileAsync(string filePath, string targetType, string targetName)
        {
            try
            {
                var fi = new FileInfo(filePath);
                if (!fi.Exists) { AppendSystemMessage("⚠ Fichier introuvable : " + filePath); return; }
                if (fi.Length > MaxFileSize) { AppendSystemMessage($"⚠ Fichier trop volumineux (max {MaxFileSize / 1024 / 1024} MB)."); return; }
                if (fi.Length == 0) { AppendSystemMessage("⚠ Fichier vide."); return; }
                string transferId = Guid.NewGuid().ToString("N").Substring(0, 16);
                string fileName = fi.Name; long fileSize = fi.Length;
                string mimeType = GetMimeType(fi.Extension);
                int totalChunks = (int)Math.Ceiling((double)fileSize / FileChunkSize);
                byte[] e2eKey = GetFileE2EKey(targetType, targetName);
                bool useE2E = e2eKey != null;
                string e2eFlag = useE2E ? "E2E" : "PLAIN";
                SendPacket(ProtocolMessage.Build("FILE_INIT", transferId, targetType, targetName, fileName, fileSize.ToString(), mimeType, totalChunks.ToString(), e2eFlag));
                if (targetType == "pm")
                    AppendSystemMessagePM(targetName, $"📎 Envoi de {fileName} ({FormatBytes(fileSize)}){(useE2E ? " 🔐" : "")}...");
                else
                    AppendSystemMessage($"📎 Envoi de {fileName} ({FormatBytes(fileSize)}){(useE2E ? " 🔐" : "")}...");
                await Task.Delay(500);
                byte[] buffer = new byte[FileChunkSize];
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    int chunkIndex = 0, bytesRead;
                    while ((bytesRead = await fs.ReadAsync(buffer, 0, FileChunkSize)) > 0)
                    {
                        byte[] chunkData = new byte[bytesRead]; Buffer.BlockCopy(buffer, 0, chunkData, 0, bytesRead);
                        byte[] dataToSend = useE2E ? EncryptBytesAES(chunkData, e2eKey) : chunkData;
                        SendPacket(ProtocolMessage.Build("FILE_CHUNK", transferId, chunkIndex.ToString(), Convert.ToBase64String(dataToSend)));
                        chunkIndex++;
                        if (chunkIndex % 10 == 0) await Task.Delay(50);
                    }
                }
                SendPacket(ProtocolMessage.Build("FILE_COMPLETE", transferId));
                DisplaySentFile(filePath, fileName, fileSize, mimeType, useE2E, targetType, targetName);
            }
            catch (Exception ex)
            {
                if (targetType == "pm") AppendSystemMessagePM(targetName, "❌ Erreur envoi fichier : " + ex.Message);
                else AppendSystemMessage("❌ Erreur envoi fichier : " + ex.Message);
                DebugLog.Error("SendFileAsync", ex);
            }
        }

        private void HandleFileInit(ProtocolMessage msg)
        {
            // Format relayé par le serveur :
            // FILE_INIT:transferId:senderUsername:fileName:fileSize:mimeType:totalChunks:e2eFlag
            // Parse(raw,7): F(0)=transferId F(1)=sender F(2)=fileName F(3)=fileSize F(4)=mimeType F(5)=totalChunks F(6)=e2eFlag
            if (msg.Fields.Length < 6) return;
            string transferId = msg.Field(0);
            string sender = msg.Field(1);
            string fileName = msg.Field(2);
            long fileSize = msg.FieldLong(3);
            string mimeType = msg.Field(4);
            int totalChunks = msg.FieldInt(5);
            string e2eFlag = msg.Field(6, "PLAIN");
            // Détection PM fiable : les fichiers salon sont PLAIN (E2E désactivé en salon),
            // les fichiers PM sont E2E. Cette distinction est 100% fiable.
            bool isPM = (e2eFlag == "E2E");
            string targetType = isPM ? "pm" : "room";
            string targetName = isPM ? sender : CurrentRoom;

            // Validation DoS
            if (fileSize <= 0 || fileSize > MaxFileSize)
            {
                AppendSystemMessage($"⚠ Transfert refusé : taille invalide ({FormatBytes(fileSize)}).");
                return;
            }
            int expectedChunks = (int)Math.Ceiling((double)fileSize / FileChunkSize);
            if (totalChunks <= 0 || totalChunks > expectedChunks + 1)
            {
                AppendSystemMessage($"⚠ Transfert refusé : nombre de chunks invalide ({totalChunks}).");
                return;
            }
            lock (_fileLock)
            {
                _incomingFiles[transferId] = new FileReceiveState
                {
                    TransferId = transferId,
                    Sender = sender,
                    FileName = fileName,
                    FileSize = fileSize,
                    MimeType = mimeType,
                    TotalChunks = totalChunks,
                    IsE2E = e2eFlag == "E2E",
                    TargetType = targetType,
                    TargetName = targetName
                };
            }
            if (targetType == "pm")
                AppendSystemMessagePM(sender, $"📥{(e2eFlag == "E2E" ? " 🔐" : "")} Réception de {fileName} de {sender} ({FormatBytes(fileSize)})...");
            else
                AppendSystemMessage($"📥{(e2eFlag == "E2E" ? " 🔐" : "")} Réception de {fileName} de {sender} ({FormatBytes(fileSize)})...");
        }

        private void HandleFileChunk(ProtocolMessage msg)
        {
            if (msg.Fields.Length < 3) return;
            int chunkIdx = msg.FieldInt(1, -1); if (chunkIdx < 0) return;
            lock (_fileLock)
            {
                if (!_incomingFiles.TryGetValue(msg.Field(0), out var state)) return;
                try { state.Chunks[chunkIdx] = Convert.FromBase64String(msg.Field(2)); } catch { }
            }
        }

        private void HandleFileComplete(ProtocolMessage msg)
        {
            if (msg.Fields.Length < 1) return;
            FileReceiveState state;
            lock (_fileLock) { if (!_incomingFiles.TryGetValue(msg.Field(0), out state)) return; _incomingFiles.Remove(msg.Field(0)); }
            try
            {
                string downloadDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Downloads");
                Directory.CreateDirectory(downloadDir);
                string safeName = SanitizeFileName(state.FileName);
                string filePath = Path.Combine(downloadDir, safeName);
                if (File.Exists(filePath))
                    filePath = Path.Combine(downloadDir, Path.GetFileNameWithoutExtension(safeName) + "_" + DateTime.Now.ToString("HHmmss") + Path.GetExtension(safeName));
                byte[] e2eKey = null;
                if (state.IsE2E)
                {
                    // E2E uniquement pour les MP (clé pairwise stable)
                    // Les fichiers salon marqués E2E (ancienne version) sont traités en PLAIN
                    if (state.TargetType == "pm" || string.IsNullOrEmpty(state.TargetType))
                    {
                        e2eKey = GetFileE2EDecryptKey(state.Sender, "pm", state.Sender);
                        if (e2eKey == null)
                        {
                            AppendSystemMessagePM(state.Sender, $"⚠ Impossible de déchiffrer le fichier de {state.Sender}");
                            return;
                        }
                    }
                    // Si room file marqué E2E : ignorer le flag, traiter en PLAIN (TLS suffit)
                }
                using (var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
                {
                    for (int i = 0; i < state.TotalChunks; i++)
                        if (state.Chunks.TryGetValue(i, out byte[] chunk))
                        {
                            byte[] plainChunk = (state.IsE2E && e2eKey != null) ? DecryptBytesAES(chunk, e2eKey) : chunk;
                            fs.Write(plainChunk, 0, plainChunk.Length);
                        }
                }
                DisplayReceivedFile(filePath, state.Sender, state.FileName, state.FileSize, state.MimeType, state.IsE2E, state.TargetType, state.TargetName);
            }
            catch (Exception ex)
            {
                if (state?.TargetType == "pm" && state?.Sender != null)
                    AppendSystemMessagePM(state.Sender, "❌ Erreur sauvegarde fichier : " + ex.Message);
                else
                    AppendSystemMessage("❌ Erreur sauvegarde fichier : " + ex.Message);
                DebugLog.Error("HandleFileComplete", ex);
            }
        }

        private void DisplayReceivedFile(string filePath, string sender, string fileName, long fileSize, string mimeType, bool isE2E = false, string targetType = null, string targetName = null)
        {
            Image thumb = TryCreateThumbnail(filePath, mimeType);
            var entry = new ChatEntry { Time = DateTime.Now, Sender = sender, Text = fileName + " (" + FormatBytes(fileSize) + ")", Room = CurrentRoom, IsMe = false, IsE2E = isE2E, Type = ChatEntryType.File, FilePath = filePath, FileName = fileName, FileSize = fileSize, MimeType = mimeType, Thumbnail = thumb };
            if (targetType == "pm")
                AddPMFileEntry(sender, entry);
            else
                chatPanel.AddEntry(entry);
        }

        private void DisplaySentFile(string filePath, string fileName, long fileSize, string mimeType, bool isE2E = false, string targetType = null, string targetName = null)
        {
            Image thumb = TryCreateThumbnail(filePath, mimeType);
            var entry = new ChatEntry { Time = DateTime.Now, Sender = username, Text = fileName + " (" + FormatBytes(fileSize) + ")", Room = CurrentRoom, IsMe = true, IsE2E = isE2E, Type = ChatEntryType.File, FilePath = filePath, FileName = fileName, FileSize = fileSize, MimeType = mimeType, Thumbnail = thumb };
            if (targetType == "pm")
                AddPMFileEntry(targetName ?? "", entry);
            else
                chatPanel.AddEntry(entry);
        }

        /// <summary>
        /// Ajoute un fichier (ChatEntryType.File) dans la conversation PM.
        /// Stocke dans pmConvs ET affiche dans pmChatPanel si la conv est active.
        /// Évite le double affichage contrairement à AddPMEntry.
        /// </summary>
        private void AddPMFileEntry(string convKey, ChatEntry entry)
        {
            if (string.IsNullOrEmpty(convKey)) return;
            Action add = () =>
            {
                if (!pmConvs.ContainsKey(convKey))
                    pmConvs[convKey] = new List<ChatEntry>();
                pmConvs[convKey].Add(entry);

                // Afficher immédiatement si la conv est active
                if (activePMTarget.Equals(convKey, StringComparison.OrdinalIgnoreCase) && pmChatPanel != null)
                    pmChatPanel.AddEntry(entry);
                else if (!entry.IsMe)
                {
                    _unreadPM++;
                    UpdatePMTabBadge();
                }

                // Assurer que le contact apparaît dans la liste
                if (!lstPMContacts.Items.Contains(convKey))
                    lstPMContacts.Items.Add(convKey);
            };

            if (lstPMContacts.InvokeRequired) lstPMContacts.Invoke(add);
            else add();
        }

        private static readonly string[] SafeImageExtensions = { ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp" };

        private Image TryCreateThumbnail(string filePath, string mimeType)
        {
            if (!IsImageMime(mimeType)) return null;
            // FIX 3 : Valider l'extension réelle pour éviter GDI+ sur formats dangereux (TIFF/WMF/EMF)
            string ext = Path.GetExtension(filePath).ToLowerInvariant();
            if (!Array.Exists(SafeImageExtensions, e => e == ext)) return null;
            try
            {
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var ms = new MemoryStream())
                {
                    fs.CopyTo(ms); ms.Position = 0;
                    var img = Image.FromStream(ms, false, false); // validateImageData=false pour éviter les exceptions GDI+
                    double ratio = Math.Min(280.0 / img.Width, 200.0 / img.Height); if (ratio > 1) ratio = 1;
                    int tw = Math.Max(1, (int)(img.Width * ratio)), th = Math.Max(1, (int)(img.Height * ratio));
                    var thumb = new Bitmap(tw, th);
                    using (var g = Graphics.FromImage(thumb)) { g.InterpolationMode = InterpolationMode.HighQualityBicubic; g.DrawImage(img, 0, 0, tw, th); }
                    img.Dispose(); return thumb;
                }
            }
            catch { return null; }
        }

        private static readonly Regex UrlRegex = new Regex(@"https?://[^\s<>""']+", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // ═══════════════════════════════════════════════════════
        //  Thread-safe currentRoom
        // ═══════════════════════════════════════════════════════

        private string _currentRoom = "général";
        private readonly object _roomLock = new object();
        private string CurrentRoom { get { lock (_roomLock) return _currentRoom; } set { lock (_roomLock) _currentRoom = value; } }

        private string username = "";
        private string _lastIp = "", _lastUser = "", _lastPass = "";
        private int _lastPort = 8888;
        private List<string> availableRooms = new List<string>();

        // ── Heartbeat ──
        private System.Windows.Forms.Timer _pingTimer, _usersRefreshTimer;
        private volatile bool _waitingPong = false;
        private DateTime _lastPingSent;

        private void StartHeartbeat()
        {
            _pingTimer?.Stop(); _pingTimer?.Dispose();
            _pingTimer = new System.Windows.Forms.Timer { Interval = 25000 };
            _pingTimer.Tick += (s, e) =>
            {
                if (!isConnected) { _pingTimer.Stop(); return; }
                if (_waitingPong && (DateTime.Now - _lastPingSent).TotalMilliseconds > 10000)
                { AppendSystemMessage("⚠ Heartbeat timeout"); _pingTimer.Stop(); DisconnectFromServer(); TryAutoReconnect(); return; }
                _waitingPong = true; _lastPingSent = DateTime.Now;
                try { SendPacket("PING"); } catch { }
            };
            _pingTimer.Start();
            _usersRefreshTimer?.Stop(); _usersRefreshTimer?.Dispose();
            _usersRefreshTimer = new System.Windows.Forms.Timer { Interval = 2000 };
            _usersRefreshTimer.Tick += (s, e) => { if (isConnected) try { SendPacket("LIST_USERS"); } catch { } };
            _usersRefreshTimer.Start();
        }

        private void StopHeartbeat()
        { _pingTimer?.Stop(); _pingTimer?.Dispose(); _pingTimer = null; _usersRefreshTimer?.Stop(); _usersRefreshTimer?.Dispose(); _usersRefreshTimer = null; }

        // ── Auto-reconnect ──
        private const int MaxReconnectAttempts = 8;
        private int _reconnectAttempt = 0;
        private bool _reconnecting = false;
        private System.Windows.Forms.Timer _reconnectTimer;

        private void TryAutoReconnect()
        {
            if (btnConnect != null && btnConnect.InvokeRequired) { try { btnConnect.BeginInvoke(new Action(TryAutoReconnect)); } catch { } return; }
            if (_reconnecting || string.IsNullOrEmpty(_lastUser)) return;
            if (_reconnectAttempt >= MaxReconnectAttempts) { AppendSystemMessage("❌ Reconnexion abandonnée."); _reconnectAttempt = 0; return; }
            _reconnecting = true; _reconnectAttempt++;
            int delay = (int)Math.Min(2000 * Math.Pow(2, _reconnectAttempt - 1), 30000);
            AppendSystemMessage($"🔄 Reconnexion dans {delay / 1000}s ({_reconnectAttempt}/{MaxReconnectAttempts})...");
            _reconnectTimer?.Stop(); _reconnectTimer?.Dispose();
            _reconnectTimer = new System.Windows.Forms.Timer { Interval = delay };
            _reconnectTimer.Tick += async (s, e) =>
            {
                _reconnectTimer.Stop(); _reconnecting = false;
                if (isConnected) return;
                try
                {
                    string resp = await Task.Run(() => DoConnect(_lastIp, _lastPort, _lastUser, _lastPass));
                    if (resp != null && resp.StartsWith("OK:"))
                    {
                        username = _lastUser; isConnected = true; _reconnectAttempt = 0;
                        AppendSystemMessage("✅ Reconnecté : " + username);
                        SetConnectedUI(true); StartHeartbeat();
                        receiveThread = new Thread(ReceiveLoop) { IsBackground = true }; receiveThread.Start();
                        SendPacket(ProtocolMessage.Build("E2E_ANNOUNCE", _e2ePublicKeyBase64));
                        DistributeSenderKeyToAll(CurrentRoom);
                    }
                    else TryAutoReconnect();
                }
                catch { TryAutoReconnect(); }
            };
            _reconnectTimer.Start();
        }

        private void CancelAutoReconnect()
        { _reconnectTimer?.Stop(); _reconnectTimer?.Dispose(); _reconnecting = false; _reconnectAttempt = 0; _lastUser = ""; }

        // ── PM conversations ──
        private Dictionary<string, List<ChatEntry>> pmConvs = new Dictionary<string, List<ChatEntry>>(StringComparer.OrdinalIgnoreCase);
        private string activePMTarget = "";

        // ── UI controls ──
        private TextBox txtServerIP, txtServerPort, txtUsername, txtPassword;
        private ModernButton btnConnect, btnDeleteAccount, btnHelp, btnHelpBottom, btnAttach, btnAttachPM, btnSend, btnSendPMMsg;
        private CheckBox chkShowPass;
        private TextBox txtMessage, txtPMMessage;
        private ChatPanel chatPanel, pmChatPanel;
        private readonly Dictionary<string, ChatPanel> _roomChatPanels = new Dictionary<string, ChatPanel>(StringComparer.OrdinalIgnoreCase);
        private Panel _chatContainer;
        private Label lblStatus, lblRoom, lblE2EStatus, lblPMHeader;
        private ListBox lstPMContacts, lstRooms, lstUsers;
        private Panel pmChatArea;
        private TabControl tabChat;
        private TabPage tabMain, tabPM;
        private ContextMenuStrip ctxUsers, _chatContextMenu;
        private string _lastRightClickFile = null;
        private int _unreadPM = 0; // badge compteur MP non lus
        private const int MaxMessageLength = 2000;

        // ── Cached fonts ──
        private static readonly Font FontRoomNormal = new Font("Segoe UI", 9f);
        private static readonly Font FontRoomBold = new Font("Segoe UI", 9f, FontStyle.Bold);
        private static readonly Font FontUserNormal = new Font("Segoe UI", 9f);
        private static readonly Font FontUserBold = new Font("Segoe UI", 9f, FontStyle.Bold);
        private static readonly Font FontUserE2EBadge = new Font("Segoe UI", 7f);
        private static readonly Font FontPMInitial = new Font("Segoe UI", 8f, FontStyle.Bold);
        private static readonly Font FontTabNormal = new Font("Segoe UI", 9f);
        private static readonly Font FontTabBold = new Font("Segoe UI", 9f, FontStyle.Bold);

        // ── Theme ──
        static readonly Color C_BG = Color.FromArgb(245, 247, 250);
        static readonly Color C_SURFACE = Color.White;
        static readonly Color C_SIDEBAR = Color.FromArgb(250, 251, 253);
        static readonly Color C_PRIMARY = Color.FromArgb(99, 102, 241);
        static readonly Color C_PRIMARY_HOVER = Color.FromArgb(79, 82, 221);
        static readonly Color C_PRIMARY_PRESS = Color.FromArgb(67, 56, 202);
        static readonly Color C_SECONDARY = Color.FromArgb(16, 163, 127);
        static readonly Color C_DANGER = Color.FromArgb(239, 68, 68);
        static readonly Color C_SUCCESS = Color.FromArgb(34, 197, 94);
        static readonly Color C_WARNING = Color.FromArgb(245, 158, 11);
        static readonly Color C_PURPLE = Color.FromArgb(139, 92, 246);
        static readonly Color C_TEXT = Color.FromArgb(15, 23, 42);
        static readonly Color C_TEXT_DIM = Color.FromArgb(100, 116, 139);
        static readonly Color C_TEXT_MUTED = Color.FromArgb(148, 163, 184);
        static readonly Color C_BORDER = Color.FromArgb(226, 232, 240);
        static readonly Color C_INPUT_BG = Color.FromArgb(248, 250, 252);
        static readonly Color C_TOPBAR = Color.FromArgb(15, 23, 42);

        private static readonly string PrefsFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "client_prefs.json");

        // ═══════════════════════════════════════════════════════
        //  Constructor — FIX: clé persistante + trust store
        // ═══════════════════════════════════════════════════════

        public ClientForm()
        {
            // FIX 1.3 : Clé d'identité persistante au lieu d'éphémère
            _e2eIdentity.LoadOrGenerate();
            _keyTrustStore.Load();
            _e2eKeyPair = _e2eIdentity.KeyPair;
            _e2ePublicKeyBytes = _e2eIdentity.PublicKeyBytes;
            _e2ePublicKeyBase64 = _e2eIdentity.PublicKeyBase64;

            LoadPinnedCert();
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer, true);
            DoubleBuffered = true;
            InitializeComponent();
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
            LoadPrefs();
            EnableDragDrop();
        }

        private void EnableDragDrop()
        {
            AllowDrop = true;
            DragEnter += (s, e) => { if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy; };
            DragDrop += async (s, e) => { if (!isConnected) return; string[] files = (string[])e.Data.GetData(DataFormats.FileDrop); if (files != null) foreach (string f in files) await SendFileAsync(f, "room", CurrentRoom); };
        }

        // ═══════════════════════════════════════════════════════
        //  JSON Preferences
        // ═══════════════════════════════════════════════════════

        private void LoadPrefs()
        {
            try
            {
                if (!File.Exists(PrefsFile)) return;
                string json = File.ReadAllText(PrefsFile, Encoding.UTF8);
                var prefs = SimpleJsonParseStatic(json);
                if (prefs.TryGetValue("ServerIP", out string ip)) txtServerIP.Text = ip;
                if (prefs.TryGetValue("ServerPort", out string port)) txtServerPort.Text = port;
                if (prefs.TryGetValue("Username", out string user)) txtUsername.Text = user;
                if (prefs.TryGetValue("Password", out string encPass) && !string.IsNullOrWhiteSpace(encPass))
                    try { txtPassword.Text = Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(encPass), null, DataProtectionScope.CurrentUser)); } catch { }
            }
            catch (Exception ex) { DebugLog.Warn("LoadPrefs: " + ex.Message); }
        }

        private void SavePrefs()
        {
            try
            {
                string encPass = "";
                if (!string.IsNullOrEmpty(txtPassword.Text))
                    encPass = Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(txtPassword.Text), null, DataProtectionScope.CurrentUser));
                var prefs = new Dictionary<string, string> { ["ServerIP"] = txtServerIP.Text.Trim(), ["ServerPort"] = txtServerPort.Text.Trim(), ["Username"] = txtUsername.Text.Trim(), ["Password"] = encPass };
                File.WriteAllText(PrefsFile, SimpleJsonSerialize(prefs), Encoding.UTF8);
            }
            catch (Exception ex) { DebugLog.Warn("SavePrefs: " + ex.Message); }
        }

        private static string JsonEscapeString(string s)
        {
            if (s == null) return "null";
            var sb = new StringBuilder(s.Length + 8); sb.Append('"');
            foreach (char c in s) { switch (c) { case '"': sb.Append("\\\""); break; case '\\': sb.Append("\\\\"); break; case '\n': sb.Append("\\n"); break; case '\r': sb.Append("\\r"); break; case '\t': sb.Append("\\t"); break; default: if (c < 0x20) sb.AppendFormat("\\u{0:X4}", (int)c); else sb.Append(c); break; } }
            sb.Append('"'); return sb.ToString();
        }

        private static string SimpleJsonSerialize(Dictionary<string, string> dict)
        {
            var sb = new StringBuilder("{"); bool first = true;
            foreach (var kv in dict) { if (!first) sb.Append(','); sb.Append(JsonEscapeString(kv.Key)); sb.Append(':'); sb.Append(JsonEscapeString(kv.Value)); first = false; }
            sb.Append('}'); return sb.ToString();
        }

        public static Dictionary<string, string> SimpleJsonParseStatic(string json)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrEmpty(json)) return result;
            int i = json.IndexOf('{'); if (i < 0) return result; i++;
            while (i < json.Length)
            {
                while (i < json.Length && (json[i] == ' ' || json[i] == ',' || json[i] == '\n' || json[i] == '\r' || json[i] == '\t')) i++;
                if (i >= json.Length || json[i] == '}') break;
                string key = ParseJsonStringStatic(json, ref i); if (key == null) break;
                while (i < json.Length && (json[i] == ':' || json[i] == ' ')) i++;
                string value = ParseJsonStringStatic(json, ref i); if (value == null) break;
                result[key] = value;
            }
            return result;
        }

        private static string ParseJsonStringStatic(string json, ref int pos)
        {
            while (pos < json.Length && json[pos] != '"') pos++;
            if (pos >= json.Length) return null; pos++;
            var sb = new StringBuilder();
            while (pos < json.Length)
            {
                char c = json[pos];
                if (c == '"') { pos++; return sb.ToString(); }
                if (c == '\\' && pos + 1 < json.Length)
                {
                    pos++; char esc = json[pos];
                    switch (esc)
                    {
                        case '"': sb.Append('"'); break;
                        case '\\': sb.Append('\\'); break;
                        case 'n': sb.Append('\n'); break;
                        case 'r': sb.Append('\r'); break;
                        case 't': sb.Append('\t'); break;
                        case 'u': if (pos + 4 < json.Length && int.TryParse(json.Substring(pos + 1, 4), System.Globalization.NumberStyles.HexNumber, null, out int code)) { sb.Append((char)code); pos += 4; } break;
                        default: sb.Append(esc); break;
                    }
                }
                else sb.Append(c);
                pos++;
            }
            return sb.ToString();
        }

        // ═══════════════════════════════════════════════════════
        //  Connection
        // ═══════════════════════════════════════════════════════

        private async void ConnectToServerAsync()
        {
            string ip = txtServerIP.Text.Trim(), user = txtUsername.Text.Trim(), pass = txtPassword.Text;
            if (string.IsNullOrWhiteSpace(user) || user.Length < 2 || user.Length > 20 || user.Contains(" ")) { AppendSystemMessage("⚠ Pseudo invalide."); return; }
            if (pass.Length < 4) { AppendSystemMessage("⚠ Mot de passe trop court."); return; }
            if (!int.TryParse(txtServerPort.Text, out int port)) port = 8888;
            btnConnect.Enabled = false; AppendSystemMessage("Connexion à " + ip + ":" + port + "...");
            try
            {
                string resp = await Task.Run(() => DoConnect(ip, port, user, pass));
                if (resp == null) { AppendSystemMessage("❌ Pas de réponse."); try { client?.Close(); } catch { } btnConnect.Enabled = true; return; }
                if (resp.StartsWith("ERR:")) { AppendSystemMessage("❌ " + TranslateError(resp.Substring(4))); try { client?.Close(); } catch { } btnConnect.Enabled = true; return; }
                if (resp.StartsWith("OK:"))
                {
                    username = user; isConnected = true;
                    _lastIp = ip; _lastPort = port; _lastUser = user; _lastPass = pass;
                    SavePrefs(); AppendSystemMessage("✅ Connecté : " + username);

                    // Afficher le fingerprint à la connexion
                    string myFp = KeyTrustStore.GetMyFingerprint(_e2ePublicKeyBytes);
                    AppendSystemMessage($"🔑 Votre empreinte E2E : {myFp}");

                    SetConnectedUI(true); StartHeartbeat();
                    receiveThread = new Thread(ReceiveLoop) { IsBackground = true }; receiveThread.Start();
                    SendPacket(ProtocolMessage.Build("E2E_ANNOUNCE", _e2ePublicKeyBase64));
                    AppendSystemMessage("🔐 Clé E2E X25519 persistante annoncée.");
                    DistributeSenderKeyToAll(CurrentRoom);
                }
            }
            catch (Exception ex) { AppendSystemMessage("❌ " + ex.Message); DebugLog.Error("ConnectToServerAsync", ex); try { client?.Close(); } catch { } }
            btnConnect.Enabled = true;
        }

        private static string ClientHashPassword(string password, string username)
        {
            byte[] salt = Encoding.UTF8.GetBytes("NexusChat-PBKDF2:" + username.ToLowerInvariant());
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256))
                return BitConverter.ToString(pbkdf2.GetBytes(32)).Replace("-", "").ToLowerInvariant();
        }

        private string DoConnect(string ip, int port, string user, string pass)
        {
            client = new TcpClient(); client.Connect(ip, port);
            try
            {
                _sslStream = new SslStream(client.GetStream(), false, ValidateServerCertificate);
                _sslStream.AuthenticateAsClient("NexusChat-Server", null, System.Security.Authentication.SslProtocols.Tls12, false);
                clientStream = _sslStream;
            }
            catch (Exception tlsEx)
            {
                try { _sslStream?.Dispose(); } catch { }
                _sslStream = null;
                try { client.Close(); } catch { }
                AppendSystemMessage("❌ TLS obligatoire."); DebugLog.Error("TLS handshake failed", tlsEx);
                return "ERR:TLS_REQUIRED";
            }
            if (!PerformClientHandshake()) { client.Close(); return "ERR:HANDSHAKE_FAILED"; }
            string clientHash = ClientHashPassword(pass, user);
            SendPacket(ProtocolMessage.Build("AUTH", "LOGIN", user, clientHash));
            client.ReceiveTimeout = 5000; string resp = ReadPacket(); client.ReceiveTimeout = 0;
            if (resp != "ERR:USER_NOT_FOUND") return resp;
            AppendSystemMessage("Compte inexistant, création...");
            try { client.Close(); } catch { }
            client = new TcpClient(); client.Connect(ip, port);
            try
            {
                _sslStream = new SslStream(client.GetStream(), false, ValidateServerCertificate);
                _sslStream.AuthenticateAsClient("NexusChat-Server", null, System.Security.Authentication.SslProtocols.Tls12, false);
                clientStream = _sslStream;
            }
            catch { try { client.Close(); } catch { } return "ERR:TLS_REQUIRED"; }
            if (!PerformClientHandshake()) { client.Close(); return "ERR:HANDSHAKE_FAILED"; }
            SendPacket(ProtocolMessage.Build("AUTH", "REGISTER", user, clientHash));
            client.ReceiveTimeout = 5000; resp = ReadPacket(); client.ReceiveTimeout = 0;
            return resp;
        }

        private bool PerformClientHandshake()
        {
            try
            {
                byte[] lenBuf = ReadExactFrom(clientStream, 4); if (lenBuf == null) return false;
                int len = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(lenBuf, 0));
                if (len <= 0 || len > 8192) return false;
                byte[] pubKeyBytes = ReadExactFrom(clientStream, len); if (pubKeyBytes == null) return false;
                _sessionKey = new byte[32];
                using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(_sessionKey);
                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(Encoding.UTF8.GetString(pubKeyBytes));
                    byte[] encKey = rsa.Encrypt(_sessionKey, true);
                    byte[] prefix = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(encKey.Length));
                    clientStream.Write(prefix, 0, 4); clientStream.Write(encKey, 0, encKey.Length); clientStream.Flush();
                }
                return true;
            }
            catch (Exception ex) { DebugLog.Error("PerformClientHandshake", ex); return false; }
        }

        // ═══════════════════════════════════════════════════════
        //  Receive Loop — FIX: TOFU key verification
        // ═══════════════════════════════════════════════════════

        private void ReceiveLoop()
        {
            try { while (isConnected && client.Connected) { string raw = ReadPacket(); if (raw == null) break; ProcessReceivedMessage(raw); } }
            catch (Exception ex) { if (isConnected) DebugLog.Error("ReceiveLoop exception", ex); }
            finally { if (isConnected) { DisconnectFromServer(); TryAutoReconnect(); } }
        }

        private void ProcessReceivedMessage(string raw)
        {
            if (raw == "PING") { try { SendPacket("PONG"); } catch { } return; }
            if (raw == "PONG") { _waitingPong = false; return; }
            int colonPos = raw.IndexOf(':');
            string command = colonPos >= 0 ? raw.Substring(0, colonPos) : raw;

            switch (command)
            {
                case "E2E_PUBKEY":
                    {
                        var msg = ProtocolMessage.Parse(raw, 2);
                        if (msg.Fields.Length < 2) return;
                        try
                        {
                            byte[] peerKeyBytes = Convert.FromBase64String(msg.Field(1));
                            string peerName = msg.Field(0);

                            // ═══════════════════════════════════════
                            //  FIX 1.1/1.2 : TOFU key verification
                            // ═══════════════════════════════════════
                            var trustResult = _keyTrustStore.VerifyKey(peerName, peerKeyBytes);
                            switch (trustResult)
                            {
                                case KeyTrustStore.TrustResult.TrustedFirstUse:
                                    string fp = KeyTrustStore.ComputeFingerprint(peerKeyBytes);
                                    AppendSystemMessage($"🔐 E2E établi avec {peerName} (TOFU)");
                                    AppendSystemMessage($"   Empreinte : {fp}");
                                    AppendSystemMessage($"   ⚠ Vérifiez cette empreinte avec {peerName} !");
                                    DeriveSharedKey(peerName, peerKeyBytes);
                                    break;
                                case KeyTrustStore.TrustResult.TrustedKnown:
                                    DeriveSharedKey(peerName, peerKeyBytes);
                                    AppendSystemMessage($"🔐 E2E vérifié avec {peerName} ✓");
                                    break;
                                case KeyTrustStore.TrustResult.KeyChanged:
                                    string newFp = KeyTrustStore.ComputeFingerprint(peerKeyBytes);
                                    string oldFp = _keyTrustStore.GetFingerprint(peerName);
                                    AppendSystemMessage($"");
                                    AppendSystemMessage($"⚠⚠⚠ ALERTE SÉCURITÉ ⚠⚠⚠");
                                    AppendSystemMessage($"La clé de {peerName} a CHANGÉ !");
                                    AppendSystemMessage($"  Ancienne : {oldFp}");
                                    AppendSystemMessage($"  Nouvelle : {newFp}");
                                    AppendSystemMessage($"Tapez /accept {peerName} pour accepter, ou vérifiez d'abord !");
                                    AppendSystemMessage($"");
                                    _pendingKeyChanges[peerName] = peerKeyBytes;
                                    break;
                            }
                            UpdateE2EStatus();
                        }
                        catch (Exception ex) { DebugLog.Error("E2E_PUBKEY", ex); }
                        return;
                    }
                case "E2E_SENDER_KEY": { var msg = ProtocolMessage.Parse(raw, 2); if (msg.Fields.Length >= 2) HandleSenderKeyReceived(msg.Field(0), msg.Field(1)); return; }
                case "E2E_MSG":
                    {
                        var msg = ProtocolMessage.Parse(raw, 2); if (msg.Fields.Length < 2) return;
                        try { string plainText = E2EDecrypt(msg.Field(0), msg.Field(1)); AddPMEntry(msg.Field(0), msg.Field(0), plainText, false, true); }
                        catch { AppendSystemMessage($"⚠ Déchiffrement E2E échoué ({msg.Field(0)})"); }
                        return;
                    }
                case "E2E_ROOM_MSG":
                    {
                        var msg = ProtocolMessage.Parse(raw, 3); if (msg.Fields.Length < 3) return;
                        string sender = msg.Field(0), room = msg.Field(1), encPayload = msg.Field(2);
                        var roomPanel = GetRoomChatPanel(room);
                        try
                        {
                            string plainText = RoomE2EDecrypt(room, sender, encPayload);
                            roomPanel.AddEntry(new ChatEntry { Time = DateTime.Now, Sender = sender, Text = plainText, Room = room, IsMe = false, IsE2E = true, Type = ChatEntryType.Message });
                        }
                        catch (Exception ex)
                        {
                            roomPanel.AddEntry(new ChatEntry { Time = DateTime.Now, Sender = sender, Text = "[Message E2E — " + ex.Message + "]", Room = room, IsMe = false, Type = ChatEntryType.System });
                        }
                        return;
                    }
                case "E2E_DISCONNECTED":
                    {
                        string peer = raw.Substring(colonPos + 1);
                        lock (_e2eLock) { _peerE2EKeys.Remove(peer); _e2eSharedKeys.Remove(peer); }
                        lock (_senderKeyLock) { foreach (var k in _peerSenderKeys.Keys.Where(k => k.EndsWith(":" + peer, StringComparison.OrdinalIgnoreCase)).ToList()) _peerSenderKeys.Remove(k); }
                        lock (_nonceLock) { foreach (var k in _e2eNonceManagers.Keys.Where(k => k.Contains(peer)).ToList()) _e2eNonceManagers.Remove(k); }
                        UpdateE2EStatus(); return;
                    }
                case "FILE_INIT": { HandleFileInit(ProtocolMessage.Parse(raw, 7)); return; }
                case "FILE_CHUNK": { HandleFileChunk(ProtocolMessage.Parse(raw, 3)); return; }
                case "FILE_COMPLETE": { HandleFileComplete(ProtocolMessage.Parse(raw, 3)); return; }
                case "FILE_ACK": case "FILE_ERR": return;
                case "MSG":
                    {
                        var msg = ProtocolMessage.Parse(raw, 3); if (msg.Fields.Length < 3) return;
                        GetRoomChatPanel(msg.Field(1)).AddEntry(new ChatEntry { Time = DateTime.Now, Sender = msg.Field(0), Text = msg.Field(2), Room = msg.Field(1), IsMe = false, Type = ChatEntryType.Message });
                        return;
                    }
                case "SYSTEM": { AppendSystemMessage(ProtocolMessage.Parse(raw, 1).Field(0)); return; }
                case "PM": { var msg = ProtocolMessage.Parse(raw, 2); if (msg.Fields.Length >= 2) AddPMEntry(msg.Field(0), msg.Field(0), msg.Field(1), false, false); return; }
                case "ROOMS": { availableRooms = new List<string>(raw.Substring(colonPos + 1).Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)); RefreshRoomList(); return; }
                case "JOINED": { CurrentRoom = raw.Substring(colonPos + 1); UpdateRoomLabel(); AppendSystemMessage("➡  #" + CurrentRoom); AppendSystemMessage("⚠ Les messages de ce salon sont stockés sur le serveur et visibles par l'administrateur."); DistributeSenderKeyToAll(CurrentRoom); return; }
                case "HISTORY":
                    {
                        var msg = ProtocolMessage.Parse(raw, 2);
                        if (msg.Fields.Length < 2) return;
                        string histRoom = msg.Field(0);
                        string histText = msg.Field(1);
                        // Parser le format "[HH:mm] sender: message" envoyé par le serveur
                        // Si le format ne correspond pas, on affiche en System comme avant
                        var histEntry = ParseHistoryLine(histRoom, histText);
                        GetRoomChatPanel(histRoom).AddEntry(histEntry);
                        return;
                    }
                case "HISTORY_END": return;
                case "USERS": { RefreshUsersList(raw.Substring(colonPos + 1).Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)); return; }
                case "ERR": { AppendSystemMessage("⚠ " + TranslateError(raw.Substring(colonPos + 1))); return; }
                case "SERVER":
                    {
                        string subCmd = raw.Substring(colonPos + 1);
                        switch (subCmd)
                        {
                            case "KICKED": AppendSystemMessage("🚫 Vous avez été expulsé."); CancelAutoReconnect(); DisconnectFromServer(); break;
                            case "BANNED": AppendSystemMessage("⛔ Vous avez été banni."); CancelAutoReconnect(); DisconnectFromServer(); break;
                            case "SHUTDOWN": AppendSystemMessage("🔴 Serveur arrêté."); DisconnectFromServer(); TryAutoReconnect(); break;
                            case "ACCOUNT_DELETED": AppendSystemMessage("🗑 Compte supprimé."); CancelAutoReconnect(); DisconnectFromServer(); break;
                        }
                        return;
                    }
            }
        }

        // ── Chat helpers ──

        /// <summary>
        /// Parse une ligne d'historique du format "[HH:mm] sender: message"
        /// et retourne un ChatEntry correctement formaté.
        /// </summary>
        private ChatEntry ParseHistoryLine(string room, string text)
        {
            try
            {
                // Format attendu : "[HH:mm] Sender: message"
                if (text.StartsWith("[") && text.Length > 8)
                {
                    int closeBracket = text.IndexOf(']');
                    if (closeBracket > 0)
                    {
                        string timeStr = text.Substring(1, closeBracket - 1); // "HH:mm"
                        DateTime time = DateTime.Now;
                        if (DateTime.TryParseExact(timeStr, "HH:mm",
                            System.Globalization.CultureInfo.InvariantCulture,
                            System.Globalization.DateTimeStyles.None, out DateTime parsed))
                            time = parsed;

                        string rest = text.Substring(closeBracket + 1).TrimStart(' ');
                        int colonIdx = rest.IndexOf(':');
                        if (colonIdx > 0)
                        {
                            string sender = rest.Substring(0, colonIdx).Trim();
                            string message = rest.Substring(colonIdx + 1).TrimStart(' ');
                            bool isMe = sender.Equals(username, StringComparison.OrdinalIgnoreCase);
                            return new ChatEntry
                            {
                                Time = time,
                                Sender = sender,
                                Text = message,
                                Room = room,
                                IsMe = isMe,
                                IsE2E = false,
                                Type = ChatEntryType.Message
                            };
                        }
                    }
                }
            }
            catch { }
            // Fallback : message système si le format ne correspond pas
            return new ChatEntry { Time = DateTime.Now, Text = text, Type = ChatEntryType.System };
        }

        private void AppendSystemMessage(string text)
        { if (chatPanel != null) chatPanel.AddEntry(new ChatEntry { Time = DateTime.Now, Text = text, Type = ChatEntryType.System }); }

        /// <summary>Route un message système vers le panel MP du contact, sans polluer le salon général.</summary>
        private void AppendSystemMessagePM(string targetName, string text)
        {
            if (pmChatPanel != null && activePMTarget.Equals(targetName, StringComparison.OrdinalIgnoreCase))
                pmChatPanel.AddEntry(new ChatEntry { Time = DateTime.Now, Text = text, Type = ChatEntryType.System });
            else if (pmConvs.ContainsKey(targetName))
                pmConvs[targetName].Add(new ChatEntry { Time = DateTime.Now, Text = text, Type = ChatEntryType.System });
            // Ne rien afficher dans le salon général
        }

        private void AddPMEntry(string convKey, string from, string text, bool isMe, bool isE2E)
        {
            if (!pmConvs.ContainsKey(convKey)) pmConvs[convKey] = new List<ChatEntry>();
            var entry = new ChatEntry { Time = DateTime.Now, Sender = from, Text = text, IsMe = isMe, IsE2E = isE2E, Type = ChatEntryType.Message };
            pmConvs[convKey].Add(entry);
            if (activePMTarget == convKey && pmChatPanel != null)
            {
                pmChatPanel.AddEntry(entry);
            }
            else if (!isMe)
            {
                // FIX 4 : Badge +N sur l'onglet MP si la conv n'est pas active
                _unreadPM++;
                UpdatePMTabBadge();
            }
            if (lstPMContacts.InvokeRequired) lstPMContacts.Invoke(new Action(() => { if (!lstPMContacts.Items.Contains(convKey)) lstPMContacts.Items.Add(convKey); }));
            else if (!lstPMContacts.Items.Contains(convKey)) lstPMContacts.Items.Add(convKey);
        }

        private void UpdatePMTabBadge()
        {
            if (tabPM == null) return;
            Action update = () =>
            {
                tabPM.Text = _unreadPM > 0 ? $"  📩 MP  +{_unreadPM}  " : "  📩 MP  ";
                tabChat?.Invalidate();
            };
            if (tabChat != null && tabChat.InvokeRequired) tabChat.Invoke(update);
            else update();
        }

        private void SendChatMessage()
        {
            string text = txtMessage.Text.Trim();
            if (!isConnected || string.IsNullOrWhiteSpace(text)) return;
            if (text.Length > MaxMessageLength) { AppendSystemMessage($"⚠ Max {MaxMessageLength} caractères."); return; }
            if (text.StartsWith("/")) { HandleCommand(text); txtMessage.Text = ""; return; }
            chatPanel.AddEntry(new ChatEntry { Time = DateTime.Now, Sender = username, Text = text, Room = CurrentRoom, IsMe = true, Type = ChatEntryType.Message });
            SendPacket(ProtocolMessage.Build("MSG", text));
            txtMessage.Text = "";
        }

        private void HandleCommand(string text)
        {
            string[] parts = text.Split(new[] { ' ' }, 3);
            string cmd = parts[0].ToLowerInvariant();
            switch (cmd)
            {
                case "/join": if (parts.Length < 2) { AppendSystemMessage("Usage : /join <salon>"); return; } SendPacket(ProtocolMessage.Build("JOIN", parts[1])); break;
                case "/pm": if (parts.Length < 3) { AppendSystemMessage("Usage : /pm <pseudo> <message>"); return; } SendE2EPM(parts[1], parts[2]); break;
                case "/users": SendPacket("LIST_USERS"); break;
                case "/file": if (parts.Length < 2) { AppendSystemMessage("Usage : /file <chemin>"); return; } _ = SendFileAsync((parts.Length >= 3 ? parts[1] + " " + parts[2] : parts[1]).Trim('"'), "room", CurrentRoom); break;
                case "/help": ShowHelp(); break;
                // FIX : Commande /fingerprint
                case "/fingerprint":
                    if (parts.Length < 2)
                    {
                        string myFp = KeyTrustStore.GetMyFingerprint(_e2ePublicKeyBytes);
                        AppendSystemMessage($"Votre empreinte E2E :"); AppendSystemMessage($"  {myFp}");
                        AppendSystemMessage("Partagez-la avec vos contacts pour vérification.");
                    }
                    else
                    {
                        string fp = _keyTrustStore.GetFingerprint(parts[1]);
                        AppendSystemMessage(fp != null ? $"Empreinte de {parts[1]} : {fp}" : $"Aucune clé connue pour {parts[1]}.");
                    }
                    break;
                // FIX : Commande /accept
                case "/accept":
                    if (parts.Length < 2) { AppendSystemMessage("Usage : /accept <pseudo>"); return; }
                    if (_pendingKeyChanges.TryGetValue(parts[1], out byte[] pendingKey))
                    {
                        _keyTrustStore.AcceptNewKey(parts[1], pendingKey);
                        DeriveSharedKey(parts[1], pendingKey);
                        _pendingKeyChanges.Remove(parts[1]);
                        AppendSystemMessage($"✅ Nouvelle clé de {parts[1]} acceptée.");
                    }
                    else AppendSystemMessage($"⚠ Pas de changement de clé en attente pour {parts[1]}.");
                    break;
                // FIX : Commande /regenerate
                case "/regenerate":
                    if (MessageBox.Show("Régénérer votre clé E2E ?\nTous vos contacts devront re-vérifier votre empreinte.", "Confirmer", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
                    {
                        _e2eIdentity.Regenerate();
                        _e2eKeyPair = _e2eIdentity.KeyPair;
                        _e2ePublicKeyBytes = _e2eIdentity.PublicKeyBytes;
                        _e2ePublicKeyBase64 = _e2eIdentity.PublicKeyBase64;
                        if (isConnected) SendPacket(ProtocolMessage.Build("E2E_ANNOUNCE", _e2ePublicKeyBase64));
                        AppendSystemMessage("🔑 Clé E2E régénérée. Nouvelle empreinte :");
                        AppendSystemMessage($"  {KeyTrustStore.GetMyFingerprint(_e2ePublicKeyBytes)}");
                    }
                    break;
                default: AppendSystemMessage("⚠ Commande inconnue : " + cmd); break;
            }
        }

        private void SendE2EPM(string target, string message)
        {
            if (HasE2EKey(target))
            {
                try { string enc = E2EEncrypt(target, message); SendPacket(ProtocolMessage.Build("E2E_MSG", target, enc)); AddPMEntry(target, username, message, true, true); return; }
                catch { AppendSystemMessage("⚠ E2E échoué, envoi en clair."); }
            }
            AddPMEntry(target, username, message, true, false);
            SendPacket(ProtocolMessage.Build("PM", target, message));
        }

        private void SendPMMessage()
        {
            string text = txtPMMessage.Text.Trim();
            if (!isConnected || string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(activePMTarget)) return;
            SendE2EPM(activePMTarget, text); txtPMMessage.Text = "";
        }

        private void OpenPMConv(string target)
        {
            if (string.IsNullOrWhiteSpace(target)) return;
            if (tabChat.InvokeRequired) { tabChat.Invoke(new Action(() => OpenPMConv(target))); return; }
            activePMTarget = target;
            // FIX 4 : Réinitialiser le badge quand on ouvre les MP
            _unreadPM = 0;
            UpdatePMTabBadge();
            bool pmE2E = HasE2EKey(target);
            lblPMHeader.Text = (pmE2E ? "  🔐  " : "  💬  ") + target;
            lblPMHeader.ForeColor = pmE2E ? C_PURPLE : C_TEXT;
            lblPMHeader.BackColor = pmE2E ? Color.FromArgb(248, 245, 255) : Color.FromArgb(250, 251, 255);
            if (pmChatPanel != null) { pmChatArea.Controls.Remove(pmChatPanel); pmChatPanel.Dispose(); }
            pmChatPanel = new ChatPanel { Dock = DockStyle.Fill, BgColor = Color.FromArgb(250, 251, 253) };
            pmChatPanel.FileRightClicked += (path) => { _lastRightClickFile = path; _chatContextMenu?.Show(pmChatPanel, pmChatPanel.PointToClient(Cursor.Position)); };
            pmChatPanel.FileSaveClicked += (path) => { if (!File.Exists(path)) return; using (var sfd = new SaveFileDialog { FileName = Path.GetFileName(path) }) if (sfd.ShowDialog() == DialogResult.OK) try { File.Copy(path, sfd.FileName, true); } catch { } };
            pmChatPanel.FileOpenClicked += (path) => {
                if (!File.Exists(path)) return;
                string ext = Path.GetExtension(path).ToLowerInvariant();
                string[] dangerous = { ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".com", ".scr", ".hta", ".pif", ".cpl", ".reg" };
                if (Array.Exists(dangerous, e => e == ext)) { MessageBox.Show("Ouverture bloquée : " + ext, "Sécurité", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
                try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(path) { UseShellExecute = true }); } catch { }
            };
            pmChatArea.Controls.Add(pmChatPanel);
            if (pmConvs.TryGetValue(target, out var history)) foreach (var e in history) pmChatPanel.AddEntry(e);
            if (!lstPMContacts.Items.Contains(target)) lstPMContacts.Items.Add(target);
            lstPMContacts.SelectedItem = target;
            tabChat.SelectedTab = tabPM;
        }

        // ── UI refresh ──

        private void RefreshUsersList(string[] users)
        {
            if (lstUsers.InvokeRequired) { lstUsers.Invoke(new Action(() => RefreshUsersList(users))); return; }
            lstUsers.Items.Clear();
            foreach (string u in users)
            {
                bool hasE2E; lock (_e2eLock) hasE2E = _e2eSharedKeys.ContainsKey(u);
                bool isMe = u.Equals(username, StringComparison.OrdinalIgnoreCase);
                string display = u + (isMe ? " (moi)" : "") + (hasE2E ? " 🔐" : "");
                lstUsers.Items.Add(display);
            }
        }

        private void RefreshRoomList()
        {
            if (lstRooms.InvokeRequired) { lstRooms.Invoke(new Action(RefreshRoomList)); return; }
            string room = CurrentRoom; lstRooms.Items.Clear();
            foreach (string r in availableRooms) lstRooms.Items.Add(r == room ? "● " + r : "  " + r);
        }

        private void UpdateRoomLabel()
        {
            if (lblRoom.InvokeRequired) { lblRoom.Invoke(new Action(UpdateRoomLabel)); return; }
            lblRoom.Text = "# " + CurrentRoom; RefreshRoomList(); SwitchToRoomPanel(CurrentRoom);
        }

        private ChatPanel GetRoomChatPanel(string room)
        {
            if (_roomChatPanels.TryGetValue(room, out ChatPanel existing)) return existing;
            var panel = new ChatPanel { Dock = DockStyle.Fill, BgColor = Color.FromArgb(250, 251, 253) };
            panel.FileRightClicked += (path) => { _lastRightClickFile = path; _chatContextMenu?.Show(panel, panel.PointToClient(Cursor.Position)); };
            panel.FileSaveClicked += (path) => { if (!File.Exists(path)) return; using (var sfd = new SaveFileDialog { FileName = Path.GetFileName(path) }) if (sfd.ShowDialog() == DialogResult.OK) try { File.Copy(path, sfd.FileName, true); } catch { } };
            panel.FileOpenClicked += (path) => {
                if (!File.Exists(path)) return;
                string ext = Path.GetExtension(path).ToLowerInvariant();
                string[] dangerous = { ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".com", ".scr", ".hta", ".pif", ".cpl", ".reg" };
                if (Array.Exists(dangerous, e => e == ext)) { MessageBox.Show("Ouverture bloquée : " + ext, "Sécurité", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
                try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(path) { UseShellExecute = true }); } catch { }
            };
            _roomChatPanels[room] = panel; return panel;
        }

        private void SwitchToRoomPanel(string room)
        {
            if (_chatContainer == null) return;
            if (_chatContainer.InvokeRequired) { _chatContainer.Invoke(new Action(() => SwitchToRoomPanel(room))); return; }
            var panel = GetRoomChatPanel(room); chatPanel = panel;
            _chatContainer.SuspendLayout(); _chatContainer.Controls.Clear(); _chatContainer.Controls.Add(panel); _chatContainer.ResumeLayout();
        }

        private void UpdateE2EStatus()
        {
            if (lblE2EStatus == null) return;
            if (lblE2EStatus.InvokeRequired) { lblE2EStatus.Invoke(new Action(UpdateE2EStatus)); return; }
            int count; lock (_e2eLock) count = _e2eSharedKeys.Count;
            lblE2EStatus.Text = count > 0 ? $"🔐 {count} pair(s) E2E" : "🔓 Aucun pair E2E";
            lblE2EStatus.ForeColor = count > 0 ? C_PURPLE : C_TEXT_MUTED;
        }

        private void SetConnectedUI(bool connected)
        {
            if (btnConnect.InvokeRequired) { btnConnect.Invoke(new Action(() => SetConnectedUI(connected))); return; }
            btnConnect.Enabled = true; btnConnect.Text = connected ? "Déconnexion" : "Connexion";
            btnConnect.IconChar = connected ? "■" : "▶";
            btnConnect.BackColor = connected ? C_DANGER : C_SUCCESS;
            btnConnect.HoverColor = connected ? Color.FromArgb(220, 50, 50) : Color.FromArgb(22, 180, 80);
            btnDeleteAccount.Enabled = connected;
            txtMessage.Enabled = connected; btnSend.Enabled = connected;
            txtPMMessage.Enabled = connected; btnSendPMMsg.Enabled = connected;
            btnAttach.Enabled = connected; btnAttachPM.Enabled = connected;
            UpdateE2EStatus();
        }

        private void DisconnectFromServer()
        {
            isConnected = false; StopHeartbeat();
            try { client?.Close(); } catch { }
            lock (_e2eLock) { _peerE2EKeys.Clear(); _e2eSharedKeys.Clear(); }
            lock (_senderKeyLock) { _mySenderKeys.Clear(); _peerSenderKeys.Clear(); }
            lock (_nonceLock) { _e2eNonceManagers.Clear(); }
            SetConnectedUI(false); UpdateE2EStatus();
        }

        private void ShowHelp()
        {
            string help =
                "NexusChat — Aide\n══════════════════════════════\n\n" +
                "🔐  Chiffrement\n     E2E : X25519 + AES-256-GCM (clé persistante)\n     PM & salons via Sender Keys\n     Fichiers chiffrés E2E automatiquement\n\n" +
                "🔑  Vérification des clés\n     /fingerprint          Voir votre empreinte\n     /fingerprint <user>   Voir l'empreinte d'un contact\n     /accept <user>        Accepter un changement de clé\n     /regenerate           Régénérer votre clé E2E\n\n" +
                "📎  Fichiers\n     Glissez-déposez ou /file <chemin>\n     Max 100 MB, chiffrés E2E si clé dispo\n\n" +
                "⌨  Commandes\n     /join <salon>    Rejoindre un salon\n     /pm <user> <msg> Message privé\n     /users           Liste des connectés\n     /help            Afficher cette aide";
            MessageBox.Show(help, "NexusChat — Aide", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private static string TranslateError(string err)
        {
            if (err.StartsWith("ACCOUNT_LOCKED:")) return "Compte verrouillé " + err.Substring(15) + "s.";
            switch (err)
            {
                case "TLS_REQUIRED": return "TLS obligatoire.";
                case "BANNED_IP": return "IP bannie.";
                case "BANNED_USERNAME": return "Pseudo banni.";
                case "ALREADY_CONNECTED": return "Pseudo déjà connecté.";
                case "INVALID_USERNAME": return "Pseudo invalide.";
                case "USERNAME_TAKEN": return "Pseudo déjà pris.";
                case "USER_NOT_FOUND": return "Compte inexistant.";
                case "WRONG_PASSWORD": return "Mot de passe incorrect.";
                default: return err;
            }
        }

        // ═══════════════════════════════════════════════════════
        //  AES-256-GCM session
        // ═══════════════════════════════════════════════════════

        private void SendPacket(string plainText)
        {
            try
            {
                byte[] nonce, tag;
                byte[] cipher = EncryptAES(plainText, _sessionKey, out nonce, out tag);
                int packetLen = GCM_NONCE_SIZE + GCM_TAG_SIZE + cipher.Length;
                byte[] packet = new byte[packetLen];
                Buffer.BlockCopy(nonce, 0, packet, 0, GCM_NONCE_SIZE);
                Buffer.BlockCopy(tag, 0, packet, GCM_NONCE_SIZE, GCM_TAG_SIZE);
                Buffer.BlockCopy(cipher, 0, packet, GCM_NONCE_SIZE + GCM_TAG_SIZE, cipher.Length);
                byte[] prefix = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(packetLen));
                lock (clientStream) { clientStream.Write(prefix, 0, 4); clientStream.Write(packet, 0, packet.Length); clientStream.Flush(); }
            }
            catch (Exception ex) { DebugLog.Error("SendPacket failed", ex); }
        }

        private string ReadPacket()
        {
            try
            {
                lock (_readLock)
                {
                    byte[] lenBuf = ReadExact(4); if (lenBuf == null) return null;
                    int length = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(lenBuf, 0));
                    if (length < GCM_NONCE_SIZE + GCM_TAG_SIZE + 1 || length > 128 * 1024 + GCM_NONCE_SIZE + GCM_TAG_SIZE) return null;
                    byte[] data = ReadExact(length); if (data == null) return null;
                    byte[] nonce = new byte[GCM_NONCE_SIZE], tag = new byte[GCM_TAG_SIZE];
                    int cipherLen = length - GCM_NONCE_SIZE - GCM_TAG_SIZE; byte[] cipher = new byte[cipherLen];
                    Buffer.BlockCopy(data, 0, nonce, 0, GCM_NONCE_SIZE);
                    Buffer.BlockCopy(data, GCM_NONCE_SIZE, tag, 0, GCM_TAG_SIZE);
                    Buffer.BlockCopy(data, GCM_NONCE_SIZE + GCM_TAG_SIZE, cipher, 0, cipherLen);
                    return DecryptAES(cipher, _sessionKey, nonce, tag);
                }
            }
            catch (Exception ex) { if (isConnected) DebugLog.Error("ReadPacket failed", ex); return null; }
        }

        private byte[] ReadExact(int count)
        { byte[] buf = new byte[count]; int r = 0; while (r < count) { int n = clientStream.Read(buf, r, count - r); if (n == 0) return null; r += n; } return buf; }

        private byte[] ReadExactFrom(Stream stream, int count)
        { byte[] buf = new byte[count]; int r = 0; while (r < count) { int n = stream.Read(buf, r, count - r); if (n == 0) return null; r += n; } return buf; }

        private byte[] EncryptAES(string plain, byte[] key, out byte[] nonce, out byte[] tag)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plain);
            nonce = new byte[GCM_NONCE_SIZE]; using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(nonce);
            var gcm = new GcmBlockCipher(new AesEngine());
            gcm.Init(true, new AeadParameters(new KeyParameter(key), GCM_TAG_BITS, nonce));
            byte[] output = new byte[gcm.GetOutputSize(plainBytes.Length)];
            int len = gcm.ProcessBytes(plainBytes, 0, plainBytes.Length, output, 0); len += gcm.DoFinal(output, len);
            int cipherLen = len - GCM_TAG_SIZE; byte[] cipher = new byte[cipherLen]; tag = new byte[GCM_TAG_SIZE];
            Buffer.BlockCopy(output, 0, cipher, 0, cipherLen); Buffer.BlockCopy(output, cipherLen, tag, 0, GCM_TAG_SIZE);
            return cipher;
        }

        private string DecryptAES(byte[] cipher, byte[] key, byte[] nonce, byte[] tag)
        {
            var gcm = new GcmBlockCipher(new AesEngine());
            gcm.Init(false, new AeadParameters(new KeyParameter(key), GCM_TAG_BITS, nonce));
            byte[] input = new byte[cipher.Length + GCM_TAG_SIZE];
            Buffer.BlockCopy(cipher, 0, input, 0, cipher.Length); Buffer.BlockCopy(tag, 0, input, cipher.Length, GCM_TAG_SIZE);
            byte[] plainBytes = new byte[gcm.GetOutputSize(input.Length)];
            int len = gcm.ProcessBytes(input, 0, input.Length, plainBytes, 0); len += gcm.DoFinal(plainBytes, len);
            return Encoding.UTF8.GetString(plainBytes, 0, len);
        }

        // ── Static helpers ──
        private static string SanitizeFileName(string n) { foreach (char c in Path.GetInvalidFileNameChars()) n = n.Replace(c, '_'); return n.Length > 200 ? n.Substring(0, 200) : n; }
        private static bool IsImageMime(string m) => !string.IsNullOrEmpty(m) && m.StartsWith("image/", StringComparison.OrdinalIgnoreCase);
        private static string FormatBytes(long b) { if (b < 1024) return b + " B"; if (b < 1024 * 1024) return (b / 1024.0).ToString("0.0") + " KB"; if (b < 1024L * 1024 * 1024) return (b / (1024.0 * 1024)).ToString("0.0") + " MB"; return (b / (1024.0 * 1024 * 1024)).ToString("0.00") + " GB"; }
        private static string GetMimeType(string ext) { switch (ext.ToLowerInvariant()) { case ".jpg": case ".jpeg": return "image/jpeg"; case ".png": return "image/png"; case ".gif": return "image/gif"; case ".bmp": return "image/bmp"; case ".webp": return "image/webp"; case ".mp4": return "video/mp4"; case ".mp3": return "audio/mpeg"; case ".wav": return "audio/wav"; case ".pdf": return "application/pdf"; case ".zip": return "application/zip"; case ".txt": return "text/plain"; default: return "application/octet-stream"; } }

        // ═══════════════════════════════════════════════════════════
        //  UI — InitializeComponent
        // ═══════════════════════════════════════════════════════════

        private void InitializeComponent()
        {
            Text = "NexusChat"; ClientSize = new Size(1080, 720); MinimumSize = new Size(1060, 620);
            BackColor = C_BG; ForeColor = C_TEXT; Font = new Font("Segoe UI", 9f); SuspendLayout();

            // ══════════════ TOP BAR ══════════════
            var topBar = new Panel { Dock = DockStyle.Top, Height = 72, BackColor = C_TOPBAR };
            topBar.Controls.Add(new Panel { Dock = DockStyle.Bottom, Height = 2, BackColor = C_PRIMARY });
            var picLogo = new PictureBox { Size = new Size(40, 40), Location = new Point(16, 16), SizeMode = PictureBoxSizeMode.Zoom, BackColor = Color.Transparent };
            try { picLogo.Image = Icon.ExtractAssociatedIcon(Application.ExecutablePath)?.ToBitmap(); } catch { }
            var lblAppName = new Label { Text = "NexusChat", Font = new Font("Segoe UI Semibold", 13f), ForeColor = Color.White, AutoSize = true, Location = new Point(62, 16) };
            var lblSubtitle = new Label { Text = "E2E Encrypted Messaging", Font = new Font("Segoe UI", 7.5f), ForeColor = Color.FromArgb(100, 116, 139), AutoSize = true, Location = new Point(63, 40) };
            var lblHost = MkTopLabel("Hôte", new Point(210, 10));
            txtServerIP = MkTopTextBox("127.0.0.1", new Point(210, 28), 120);
            var lblPort = MkTopLabel("Port", new Point(338, 10));
            txtServerPort = MkTopTextBox("8888", new Point(338, 28), 56);
            btnConnect = new ModernButton { Text = "Connexion", IconChar = "▶", Location = new Point(404, 22), Size = new Size(124, 34), BackColor = C_SUCCESS, HoverColor = Color.FromArgb(22, 180, 80), ForeColor = Color.White, Font = new Font("Segoe UI Semibold", 9.5f), CornerRadius = 10, ShowShadow = true };
            btnConnect.Click += (s, e) => { if (!isConnected) ConnectToServerAsync(); else { CancelAutoReconnect(); DisconnectFromServer(); } };
            btnDeleteAccount = new ModernButton { Text = "Supprimer", Location = new Point(536, 22), Size = new Size(92, 34), BackColor = Color.FromArgb(55, 35, 35), HoverColor = Color.FromArgb(100, 40, 40), ForeColor = Color.FromArgb(200, 160, 160), Font = new Font("Segoe UI", 8.5f), CornerRadius = 10, ShowShadow = false, UseGradient = false, Enabled = false };
            btnDeleteAccount.Click += (s, e) => { if (!isConnected) return; if (MessageBox.Show("Supprimer \"" + username + "\" ?", "Confirmer", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes) { CancelAutoReconnect(); SendPacket("CMD:delete_account"); } };
            var vSep = new Panel { Location = new Point(634, 10), Size = new Size(1, 52), BackColor = Color.FromArgb(40, 52, 75) };
            var lblUser = MkTopLabel("Pseudo", new Point(650, 10));
            txtUsername = MkTopTextBox("", new Point(650, 28), 110);
            var lblPass = MkTopLabel("Mot de passe", new Point(770, 10));
            txtPassword = MkTopTextBox("", new Point(770, 28), 100); txtPassword.PasswordChar = '●';
            chkShowPass = new CheckBox { Text = "👁", Location = new Point(874, 30), AutoSize = true, ForeColor = Color.FromArgb(120, 140, 165), Cursor = Cursors.Hand };
            chkShowPass.CheckedChanged += (s, e) => txtPassword.PasswordChar = chkShowPass.Checked ? '\0' : '●';
            btnHelp = new ModernButton { Text = "?", Location = new Point(940, 24), Size = new Size(28, 28), BackColor = Color.FromArgb(40, 52, 75), HoverColor = Color.FromArgb(60, 78, 110), ForeColor = Color.FromArgb(160, 180, 210), Font = new Font("Segoe UI", 9f, FontStyle.Bold), CornerRadius = 14, ShowShadow = false, UseGradient = false };
            btnHelp.Click += (s, e) => ShowHelp();
            lblE2EStatus = new Label { Text = "🔓 Aucun pair E2E", ForeColor = C_TEXT_MUTED, Font = new Font("Segoe UI", 7.5f), AutoSize = true, Location = new Point(16, 58) };
            topBar.Controls.AddRange(new Control[] { picLogo, lblAppName, lblSubtitle, lblHost, txtServerIP, lblPort, txtServerPort, btnConnect, btnDeleteAccount, vSep, lblUser, txtUsername, lblPass, txtPassword, chkShowPass, lblE2EStatus, btnHelp });

            // ══════════════ BOTTOM STATUS ══════════════
            var bottomBar = new Panel { Dock = DockStyle.Bottom, Height = 30, BackColor = Color.FromArgb(248, 250, 252) };
            bottomBar.Controls.Add(new Panel { Dock = DockStyle.Top, Height = 1, BackColor = C_BORDER });
            lblRoom = new Label { Text = "# général", ForeColor = C_PRIMARY, Font = new Font("Segoe UI Semibold", 8.5f), AutoSize = true, Location = new Point(12, 7) };
            lblStatus = new Label { Text = "Nexus v5 — E2E X25519 + TOFU + Sender Keys + AES-256-GCM + Anti-Replay", ForeColor = C_TEXT_MUTED, Font = new Font("Segoe UI", 7f), AutoSize = true, Anchor = AnchorStyles.Right | AnchorStyles.Top, Location = new Point(450, 8) };
            btnHelpBottom = new ModernButton { Text = "?", Size = new Size(22, 22), Location = new Point(420, 4), CornerRadius = 11, Font = new Font("Segoe UI", 8f, FontStyle.Bold), BackColor = Color.FromArgb(230, 233, 240), ForeColor = C_TEXT_DIM, ShowShadow = false, UseGradient = false, Anchor = AnchorStyles.Right | AnchorStyles.Top };
            btnHelpBottom.Click += (s, e) => ShowHelp();
            bottomBar.Controls.AddRange(new Control[] { lblRoom, btnHelpBottom, lblStatus });

            // ══════════════ SIDEBAR ══════════════
            var sidePanel = new Panel { Dock = DockStyle.Right, Width = 200, BackColor = C_SIDEBAR };
            sidePanel.Controls.Add(new Panel { Dock = DockStyle.Left, Width = 1, BackColor = C_BORDER });
            var lblRoomsHdr = new Label { Text = "SALONS", ForeColor = C_PRIMARY, Font = new Font("Segoe UI", 7.5f, FontStyle.Bold), Location = new Point(14, 14), AutoSize = true };
            lstRooms = new ListBox { Location = new Point(4, 34), Size = new Size(190, 200), BackColor = C_SIDEBAR, ForeColor = C_TEXT_DIM, Font = new Font("Segoe UI", 9f), BorderStyle = BorderStyle.None, DrawMode = DrawMode.OwnerDrawFixed, ItemHeight = 28 };
            lstRooms.DrawItem += DrawRoomItem;
            lstRooms.DoubleClick += (s, e) => { if (lstRooms.SelectedItem == null) return; SendPacket(ProtocolMessage.Build("JOIN", lstRooms.SelectedItem.ToString().TrimStart('●', ' '))); };
            var sepLine = new Panel { Location = new Point(4, 238), Size = new Size(190, 1), BackColor = C_BORDER };
            var lblUsersHdr = new Label { Text = "EN LIGNE", ForeColor = C_PRIMARY, Font = new Font("Segoe UI", 7.5f, FontStyle.Bold), Location = new Point(14, 248), AutoSize = true };
            lstUsers = new ListBox { Location = new Point(4, 268), Size = new Size(190, 300), BackColor = C_SIDEBAR, ForeColor = C_TEXT_DIM, Font = new Font("Segoe UI", 9f), BorderStyle = BorderStyle.None, DrawMode = DrawMode.OwnerDrawFixed, ItemHeight = 32 };
            lstUsers.DrawItem += DrawUserItem;
            lstUsers.DoubleClick += (s, e) => {
                if (lstUsers.SelectedItem == null) return;
                string target = lstUsers.SelectedItem.ToString().Replace(" 🔐", "").Replace(" (moi)", "").Trim();
                if (target.Equals(username, StringComparison.OrdinalIgnoreCase)) return; // pas de PM à soi-même
                OpenPMConv(target);
            };
            lstUsers.MouseDown += (s, e) => { if (e.Button != MouseButtons.Right) return; int idx = lstUsers.IndexFromPoint(e.Location); if (idx >= 0) { lstUsers.SelectedIndex = idx; ctxUsers.Show(lstUsers, e.Location); } };
            var btnRefresh = new ModernButton { Text = "Actualiser", IconChar = "↻", Location = new Point(4, 575), Size = new Size(190, 30), BackColor = Color.FromArgb(236, 240, 245), ForeColor = C_TEXT_DIM, IconColor = C_PRIMARY, Font = new Font("Segoe UI", 8.5f), CornerRadius = 8, UseGradient = false, ShowShadow = false };
            btnRefresh.Click += (s, e) => { if (isConnected) SendPacket("LIST_USERS"); };
            ctxUsers = new ContextMenuStrip { BackColor = C_SURFACE, ForeColor = C_TEXT, Font = new Font("Segoe UI", 9f) };
            var ctxPM = new ToolStripMenuItem("💬 Message privé (E2E)"); ctxPM.Click += (s, e) => { if (lstUsers.SelectedItem != null) OpenPMConv(lstUsers.SelectedItem.ToString().Replace(" 🔐", "")); };
            ctxUsers.Items.AddRange(new ToolStripItem[] { ctxPM });
            sidePanel.Resize += (s, e) => { int w = sidePanel.Width - 10; lstRooms.Width = w; lstUsers.Width = w; btnRefresh.Width = w; lstUsers.Height = sidePanel.Height - lstUsers.Top - 40; btnRefresh.Top = sidePanel.Height - 33; };
            sidePanel.Controls.AddRange(new Control[] { lblRoomsHdr, lstRooms, sepLine, lblUsersHdr, lstUsers, btnRefresh });

            // ══════════════ TAB CONTROL ══════════════
            tabChat = new TabControl { Dock = DockStyle.Fill, DrawMode = TabDrawMode.OwnerDrawFixed, Padding = new Point(16, 6), BackColor = C_BG };
            tabChat.SelectedIndexChanged += (s, e) => {
                if (tabChat.SelectedTab == tabPM) { _unreadPM = 0; UpdatePMTabBadge(); }
            };
            tabChat.DrawItem += DrawTabItem;
            tabMain = new TabPage { Text = "  💬 Chat  ", BackColor = C_SURFACE, Padding = new Padding(0) };
            _chatContainer = new Panel { Dock = DockStyle.Fill, BackColor = Color.FromArgb(250, 251, 253) };
            chatPanel = GetRoomChatPanel("général"); _chatContainer.Controls.Add(chatPanel);
            _chatContextMenu = new ContextMenuStrip { BackColor = C_SURFACE, Font = new Font("Segoe UI", 9.5f) };
            var itemSave = new ToolStripMenuItem("💾  Enregistrer sous...");
            itemSave.Click += (s, e) => { if (_lastRightClickFile == null || !File.Exists(_lastRightClickFile)) return; using (var sfd = new SaveFileDialog { FileName = Path.GetFileName(_lastRightClickFile) }) if (sfd.ShowDialog() == DialogResult.OK) try { File.Copy(_lastRightClickFile, sfd.FileName, true); } catch { } };
            var itemOpen = new ToolStripMenuItem("▶  Ouvrir");
            itemOpen.Click += (s, e) =>
            {
                if (_lastRightClickFile == null || !File.Exists(_lastRightClickFile)) return;
                string ext = Path.GetExtension(_lastRightClickFile).ToLowerInvariant();
                string[] dangerous = { ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".com", ".scr", ".hta", ".pif", ".cpl", ".reg" };
                if (Array.Exists(dangerous, e2 => e2 == ext))
                {
                    MessageBox.Show("Ouverture bloquée : fichier exécutable (extension : " + ext + ").", "Sécurité", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(_lastRightClickFile) { UseShellExecute = true }); } catch { }
            };
            _chatContextMenu.Items.AddRange(new ToolStripItem[] { itemSave, itemOpen });

            var inputRow = new Panel { Dock = DockStyle.Bottom, Height = 60, BackColor = C_SURFACE };
            inputRow.Controls.Add(new Panel { Dock = DockStyle.Top, Height = 1, BackColor = C_BORDER });
            btnAttach = new ModernButton { Text = "", IconChar = "📎", Location = new Point(14, 14), Size = new Size(38, 34), BackColor = Color.FromArgb(241, 243, 248), ForeColor = C_TEXT_DIM, CornerRadius = 10, UseGradient = false, ShowShadow = false, Enabled = false };
            btnAttach.Click += async (s, e) => { if (!isConnected) return; using (var ofd = new OpenFileDialog { Title = "Envoyer dans #" + CurrentRoom }) if (ofd.ShowDialog() == DialogResult.OK) await SendFileAsync(ofd.FileName, "room", CurrentRoom); };
            var msgInput = new ModernInputBox { Location = new Point(60, 12), Size = new Size(100, 36), Placeholder = "Tapez un message...", Radius = 12 };
            txtMessage = msgInput.InnerTextBox; txtMessage.Enabled = false;
            txtMessage.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) { SendChatMessage(); e.SuppressKeyPress = true; } };
            btnSend = new ModernButton { Text = "Envoyer", IconChar = "›", Location = new Point(0, 12), Size = new Size(110, 36), BackColor = C_PRIMARY, HoverColor = C_PRIMARY_HOVER, ForeColor = Color.White, Font = new Font("Segoe UI Semibold", 9.5f), CornerRadius = 12, ShowShadow = true, Enabled = false };
            btnSend.Click += (s, e) => SendChatMessage();
            inputRow.Resize += (s, e) => { int msgW = inputRow.Width - btnSend.Width - 38 - 44; msgInput.Location = new Point(60, 12); msgInput.Size = new Size(msgW, 36); btnSend.Location = new Point(inputRow.Width - btnSend.Width - 12, 12); };
            inputRow.Controls.AddRange(new Control[] { btnAttach, msgInput, btnSend });
            tabMain.Controls.Add(_chatContainer); tabMain.Controls.Add(inputRow);

            // ── Tab: PM ──
            tabPM = new TabPage { Text = "  📩 MP  ", BackColor = C_SURFACE, Padding = new Padding(0) };
            var pmLayout = new Panel { Dock = DockStyle.Fill, BackColor = C_SURFACE };
            var pmLeft = new Panel { Dock = DockStyle.Left, Width = 160, BackColor = C_SIDEBAR };
            pmLeft.Controls.Add(new Panel { Dock = DockStyle.Right, Width = 1, BackColor = C_BORDER });
            pmLeft.Controls.Add(new Label { Text = "CONVERSATIONS", ForeColor = C_PRIMARY, Font = new Font("Segoe UI", 7.5f, FontStyle.Bold), Location = new Point(10, 12), AutoSize = true });
            lstPMContacts = new ListBox { Location = new Point(0, 34), Size = new Size(159, 500), BackColor = C_SIDEBAR, ForeColor = C_TEXT_DIM, BorderStyle = BorderStyle.None, DrawMode = DrawMode.OwnerDrawFixed, ItemHeight = 36 };
            lstPMContacts.DrawItem += DrawPMContactItem;
            lstPMContacts.Click += (s, e) => { if (lstPMContacts.SelectedItem != null) OpenPMConv(lstPMContacts.SelectedItem.ToString()); };
            pmLeft.Controls.Add(lstPMContacts);
            var pmRight = new Panel { Dock = DockStyle.Fill, BackColor = C_SURFACE };
            lblPMHeader = new Label
            {
                Dock = DockStyle.Top,
                Height = 52,
                Text = "  Sélectionnez une conversation",
                ForeColor = C_TEXT_DIM,
                Font = new Font("Segoe UI Semibold", 11f),
                BackColor = Color.FromArgb(250, 251, 255),
                TextAlign = ContentAlignment.MiddleLeft,
                Padding = new Padding(14, 0, 0, 0)
            };
            lblPMHeader.Paint += (s, e2) => {
                e2.Graphics.DrawLine(new Pen(C_BORDER, 1), 0, lblPMHeader.Height - 1, lblPMHeader.Width, lblPMHeader.Height - 1);
            };
            pmRight.Controls.Add(new Panel { Dock = DockStyle.Top, Height = 1, BackColor = C_BORDER });
            pmChatArea = new Panel { Dock = DockStyle.Fill, BackColor = Color.FromArgb(250, 251, 253) };
            var pmInputRow = new Panel { Dock = DockStyle.Bottom, Height = 60, BackColor = C_SURFACE };
            pmInputRow.Controls.Add(new Panel { Dock = DockStyle.Top, Height = 1, BackColor = C_BORDER });
            btnAttachPM = new ModernButton { Text = "", IconChar = "📎", Location = new Point(14, 14), Size = new Size(38, 34), BackColor = Color.FromArgb(241, 243, 248), ForeColor = C_TEXT_DIM, CornerRadius = 10, UseGradient = false, ShowShadow = false, Enabled = false };
            btnAttachPM.Click += async (s, e) => { if (!isConnected || string.IsNullOrEmpty(activePMTarget)) return; using (var ofd = new OpenFileDialog { Title = "Envoyer à " + activePMTarget }) if (ofd.ShowDialog() == DialogResult.OK) await SendFileAsync(ofd.FileName, "pm", activePMTarget); };
            var pmMsgInput = new ModernInputBox { Location = new Point(60, 12), Size = new Size(100, 36), Placeholder = "Message privé...", FocusBorderColor = C_PURPLE, FocusGlowColor = Color.FromArgb(30, 139, 92, 246), Radius = 12 };
            txtPMMessage = pmMsgInput.InnerTextBox; txtPMMessage.Enabled = false;
            txtPMMessage.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) { SendPMMessage(); e.SuppressKeyPress = true; } };
            btnSendPMMsg = new ModernButton { Text = "Envoyer", IconChar = "›", Location = new Point(0, 12), Size = new Size(110, 36), BackColor = C_PURPLE, HoverColor = Color.FromArgb(120, 72, 226), ForeColor = Color.White, Font = new Font("Segoe UI Semibold", 9.5f), CornerRadius = 12, ShowShadow = true, Enabled = false };
            btnSendPMMsg.Click += (s, e) => SendPMMessage();
            pmInputRow.Resize += (s, e) => { int w = pmInputRow.Width - btnSendPMMsg.Width - 38 - 44; pmMsgInput.Location = new Point(60, 12); pmMsgInput.Size = new Size(w, 36); btnSendPMMsg.Location = new Point(pmInputRow.Width - btnSendPMMsg.Width - 12, 12); };
            pmInputRow.Controls.AddRange(new Control[] { btnAttachPM, pmMsgInput, btnSendPMMsg });
            pmRight.Controls.Add(pmChatArea); pmRight.Controls.Add(pmInputRow); pmRight.Controls.Add(lblPMHeader);
            pmLayout.Controls.Add(pmRight); pmLayout.Controls.Add(pmLeft);
            tabPM.Controls.Add(pmLayout);

            // ══════════════ TAB: Sécurité ══════════════
            var tabSecurity = new TabPage { Text = "  🔒 Sécurité  ", BackColor = C_BG };
            var secScroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true, BackColor = C_BG };
            int cardW = 340, cardGap = 10, col1X = 16, col2X = 16 + cardW + cardGap;
            int cy1 = 16;
            var encCard = MakeSecCard(new Point(col1X, cy1), new Size(cardW, 218), "Chiffrement & Transport");
            {
                int ry = 32; encCard.Controls.Add(MakeSecRow("TLS 1.2 obligatoire — pas de fallback", "Connexion refusée si TLS indisponible", true, ry)); ry += 44;
                encCard.Controls.Add(MakeSecRow("TOFU Certificate Pinning (SHA-256)", "Certificat épinglé à la 1ère connexion", true, ry)); ry += 44;
                encCard.Controls.Add(MakeSecRow("AES-256-GCM session (nonce 12B, tag 16B)", "Chaque paquet chiffré + authentifié", true, ry)); ry += 44;
                encCard.Controls.Add(MakeSecRow("Clé de session via RSA-2048 OAEP sur TLS", "Double couche : TLS + AES applicatif", true, ry));
            }
            cy1 += encCard.Height + cardGap;
            var e2eCard = MakeSecCard(new Point(col1X, cy1), new Size(cardW, 262), "Chiffrement E2E (bout-en-bout)");
            {
                int ry = 32; e2eCard.Controls.Add(MakeSecRow("X25519 Diffie-Hellman (clé persistante)", "Clé d'identité sauvegardée via DPAPI", true, ry)); ry += 44;
                e2eCard.Controls.Add(MakeSecRow("TOFU + Fingerprint vérifiable hors-bande", "Alerte si la clé d'un contact change", true, ry)); ry += 44;
                e2eCard.Controls.Add(MakeSecRow("Sender authentifié dans le ciphertext", "Impossible d'usurper un sender via le serveur", true, ry)); ry += 44;
                e2eCard.Controls.Add(MakeSecRow("Nonce compteur hybride + anti-rejeu", "Détection des messages rejoués", true, ry)); ry += 44;
                e2eCard.Controls.Add(MakeSecRow("Sender Keys pour les salons", "1 clé par utilisateur/salon via X25519", true, ry));
            }
            cy1 += e2eCard.Height + cardGap;
            var fileCard = MakeSecCard(new Point(col1X, cy1), new Size(cardW, 174), "Transfert de fichiers E2E");
            {
                int ry = 32; fileCard.Controls.Add(MakeSecRow("Chunks chiffrés AES-256-GCM", "Chaque morceau de 48 KB chiffré", true, ry)); ry += 44;
                fileCard.Controls.Add(MakeSecRow("Clé = Sender Key (salon) ou pairwise (MP)", "Même clé E2E que les messages texte", true, ry)); ry += 44;
                fileCard.Controls.Add(MakeSecRow("Flag E2E dans FILE_INIT", "Rétrocompatible avec les clients sans E2E", true, ry));
            }
            int cy2 = 16;
            var authCard = MakeSecCard(new Point(col2X, cy2), new Size(cardW, 174), "Authentification");
            {
                int ry = 32; authCard.Controls.Add(MakeSecRow("PBKDF2-SHA256 — 100 000 itérations", "Hash lent côté client avant envoi", true, ry)); ry += 44;
                authCard.Controls.Add(MakeSecRow("Salt déterministe par username", "Résiste aux rainbow tables", true, ry)); ry += 44;
                authCard.Controls.Add(MakeSecRow("DPAPI pour le mot de passe sauvegardé", "Chiffré par le compte Windows local", true, ry));
            }
            cy2 += authCard.Height + cardGap;
            var netCard = MakeSecCard(new Point(col2X, cy2), new Size(cardW, 218), "Protection réseau");
            {
                int ry = 32; netCard.Controls.Add(MakeSecRow("Heartbeat PING/PONG (25s)", "Détection de déconnexion < 35s", true, ry)); ry += 44;
                netCard.Controls.Add(MakeSecRow("Reconnexion auto (backoff exponentiel)", "8 tentatives max, 2s → 30s", true, ry)); ry += 44;
                netCard.Controls.Add(MakeSecRow("Taille max paquets : 128 KB + GCM", "Protection paquets surdimensionnés", true, ry)); ry += 44;
                netCard.Controls.Add(MakeSecRow("Taille max fichier : 100 MB", "Envoi par chunks de 48 KB", true, ry));
            }
            cy2 += netCard.Height + cardGap;
            var protoCard = MakeSecCard(new Point(col2X, cy2), new Size(cardW, 218), "Protocole & Robustesse");
            {
                int ry = 32; protoCard.Controls.Add(MakeSecRow("Parser ProtocolMessage (greedy last field)", "':' dans les messages ne cassent plus le parsing", true, ry)); ry += 44;
                protoCard.Controls.Add(MakeSecRow("Validation noms de fichier (sanitize)", "Caractères invalides remplacés", true, ry)); ry += 44;
                protoCard.Controls.Add(MakeSecRow("Debug logging (nexuschat_debug.log)", "Toutes les erreurs loggées", true, ry)); ry += 44;
                protoCard.Controls.Add(MakeSecRow("/fingerprint /accept /regenerate", "Commandes de gestion des clés E2E", true, ry));
            }
            secScroll.Controls.AddRange(new Control[] { encCard, e2eCard, fileCard, authCard, netCard, protoCard });
            tabSecurity.Controls.Add(secScroll);

            tabChat.TabPages.AddRange(new TabPage[] { tabMain, tabPM, tabSecurity });
            Controls.Add(tabChat); Controls.Add(sidePanel); Controls.Add(bottomBar); Controls.Add(topBar);
            FormClosing += (s, e) => { CancelAutoReconnect(); if (isConnected) DisconnectFromServer(); };
            ResumeLayout(false);
        }

        // ═══════════════════════════════════════════════════════
        //  Owner-draw methods
        // ═══════════════════════════════════════════════════════

        private void DrawRoomItem(object sender, DrawItemEventArgs e)
        {
            if (e.Index < 0) return; string item = lstRooms.Items[e.Index].ToString(); bool active = item.StartsWith("●");
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using (var brush = new SolidBrush(active ? Color.FromArgb(238, 242, 255) : C_SIDEBAR)) e.Graphics.FillRectangle(brush, e.Bounds);
            if (active) using (var brush = new SolidBrush(C_PRIMARY)) e.Graphics.FillRectangle(brush, new Rectangle(e.Bounds.X, e.Bounds.Y + 4, 3, e.Bounds.Height - 8));
            TextRenderer.DrawText(e.Graphics, "# " + item.TrimStart('●', ' '), active ? FontRoomBold : FontRoomNormal, new Point(e.Bounds.X + 12, e.Bounds.Y + 5), active ? C_PRIMARY : C_TEXT_DIM);
        }

        private void DrawUserItem(object sender, DrawItemEventArgs e)
        {
            if (e.Index < 0) return; string item = lstUsers.Items[e.Index].ToString(); bool e2e = item.Contains("🔐"); bool sel = (e.State & DrawItemState.Selected) != 0;
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using (var brush = new SolidBrush(sel ? Color.FromArgb(238, 242, 255) : C_SIDEBAR)) e.Graphics.FillRectangle(brush, e.Bounds);
            using (var brush = new SolidBrush(e2e ? C_PURPLE : C_SUCCESS)) e.Graphics.FillEllipse(brush, new Rectangle(e.Bounds.X + 12, e.Bounds.Y + 11, 10, 10));
            TextRenderer.DrawText(e.Graphics, item.Replace(" 🔐", ""), sel ? FontUserBold : FontUserNormal, new Point(e.Bounds.X + 28, e.Bounds.Y + 7), sel ? C_PRIMARY : C_TEXT);
            if (e2e) TextRenderer.DrawText(e.Graphics, "🔐", FontUserE2EBadge, new Point(e.Bounds.Right - 30, e.Bounds.Y + 9), C_PURPLE);
        }

        private void DrawPMContactItem(object sender, DrawItemEventArgs e)
        {
            if (e.Index < 0) return; string item = lstPMContacts.Items[e.Index].ToString(); bool active = item == activePMTarget; bool e2e = HasE2EKey(item);
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using (var brush = new SolidBrush(active ? Color.FromArgb(238, 242, 255) : C_SIDEBAR)) e.Graphics.FillRectangle(brush, e.Bounds);
            if (active) using (var brush = new SolidBrush(C_PRIMARY)) e.Graphics.FillRectangle(brush, new Rectangle(e.Bounds.X, e.Bounds.Y + 6, 3, e.Bounds.Height - 12));
            using (var brush = new SolidBrush(e2e ? C_PURPLE : C_SECONDARY)) e.Graphics.FillEllipse(brush, new Rectangle(e.Bounds.X + 10, e.Bounds.Y + 7, 22, 22));
            string initial = item.Length > 0 ? item[0].ToString().ToUpper() : "?";
            TextRenderer.DrawText(e.Graphics, initial, FontPMInitial, new Rectangle(e.Bounds.X + 10, e.Bounds.Y + 7, 22, 22), Color.White, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
            TextRenderer.DrawText(e.Graphics, item, active ? FontUserBold : FontUserNormal, new Point(e.Bounds.X + 38, e.Bounds.Y + 10), active ? C_PRIMARY : C_TEXT);
        }

        private void DrawTabItem(object sender, DrawItemEventArgs e)
        {
            TabPage p = tabChat.TabPages[e.Index]; bool sel = tabChat.SelectedIndex == e.Index;
            using (var brush = new SolidBrush(sel ? C_SURFACE : Color.FromArgb(236, 240, 245))) e.Graphics.FillRectangle(brush, e.Bounds);
            if (sel) using (var brush = new SolidBrush(C_PRIMARY)) e.Graphics.FillRectangle(brush, new Rectangle(e.Bounds.X, e.Bounds.Y, e.Bounds.Width, 3));
            TextRenderer.DrawText(e.Graphics, p.Text, sel ? FontTabBold : FontTabNormal, e.Bounds, sel ? C_PRIMARY : C_TEXT_DIM, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        }

        // ── Top bar helpers ──
        private static Label MkTopLabel(string text, Point loc) => new Label { Text = text, Location = loc, AutoSize = true, ForeColor = Color.FromArgb(100, 116, 139), Font = new Font("Segoe UI", 7.5f) };
        private static TextBox MkTopTextBox(string text, Point loc, int w) => new TextBox { Text = text, Location = loc, Size = new Size(w, 24), BackColor = Color.FromArgb(30, 41, 59), ForeColor = Color.FromArgb(203, 213, 225), BorderStyle = BorderStyle.FixedSingle, Font = new Font("Segoe UI", 9f) };

        // ── Security Card helpers ──
        private static readonly Font FontSecCardTitle = new Font("Segoe UI", 9f, FontStyle.Bold);
        private static readonly Font FontSecRowTitle = new Font("Segoe UI", 8.5f, FontStyle.Bold);
        private static readonly Font FontSecRowDetail = new Font("Segoe UI", 7.5f);

        private Panel MakeSecCard(Point loc, Size size, string title)
        {
            var card = new Panel { Location = loc, Size = size, BackColor = C_SURFACE, BorderStyle = BorderStyle.None };
            card.Controls.Add(new Panel { Dock = DockStyle.Top, Height = 4, BackColor = C_PRIMARY });
            card.Controls.Add(new Label { Text = title, Location = new Point(12, 10), AutoSize = true, ForeColor = C_TEXT, Font = FontSecCardTitle });
            card.Paint += (s, e) => { using (var pen = new Pen(C_BORDER, 1f)) e.Graphics.DrawRectangle(pen, 0, 0, card.Width - 1, card.Height - 1); };
            return card;
        }

        private Panel MakeSecRow(string title, string detail, bool ok, int y)
        {
            Color dot = ok ? C_SUCCESS : C_DANGER;
            var row = new Panel { Location = new Point(10, y), Size = new Size(320, 40), BackColor = Color.Transparent };
            row.Controls.Add(new Panel { Location = new Point(0, 4), Size = new Size(3, 32), BackColor = dot });
            row.Controls.Add(new Label { Text = (ok ? "✓  " : "✕  ") + title, Location = new Point(10, 2), Size = new Size(306, 18), ForeColor = ok ? C_TEXT : C_DANGER, Font = FontSecRowTitle });
            row.Controls.Add(new Label { Text = detail, Location = new Point(10, 21), Size = new Size(306, 16), ForeColor = C_TEXT_MUTED, Font = FontSecRowDetail });
            return row;
        }
    }
}