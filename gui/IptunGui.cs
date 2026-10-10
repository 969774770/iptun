// iptun 客户端 GUI 设置程序
// 功能：填写服务器地址 / Token / 实例名，一键安装并启动、停止、卸载 Windows 服务；
//       实时显示服务与隧道连接状态。
// 编译：csc.exe /win32manifest:app.manifest /r:System.ServiceProcess.dll ...
using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Text.RegularExpressions;
using System.Timers;
using System.ServiceProcess;
using System.Windows.Forms;

namespace IptunGui
{
    public class MainForm : Form
    {
        const string SvcBase = "IPTunClient_";

        TextBox txtServer, txtToken, txtAdapter;
        Button btnStart, btnStop, btnUninstall;
        Label lblDot, lblState, lblSvc, lblTunnel, lblLanding, lblHeartbeat, lblMsg;
        System.Timers.Timer timer;

        string AppDir { get { return AppDomain.CurrentDomain.BaseDirectory; } }
        string ClientExe { get { return Path.Combine(AppDir, "iptun-client.exe"); } }
        string ConfigPath { get { return Path.Combine(AppDir, "config.json"); } }

        public MainForm()
        {
            Text = "iptun 客户端设置";
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(520, 560);
            Font = new Font("Microsoft YaHei UI", 9F);
            BackColor = Color.FromArgb(245, 247, 250);

            BuildUi();
            LoadConfigToUi();
            RefreshStatus();
            timer = new System.Timers.Timer(2000);
            timer.Elapsed += delegate { BeginInvoke((MethodInvoker)delegate { RefreshStatus(); }); };
            timer.Start();
        }

        void BuildUi()
        {
            var title = new Label
            {
                Text = "iptun 公网IP落地客户端",
                Font = new Font("Microsoft YaHei UI", 14F, FontStyle.Bold),
                ForeColor = Color.FromArgb(30, 64, 175),
                AutoSize = true,
                Location = new Point(20, 16)
            };
            var sub = new Label
            {
                Text = "填写服务器信息并启动，本机服务即可通过服务器公网IP被访问（真实源IP透传）",
                ForeColor = Color.FromArgb(100, 116, 139),
                AutoSize = true,
                Location = new Point(20, 46)
            };
            Controls.Add(title);
            Controls.Add(sub);

            var box = new GroupBox
            {
                Text = "连接设置",
                Location = new Point(20, 76),
                Size = new Size(480, 218)
            };
            Controls.Add(box);

            AddLabel(box, "服务器地址：", 22, 34, 90);
            txtServer = AddInput(box, 118, 30, 330, "例如 1.2.3.4:7000");
            AddHint(box, "格式：服务器IP:端口（隧道端口默认 7000）", 118, 55);

            AddLabel(box, "Token：", 22, 82, 90);
            txtToken = AddInput(box, 118, 78, 330, "");
            AddHint(box, "在服务器 Web 控制台创建客户端后获得", 118, 103);

            AddLabel(box, "实例名称：", 22, 130, 90);
            txtAdapter = AddInput(box, 118, 126, 150, "IPTun");
            AddHint(box, "同一台电脑挂多个客户端时填不同名字，如 IPTUNA / IPTUNB", 118, 151);

            btnStart = new Button
            {
                Text = "保存并启动",
                Location = new Point(20, 308),
                Size = new Size(150, 38),
                BackColor = Color.FromArgb(37, 99, 235),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Bold)
            };
            btnStart.FlatAppearance.BorderSize = 0;
            btnStart.Click += BtnStart_Click;

            btnStop = new Button
            {
                Text = "停止",
                Location = new Point(185, 308),
                Size = new Size(150, 38),
                FlatStyle = FlatStyle.Flat
            };
            btnStop.Click += BtnStop_Click;

            btnUninstall = new Button
            {
                Text = "卸载服务",
                Location = new Point(350, 308),
                Size = new Size(150, 38),
                FlatStyle = FlatStyle.Flat,
                ForeColor = Color.FromArgb(185, 28, 28)
            };
            btnUninstall.Click += BtnUninstall_Click;
            Controls.Add(btnStart);
            Controls.Add(btnStop);
            Controls.Add(btnUninstall);

            var sbox = new GroupBox
            {
                Text = "运行状态",
                Location = new Point(20, 360),
                Size = new Size(480, 150)
            };
            Controls.Add(sbox);

            lblDot = new Label
            {
                Text = "●",
                Font = new Font("Segoe UI", 16F, FontStyle.Bold),
                ForeColor = Color.Gray,
                AutoSize = true,
                Location = new Point(18, 28)
            };
            lblState = new Label
            {
                Text = "未知",
                Font = new Font("Microsoft YaHei UI", 12F, FontStyle.Bold),
                AutoSize = true,
                Location = new Point(46, 30)
            };
            lblSvc = MakeStateLine(sbox, "服务状态：", 70, 64);
            lblTunnel = MakeStateLine(sbox, "隧道状态：", 70, 88);
            lblLanding = MakeStateLine(sbox, "落地地址：", 70, 112);
            lblHeartbeat = MakeStateLine(sbox, "最后心跳：", 270, 112);
            lblMsg = new Label
            {
                Text = "",
                ForeColor = Color.FromArgb(100, 116, 139),
                AutoSize = true,
                Location = new Point(22, 132)
            };
            sbox.Controls.Add(lblDot);
            sbox.Controls.Add(lblState);
            sbox.Controls.Add(lblMsg);

            var foot = new Label
            {
                Text = "服务随系统开机自启，崩溃后 5 秒自动重启",
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = true,
                Location = new Point(22, 522)
            };
            Controls.Add(foot);
        }

        Label MakeStateLine(Control parent, string text, int x, int y)
        {
            var cap = new Label { Text = text, AutoSize = true, Location = new Point(x - 52, y), ForeColor = Color.FromArgb(71, 85, 105) };
            var val = new Label { Text = "-", AutoSize = true, Location = new Point(x + 20, y), ForeColor = Color.FromArgb(15, 23, 42) };
            parent.Controls.Add(cap);
            parent.Controls.Add(val);
            return val;
        }

        void AddLabel(Control p, string text, int x, int y, int w)
        {
            p.Controls.Add(new Label { Text = text, AutoSize = true, Location = new Point(x, y + 3) });
        }

        TextBox AddInput(Control p, int x, int y, int w, string placeholder)
        {
            var t = new TextBox
            {
                Location = new Point(x, y),
                Size = new Size(w, 24),
                Text = placeholder,
                ForeColor = placeholder == "" ? Color.Black : Color.FromArgb(148, 163, 184)
            };
            var ph = placeholder;
            t.GotFocus += delegate
            {
                if (t.ForeColor != Color.Black && t.Text == ph) { t.Text = ""; t.ForeColor = Color.Black; }
            };
            t.LostFocus += delegate
            {
                if (string.IsNullOrEmpty(t.Text)) { t.Text = ph; t.ForeColor = Color.FromArgb(148, 163, 184); }
            };
            p.Controls.Add(t);
            return t;
        }

        void AddHint(Control p, string text, int x, int y)
        {
            p.Controls.Add(new Label { Text = text, ForeColor = Color.FromArgb(148, 163, 184), AutoSize = true, Location = new Point(x, y), Font = new Font("Microsoft YaHei UI", 7.5F) });
        }

        // ---------- 配置读写 ----------

        class UiConfig { public string server, token, adapter; }

        string TextOrEmpty(TextBox t)
        {
            return t.ForeColor == Color.Black ? t.Text.Trim() : "";
        }

        UiConfig Collect()
        {
            return new UiConfig
            {
                server = TextOrEmpty(txtServer),
                token = TextOrEmpty(txtToken),
                adapter = TextOrEmpty(txtAdapter)
            };
        }

        void LoadConfigToUi()
        {
            if (!File.Exists(ConfigPath)) return;
            var json = File.ReadAllText(ConfigPath);
            var c = new UiConfig
            {
                server = JStr(json, "server"),
                token = JStr(json, "token"),
                adapter = JStr(json, "adapter")
            };
            if (!string.IsNullOrEmpty(c.server)) { txtServer.Text = c.server; txtServer.ForeColor = Color.Black; }
            if (!string.IsNullOrEmpty(c.token)) { txtToken.Text = c.token; txtToken.ForeColor = Color.Black; }
            if (!string.IsNullOrEmpty(c.adapter)) { txtAdapter.Text = c.adapter; txtAdapter.ForeColor = Color.Black; }
        }

        static string JStr(string json, string key)
        {
            var m = Regex.Match(json, "\"" + key + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
            if (!m.Success) return "";
            return m.Groups[1].Value.Replace("\\\"", "\"").Replace("\\\\", "\\");
        }

        // ---------- 服务管理 ----------

        string SvcName(string adapter)
        {
            if (string.IsNullOrEmpty(adapter)) adapter = "IPTun";
            return SvcBase + adapter.ToUpperInvariant();
        }

        ServiceController FindService(string name)
        {
            try
            {
                var sc = new ServiceController(name);
                var _ = sc.Status; // 不存在时抛异常
                return sc;
            }
            catch { return null; }
        }

        void BtnStart_Click(object sender, EventArgs e)
        {
            var c = Collect();
            if (string.IsNullOrEmpty(c.server) || !c.server.Contains(":"))
            {
                MessageBox.Show("请填写正确的服务器地址，格式 IP:端口，如 1.2.3.4:7000", "提示");
                return;
            }
            if (string.IsNullOrEmpty(c.token))
            {
                MessageBox.Show("请填写 Token（在服务器 Web 控制台创建客户端后获得）", "提示");
                return;
            }
            if (string.IsNullOrEmpty(c.adapter) || !Regex.IsMatch(c.adapter, @"^[A-Za-z0-9_\-]{1,32}$"))
            {
                MessageBox.Show("实例名称只能包含字母/数字/下划线/短横线（默认 IPTun）", "提示");
                return;
            }
            if (!File.Exists(ClientExe))
            {
                MessageBox.Show("同目录未找到 iptun-client.exe，请将本程序与客户端放在同一文件夹", "错误");
                return;
            }
            try
            {
                File.WriteAllText(ConfigPath,
                    "{\r\n" +
                    "  \"server\": \"" + JEsc(c.server) + "\",\r\n" +
                    "  \"token\": \"" + JEsc(c.token) + "\",\r\n" +
                    "  \"adapter\": \"" + JEsc(c.adapter) + "\"\r\n" +
                    "}\r\n",
                    new System.Text.UTF8Encoding(false));

                var name = SvcName(c.adapter);
                StopIfRunning(name);
                RunSc("delete", name, "", true);
                // binPath 只带 -adapter；服务器/Token/密钥由 config.json 提供
                // 注意：sc.exe 的 binPath 值带启动参数时，整个值必须用外层引号包裹、
                // 内部引号用 \" 转义；否则当安装路径含空格（OneDrive/Program Files/
                // 微信接收文件夹等）时 sc create 会报用法错误。
                string binPath = "\\\"" + ClientExe + "\\\" -adapter " + c.adapter;
                RunSc("create", name,
                    "binPath= \"" + binPath + "\" start= auto DisplayName= \"iptun公网IP落地客户端(" + name + ")\"", false);
                RunSc("description", name, "\"iptun 加密三层隧道客户端（公网IP落地，真实访问者IP透传）\"", false);
                RunSc("failure", name, "reset= 86400 actions= restart/5000/restart/5000/restart/5000", true);
                RunSc("start", name, "", false);
                lblMsg.ForeColor = Color.FromArgb(22, 101, 52);
                lblMsg.Text = "配置已保存，服务启动中…";
            }
            catch (Exception ex)
            {
                MessageBox.Show("启动失败：" + ex.Message, "错误");
            }
        }

        static string JEsc(string s)
        {
            return (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
        }

        void BtnStop_Click(object sender, EventArgs e)
        {
            try
            {
                StopIfRunning(SvcName(TextOrEmpty(txtAdapter)));
                lblMsg.ForeColor = Color.FromArgb(146, 64, 14);
                lblMsg.Text = "服务已停止（配置保留，可再次启动）";
            }
            catch (Exception ex) { MessageBox.Show(ex.Message, "错误"); }
        }

        void BtnUninstall_Click(object sender, EventArgs e)
        {
            if (MessageBox.Show("确定卸载该客户端的 Windows 服务？配置文件保留。", "确认",
                MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return;
            try
            {
                var name = SvcName(TextOrEmpty(txtAdapter));
                StopIfRunning(name);
                RunSc("delete", name, "", true);
                lblMsg.ForeColor = Color.FromArgb(146, 64, 14);
                lblMsg.Text = "服务已卸载";
            }
            catch (Exception ex) { MessageBox.Show(ex.Message, "错误"); }
        }

        void StopIfRunning(string name)
        {
            using (var sc = FindService(name))
            {
                if (sc == null) return;
                sc.Refresh();
                if (sc.Status == ServiceControllerStatus.Running || sc.Status == ServiceControllerStatus.StartPending)
                {
                    try { sc.Stop(); sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(8)); }
                    catch { }
                }
            }
        }

        void RunSc(string verb, string name, string args, bool ignoreError)
        {
            var psi = new ProcessStartInfo("sc.exe", verb + " " + name + " " + args)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using (var p = Process.Start(psi))
            {
                p.WaitForExit(15000);
                string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                if (p.ExitCode != 0 && !ignoreError)
                    throw new Exception("sc " + verb + " 失败：" + output.Trim());
            }
        }

        // ---------- 状态轮询 ----------

        void RefreshStatus()
        {
            var adapter = TextOrEmpty(txtAdapter);
            var name = SvcName(adapter);
            ServiceControllerStatus? svc = null;
            bool installed = false;
            using (var sc = FindService(name))
            {
                if (sc != null) { installed = true; try { sc.Refresh(); svc = sc.Status; } catch { } }
            }
            lblSvc.Text = installed ? (svc == null ? "查询中" : ZhStatus(svc.Value)) : "未安装";

            var st = ReadStatus(adapter);
            if (!installed)
            {
                SetDot(Color.Gray, "未安装");
                lblTunnel.Text = "-";
                lblLanding.Text = "-";
                lblHeartbeat.Text = "-";
                lblMsg.ForeColor = Color.FromArgb(100, 116, 139);
                lblMsg.Text = "填写参数后点击“保存并启动”";
                SetButtons(true, false, false);
                return;
            }

            SetButtons(true, true, true);
            if (svc == ServiceControllerStatus.Running)
            {
                if (st != null && st.state == "connected")
                {
                    SetDot(Color.FromArgb(34, 197, 94), "运行中 · 已连接");
                    lblTunnel.Text = "已连接";
                    lblLanding.Text = string.IsNullOrEmpty(st.landing_ip) ? "-" : st.landing_ip;
                    lblHeartbeat.Text = st.last_seen ?? "-";
                    lblMsg.ForeColor = Color.FromArgb(22, 101, 52);
                    lblMsg.Text = st.message ?? "";
                }
                else if (st != null && st.state == "connecting")
                {
                    SetDot(Color.FromArgb(245, 158, 11), "运行中 · 连接中");
                    lblTunnel.Text = "连接/重连中";
                    lblLanding.Text = "-";
                    lblHeartbeat.Text = st.last_seen ?? "-";
                    lblMsg.ForeColor = Color.FromArgb(146, 64, 14);
                    lblMsg.Text = st.message ?? "正在与服务器握手…";
                }
                else
                {
                    SetDot(Color.FromArgb(245, 158, 11), "运行中");
                    lblTunnel.Text = "启动中";
                    lblLanding.Text = "-";
                    lblHeartbeat.Text = "-";
                }
            }
            else if (svc == ServiceControllerStatus.Stopped)
            {
                SetDot(Color.FromArgb(100, 116, 139), "已停止");
                lblTunnel.Text = "离线";
                lblLanding.Text = st != null ? (st.landing_ip ?? "-") : "-";
                lblHeartbeat.Text = st != null ? (st.last_seen ?? "-") : "-";
                lblMsg.ForeColor = Color.FromArgb(146, 64, 14);
                lblMsg.Text = "服务已停止";
            }
            else
            {
                SetDot(Color.FromArgb(245, 158, 11), ZhStatus(svc ?? ServiceControllerStatus.Stopped) + "…");
                lblTunnel.Text = "-";
                lblLanding.Text = "-";
                lblHeartbeat.Text = "-";
            }
        }

        void SetButtons(bool start, bool stop, bool uninstall)
        {
            btnStart.Enabled = start;
            btnStop.Enabled = stop;
            btnUninstall.Enabled = uninstall;
        }

        void SetDot(Color c, string text)
        {
            lblDot.ForeColor = c;
            lblState.Text = text;
        }

        static string ZhStatus(ServiceControllerStatus s)
        {
            switch (s)
            {
                case ServiceControllerStatus.Running: return "运行中";
                case ServiceControllerStatus.Stopped: return "已停止";
                case ServiceControllerStatus.StartPending: return "启动中";
                case ServiceControllerStatus.StopPending: return "停止中";
                default: return s.ToString();
            }
        }

        class RunStatus { public string state, landing_ip, last_seen, message, server; }

        RunStatus ReadStatus(string adapter)
        {
            try
            {
                string dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "iptun");
                string name = "status-" + (string.IsNullOrEmpty(adapter) ? "IPTun" : adapter) + ".json";
                string path = Path.Combine(dir, name);
                if (!File.Exists(path)) return null;
                var json = File.ReadAllText(path);
                return new RunStatus
                {
                    state = JStr(json, "state"),
                    landing_ip = JStr(json, "landing_ip"),
                    last_seen = JStr(json, "last_seen"),
                    message = JStr(json, "message"),
                    server = JStr(json, "server")
                };
            }
            catch { return null; }
        }
    }

    static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}
