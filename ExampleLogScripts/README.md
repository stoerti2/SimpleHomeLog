<h1>📁 SimpleHomeLog Filesystem Monitor Scripts</h1>

<p>This repository contains a collection of bash scripts that generate <strong>syslog output</strong> for monitoring filesystem usage on Linux systems. These scripts are designed to work with the <strong>SimpleHomeLog SIEM</strong> environment and are compatible with the <code>holeSyslogs.pl</code> Perl parser.</p>

<hr>

<h2>📋 Table of Contents</h2>
<ul>
    <li><a href="#overview">Overview</a></li>
    <li><a href="#scripts">Available Scripts</a></li>
    <li><a href="#requirements">Requirements</a></li>
    <li><a href="#installation">Installation</a></li>
    <li><a href="#configuration">Configuration</a></li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#cron-setup">Cron Setup (Automation)</a></li>
    <li><a href="#log-format">Syslog Output Format</a></li>
    <li><a href="#testing">Testing & Verification</a></li>
    <li><a href="#license">License</a></li>
</ul>

<hr>

<h2 id="overview">📖 Overview</h2>

<p>These bash scripts monitor local filesystems and send usage information to the system syslog. The scripts are specifically adapted to include the <strong>process ID (PID)</strong> in the syslog tag (e.g., <code>fs_monitor[12345]</code>), which allows the <code>holeSyslogs.pl</code> Perl parser to correctly parse and process the log messages.</p>

<p><strong>Key features:</strong></p>
<ul>
    <li>Monitors disk usage on all mounted local filesystems</li>
    <li>Ignores virtual/pseudo filesystems (tmpfs, devtmpfs, squashfs, etc.)</li>
    <li>Generates severity-based syslog messages (INFO, LOW, MEDIUM, HIGH, CRITICAL)</li>
    <li>Uses proper syslog facilities (<code>user.notice</code>, <code>user.warning</code>, <code>user.err</code>, <code>user.crit</code>, <code>user.emerg</code>)</li>
    <li>PID-aware tagging for compatibility with Perl-based log parsers</li>
    <li>MIT Licensed - free to use and modify</li>
</ul>

<hr>

<h2 id="scripts">📜 Available Scripts</h2>

<h3>fs_check.sh</h3>
<p>The main filesystem monitoring script. It checks all locally mounted filesystems and logs their usage percentages with appropriate severity levels.</p>

<p><strong>Severity thresholds:</strong></p>
<table border="1" cellpadding="8" cellspacing="0">
    <tr bgcolor="#f0f0f0">
        <th>Usage</th>
        <th>Severity</th>
        <th>Syslog Facility</th>
    </tr>
    <tr><td>95% - 100%</td><td>CRITICAL</td><td><code>user.crit</code> + <code>user.emerg</code></td></tr>
    <tr><td>90% - 94%</td><td>HIGH</td><td><code>user.err</code></td></tr>
    <tr><td>85% - 89%</td><td>MEDIUM</td><td><code>user.warning</code></td></tr>
    <tr><td>75% - 84%</td><td>LOW</td><td><code>user.notice</code></td></tr>
    <tr><td>&lt; 75%</td><td>INFO</td><td><code>user.info</code></td></tr>
</table>

<hr>

<h2 id="requirements">⚙️ Requirements</h2>

<ul>
    <li><strong>Operating System:</strong> Linux (tested on Ubuntu, Debian, CentOS, RHEL)</li>
    <li><strong>Shell:</strong> Bash 4.0 or higher</li>
    <li><strong>Utilities:</strong> <code>df</code>, <code>grep</code>, <code>awk</code>, <code>sed</code>, <code>logger</code> (standard on all Linux distributions)</li>
    <li><strong>Syslog:</strong> rsyslog, syslog-ng, or any syslog implementation</li>
    <li><strong>Perl (optional):</strong> Only if using the <code>holeSyslogs.pl</code> parser</li>
</ul>

<hr>

<h2 id="installation">📥 Installation</h2>

<ol>
    <li><strong>Clone the repository:</strong>
        <pre><code>git clone https://github.com/stoerti2/simplehomelog.git
cd simplehomelog-fsmonitor</code></pre>
    </li>
    <li><strong>Make scripts executable:</strong>
        <pre><code>chmod +x fs_check.sh</code></pre>
    </li>
    <li><strong>(Optional) Move to system directory:</strong>
        <pre><code>sudo cp fs_check.sh /usr/local/bin/</code></pre>
    </li>
</ol>

<hr>

<h2 id="configuration">🔧 Configuration</h2>

<p>Edit the script to adjust the following variables (at the top of the file):</p>

<pre><code>WARNING_LOW=75      # Threshold for LOW severity
WARNING_MEDIUM=85   # Threshold for MEDIUM severity  
WARNING_HIGH=90     # Threshold for HIGH severity
WARNING_CRITICAL=95 # Threshold for CRITICAL severity

IGNORE_FS="tmpfs|devtmpfs|squashfs|overlay|fuse|udev|proc|sysfs|cgroup"
TAG="fs_monitor"    # Syslog tag (PID is automatically appended)
</code></pre>

<p><strong>Note:</strong> The script automatically adds the PID in the format <code>fs_monitor[PID]</code> – <strong>do not change this format</strong> if you are using the Perl parser.</p>

<hr>

<h2 id="usage">🚀 Usage</h2>

<h3>Manual execution:</h3>
<pre><code>./fs_check.sh</code></pre>

<p>Or with full path:</p>
<pre><code>/usr/local/bin/fs_check.sh</code></pre>

<h3>What happens:</h3>
<ul>
    <li>The script runs <code>df -hP</code> to get filesystem usage</li>
    <li>It ignores virtual filesystems defined in <code>IGNORE_FS</code></li>
    <li>For each real filesystem, it calculates the usage percentage</li>
    <li>Based on the percentage, it assigns a severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)</li>
    <li>It sends the log message to syslog with the appropriate facility</li>
    <li>For CRITICAL (≥95%), it also sends an emergency-level message</li>
</ul>

<hr>

<h2 id="cron-setup">⏰ Cron Setup (Automation)</h2>

<p>To run the script automatically every 15 minutes, add the following line to your crontab:</p>

<pre><code>*/15 * * * * /usr/local/bin/fs_check.sh</code></pre>

<p><strong>Edit crontab:</strong></p>
<pre><code>crontab -e</code></pre>

<p><strong>Other common intervals:</strong></p>
<ul>
    <li>Every 5 minutes: <code>*/5 * * * *</code></li>
    <li>Every hour: <code>0 * * * *</code></li>
    <li>Daily at midnight: <code>0 0 * * *</code></li>
</ul>

<hr>

<h2 id="log-format">📝 Syslog Output Format</h2>

<p>The script produces syslog messages in the following format:</p>

<pre><code>&lt;priority&gt; timestamp hostname fs_monitor[PID]: SimpleHomeLog: SEVERITY: message</code></pre>

<p><strong>Example outputs:</strong></p>

<pre><code>Apr 23 10:15:01 myserver fs_monitor[12345]: SimpleHomeLog: INFO: Filesystem check started
Apr 23 10:15:01 myserver fs_monitor[12345]: SimpleHomeLog: LOW: /var - 78% (15G of 20G), free: 5G
Apr 23 10:15:01 myserver fs_monitor[12345]: SimpleHomeLog: MEDIUM: /home - 87% (87G of 100G), free: 13G
Apr 23 10:15:01 myserver fs_monitor[12345]: SimpleHomeLog: HIGH: / - 92% (92G of 100G), free: 8G
Apr 23 10:15:01 myserver fs_monitor[12345]: SimpleHomeLog: CRITICAL: /data - 97% (97G of 100G), free: 3G
Apr 23 10:15:02 myserver fs_monitor[12345]: SimpleHomeLog: INFO: Filesystem check completed
Apr 23 10:15:02 myserver fs_monitor[12345]: SimpleHomeLog: CRITICAL: /data is 97% full!  (emergency level)
</code></pre>

<hr>

<h2 id="testing">🧪 Testing & Verification</h2>

<h3>Check syslog output:</h3>
<pre><code>tail -n 20 /var/log/syslog | grep fs_monitor</code></pre>

<p>Or for rsyslog:</p>
<pre><code>tail -n 20 /var/log/messages | grep fs_monitor</code></pre>

<h3>Run with debug (view logs in real-time):</h3>
<pre><code>./fs_check.sh && tail -f /var/log/syslog | grep fs_monitor</code></pre>

<h3>Verify PID format (important for Perl parser):</h3>
<pre><code>./fs_check.sh
grep "fs_monitor\[" /var/log/syslog | tail -n 5</code></pre>

<p>You should see output like: <code>fs_monitor[12345]</code> (with numbers inside brackets).</p>

<hr>

<h2 id="license">📄 License</h2>

<p>All scripts in this repository are released under the <strong>MIT License</strong>.</p>

<pre><code>MIT License

Copyright (c) 2026 Klaus Baumdick

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
</code></pre>

<hr>

<h2>🙏 Support</h2>

<p>For issues, questions, or contributions, please open an issue on GitHub.</p>

<hr>

<p><strong>Happy Monitoring! 🚀</strong></p>

</body>
</html>
