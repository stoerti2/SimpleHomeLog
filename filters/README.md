<H1>SimpleHomeLog SIEM – Filter Module System</H1>

This directory (`filters/`) contains pluggable Perl filter modules used by the [SimpleHomeLog SIEM Multi-Server Log Collector]. 
The main script loads every `*.pm` file from this folder at startup and invokes each module's `filter()` subroutine to decide 
whether a log line should be discarded (ignored) or kept for further analysis.

<H2>Purpose</H2>

The filter system provides an extensible way to remove boring, repetitive, or non‑security‑relevant log entries before they are parsed, grouped, and stored in the PostgreSQL database. 
This reduces database noise, improves storage efficiency, and allows you to tailor the SIEM to your specific environment without modifying the core collector.

<H2>How It Works</H2>

1. The main script (`holeSyslogs.pl`) scans the `filters/` directory for files ending with `.pm`.
2. Each module is loaded via `require` and its `filter()` subroutine is registered.
3. During log processing, each incoming line is first checked against static ignore patterns (defined in the main script).  
4. If not already ignored, the line is passed to every loaded filter module in the order they were loaded.
5. If any filter returns a true value (typically `1`), the line is discarded.
6. Only lines that pass all filters proceed to parsing and insertion.

<H2>Module API</H2>

Every filter module must export at least one subroutine:

<b>filter($line)</b>
- Parameter: a single log line as a string (newline stripped).
- Return value: return `1` to ignore the line, or `0` (or any false value) to keep it.
- This subroutine is called for every log line that hasn't already been ignored by static patterns.

<b>init(\%config) (optional)</b>
- Parameter: a reference to a hash containing the module's configuration (parsed from an optional `.conf` file, see below).
- Called once during module loading, before any `filter()` calls.
- Use it to set up internal state, load external resources, or store configuration values.

<H2>Configuration Files</H2>

Each module can have an optional configuration file with the same base name and a `.conf` extension.  
For example, `wordpress_check.pm` can have `wordpress_check.conf`.

- The configuration file is parsed line by line.
- Lines starting with `#` or empty lines are ignored.
- Each line should follow the format:  
  `key = value`   or   `key: value`
- Whitespace around the key/value is trimmed.
- The resulting hash is passed to the module's `init()` routine.

<b>Example `.conf` file</b>
```ini
# WordPress paths to ignore
ignore_paths = /wp-login.php, /xmlrpc.php
threshold    = 10
```

<H2>Creating a New Filter Module</H2>

1. Create a new file `your_filter.pm` inside the `filters/` directory.
2. Define the `filter()` subroutine (mandatory) and optionally `init()`.
3. Use the package name matching the filename (e.g., `package your_filter;` as the first line).
4. Make sure the file returns a true value (end with `1;`).

<b>Minimal Example – `ignore_debug.pm`</b>
```perl
package ignore_debug;

sub filter {
    my ($line) = @_;
    # Ignore any line containing "DEBUG"
    return 1 if $line =~ /DEBUG/i;
    return 0;
}

1;
```

<H2>Advanced Example – `ratelimit_filter.pm` with configuration</H2>
File `ratelimit_filter.pm`:

```perl
package ratelimit_filter;

use strict;
use warnings;
use Time::HiRes qw(time);

my $threshold   = 10;   # default
my $time_window = 5;    # seconds
my @log_entries;

sub init {
    my ($config) = @_;
    $threshold   = $config->{threshold}   // $threshold;
    $time_window = $config->{time_window} // $time_window;
}

sub filter {
    my ($line) = @_;
    my $now = time();
    # Keep only the last N seconds of timestamps
    @log_entries = grep { $_ > $now - $time_window } @log_entries;

    # If we already have enough entries, ignore this line
    if (@log_entries >= $threshold) {
        return 1;
    }
    push @log_entries, $now;
    return 0;
}
1;
```

File `ratelimit_filter.conf`:
```perl
threshold = 20
time_window = 10
```

<H2>Order of Execution</H2>

Filters are loaded in alphabetical order (as returned by `readdir`). If you need a specific ordering, prefix the filenames with numbers, e.g.:
- `01_block_known_bad.pm`
- `02_check_ssh_fails.pm`
- `99_catchall.pm`

<H2>Error Handling</H2>

- If a module fails to compile (`require` fails), an error is printed and the module is skipped.
- If a module lacks a `filter()` subroutine, it is silently ignored.
- Exceptions thrown inside `filter()` are not caught by the main script. To avoid aborting the entire collection run, wrap your filter code in `eval` if necessary. A filter should never die.

<H2>Best Practices</H2>

- Keep filters fast and efficient – they run on every log line.
- Do not perform heavy I/O inside `filter()`; use `init()` to open files or databases.
- Return `0` (explicit false) if the line should be kept; returning `undef` is also acceptable but less clear.
- Document your module with a brief comment at the top explaining what it filters.
- Test your filter by creating a small dummy log file and running the collector with `--dry-run` or manually invoking the filter.

 <H2>Why Use Filters Instead of Changing the Main Script?</H2>

- Separation of concerns: Each filter addresses a specific noise source.
- Reusability: Share filters across different systems or projects.
- Easy updates: Add or remove filters without touching the core collector.
- Team collaboration: Different administrators can contribute filters for their areas.
