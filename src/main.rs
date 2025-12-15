use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use aho_corasick::AhoCorasick;
const RESET: &str = "\u{001b}[0m";
const YELLOW: &str = "\u{001b}[33m";
const GREEN: &str = "\u{001b}[32m";
const RED: &str = "\u{001b}[91m";

const ASCII_ART_RAW: &str = r#"
   ___                ______          __  
  / _ \__ ____ _  ___/_  __/__  ___  / /__
 / // / // /  ' \/ _ \/ / / _ \/ _ \/ (_-<
/____/\_,_/_/_/_/ .__/_/  \___/\___/_/___/
               /_/                         
"#;

const BANNER_SUBTITLE: &str = "DumpScan - Scan text dumps for strings with live status output";
const BANNER_CREDIT: &str = "made by 0bscura with <3";

static COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct ConvertOptions {
    path: PathBuf,
    output: Option<PathBuf>,
    delimiter: String,
    site_from: Option<String>,
}

#[derive(Debug)]
struct ScanOptions {
    needles: Vec<String>,
    path: PathBuf,
    ignore_case: bool,
    output: Option<PathBuf>,
    threads: usize,
}

#[derive(Debug)]
struct PasswordEntry {
    value: String,
    service: String,
    source: String,
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || is_help(&args[0]) {
        print_help();
        return;
    }

    match args[0].as_str() {
        "convert" => {
            let opts = match parse_convert_options(&args[1..]) {
                Ok(o) => o,
                Err(e) => exit_with_error(&e),
            };
            if let Err(e) = run_convert(opts) {
                exit_with_error(&e.to_string());
            }
        }
        "scan" => {
            let opts = match parse_scan_options(&args[1..]) {
                Ok(o) => o,
                Err(e) => exit_with_error(&e),
            };
            if let Err(e) = run_scan(opts) {
                exit_with_error(&e.to_string());
            }
        }
        other => {
            eprintln!("Unknown command: {other}\n");
            print_help();
            process::exit(1);
        }
    }
}

fn is_help(flag: &str) -> bool {
    flag == "-h" || flag == "--help" || flag == "help"
}

fn print_help() {
    println!(
        "{banner}\n\nUsage:\n  dumptools <command> [options]\n\nCommands:\n  convert    Convert text dumps into grouped JSONL\n  scan       Search dumps for strings/emails with live status\n\nRun `dumptools <command> --help` for command-specific options.",
        banner = banner_block()
    );
}

fn parse_convert_options(args: &[String]) -> Result<ConvertOptions, String> {
    if args.iter().any(|a| is_help(a)) {
        print_convert_help();
        process::exit(0);
    }

    let mut path = PathBuf::from(".");
    let mut output = None;
    let mut delimiter = ":".to_string();
    let mut site_from = None;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--path" | "-p" => {
                let val = iter
                    .next()
                    .ok_or_else(|| "Missing value after --path".to_string())?;
                path = PathBuf::from(val);
            }
            "--output" | "-o" => {
                let val = iter
                    .next()
                    .ok_or_else(|| "Missing value after --output".to_string())?;
                output = Some(PathBuf::from(val));
            }
            "--delimiter" | "-d" => {
                let val = iter
                    .next()
                    .ok_or_else(|| "Missing value after --delimiter".to_string())?;
                delimiter = val.clone();
            }
            "--site-from" => {
                let val = iter
                    .next()
                    .ok_or_else(|| "Missing value after --site-from".to_string())?;
                site_from = Some(val.clone());
            }
            unknown if unknown.starts_with('-') => {
                return Err(format!("Unknown flag: {unknown}"))
            }
            unexpected => return Err(format!("Unexpected argument: {unexpected}")),
        }
    }

    Ok(ConvertOptions {
        path,
        output,
        delimiter,
        site_from,
    })
}

fn parse_scan_options(args: &[String]) -> Result<ScanOptions, String> {
    if args.iter().any(|a| is_help(a)) {
        print_scan_help();
        process::exit(0);
    }

    let mut needle: Option<String> = None;
    let mut needle_is_file = false;
    let mut path = PathBuf::from(".");
    let mut ignore_case = true; // default to case-insensitive
    let mut output = None;
    let mut threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--path" | "-p" => {
                let val = iter
                    .next()
                    .ok_or_else(|| "Missing value after --path".to_string())?;
                path = PathBuf::from(val);
            }
            "--file" | "-f" => {
                needle_is_file = true;
            }
            "--ignore-case" | "-i" => {
                ignore_case = true;
            }
            "--output" | "-o" => {
                let val = iter
                    .next()
                    .ok_or_else(|| "Missing value after --output".to_string())?;
                output = Some(PathBuf::from(val));
            }
            "--case-sensitive" | "-s" => {
                ignore_case = false;
            }
            "--threads" | "-t" => {
                let val = iter
                    .next()
                    .ok_or_else(|| "Missing value after --threads".to_string())?;
                threads = val
                    .parse::<usize>()
                    .map_err(|_| "Invalid number for --threads".to_string())?;
                if threads == 0 {
                    return Err("--threads must be at least 1".to_string());
                }
            }
            unknown if unknown.starts_with('-') => return Err(format!("Unknown flag: {unknown}")),
            positional => {
                if needle.is_some() {
                    return Err("Only one needle argument is allowed".to_string());
                }
                needle = Some(positional.to_string());
            }
        }
    }

    let needle = needle.ok_or_else(|| "Missing needle argument".to_string())?;

    let needles = if needle_is_file {
        load_needles_from_file(&needle, ignore_case)?
    } else if ignore_case {
        vec![needle.to_lowercase()]
    } else {
        vec![needle]
    };

    if output.is_none() {
        return Err("Output file is required for scan (-o/--output)".to_string());
    }

    Ok(ScanOptions {
        needles,
        path,
        ignore_case,
        output,
        threads,
    })
}

fn run_convert(opts: ConvertOptions) -> io::Result<()> {
    let files = collect_text_files(&opts.path)?;
    if files.is_empty() {
        println!("No .txt files found under {}", opts.path.display());
        return Ok(());
    }

    let mut grouped: HashMap<String, Vec<PasswordEntry>> = HashMap::new();

    for file in &files {
        let reader = BufReader::new(File::open(file)?);
        for line in reader.lines() {
            let raw = line?;
            if let Some((email, password, service)) =
                parse_credential_line(&raw, &opts.delimiter, opts.site_from.as_deref())
            {
                let entry = PasswordEntry {
                    value: password,
                    service,
                    source: file.display().to_string(),
                };
                grouped.entry(email).or_default().push(entry);
            }
        }
    }

    let mut writer: Box<dyn Write> = match &opts.output {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(io::stdout()),
    };

    for (email, entries) in grouped {
        write_document(&mut writer, &email, &entries)?;
    }

    Ok(())
}

fn run_scan(opts: ScanOptions) -> io::Result<()> {
    print_banner();

    println!("Needles: {:?}", opts.needles);
    println!("Path: {}", opts.path.display());
    println!("Case-insensitive: {}", opts.ignore_case);
    println!(
        "Output file: {}",
        opts.output
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "None".to_string())
    );
    println!("Threads: {}\n", opts.threads);

    let files = collect_text_files(&opts.path)?;
    let total = files.len();

    println!(
        "Loaded {total} files",
    );
    let dir_counts = directory_counts(&files, &opts.path);
    let max_count_width = dir_counts
        .iter()
        .map(|(_, c)| c.to_string().len())
        .max()
        .unwrap_or(1);
    for (dir, count) in dir_counts {
        let dir_display = if dir == PathBuf::from(".") {
            base_label(&opts.path)
        } else {
            format!("{}/{}", base_label(&opts.path), dir.display())
        };
        println!(
            "  {} Loaded {:>width$} files in  {}",
            colour("→", GREEN),
            count,
            dir_display,
            width = max_count_width
        );
    }
    println!();
    println!();

    let output_path = opts.output.expect("checked above");
    let output_file = Arc::new(Mutex::new(BufWriter::new(File::create(output_path)?)));
    let (email_needles, other_needles): (Vec<String>, Vec<String>) = opts
        .needles
        .into_iter()
        .partition(|n| n.contains('@'));

    let _total_needles = email_needles.len() + other_needles.len();

    let other_patterns = Arc::new(other_needles);
    let ac = if other_patterns.is_empty() {
        None
    } else {
        Some(
            AhoCorasick::builder()
                .ascii_case_insensitive(opts.ignore_case)
                .build(other_patterns.as_slice())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("AC build failed: {e}")))?,
        )
    };

    let email_set: HashSet<String> = email_needles.into_iter().collect();
    let ac = Arc::new(ac);
    let email_set = Arc::new(email_set);
    let total_files = files.len();
    let stdout = Arc::new(Mutex::new(io::stdout()));
    let total_hits = Arc::new(AtomicUsize::new(0));
    let threads = opts.threads.max(1);
    let active_threads = threads.min(total_files.max(1));
    let mut initial_statuses = Vec::with_capacity(active_threads);
    for tid in 0..active_threads {
        initial_statuses.push(format!("[Thread {}] waiting...", tid + 1));
    }
    let statuses = Arc::new(Mutex::new(initial_statuses));
    let base_label = base_label(&opts.path);
    let root_path = Arc::new(opts.path.clone());

    // Reserve lines for thread status slots, then render them
    for _ in 0..active_threads {
        println!();
    }
    render_status(&statuses, &stdout)?;

    let mut handles = Vec::new();
    let chunk_size = (total_files + active_threads - 1) / active_threads;

    for thread_id in 0..active_threads {
        let start = thread_id * chunk_size;
        if start >= total_files {
            break;
        }
        let end = ((thread_id + 1) * chunk_size).min(total_files);
        let chunk_slice = &files[start..end];
        let chunk_vec: Vec<(usize, PathBuf)> = chunk_slice
            .iter()
            .enumerate()
            .map(|(i, p)| (i, p.clone()))
            .collect();
        let chunk_len = chunk_vec.len();

        let ac = ac.clone();
        let other_patterns = other_patterns.clone();
        let email_set = email_set.clone();
        let output_file = output_file.clone();
        let stdout = stdout.clone();
        let statuses = statuses.clone();
        let total_hits = total_hits.clone();
        let ignore_case = opts.ignore_case;
        let base_label = base_label.clone();
        let root_path = root_path.clone();

        let handle = std::thread::spawn(move || -> io::Result<()> {
            for (local_idx, file) in chunk_vec {
                let matches =
                    scan_file_multi(&file, ignore_case, &ac, &other_patterns, &email_set, &output_file)?;

                total_hits.fetch_add(matches, Ordering::SeqCst);

                let mut line = format!(
                    "[Thread {}] Checking file {}/{}: {}...",
                    thread_id + 1,
                    local_idx + 1,
                    chunk_len,
                    display_path(&base_label, &root_path, &file)
                );
                if matches > 0 {
                    line.push_str(&format!(" Found {} matches.", matches));
                }

                {
                    let mut status_guard = statuses.lock().unwrap();
                    if let Some(slot) = status_guard.get_mut(thread_id) {
                        *slot = line;
                    }
                }
                render_status(&statuses, &stdout)?;
            }
            Ok(())
        });
        handles.push(handle);
    }

    for handle in handles {
        if let Err(e) = handle
            .join()
            .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::Other, "Thread panicked")))
        {
            return Err(e);
        }
    }

    let hits = total_hits.load(Ordering::SeqCst);
    println!("\n[{}] {} Scan Complete!", timestamp(), colour("[*]", YELLOW));
    println!(
        "[{}] {} Total hits: {}\n",
        timestamp(),
        colour("[+]", GREEN),
        hits
    );

    Ok(())
}

fn render_status(
    statuses: &Arc<Mutex<Vec<String>>>,
    stdout: &Arc<Mutex<io::Stdout>>,
) -> io::Result<()> {
    let statuses_guard = statuses.lock().unwrap();
    let mut out = stdout.lock().unwrap();
    write!(out, "\x1b[{}A", statuses_guard.len())?;
    for line in statuses_guard.iter() {
        writeln!(out, "\r\x1b[K{}", line)?;
    }
    out.flush()
}

fn parse_credential_line(
    line: &str,
    delimiter: &str,
    site_from: Option<&str>,
) -> Option<(String, String, String)> {
    if line.trim().is_empty() {
        return None;
    }

    let parts: Vec<&str> = line.splitn(3, delimiter).collect();
    if parts.len() < 2 {
        return None;
    }

    let email = parts[0].trim();
    let password = parts[1].trim();
    if email.is_empty() || password.is_empty() {
        return None;
    }

    let service = parts
        .get(2)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| site_from.map(|s| s.to_string()))
        .unwrap_or_default();

    Some((email.to_string(), password.to_string(), service))
}

fn write_document<W: Write>(
    writer: &mut W,
    email: &str,
    entries: &[PasswordEntry],
) -> io::Result<()> {
    write!(
        writer,
        "{{\"_id\":\"{}\",\"email\":\"{}\",\"passwords\":[",
        generate_id(),
        json_escape(email)
    )?;

    for (idx, entry) in entries.iter().enumerate() {
        if idx > 0 {
            write!(writer, ",")?;
        }
        write!(
            writer,
            "{{\"value\":\"{}\",\"for\":\"{}\",\"source\":\"{}\"}}",
            json_escape(&entry.value),
            json_escape(&entry.service),
            json_escape(&entry.source),
        )?;
    }

    writeln!(writer, "]}}")?;
    Ok(())
}

fn collect_text_files(path: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_recursive(path, &mut files)?;
    Ok(files)
}

fn collect_recursive(path: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    if path.is_file() {
        if path.extension().and_then(|ext| ext.to_str()).map(|e| e.eq_ignore_ascii_case("txt")).unwrap_or(false) {
            files.push(path.to_path_buf());
        }
        return Ok(());
    }

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            collect_recursive(&p, files)?;
        } else if p.extension().and_then(|ext| ext.to_str()).map(|e| e.eq_ignore_ascii_case("txt")).unwrap_or(false) {
            files.push(p);
        }
    }
    Ok(())
}

fn scan_file_multi(
    path: &Path,
    ignore_case: bool,
    ac: &Arc<Option<AhoCorasick>>,
    other_patterns: &Arc<Vec<String>>,
    email_set: &Arc<HashSet<String>>,
    output_file: &Arc<Mutex<BufWriter<File>>>,
) -> io::Result<usize> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut found = 0;
    let mut hits: Vec<String> = Vec::new();

    for (line_no, line) in reader.lines().enumerate() {
        let line = line?;
        let hay = &line;

        // AC for non-email needles
        if let Some(ac_ref) = ac.as_ref() {
            for mat in ac_ref.find_iter(hay) {
                let needle = other_patterns
                    .get(mat.pattern().as_usize())
                    .map(|s: &String| s.as_str())
                    .unwrap_or("");
                hits.push(format_hit(path, line_no + 1, needle));
                found += 1;
            }
        }

        // Exact-token email matches
        if !email_set.is_empty() {
            for token in email_like_tokens(hay, ignore_case) {
                if email_set.contains(&token) {
                    hits.push(format_hit(path, line_no + 1, &token));
                    found += 1;
                }
            }
        }
    }

    if !hits.is_empty() {
        let mut out_guard = output_file.lock().unwrap();
        for h in hits {
            writeln!(&mut *out_guard, "{}", h)?;
        }
    }

    Ok(found)
}

fn format_hit(path: &Path, line_no: usize, needle: &str) -> String {
    format!(
        "{{\"line\":{},\"file\":\"{}\",\"needle\":\"{}\",\"timestamp\":\"{}\"}}",
        line_no,
        json_escape(&path.display().to_string()),
        json_escape(needle),
        timestamp()
    )
}

fn email_like_tokens(line: &str, to_lower: bool) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();

    for ch in line.chars() {
        if is_email_char(ch) {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(normalize_token(&current, to_lower));
            current.clear();
        }
    }

    if !current.is_empty() {
        tokens.push(normalize_token(&current, to_lower));
    }

    tokens
}

fn normalize_token(token: &str, to_lower: bool) -> String {
    if to_lower {
        token.to_lowercase()
    } else {
        token.to_string()
    }
}

fn is_email_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '%' | '+' | '-' | '@')
}

fn load_needles_from_file(path: &str, ignore_case: bool) -> Result<Vec<String>, String> {
    let file = File::open(path).map_err(|e| format!("Failed to open needle file {path}: {e}"))?;
    let reader = BufReader::new(file);
    let mut needles = Vec::new();
    let mut seen = HashSet::new();

    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read needle file: {e}"))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let normalized = if ignore_case {
            trimmed.to_lowercase()
        } else {
            trimmed.to_string()
        };
        if seen.insert(normalized.clone()) {
            needles.push(normalized);
        }
    }
    if needles.is_empty() {
        return Err("Needle file is empty".to_string());
    }
    Ok(needles)
}

fn print_convert_help() {
    println!(
        "{banner}\n\nUsage:\n  dumptools convert [options]\n\nOptions:\n  -p, --path <dir>       Directory to scan recursively for *.txt (default: .)\n  -o, --output <file>    Write JSONL to file (default: stdout)\n  -d, --delimiter <str>  Field delimiter between email/password (default: :) \n      --site-from <val>  Constant value for the `for` field when none is present per line\n",
        banner = banner_block()
    );
}

fn print_scan_help() {
    println!(
        "{banner}\n\nUsage:\n  dumptools scan <needle> [options]\n\nOptions:\n  -p, --path <dir>     Directory to scan recursively for *.txt (default: .)\n  -f, --file           Treat needle as file containing needles (one per line)\n  -s, --case-sensitive Case-sensitive search (default: insensitive)\n  -t, --threads <n>    Number of worker threads (default: detected cores)\n  -o, --output <file>  Write matches to a file\n",
        banner = banner_block()
    );
}

fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let (year, month, day) = days_to_date(secs.div_euclid(86_400));
    let seconds_in_day = secs.rem_euclid(86_400);
    let hour = (seconds_in_day / 3_600) as u32;
    let minute = ((seconds_in_day % 3_600) / 60) as u32;
    let second = (seconds_in_day % 60) as u32;

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hour, minute, second
    )
}

fn days_to_date(days_since_epoch: i64) -> (i32, u32, u32) {
    // From Howard Hinnant's date algorithms (UTC).
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + 3 - 12 * (mp / 10);
    let year = era * 400 + yoe + (mp / 10);
    (year as i32, month as u32, day as u32)
}

fn colour(text: &str, code: &str) -> String {
    if io::stdout().is_terminal() {
        format!("{code}{text}{RESET}")
    } else {
        text.to_string()
    }
}

fn print_banner() {
    println!("{}\n", banner_block());
}

fn banner_block() -> String {
    if io::stdout().is_terminal() {
        format!(
            "{RED}{art}{RESET}\n{YELLOW}{subtitle}{RESET}\n{RED}{credit}{RESET}",
            art = ASCII_ART_RAW,
            subtitle = BANNER_SUBTITLE,
            credit = BANNER_CREDIT
        )
    } else {
        format!(
            "{art}\n{subtitle}\n{credit}",
            art = ASCII_ART_RAW,
            subtitle = BANNER_SUBTITLE,
            credit = BANNER_CREDIT
        )
    }
}

fn base_label(path: &Path) -> String {
    if path == Path::new(".") {
        return "./".to_string();
    }
    path.file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| path.display().to_string())
}

fn display_path(base_label: &str, root: &Path, file: &Path) -> String {
    if let Ok(rel) = file.strip_prefix(root) {
        if let Some(rel_str) = rel.to_str() {
            return format!("{}/{}", base_label, rel_str);
        }
    }
    let fallback = file
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| file.display().to_string());
    format!("{}/{}", base_label, fallback)
}

fn directory_counts(files: &[PathBuf], root: &Path) -> Vec<(PathBuf, usize)> {
    let mut counts: HashMap<PathBuf, usize> = HashMap::new();
    for file in files {
        let dir = file
            .parent()
            .and_then(|p| p.strip_prefix(root).ok().map(|rel| rel.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));
        *counts.entry(dir).or_insert(0) += 1;
    }
    let mut items: Vec<(PathBuf, usize)> = counts.into_iter().collect();
    items.sort_by(|a, b| a.0.cmp(&b.0));
    items
}

fn json_escape(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0C}' => escaped.push_str("\\f"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c < '\u{20}' => escaped.push_str(&format!("\\u{:04x}", c as u32)),
            c => escaped.push(c),
        }
    }
    escaped
}

fn generate_id() -> String {
    if let Some(bytes) = random_bytes() {
        return format_uuid_like(&bytes);
    }

    // Fallback: timestamp + counter
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:x}-{count:x}")
}

fn random_bytes() -> Option<[u8; 16]> {
    let mut buf = [0u8; 16];
    if let Ok(mut f) = File::open("/dev/urandom") {
        use std::io::Read;
        if f.read_exact(&mut buf).is_ok() {
            return Some(buf);
        }
    }
    None
}

fn format_uuid_like(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn exit_with_error(msg: &str) -> ! {
    eprintln!("Error: {msg}");
    process::exit(1);
}
