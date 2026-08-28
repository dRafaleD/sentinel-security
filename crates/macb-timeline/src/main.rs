use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use macb_timeline::{
    annotate_records, build_timeline, create_scanner, filter_records, filter_timeline,
    filter_records_by_time, filter_timeline_by_time, hash_records, scan_path, sort_records,
    sort_timeline, write_records, write_timeline, Cli, Command, HashAlgorithm, OutputFormat,
    ScanArgs, ScanOptions, Severity, SortField, TimeRange, TimelineArgs,
};
#[cfg(all(feature = "tsk", libtsk_available))]
use macb_timeline::print_image_partitions;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan(args) => run_scan(args),
        Command::Timeline(args) => run_timeline(args),
    }
}

fn run_scan(args: ScanArgs) -> Result<()> {
    #[cfg(all(feature = "tsk", libtsk_available))]
    if args.list_partitions {
        let image = args
            .image
            .ok_or_else(|| anyhow::anyhow!("--image is required with --list-partitions"))?;
        print!("{}", print_image_partitions(&image)?);
        return Ok(());
    }

    let min_severity = Severity::from(args.min_severity);
    let sort = SortField::from(args.sort);
    let output = OutputFormat::from(args.output);
    let follow_symlinks = args.follow_symlinks;
    let recursive = args.recursive;
    let anomalies_only = args.anomalies_only;
    let jobs = args.jobs;
    let hash = parse_hash_option(args.hash.as_deref())?;
    let time_range = TimeRange::parse(args.since.as_deref(), args.until.as_deref())?;
    let path = args.path;
    #[cfg(libtsk_available)]
    let image = args.image;
    #[cfg(libtsk_available)]
    let partition = args.partition;
    #[cfg(libtsk_available)]
    let offset = args.offset;
    #[cfg(libtsk_available)]
    let include_deleted = args.include_deleted;
    #[cfg(not(libtsk_available))]
    let include_deleted = false;
    let scan_options = ScanOptions::build(
        args.max_depth,
        recursive,
        &args.include,
        &args.exclude,
        args.quiet,
        include_deleted,
        hash,
    )?;
    let require_exists = scan_requires_existing_path(
        path.as_deref(),
        #[cfg(libtsk_available)]
        image.as_deref(),
    );
    let target_path = resolve_scan_path(
        path.as_deref(),
        #[cfg(libtsk_available)]
        image.as_deref(),
    )?;

    let scanner = create_scanner(
        follow_symlinks,
        jobs,
        scan_options.clone(),
        #[cfg(libtsk_available)]
        image,
        #[cfg(libtsk_available)]
        partition,
        #[cfg(libtsk_available)]
        offset,
    )?;

    let mut records = annotate_records(scan_path(
        scanner.as_ref(),
        &target_path,
        require_exists,
    )?);

    if let Some(algorithm) = scan_options.hash {
        hash_records(&mut records, algorithm, jobs)?;
    }

    records = filter_records_by_time(records, time_range);
    records = filter_records(records, anomalies_only, min_severity);
    sort_records(&mut records, sort);

    write_output(args.output_file.as_deref(), |writer| {
        write_records(writer, &records, output, min_severity)
    })
}

fn run_timeline(args: TimelineArgs) -> Result<()> {
    #[cfg(all(feature = "tsk", libtsk_available))]
    if args.list_partitions {
        let image = args
            .image
            .ok_or_else(|| anyhow::anyhow!("--image is required with --list-partitions"))?;
        print!("{}", print_image_partitions(&image)?);
        return Ok(());
    }

    let min_severity = Severity::from(args.min_severity);
    let sort = SortField::from(args.sort);
    let output = OutputFormat::from(args.format);
    let follow_symlinks = args.follow_symlinks;
    let recursive = args.recursive;
    let anomalies_only = args.anomalies_only;
    let jobs = args.jobs;
    let hash = parse_hash_option(args.hash.as_deref())?;
    let time_range = TimeRange::parse(args.since.as_deref(), args.until.as_deref())?;
    let path = args.path;
    #[cfg(libtsk_available)]
    let image = args.image;
    #[cfg(libtsk_available)]
    let partition = args.partition;
    #[cfg(libtsk_available)]
    let offset = args.offset;
    #[cfg(libtsk_available)]
    let include_deleted = args.include_deleted;
    #[cfg(not(libtsk_available))]
    let include_deleted = false;
    let scan_options = ScanOptions::build(
        args.max_depth,
        recursive,
        &args.include,
        &args.exclude,
        args.quiet,
        include_deleted,
        hash,
    )?;
    let require_exists = timeline_requires_existing_path(
        path.as_deref(),
        #[cfg(libtsk_available)]
        image.as_deref(),
    );
    let target_path = resolve_scan_path(
        path.as_deref(),
        #[cfg(libtsk_available)]
        image.as_deref(),
    )?;

    let scanner = create_scanner(
        follow_symlinks,
        jobs,
        scan_options.clone(),
        #[cfg(libtsk_available)]
        image,
        #[cfg(libtsk_available)]
        partition,
        #[cfg(libtsk_available)]
        offset,
    )?;

    let mut records = annotate_records(scan_path(
        scanner.as_ref(),
        &target_path,
        require_exists,
    )?);

    if let Some(algorithm) = scan_options.hash {
        hash_records(&mut records, algorithm, jobs)?;
    }

    let mut events = build_timeline(&records);
    events = filter_timeline_by_time(events, time_range);
    events = filter_timeline(events, anomalies_only, min_severity);
    sort_timeline(&mut events, sort);

    write_output(args.output_file.as_deref(), |writer| {
        write_timeline(writer, &events, output, min_severity)
    })
}

fn parse_hash_option(value: Option<&str>) -> Result<Option<HashAlgorithm>> {
    value
        .map(HashAlgorithm::parse)
        .transpose()
}

fn write_output(
    output_file: Option<&Path>,
    write_fn: impl FnOnce(&mut dyn Write) -> io::Result<()>,
) -> Result<()> {
    match output_file {
        Some(path) => {
            let file = File::create(path)?;
            let mut writer = BufWriter::new(file);
            write_fn(&mut writer)?;
            writer.flush()?;
        }
        None => {
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            write_fn(&mut handle)?;
            handle.flush()?;
        }
    }

    Ok(())
}

fn resolve_scan_path(
    path: Option<&Path>,
    #[cfg(libtsk_available)] image: Option<&Path>,
) -> Result<PathBuf> {
    #[cfg(libtsk_available)]
    if image.is_some() {
        return Ok(PathBuf::from("/"));
    }

    path.map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("a scan path is required for live filesystem scans"))
}

fn scan_requires_existing_path(
    path: Option<&Path>,
    #[cfg(libtsk_available)] image: Option<&Path>,
) -> bool {
    #[cfg(libtsk_available)]
    {
        let _ = path;
        image.is_none()
    }
    #[cfg(not(libtsk_available))]
    {
        let _ = path;
        true
    }
}

fn timeline_requires_existing_path(
    path: Option<&Path>,
    #[cfg(libtsk_available)] image: Option<&Path>,
) -> bool {
    scan_requires_existing_path(path, #[cfg(libtsk_available)] image)
}
