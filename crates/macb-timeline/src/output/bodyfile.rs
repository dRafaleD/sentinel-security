use std::io::{self, Write};

use crate::model::MacbRecord;

/// Write records in Sleuth Kit mactime bodyfile format:
/// `MD5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime`
pub fn write_records_bodyfile(writer: &mut dyn Write, records: &[MacbRecord]) -> io::Result<()> {
    for record in records {
        writeln!(
            writer,
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            bodyfile_hash(record),
            bodyfile_path(record),
            record.inode.unwrap_or(0),
            format_bodyfile_mode(record),
            record.uid.unwrap_or(0),
            record.gid.unwrap_or(0),
            record.size,
            epoch_secs(record.atime),
            epoch_secs(record.mtime),
            epoch_secs(record.ctime),
            epoch_secs(record.btime),
        )?;
    }

    Ok(())
}

fn bodyfile_hash(record: &MacbRecord) -> &str {
    if let Some(md5) = record.md5.as_deref() {
        return md5;
    }
    "0"
}

fn bodyfile_path(record: &MacbRecord) -> String {
    let path = record.path.display().to_string().replace('\\', "/");
    if record.deleted {
        format!("*(deleted)*{path}")
    } else {
        path
    }
}

fn epoch_secs(timestamp: Option<chrono::DateTime<chrono::Utc>>) -> i64 {
    timestamp.map(|value| value.timestamp()).unwrap_or(0)
}

pub fn format_bodyfile_mode(record: &MacbRecord) -> String {
    let mode = record
        .mode
        .unwrap_or(if record.is_dir { 0o040755 } else { 0o100644 });
    let file_type = match mode & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        0o100000 => '-',
        0o140000 => 's',
        0o010000 => 'p',
        0o020000 => 'b',
        0o060000 => 'c',
        _ if record.is_dir => 'd',
        _ => '-',
    };
    format!("{}/{}", file_type, format_rwx(mode & 0o777))
}

fn format_rwx(bits: u32) -> String {
    const MASKS: [(u32, char, char, char); 3] = [
        (0o700, 'r', 'w', 'x'),
        (0o070, 'r', 'w', 'x'),
        (0o007, 'r', 'w', 'x'),
    ];

    let mut output = String::with_capacity(9);
    for (mask, r, w, x) in MASKS {
        let shift = mask.trailing_zeros();
        let triplet = (bits & mask) >> shift;
        output.push(if triplet & 4 != 0 { r } else { '-' });
        output.push(if triplet & 2 != 0 { w } else { '-' });
        output.push(if triplet & 1 != 0 { x } else { '-' });
    }
    output
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use chrono::{TimeZone, Utc};

    use super::*;

    #[test]
    fn writes_bodyfile_line() {
        let record = MacbRecord {
            path: PathBuf::from("/etc/passwd"),
            inode: Some(1234),
            mtime: Some(Utc.timestamp_opt(1_700_000_200, 0).unwrap()),
            atime: Some(Utc.timestamp_opt(1_700_000_100, 0).unwrap()),
            ctime: Some(Utc.timestamp_opt(1_700_000_300, 0).unwrap()),
            btime: None,
            size: 2048,
            mode: Some(0o100644),
            uid: Some(0),
            gid: Some(0),
            md5: None,
            sha256: None,
            deleted: false,
            is_dir: false,
            anomalies: Vec::new(),
        };

        let mut buffer = Vec::new();
        write_records_bodyfile(&mut buffer, &[record]).unwrap();
        let line = String::from_utf8(buffer).unwrap();
        assert!(line.starts_with("0|/etc/passwd|1234|-/rw-r--r--|0|0|2048|"));
    }

    #[test]
    fn marks_deleted_paths() {
        let record = MacbRecord {
            path: PathBuf::from("/lost/file.txt"),
            inode: Some(9),
            mtime: None,
            atime: None,
            ctime: None,
            btime: None,
            size: 0,
            mode: None,
            uid: None,
            gid: None,
            md5: None,
            sha256: None,
            deleted: true,
            is_dir: false,
            anomalies: Vec::new(),
        };

        assert_eq!(bodyfile_path(&record), "*(deleted)*/lost/file.txt");
    }
}
