// SPDX-License-Identifier: LGPL-2.1-or-later
fn select_files(directories: &[PathBuf]) -> io::Result<Vec<SelectedFile>> {
    let mut selected = BTreeMap::<String, SelectedFile>::new();
    for directory in directories {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("rr") {
                continue;
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let metadata = fs::symlink_metadata(&path)?;
            let masked = metadata.file_type().is_symlink()
                && fs::read_link(&path).is_ok_and(|target| target == Path::new("/dev/null"));
            if masked || fs::metadata(&path).is_ok_and(|metadata| metadata.is_file()) {
                selected.insert(name.to_owned(), SelectedFile { path, masked });
            }
        }
    }
    Ok(selected.into_values().collect())
}

fn fingerprint(files: &[SelectedFile]) -> io::Result<Vec<FileStamp>> {
    files
        .iter()
        .map(|file| {
            let metadata = if file.masked {
                fs::symlink_metadata(&file.path)?
            } else {
                fs::metadata(&file.path)?
            };
            Ok(FileStamp {
                path: file.path.clone(),
                masked: file.masked,
                length: metadata.len(),
                modified: metadata.modified().ok(),
            })
        })
        .collect()
}

fn load_selected_files(files: &[SelectedFile]) -> HashMap<String, Vec<StaticRecord>> {
    let mut records = HashMap::<String, Vec<StaticRecord>>::new();
    for file in files.iter().filter(|file| !file.masked) {
        let Some(value) = read_json_file(&file.path) else {
            continue;
        };
        match value {
            Value::Object(_) => add_record_value(&mut records, &value),
            Value::Array(values) => {
                for value in &values {
                    add_record_value(&mut records, value);
                }
            }
            _ => {}
        }
    }
    records
}

fn read_json_file(path: &Path) -> Option<Value> {
    let file = fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_FILE_READ)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > MAX_RECORD_FILE_SIZE {
        return None;
    }
    let text = String::from_utf8(bytes).ok()?;
    json::parse(&text).ok()
}

