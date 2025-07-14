# Path Filtering in dirt eBPF

This document explains how to use the new path filtering feature in dirt to limit file system event monitoring to specific files and directories.

## Overview

The path filtering feature allows you to specify which files and directories should be monitored by the eBPF program. This is useful for:

- Reducing noise from irrelevant file system events
- Focusing monitoring on critical system files
- Improving performance by filtering out unnecessary events
- Compliance requirements that specify which files must be monitored

## Usage

### Command Line Option

Use the `-p` option to specify a file containing allowed paths:

```bash
sudo ./dirt -p /path/to/allowed_paths.txt
```

### Allowed Paths File Format

The allowed paths file should contain one path per line. The format supports:

- **Exact file paths**: `/etc/passwd`
- **Directory paths**: `/var/log`
- **Comments**: Lines starting with `#` are ignored
- **Empty lines**: Are ignored

Example file (`allowed_paths.txt`):
```
# Critical system files
/etc/passwd
/etc/shadow
/etc/hosts

# Log directories
/var/log
/var/log/apache2

# Configuration files
/etc/ssh/sshd_config
/etc/nginx/nginx.conf

# User documents
/home/user/documents
```

## Implementation Details

### How It Works

1. **BPF Map**: A hash map stores allowed paths with their hash as the key
2. **Path Hashing**: Each path is hashed using a simple rolling hash function
3. **Runtime Filtering**: The eBPF program checks if a file's path is in the allowed list before processing events
4. **Fallback Behavior**: If no allowed paths file is specified, all files are monitored (backward compatibility)

### Performance Considerations

- **Hash-based Lookup**: O(1) average case lookup time
- **Memory Usage**: Each allowed path uses ~128 bytes in the BPF map
- **Maximum Paths**: Limited to 1024 paths (configurable via `MAP_ALLOWED_PATHS_MAX`)
- **Path Length**: Maximum path length is 96 characters (configurable via `FILEPATH_LEN_MAX`)

### Filtering Logic

The filtering happens in the `handle_fs_event` function in `dirt.bpf.c`:

1. File path is reconstructed from the dentry structure
2. Path is checked against the allowed paths map
3. If not found or not enabled, the event is discarded
4. If found and enabled, the event is processed normally

## Examples

### Monitor Only Critical System Files

Create `critical_files.txt`:
```
/etc/passwd
/etc/shadow
/etc/sudoers
/etc/ssh/sshd_config
```

Run:
```bash
sudo ./dirt -p critical_files.txt -V
```

### Monitor Application Logs

Create `app_logs.txt`:
```
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/apache2/access.log
/var/log/mysql/error.log
```

Run:
```bash
sudo ./dirt -p app_logs.txt -x /tmp/dirt.sock -d
```

### Monitor User Documents

Create `user_docs.txt`:
```
/home/user/documents
/home/user/desktop
/home/user/downloads
```

Run:
```bash
sudo ./dirt -p user_docs.txt -o json-min
```

## Troubleshooting

### Common Issues

1. **File Not Found**: Ensure the allowed paths file exists and is readable
2. **No Events**: Check that the paths in your file actually exist and are being accessed
3. **Permission Denied**: Run with sudo/root privileges
4. **Too Many Paths**: Reduce the number of paths (max 1024)

### Debug Mode

Use debug mode to see what's happening:

```bash
sudo ./dirt -p allowed_paths.txt -V -D '*'
```

Then in another terminal:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Verbose Output

Use the `-V` flag to see configuration details:

```bash
sudo ./dirt -p allowed_paths.txt -V
```

This will show:
- Whether path filtering is enabled
- The path to the allowed paths file
- Number of paths loaded

## Advanced Usage

### Dynamic Path Updates

The current implementation loads paths at startup. For dynamic updates, you would need to:

1. Stop the dirt process
2. Update the allowed paths file
3. Restart dirt

### Pattern Matching

The current implementation only supports exact path matching. For pattern matching (e.g., wildcards), you would need to:

1. Modify the `is_path_allowed` function in `dirt.bpf.c`
2. Implement pattern matching logic
3. Consider performance implications

### Integration with Configuration Management

You can integrate path filtering with configuration management systems:

```bash
# Example: Generate allowed paths from Puppet/Ansible
puppet resource file | grep -E "path.*=>.*['\"](.*)['\"]" | cut -d"'" -f2 > allowed_paths.txt
sudo ./dirt -p allowed_paths.txt -d
```

## Security Considerations

- **Path Validation**: The implementation doesn't validate paths for security (e.g., symlink attacks)
- **Privilege Escalation**: Running as root is required for eBPF functionality
- **Information Disclosure**: Be careful not to include sensitive paths in error messages

## Future Enhancements

Potential improvements to consider:

1. **Pattern Matching**: Support for wildcards and regex patterns
2. **Dynamic Updates**: Runtime path list updates without restart
3. **Path Validation**: Security validation of allowed paths
4. **Performance Optimization**: More efficient path matching algorithms
5. **Configuration API**: REST API for managing allowed paths 