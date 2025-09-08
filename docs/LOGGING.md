# RAVN Logging System

## Overview

RAVN includes a professional logging system that replaces `printf` statements with structured, configurable logging. This provides better debugging capabilities, log levels, timestamps, and file output.

## Features

- **5 Log Levels**: DEBUG, INFO, WARN, ERROR, FATAL
- **Timestamps**: Precise timestamps with millisecond precision
- **File Output**: Logs to files or stderr
- **Color Support**: Colored output for terminal (optional)
- **Thread Safety**: Thread-safe logging
- **Runtime Configuration**: Change log levels and settings at runtime

## Quick Start

```c
#include "utils/logger.h"

int main() {
    // Initialize logger
    logger_init(LOG_LEVEL_DEBUG, "myapp.log");
    
    // Use logging macros
    LOG_INFO("Application started");
    LOG_DEBUG("Debug information: %d", some_value);
    LOG_ERROR("Error occurred: %s", error_message);
    
    // Cleanup
    logger_cleanup();
    return 0;
}
```

## Log Levels

| Level | Description | When to Use |
|-------|-------------|-------------|
| `DEBUG` | Detailed debugging information | Development, troubleshooting |
| `INFO` | General information about program flow | Normal operation events |
| `WARN` | Warning messages | Potential issues, recoverable errors |
| `ERROR` | Error conditions | Recoverable errors, failed operations |
| `FATAL` | Fatal errors | Unrecoverable errors, program termination |

## API Reference

### Initialization

```c
int logger_init(log_level_t level, const char *log_file);
```

- `level`: Minimum log level to output
- `log_file`: Path to log file (NULL for stderr)
- Returns: 0 on success, -1 on failure

### Logging Macros

```c
LOG_DEBUG(format, ...)   // Debug messages
LOG_INFO(format, ...)    // Info messages  
LOG_WARN(format, ...)    // Warning messages
LOG_ERROR(format, ...)   // Error messages
LOG_FATAL(format, ...)   // Fatal messages
```

### Configuration

```c
void logger_set_level(log_level_t level);           // Change log level
void logger_set_file(const char *file_path);        // Change output file
void logger_set_colors(int enable);                 // Enable/disable colors
void logger_set_timestamps(int enable);             // Enable/disable timestamps
void logger_set_thread_id(int enable);              // Enable/disable thread IDs
```

### Cleanup

```c
void logger_cleanup(void);
```

## Log Format

```
[2025-09-08 22:50:19.484] [INFO] [main.c:25:function_name] Your message here
```

- **Timestamp**: `YYYY-MM-DD HH:MM:SS.mmm`
- **Level**: `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`
- **Location**: `filename:line:function`
- **Message**: Your formatted message

## Examples

### Basic Usage

```c
#include "utils/logger.h"

void process_data(int count) {
    LOG_DEBUG("Processing %d items", count);
    
    for (int i = 0; i < count; i++) {
        if (i % 100 == 0) {
            LOG_INFO("Progress: %d/%d", i, count);
        }
        
        if (process_item(i) < 0) {
            LOG_ERROR("Failed to process item %d", i);
            return;
        }
    }
    
    LOG_INFO("Successfully processed %d items", count);
}
```

### Error Handling

```c
int connect_to_server(const char *host, int port) {
    LOG_DEBUG("Connecting to %s:%d", host, port);
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        LOG_ERROR("Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    // ... connection logic ...
    
    if (connect(sock, &addr, sizeof(addr)) < 0) {
        LOG_ERROR("Failed to connect to %s:%d: %s", host, port, strerror(errno));
        close(sock);
        return -1;
    }
    
    LOG_INFO("Connected to %s:%d", host, port);
    return sock;
}
```

### Runtime Configuration

```c
int main() {
    logger_init(LOG_LEVEL_INFO, "app.log");
    
    LOG_INFO("Application started");
    
    // Change to debug mode for troubleshooting
    if (argc > 1 && strcmp(argv[1], "--debug") == 0) {
        logger_set_level(LOG_LEVEL_DEBUG);
        LOG_DEBUG("Debug mode enabled");
    }
    
    // ... application logic ...
    
    logger_cleanup();
    return 0;
}
```

## Integration with RAVN

The RAVN project uses the logger throughout:

- **Main application**: Startup/shutdown messages
- **eBPF monitoring**: System event logging
- **Redis operations**: Connection and data logging
- **AI engine**: Model loading and analysis logging

## Best Practices

1. **Use appropriate log levels**:
   - DEBUG: Development and troubleshooting
   - INFO: Normal operation events
   - WARN: Potential issues
   - ERROR: Recoverable errors
   - FATAL: Unrecoverable errors

2. **Include context**:
   ```c
   LOG_ERROR("Failed to send event %d to Redis: %s", event_id, error_msg);
   ```

3. **Use structured messages**:
   ```c
   LOG_INFO("User %s (ID: %d) performed action %s", username, user_id, action);
   ```

4. **Log function entry/exit for debugging**:
   ```c
   void critical_function() {
       LOG_DEBUG("Entering critical_function");
       // ... function logic ...
       LOG_DEBUG("Exiting critical_function");
   }
   ```

5. **Clean up properly**:
   ```c
   // Always call logger_cleanup() before program exit
   logger_cleanup();
   ```

## Performance

- Logging is thread-safe and efficient
- DEBUG messages are compiled out in release builds (if desired)
- File I/O is buffered for performance
- Minimal overhead when logging is disabled

## Troubleshooting

### Log file not created
- Check file permissions
- Ensure directory exists
- Verify logger_init() succeeded

### Messages not appearing
- Check log level setting
- Verify logger_init() was called
- Check if logger_cleanup() was called too early

### Performance issues
- Use appropriate log levels
- Consider disabling timestamps/colors in production
- Use file output instead of stderr for high-volume logging
