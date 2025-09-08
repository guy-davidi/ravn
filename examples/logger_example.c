#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../src/utils/logger.h"

int main() {
    // Initialize logger with DEBUG level and log to file
    if (logger_init(LOG_LEVEL_DEBUG, "example.log") != 0) {
        fprintf(stderr, "Failed to initialize logger\n");
        return 1;
    }
    
    // Example of different log levels
    LOG_DEBUG("This is a debug message - only shows in DEBUG level");
    LOG_INFO("This is an info message - shows in INFO level and above");
    LOG_WARN("This is a warning message - shows in WARN level and above");
    LOG_ERROR("This is an error message - shows in ERROR level and above");
    LOG_FATAL("This is a fatal message - always shows");
    
    // Example with variables
    int user_id = 12345;
    char *username = "admin";
    float cpu_usage = 85.6;
    
    LOG_INFO("User %s (ID: %d) logged in", username, user_id);
    LOG_WARN("High CPU usage detected: %.1f%%", cpu_usage);
    
    // Example of conditional logging
    if (cpu_usage > 80.0) {
        LOG_ERROR("CPU usage critical: %.1f%% - taking action", cpu_usage);
    }
    
    // Example of function entry/exit logging
    LOG_DEBUG("Entering critical function");
    sleep(1); // Simulate some work
    LOG_DEBUG("Exiting critical function");
    
    // Change log level at runtime
    LOG_INFO("Changing log level to WARN");
    logger_set_level(LOG_LEVEL_WARN);
    
    LOG_DEBUG("This debug message won't show (level too low)");
    LOG_WARN("This warning will still show");
    
    // Cleanup
    LOG_INFO("Example completed - cleaning up logger");
    logger_cleanup();
    
    return 0;
}
