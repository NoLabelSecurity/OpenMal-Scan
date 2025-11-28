// Programmer:      Brian Lorick
// Date:            **/**/****
// Program Name:    Malware Scanner (Monitor Header)
// Description:     Declares real-time monitoring functions for directories. The
//                  monitor observes file changes and triggers scan or hash operations.

#ifndef MONITOR_H
#define MONITOR_H

#define _CRT_SECURE_NO_WARNINGS                        // Disable unsafe function warnings

#include <stdio.h>                                     // Needed for printing
#include <stdlib.h>                                    // Needed for dynamic memory
#include <string.h>                                    // Needed for string operations
#include <time.h>                                      // Needed for timestamps

#include "scanner.h"                                   // Needed for scanning functions
#include "hash.h"                                      // Needed for hashing functions

//**********************************************************
// Constant Declarations
//**********************************************************

#define MONITOR_INTERVAL_SECONDS     3                 // Polling interval between checks
#define MAX_MONITOR_FILES            2048              // Max files tracked per directory

//**********************************************************
// Data Structures
//**********************************************************

typedef struct
{
    char filePath[MAX_PATH_LENGTH];                    // Full path to file
    time_t lastModifiedTime;                           // Last modification timestamp
}
MonitoredFile;                                         // Structure representing one file entry

//**********************************************************
// Function Prototypes
//**********************************************************

int startDirectoryMonitor(const char *directoryPath,
                          Signature signatureList[],
                          int signatureCount);
// Starts the real-time monitor loop for a directory. Re-checks directory
// contents every MONITOR_INTERVAL_SECONDS.

int buildInitialFileList(const char *directoryPath,
                         MonitoredFile fileList[],
                         int *fileCount);
// Builds an initial list of files and their modification times.

int checkForDirectoryChanges(const char *directoryPath,
                             MonitoredFile fileList[],
                             int *fileCount,
                             Signature signatureList[],
                             int signatureCount);
// Checks directory for file changes and performs appropriate actions.

int getFileModifiedTime(const char *filePath,
                        time_t *modifiedTime);
// Retrieves last modified time of a file.

#endif // MONITOR_H
