// Programmer:      Brian Lorick
// Date:            **/**/****
// Program Name:    Malware Scanner (Monitor Implementation)
// Description:     Implements real-time directory monitoring. Detects new, modified,
//                  or deleted files and triggers scanning and hashing actions.

#define _CRT_SECURE_NO_WARNINGS                        // Disable unsafe function warnings

#include "monitor.h"                                   // Include header for prototypes
#include <sys/stat.h>                                  // Needed for file metadata
#include <dirent.h>                                    // Needed for directory reading

//**********************************************************
// getFileModifiedTime()
// Fetches the last modified timestamp of a file.
//**********************************************************
int getFileModifiedTime(const char *filePath,
                        time_t *modifiedTime)
{
    struct stat fileStats;                             // Structure holding file metadata

    if (stat(filePath, &fileStats) != 0)                // Attempt to read metadata
    {
        return 0;                                       // Failure (file may not exist)
    }

    *modifiedTime = fileStats.st_mtime;                // Store modification time

    return 1;                                           // Success
}

//**********************************************************
// buildInitialFileList()
// Scans directory once and builds table of current files.
//**********************************************************
int buildInitialFileList(const char *directoryPath,
                         MonitoredFile fileList[],
                         int *fileCount)
{
    DIR *dirPtr = opendir(directoryPath);              // Attempt to open directory

    if (dirPtr == NULL)                                // Directory failed to open
    {
        perror("Monitor: Error opening directory");     // Print error message
        return 0;                                       // Failure
    }

    struct dirent *entry = NULL;                       // Directory entry pointer
    char fullPath[MAX_PATH_LENGTH];                    // Buffer for full pathnames
    int localCount = 0;                                // Local file counter

    while ((entry = readdir(dirPtr)) != NULL)          // Read directory entries
    {
        if (strcmp(entry->d_name, ".") == 0 ||         // Skip current directory
            strcmp(entry->d_name, "..") == 0)          // Skip parent directory
        {
            continue;
        }

        snprintf(fullPath, MAX_PATH_LENGTH, "%s/%s",
                 directoryPath, entry->d_name);        // Build full file path

        struct stat pathStats;

        if (stat(fullPath, &pathStats) != 0)           // Unable to stat file
        {
            continue;
        }

        if (S_ISREG(pathStats.st_mode))                // Accept only regular files
        {
            strncpy(fileList[localCount].filePath,
                    fullPath, MAX_PATH_LENGTH);        // Store path

            fileList[localCount].lastModifiedTime =
                pathStats.st_mtime;                    // Store timestamp

            localCount++;                              // Increment count

            if (localCount >= MAX_MONITOR_FILES)       // Prevent overflow
            {
                break;
            }
        }
    }

    closedir(dirPtr);                                   // Close directory handle

    *fileCount = localCount;                            // Return number of tracked files

    return 1;                                           // Success
}

//**********************************************************
// checkForDirectoryChanges()
// Detects new, modified, or deleted files.
//**********************************************************
int checkForDirectoryChanges(const char *directoryPath,
                             MonitoredFile fileList[],
                             int *fileCount,
                             Signature signatureList[],
                             int signatureCount)
{
    DIR *dirPtr = opendir(directoryPath);              // Attempt to open directory

    if (dirPtr == NULL)
    {
        perror("Monitor: Error opening directory");     // Error message
        return 0;                                       // Failure
    }

    struct dirent *entry = NULL;                       // Directory entry pointer
    char fullPath[MAX_PATH_LENGTH];                    // Buffer for full path
    int updatedCount = *fileCount;                     // Current number of files
    int fileFoundFlag = 0;                             // Tracks if file exists in current pass

    while ((entry = readdir(dirPtr)) != NULL)          // Loop through entries
    {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        snprintf(fullPath, MAX_PATH_LENGTH, "%s/%s",
                 directoryPath, entry->d_name);        // Create full path

        struct stat pathStats;

        if (stat(fullPath, &pathStats) != 0)           // Ignore unreadable entries
        {
            continue;
        }

        if (!S_ISREG(pathStats.st_mode))               // Only monitor regular files
        {
            continue;
        }

        fileFoundFlag = 0;                             // Reset flag for this file

        for (int i = 0; i < *fileCount; i++)           // Check if file is tracked
        {
            if (strcmp(fullPath, fileList[i].filePath) == 0)
            {
                fileFoundFlag = 1;                     // File already exists in table

                time_t modifiedTime = 0;               // Local timestamp storage
                getFileModifiedTime(fullPath, &modifiedTime);

                if (modifiedTime != fileList[i].lastModifiedTime)
                {
                    printf("\n[MONITOR] File modified: %s\n", fullPath);

                    scanFile(fullPath, signatureList, signatureCount);
                    printFileHashes(fullPath);         // Print updated hashes

                    fileList[i].lastModifiedTime = modifiedTime;
                }
                break;
            }
        }

        if (!fileFoundFlag)                            // File is new
        {
            printf("\n[MONITOR] New file detected: %s\n", fullPath);

            scanFile(fullPath, signatureList, signatureCount); // Scan new file
            printFileHashes(fullPath);                 // Hash new file

            strncpy(fileList[updatedCount].filePath,
                    fullPath, MAX_PATH_LENGTH);

            getFileModifiedTime(fullPath,
                                 &fileList[updatedCount].lastModifiedTime);

            updatedCount++;                            // Add to monitoring list
        }
    }

    closedir(dirPtr);                                   // Close directory

    *fileCount = updatedCount;                          // Update file count

    return 1;                                           // Success
}

//**********************************************************
// startDirectoryMonitor()
// Main loop: polls directory every few seconds.
//**********************************************************
int startDirectoryMonitor(const char *directoryPath,
                          Signature signatureList[],
                          int signatureCount)
{
    MonitoredFile fileList[MAX_MONITOR_FILES];         // Table of monitored files
    int fileCount = 0;                                 // Number of monitored files

    if (!buildInitialFileList(directoryPath,
                               fileList,
                               &fileCount))
    {
        return 0;                                       // Initialization failed
    }

    printf("\n[MONITOR] Monitoring directory: %s\n", directoryPath);

    while (1)                                           // Run indefinitely
    {
        checkForDirectoryChanges(directoryPath,
                                 fileList,
                                 &fileCount,
                                 signatureList,
                                 signatureCount);

        printf("[MONITOR] Sleeping %d seconds...\n",
               MONITOR_INTERVAL_SECONDS);

        sleep(MONITOR_INTERVAL_SECONDS);               // Wait before next check
    }

    return 1;                                           // (Unreachable)
}
