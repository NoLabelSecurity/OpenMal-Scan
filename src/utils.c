// Programmer:      Brian Lorick
// Date:            **/**/****
// Program Name:    Malware Scanner (Utilities Implementation)
// Description:     Implements helper functions for string operations, path 
//                  normalization, timestamp formatting, and logging utilities.

#define _CRT_SECURE_NO_WARNINGS                        // Disable unsafe-function warnings

#include "utils.h"                                     // Include header for prototypes
#include <time.h>                                      // Needed for date/time operations

//**********************************************************
// toLowerCase()
// Converts an entire string to lowercase in-place.
//**********************************************************
void toLowerCase(char *text)
{
    while (*text != '\0')                              // Loop through characters
    {
        *text = (char)tolower(*text);                  // Convert character
        text++;                                        // Move to next character
    }
}

//**********************************************************
// stringsEqualIgnoreCase()
// Compares two strings ignoring uppercase/lowercase.
//**********************************************************
int stringsEqualIgnoreCase(const char *strA,
                           const char *strB)
{
    while (*strA && *strB)                             // Loop while neither reached end
    {
        if (tolower(*strA) != tolower(*strB))          // Compare lowercase characters
        {
            return 0;                                  // They differ → not equal
        }
        strA++;                                        // Move to next character
        strB++;
    }

    return (*strA == '\0' && *strB == '\0');           // Must end at the same time
}

//**********************************************************
// normalizeFilePath()
// Ensures file path consistency (use forward slashes only).
//**********************************************************
void normalizeFilePath(char *path)
{
    while (*path != '\0')                              // Loop through characters
    {
        if (*path == '\\')                             // If backslash found
        {
            *path = '/';                               // Convert to forward slash
        }
        path++;                                        // Move to next character
    }
}

//**********************************************************
// getCurrentTimestamp()
// Generates human-readable timestamp string.
//**********************************************************
void getCurrentTimestamp(char *outputBuffer,
                         int bufferSize)
{
    time_t rawTime;                                    // Time value storage
    struct tm *timeInfo;                               // Struct for broken-down time

    time(&rawTime);                                    // Retrieve current time
    timeInfo = localtime(&rawTime);                    // Convert to local time format

    snprintf(outputBuffer,
             bufferSize,
             "%02d-%02d-%04d %02d:%02d:%02d",          // Format string
             timeInfo->tm_mon + 1,                     // Month (0–11 → 1–12)
             timeInfo->tm_mday,                        // Day
             timeInfo->tm_year + 1900,                 // Year correction
             timeInfo->tm_hour,                        // Hour
             timeInfo->tm_min,                         // Minute
             timeInfo->tm_sec);                        // Second
}

//**********************************************************
// writeLogMessage()
// Writes a timestamped log message to stdout.
//**********************************************************
void writeLogMessage(const char *message)
{
    char timeString[MAX_TIME_STRING_LENGTH];           // Buffer for timestamp

    getCurrentTimestamp(timeString,                    // Generate timestamp
                        MAX_TIME_STRING_LENGTH);

    printf("[%s] %s\n",                                // Print timestamp + message
           timeString,
           message);
}
