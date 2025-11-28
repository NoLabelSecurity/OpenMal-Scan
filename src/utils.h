// Programmer:      Brian Lorick
// Date:            **/**/****
// Program Name:    Malware Scanner (Utilities Header)
// Description:     Declares helper functions for string processing, path utilities, 
//                  case-insensitive operations, and logging support used across the
//                  malware scanner application.

#ifndef UTILS_H
#define UTILS_H

#define _CRT_SECURE_NO_WARNINGS                        // Disable warnings for unsafe functions

#include <stdio.h>                                     // Needed for printing/logging
#include <stdlib.h>                                    // Needed for memory allocation
#include <string.h>                                    // Needed for string manipulation
#include <ctype.h>                                     // Needed for tolower()

//**********************************************************
// Constant Declarations
//**********************************************************

#define MAX_LOG_MESSAGE_LENGTH       512               // Maximum string length for log entries
#define MAX_TIME_STRING_LENGTH       64                // Size for formatted timestamp strings

//**********************************************************
// Function Prototypes
//**********************************************************

void toLowerCase(char *text);
// Converts a string to lowercase in-place.

int stringsEqualIgnoreCase(const char *strA,
                           const char *strB);
// Compares two strings ignoring case differences.

void normalizeFilePath(char *path);
// Converts backslashes to forward slashes and cleans path formatting.

void getCurrentTimestamp(char *outputBuffer,
                         int bufferSize);
// Fills buffer with current system time as a readable string.

void writeLogMessage(const char *message);
// Writes a formatted log message with a timestamp.

#endif // UTILS_H
