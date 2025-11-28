// Programmer:      Brian Lorick
// Date:            **/**/****
// Program Name:    Malware Scanner (Scanner Implementation)
// Description:     Implements file scanning, directory recursion, wildcard matching,
//                  regex matching, byte-offset reporting, and signature loading.

#define _CRT_SECURE_NO_WARNINGS                    // Disable warnings for unsafe functions

#include "scanner.h"                               // Include header for declarations

//**********************************************************
// loadSignaturesFromFile()
// Loads signatures from a file line-by-line.
// Detects regex signatures if line begins with "regex:"
//**********************************************************
int loadSignaturesFromFile(const char *fileName,
                           Signature signatureList[],
                           int *signatureCount)
{
    FILE *filePtr = fopen(fileName, "r");          // Open signature file for reading
    if (filePtr == NULL)                           // Check if file failed to open
    {
        perror("Error opening signature file");    // Print system error
        return 0;                                  // Failure
    }

    char lineBuffer[MAX_SIGNATURE_LENGTH];         // Temp buffer for each line

    *signatureCount = 0;                           // Initialize count to zero

    while (fgets(lineBuffer, MAX_SIGNATURE_LENGTH, filePtr) != NULL)
    {
        lineBuffer[strcspn(lineBuffer, "\r\n")] = '\0'; // Remove newline characters

        if (strlen(lineBuffer) == 0)               // Skip empty lines
        {
            continue;
        }

        Signature *sig = &signatureList[*signatureCount]; // Pointer to next signature entry

        if (strncmp(lineBuffer, "regex:", 6) == 0)        // If signature is a regex
        {
            sig->isRegex = 1;                             // Mark as regex type
            strncpy(sig->signatureText, lineBuffer + 6, MAX_SIGNATURE_LENGTH);
        }
        else
        {
            sig->isRegex = 0;                             // Literal or wildcard signature
            strncpy(sig->signatureText, lineBuffer, MAX_SIGNATURE_LENGTH);
        }

        (*signatureCount)++;                              // Increment signature count

        if (*signatureCount >= MAX_SIGNATURES)            // Prevent overflow
        {
            break;
        }
    }

    fclose(filePtr);                                      // Close signature file
    return 1;                                             // Success
}

//**********************************************************
// matchSignature()
// Standard substring search (literal search only)
//**********************************************************
int matchSignature(const char *buffer,
                   const char *signature)
{
    return (strstr(buffer, signature) != NULL);           // Returns 1 if found
}

//**********************************************************
// matchWildcard()
// Supports '*' (any sequence) and '?' (single-char)
//**********************************************************
int matchWildcard(const char *text,
                  const char *pattern)
{
    // If end of pattern reached, text must also be at end
    if (*pattern == '\0')
    {
        return (*text == '\0');
    }

    // Handle '*'
    if (*pattern == '*')
    {
        return matchWildcard(text, pattern + 1)
            || (*text && matchWildcard(text + 1, pattern));
    }

    // Handle '?'
    if (*pattern == '?')
    {
        return (*text && matchWildcard(text + 1, pattern + 1));
    }

    // Handle literal match
    if (*text == *pattern)
    {
        return matchWildcard(text + 1, pattern + 1);
    }

    return 0;
}

//**********************************************************
// matchRegex()
// Uses POSIX regex matching for advanced signatures
//**********************************************************
int matchRegex(const char *text,
               const char *pattern)
{
    regex_t regexObject;                                // Regex object

    if (regcomp(&regexObject, pattern, REG_EXTENDED | REG_NOSUB) != 0)
    {
        return 0;                                       // Failed to compile regex
    }

    int result = (regexec(&regexObject, text, 0, NULL, 0) == 0);

    regfree(&regexObject);                              // Free regex object

    return result;                                      // Return match result
}

//**********************************************************
// scanFile()
// Reads file in chunks and checks all signatures against it.
// Reports byte offsets for each match.
//**********************************************************
int scanFile(const char *filePath,
             Signature signatureList[],
             int signatureCount)
{
    FILE *filePtr = fopen(filePath, "rb");             // Open file in binary mode

    if (filePtr == NULL)
    {
        perror("Error opening file");
        return 0;                                       // Failure
    }

    char buffer[BUFFER_SIZE + 1];                       // Read buffer (+1 for null terminator)
    long fileOffset = 0;                                // Tracks position in file
    size_t bytesRead = 0;                               // Number of bytes read
    int totalMatches = 0;                               // Total matches found

    printf("\nScanning file: %s\n", filePath);         // Display file being scanned

    while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, filePtr)) > 0)
    {
        buffer[bytesRead] = '\0';                      // Null terminate buffer

        for (int i = 0; i < signatureCount; i++)
        {
            Signature *sig = &signatureList[i];        // Pointer to current signature

            char *scanPtr = buffer;                    // Scan pointer for searching

            while (*scanPtr != '\0')
            {
                int matchFound = 0;                    // Track match on this iteration

                if (sig->isRegex)                      // Regex signature
                {
                    matchFound = matchRegex(scanPtr, sig->signatureText);
                }
                else if (strchr(sig->signatureText, '*') != NULL ||
                         strchr(sig->signatureText, '?') != NULL)  // Wildcard signature
                {
                    matchFound = matchWildcard(scanPtr, sig->signatureText);
                }
                else                                   // Literal match
                {
                    matchFound = matchSignature(scanPtr, sig->signatureText);
                }

                if (matchFound)                        // If a signature match occurred
                {
                    long matchOffset = fileOffset + (scanPtr - buffer);

                    printf("  [MATCH] Signature \"%s\" found at offset %ld\n",
                           sig->signatureText, matchOffset);

                    totalMatches++;
                }

                scanPtr++;                             // Move pointer forward
            }
        }

        fileOffset += bytesRead;                       // Update global file position
    }

    fclose(filePtr);                                    // Close file

    if (totalMatches == 0)
    {
        printf("  No signatures found in %s\n", filePath);
    }
    else
    {
        printf("  Total matches: %d\n", totalMatches);
    }

    return totalMatches;                                // Return number of matches found
}

//**********************************************************
// scanDirectoryRecursive()
// Recursively scans directories and subdirectories.
//**********************************************************
int scanDirectoryRecursive(const char *directoryPath,
                           Signature signatureList[],
                           int signatureCount)
{
    DIR *dirPtr = opendir(directoryPath);              // Try opening directory

    if (dirPtr == NULL)                                // Failed to open
    {
        perror("Error opening directory");
        return 0;
    }

    struct dirent *entry;                              // Directory entry structure
    char fullPath[MAX_PATH_LENGTH];                    // Full path buffer

    while ((entry = readdir(dirPtr)) != NULL)
    {
        // Skip self and parent directories
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        snprintf(fullPath, MAX_PATH_LENGTH, "%s/%s", directoryPath, entry->d_name);

        struct stat pathStat;

        if (stat(fullPath, &pathStat) == -1)
        {
            continue;
        }

        // If entry is a directory → recurse
        if (S_ISDIR(pathStat.st_mode))
        {
            scanDirectoryRecursive(fullPath, signatureList, signatureCount);
        }
        else if (S_ISREG(pathStat.st_mode))
        {
            scanFile(fullPath, signatureList, signatureCount);
        }
    }

    closedir(dirPtr);                                   // Close directory

    return 1;                                           // Success
}
