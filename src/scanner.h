// Programmer:      Brian Lorick
// Date:            **/**/****
// Program Name:    Malware Scanner (Header)
// Description:     Header for scanner module. Declares functions for file scanning,
//                  directory recursion, signature loading, wildcard matching, and 
//                  regex matching.

#ifndef SCANNER_H
#define SCANNER_H

#define _CRT_SECURE_NO_WARNINGS                   // Disable warnings for unsafe functions

#include <stdio.h>                                // Needed for FILE operations
#include <stdlib.h>                               // Needed for memory allocation
#include <string.h>                               // Needed for string functions
#include <dirent.h>                               // Needed for directory traversal
#include <sys/stat.h>                             // Needed for file status / types
#include <regex.h>                                // Needed for regex pattern matching

//**********************************************************
// Constant Declarations
//**********************************************************

#define BUFFER_SIZE               4096            // File read buffer size
#define MAX_SIGNATURE_LENGTH      256             // Maximum signature length
#define MAX_SIGNATURES            512             // Max number of signatures loaded
#define MAX_PATH_LENGTH           512             // Max path length for files/directories

//**********************************************************
// Data Structures
//**********************************************************

typedef struct 
{
    char signatureText[MAX_SIGNATURE_LENGTH];     // Holds signature string
    int  isRegex;                                 // 1 = regex signature, 0 = literal/wildcard
}
Signature;                                        // Structure for storing malware signatures

//**********************************************************
// Function Prototypes
//**********************************************************

int loadSignaturesFromFile(const char *fileName,
                           Signature signatureList[],
                           int *signatureCount);
// Loads signatures from file and identifies regex types.

int scanFile(const char *filePath,
             Signature signatureList[],
             int signatureCount);
// Scans a single file for all signatures.

int scanDirectoryRecursive(const char *directoryPath,
                           Signature signatureList[],
                           int signatureCount);
// Recursively scans through directory and subdirectories.

int matchWildcard(const char *text,
                  const char *pattern);
// Performs wildcard pattern matching (* and ? supported).

int matchSignature(const char *buffer,
                   const char *signature);
// Standard literal signature search.

int matchRegex(const char *text,
               const char *pattern);
// Performs regex matching against text.

#endif // SCANNER_H
