// Programmer:      Brian Lorick
// Date:            **/**/****
// Program Name:    Malware Scanner (Hashing Header)
// Description:     Declares hashing functions for MD5 and SHA-256, including
//                  utilities to compute hashes for files and strings.

#ifndef HASH_H
#define HASH_H

#define _CRT_SECURE_NO_WARNINGS                        // Disable warnings for unsafe functions

#include <stdio.h>                                     // Needed for FILE operations
#include <stdlib.h>                                    // Needed for memory functions
#include <string.h>                                    // Needed for string operations

//**********************************************************
// Constant Declarations
//**********************************************************

#define MD5_HASH_SIZE            16                    // MD5 outputs 16 bytes
#define SHA256_HASH_SIZE         32                    // SHA-256 outputs 32 bytes
#define HEX_STRING_LENGTH        65                    // 64 chars for SHA-256 + null terminator

//**********************************************************
// Function Prototypes
//**********************************************************

int computeMd5HashForFile(const char *filePath,
                          unsigned char outputHash[MD5_HASH_SIZE]);
// Computes MD5 hash of a file.

int computeSha256HashForFile(const char *filePath,
                             unsigned char outputHash[SHA256_HASH_SIZE]);
// Computes SHA-256 hash of a file.

void convertHashToHexString(const unsigned char *hashBytes,
                            int hashLength,
                            char *outputHexString);
// Converts raw hash bytes to a human-readable hexadecimal string.

int printFileHashes(const char *filePath);
// Convenience function: prints MD5 + SHA-256 hashes for a file.

#endif // HASH_H
