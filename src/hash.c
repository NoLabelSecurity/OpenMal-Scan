// Programmer:      Brian Lorick
// Date:            **/**/****
// Program Name:    Malware Scanner (Hashing Implementation)
// Description:     Implements MD5 and SHA-256 hashing for files using OpenSSL. 
//                  Includes hex conversion utilities and unified hash reporting.

#define _CRT_SECURE_NO_WARNINGS                        // Disable unsafe function warnings

#include "hash.h"                                      // Include header for prototypes
#include <openssl/md5.h>                               // OpenSSL MD5 implementation
#include <openssl/sha.h>                               // OpenSSL SHA-256 implementation

//**********************************************************
// computeMd5HashForFile()
// Computes MD5 hash of a file and writes result to output buffer.
//**********************************************************
int computeMd5HashForFile(const char *filePath,
                          unsigned char outputHash[MD5_HASH_SIZE])
{
    FILE *filePtr = fopen(filePath, "rb");             // Open file in binary mode

    if (filePtr == NULL)                               // Check if open failed
    {
        perror("MD5: Error opening file");             // Print system error message
        return 0;                                       // Failure
    }

    MD5_CTX md5Context;                                 // MD5 context structure
    MD5_Init(&md5Context);                              // Initialize MD5 state

    unsigned char buffer[4096];                         // Read buffer
    size_t bytesRead = 0;                               // Number of bytes read

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), filePtr)) > 0)
    {
        MD5_Update(&md5Context, buffer, bytesRead);     // Hash data chunk
    }

    fclose(filePtr);                                    // Close file

    MD5_Final(outputHash, &md5Context);                 // Output final MD5 hash value

    return 1;                                           // Success
}

//**********************************************************
// computeSha256HashForFile()
// Computes SHA-256 hash of a file into output buffer.
//**********************************************************
int computeSha256HashForFile(const char *filePath,
                             unsigned char outputHash[SHA256_HASH_SIZE])
{
    FILE *filePtr = fopen(filePath, "rb");              // Open file for reading

    if (filePtr == NULL)                                // Check if open failed
    {
        perror("SHA256: Error opening file");           // Print error message
        return 0;                                       // Failure
    }

    SHA256_CTX shaContext;                              // SHA-256 context
    SHA256_Init(&shaContext);                           // Initialize hashing context

    unsigned char buffer[4096];                         // Buffer for reading file chunks
    size_t bytesRead = 0;                               // Tracks bytes read

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), filePtr)) > 0)
    {
        SHA256_Update(&shaContext, buffer, bytesRead);  // Hash chunk of data
    }

    fclose(filePtr);                                    // Close file after reading

    SHA256_Final(outputHash, &shaContext);              // Produce final SHA-256 hash

    return 1;                                           // Success
}

//**********************************************************
// convertHashToHexString()
// Converts a raw hash byte array into a readable hex string.
//**********************************************************
void convertHashToHexString(const unsigned char *hashBytes,
                            int hashLength,
                            char *outputHexString)
{
    for (int i = 0; i < hashLength; i++)                // Iterate through all bytes
    {
        sprintf(&outputHexString[i * 2], "%02x", hashBytes[i]);
        // Convert each byte to two-character hex representation
    }

    outputHexString[hashLength * 2] = '\0';             // Null-terminate hex string
}

//**********************************************************
// printFileHashes()
// Convenience function: prints MD5 and SHA-256 hashes.
//**********************************************************
int printFileHashes(const char *filePath)
{
    unsigned char md5Hash[MD5_HASH_SIZE];               // Buffer for MD5 hash
    unsigned char shaHash[SHA256_HASH_SIZE];            // Buffer for SHA-256 hash

    char md5Hex[MD5_HASH_SIZE * 2 + 1];                  // MD5 hex string buffer
    char shaHex[SHA256_HASH_SIZE * 2 + 1];               // SHA-256 hex string buffer

    printf("\nHashing file: %s\n", filePath);           // Display file being hashed

    if (!computeMd5HashForFile(filePath, md5Hash))      // Attempt MD5 hash
    {
        return 0;                                       // Error occurred
    }

    if (!computeSha256HashForFile(filePath, shaHash))   // Attempt SHA-256 hash
    {
        return 0;                                       // Error occurred
    }

    convertHashToHexString(md5Hash, MD5_HASH_SIZE, md5Hex);
    convertHashToHexString(shaHash, SHA256_HASH_SIZE, shaHex);

    printf("  MD5:     %s\n", md5Hex);                  // Print MD5 hash
    printf("  SHA-256: %s\n", shaHex);                  // Print SHA-256 hash

    return 1;                                           // Success
}
