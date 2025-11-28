// Programmer:      Brian Lorick
// Date:            **/**/****
// Program Name:    Malware Scanner (Main Program)
// Description:     Provides console interface for malware scanning, hashing, and 
//                  directory monitoring. Coordinates all modules and controls 
//                  user-driven actions.

#define _CRT_SECURE_NO_WARNINGS                        // Disable unsafe function warnings

#include <stdio.h>                                     // Needed for console I/O
#include <stdlib.h>                                    // Needed for dynamic memory
#include <string.h>                                    // Needed for string manipulation

#include "scanner.h"                                   // Scanner module
#include "hash.h"                                      // Hashing module
#include "monitor.h"                                   // Real-time monitor module
#include "utils.h"                                     // Utility functions

//**********************************************************
// Constant Declarations
//**********************************************************

#define SIGNATURE_FILE_PATH        "signatures.txt"    // Default signature list file

//**********************************************************
// Function Prototypes (Local to main.c)
//**********************************************************

void printMainMenu();
// Displays user options.

void handleScanSingleFile(Signature signatureList[],
                          int signatureCount);
// Handles scanning one file.

void handleScanDirectory(Signature signatureList[],
                         int signatureCount);
// Handles recursive directory scanning.

void handleHashFile();
// Handles hashing a file.

void handleMonitorDirectory(Signature signatureList[],
                            int signatureCount);
// Handles starting real-time monitoring.

//**********************************************************
// printMainMenu()
//**********************************************************
void printMainMenu()
{
    printf("\n================= Malware Scanner Menu =================\n");
    printf("  1. Load signatures from file\n");
    printf("  2. Scan a single file\n");
    printf("  3. Scan a directory (recursive)\n");
    printf("  4. Hash a file (MD5 & SHA-256)\n");
    printf("  5. Start real-time directory monitor\n");
    printf("  6. Exit\n");
    printf("=========================================================\n");
    printf("Select an option: ");
}

//**********************************************************
// handleScanSingleFile()
//**********************************************************
void handleScanSingleFile(Signature signatureList[],
                          int signatureCount)
{
    char fileName[MAX_PATH_LENGTH];                    // Buffer for filename

    printf("\nEnter file path to scan: ");
    scanf("%s", fileName);                              // Read input

    normalizeFilePath(fileName);                        // Clean file path formatting

    scanFile(fileName,                                 // Perform scan
             signatureList,
             signatureCount);
}

//**********************************************************
// handleScanDirectory()
//**********************************************************
void handleScanDirectory(Signature signatureList[],
                         int signatureCount)
{
    char directoryPath[MAX_PATH_LENGTH];               // Buffer for directory path

    printf("\nEnter directory path to scan: ");
    scanf("%s", directoryPath);

    normalizeFilePath(directoryPath);                   // Normalize path

    scanDirectoryRecursive(directoryPath,               // Perform recursive scan
                           signatureList,
                           signatureCount);
}

//**********************************************************
// handleHashFile()
//**********************************************************
void handleHashFile()
{
    char fileName[MAX_PATH_LENGTH];                    // Buffer for filename

    printf("\nEnter file path to hash: ");
    scanf("%s", fileName);

    normalizeFilePath(fileName);                        // Clean path formatting

    printFileHashes(fileName);                          // Print MD5 and SHA-256
}

//**********************************************************
// handleMonitorDirectory()
//**********************************************************
void handleMonitorDirectory(Signature signatureList[],
                            int signatureCount)
{
    char directoryPath[MAX_PATH_LENGTH];               // Directory to monitor

    printf("\nEnter directory to monitor in real-time: ");
    scanf("%s", directoryPath);

    normalizeFilePath(directoryPath);                   // Clean formatting

    startDirectoryMonitor(directoryPath,                // Begin monitoring loop
                          signatureList,
                          signatureCount);
}

//**********************************************************
// main()
//**********************************************************
int main(void)
{
    Signature signatureList[MAX_SIGNATURES];           // Array holding signatures
    int signatureCount = 0;                            // Number of loaded signatures
    int menuChoice = 0;                                // User's menu selection
    int signaturesLoaded = 0;                          // Whether signatures loaded

    while (1)                                           // Main loop
    {
        printMainMenu();                                // Display menu
        scanf("%d", &menuChoice);                       // Read choice

        switch (menuChoice)                             // Handle menu choice
        {
            case 1:
            {
                printf("\nLoading signatures from: %s\n",
                       SIGNATURE_FILE_PATH);

                signaturesLoaded =
                    loadSignaturesFromFile(SIGNATURE_FILE_PATH,
                                           signatureList,
                                           &signatureCount);

                if (signaturesLoaded)
                {
                    printf("Loaded %d signatures successfully.\n",
                           signatureCount);
                }
                else
                {
                    printf("Failed to load signatures.\n");
                }
                break;
            }

            case 2:
            {
                if (!signaturesLoaded)
                {
                    printf("\nERROR: Load signatures first!\n");
                }
                else
                {
                    handleScanSingleFile(signatureList,
                                         signatureCount);
                }
                break;
            }

            case 3:
            {
                if (!signaturesLoaded)
                {
                    printf("\nERROR: Load signatures first!\n");
                }
                else
                {
                    handleScanDirectory(signatureList,
                                        signatureCount);
                }
                break;
            }

            case 4:
            {
                handleHashFile();                       // Hash a file
                break;
            }

            case 5:
            {
                if (!signaturesLoaded)
                {
                    printf("\nERROR: Load signatures first!\n");
                }
                else
                {
                    handleMonitorDirectory(signatureList,
                                           signatureCount);
                }
                break;
            }

            case 6:
            {
                printf("\nExiting Malware Scanner.\n");
                return 0;                               // End program
            }

            default:
            {
                printf("\nInvalid selection. Try again.\n");
                break;
            }
        }
    }

    return 0;                                           // Unreachable, but included
} // end main()
