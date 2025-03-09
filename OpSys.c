#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

typedef struct __attribute__((__packed__))
{
    uint8_t BS_jmpBoot[3];    // x86 jump instr. to boot code
    uint8_t BS_OEMName[8];    // What created the filesystem
    uint16_t BPB_BytsPerSec;  // Bytes per Sector
    uint8_t BPB_SecPerClus;   // Sectors per Cluster
    uint16_t BPB_RsvdSecCnt;  // Reserved Sector Count
    uint8_t BPB_NumFATs;      // Number of copies of FAT
    uint16_t BPB_RootEntCnt;  // FAT12/FAT16: size of root DIR
    uint16_t BPB_TotSec16;    // Sectors, may be 0, see below
    uint8_t BPB_Media;        // Media type, e.g. fixed
    uint16_t BPB_FATSz16;     // Sectors in FAT (FAT12 or FAT16)
    uint16_t BPB_SecPerTrk;   // Sectors per Track
    uint16_t BPB_NumHeads;    // Number of heads in disk
    uint32_t BPB_HiddSec;     // Hidden Sector count
    uint32_t BPB_TotSec32;    // Sectors if BPB_TotSec16 == 0
    uint8_t BS_DrvNum;        // 0 = floppy, 0x80 = hard disk
    uint8_t BS_Reserved1;     //
    uint8_t BS_BootSig;       // Should = 0x29
    uint32_t BS_VolID;        // 'Unique' ID for volume
    uint8_t BS_VolLab[11];    // Non zero terminated string
    uint8_t BS_FilSysType[8]; // e.g. 'FAT16 ' (Not 0 term.)
} BootSector;

typedef struct
{
    uint8_t DIR_Name[11];     // Non zero terminated string
    uint8_t DIR_Attr;         // File attributes
    uint8_t DIR_NTRes;        // Used by Windows NT, ignore
    uint8_t DIR_CrtTimeTenth; // Tenths of sec. 0...199
    uint16_t DIR_CrtTime;     // Creation Time in 2s intervals
    uint16_t DIR_CrtDate;     // Date file created
    uint16_t DIR_LstAccDate;  // Date of last read or write
    uint16_t DIR_FstClusHI;   // Top 16 bits file's 1st cluster
    uint16_t DIR_WrtTime;     // Time of last write
    uint16_t DIR_WrtDate;     // Date of last write
    uint16_t DIR_FstClusLO;   // Lower 16 bits file's 1st cluster
    uint32_t DIR_FileSize;    // File size in bytes

} DirectoryEntry;

typedef struct
{
    uint8_t LDIR_Ord;        // Order/ position in sequence/ set
    uint8_t LDIR_Name1[10];  // First 5 UNICODE characters
    uint8_t LDIR_Attr;       // = ATTR_LONG_NAME (xx001111)
    uint8_t LDIR_Type;       // Should = 0
    uint8_t LDIR_Chksum;     // Checksum of short name
    uint8_t LDIR_Name2[12];  // Middle 6 UNICODE characters
    uint16_t LDIR_FstClusLO; // MUST be zero
    uint8_t LDIR_Name3[4];   // Last 2 UNICODE characters
} LongFile;

// Function to open the file and read the BootSector
int openAndReadBootSector(const char *fat16, BootSector *bootSector)
{
    int fd = open("fat16.img", 'r');
    ssize_t bytes_read = read(fd, bootSector, sizeof(BootSector));

    close(fd);
    return 0;
}

// Function to load the FAT into memory
int loadFAT(const BootSector *bootSector, uint16_t **fat)
{
    // this calculates the starting position of the fat table
    off_t fat_start = bootSector->BPB_RsvdSecCnt * bootSector->BPB_BytsPerSec;

    // this opens the fat16 file for reading
    int fd = open("fat16.img", 'r');

    // allocates memory to store in the fat table
    *fat = (uint16_t *)malloc(bootSector->BPB_FATSz16 * bootSector->BPB_BytsPerSec);

    // moves the file cursor to the start of the fat table
    lseek(fd, fat_start, SEEK_SET);

    // this read the fat into the allocated memory
    ssize_t bytes_read = read(fd, *fat, bootSector->BPB_FATSz16 * bootSector->BPB_BytsPerSec);

    close(fd);
    return 0;
}

void printBootSector(BootSector *bootSector)
{
    // output Boot Sector information
    printf("Bytes per Sector: %u\n", bootSector->BPB_BytsPerSec);
    printf("Sectors per Cluster: %u\n", bootSector->BPB_SecPerClus);
    printf("Reserved Sector Count: %u\n", bootSector->BPB_RsvdSecCnt);
    printf("Number of copies of FAT: %u\n", bootSector->BPB_NumFATs);
    printf("FAT12/FAT16: size of root DIR: %u\n", bootSector->BPB_RootEntCnt);
    printf("Sectors, may be 0, see below: %u\n", bootSector->BPB_TotSec16);
    printf("Sectors in FAT (FAT12 or FAT16): %u\n", bootSector->BPB_FATSz16);
    printf("Sectors if BPB_TotSec16 == 0: %u\n", bootSector->BPB_TotSec32);
    printf("Non zero terminated string: %s\n", bootSector->BS_VolLab);
}

// funtion to print the clusters
// Given a Starting Cluster, Produce an Ordered List of Clusters for a File
void printFileClusters(uint16_t *fat, uint16_t start_cluster)
{
    printf("Clusters for the file starting from cluster %u:\n", start_cluster);
    uint16_t next_cluster = start_cluster;

    // traverses through the FAT entries of a file starting from a specified cluster
    // prints the sequence of of the clusters that make up a file

    while (1)
    {
        // prints the cluster number that is currently being processed
        // Retrieves the next cluster number in the sequence based on the current cluster number by accessing the FAT array.
        printf("%u -> ", next_cluster);
        next_cluster = fat[next_cluster];

        // 0xfff8 is the end of the the file
        // exits loop using break
        if (next_cluster >= 0xfff8)
        {
            printf("65528.\n");
            break;
        }
    }
}

// Function to read and print the content of a specified cluster within the FAT16 image file
void printNCluster(const BootSector *bootSector, uint16_t *fat, int nth_cluster, uint8_t *buffer, size_t bytes_to_read)
{
    int fd = open("fat16.img", 'r');
    if (fd == -1)
    {
        perror("Error opening file");
        return;
    }
    // Calculate the extra offset for the data section
    //
    off_t extraOffset = bootSector->BPB_RsvdSecCnt * bootSector->BPB_BytsPerSec +
                        (bootSector->BPB_NumFATs * bootSector->BPB_FATSz16 * bootSector->BPB_BytsPerSec) +
                        (bootSector->BPB_RootEntCnt * 32); // Size of root directory

    // Calculate the cluster's offset within the data section
    // subtracts 2 from the cluster number because clusters are indexed from 0-2 but in fat 16 it starts at 2
    off_t cluster_offset = (nth_cluster - 2) * bootSector->BPB_SecPerClus * bootSector->BPB_BytsPerSec;

    // Add the cluster's offset to the extra offset to reach the correct data sector
    // The resulting extraOffset now represents the position in the file where the data of the specified cluster begins
    extraOffset += cluster_offset;

    // moves the file cursor to the calculated offset
    off_t seek_result = lseek(fd, extraOffset, SEEK_SET);
    if (seek_result == -1)
    {
        perror("Error seeking to cluster");
        close(fd);
        return;
    }

    ssize_t bytes_read = read(fd, buffer, bytes_to_read);
    if (bytes_read == -1)
    {
        perror("Error reading cluster");
        close(fd);
        return;
    }

    // prints the contents of the cluster
    printf("Bytes read from cluster %d:\n", nth_cluster);
    for (ssize_t i = 0; i < bytes_read; i++)
    {
        printf("%c", buffer[i]);
    }
    printf("\n");

    close(fd);
}

// Function to access and process root directory entries
void processRootDirectory(const BootSector *bootSector)
{
    int fd = open("fat16.img", 'r');

    // Calculate the starting sector of the root directory
    off_t rootDirStart = bootSector->BPB_RsvdSecCnt + bootSector->BPB_NumFATs * bootSector->BPB_FATSz16;
    off_t seek_result = lseek(fd, rootDirStart * bootSector->BPB_BytsPerSec, SEEK_SET);

    DirectoryEntry entry;

    // Print headers
    printf(" Starting Cluster \t Last Modified  \t   File Size \t Attributes \t  File Name \n");

    // Read and process directory entries
    // the while loop reads DirectoryEntry from the file fd
    // the loop continues as long as there are bytes to read
    while (read(fd, &entry, sizeof(DirectoryEntry)) > 0)
    {
        // Check for end of directory or unused entry
        // this condition checks the first byte of DIR_Name array
        // a value starting with 0x00 means that there are no valid entries
        // a value with 0xE5 means a deleted entry
        if (entry.DIR_Name[0] == 0x00 || entry.DIR_Name[0] == 0xE5)
        {
            if (entry.DIR_Name[0] == 0x00)
            {
                // No further valid entries in the directory
                break;
            }
            else
            {
                // Unused entry due to a deleted file, ignore and moves on to the next iteration to read the directory
                continue;
            }
        }

        // Check if it's a regular file
        // Condition 1: Check if the lower four bits of DIR_Attr are all zero or if DIR_FileSize is zero
        // Condition 2: Check if the first byte of the name is not a deleted file marker (0xE5)
        // and not indicating the end of valid entries (0x00)
        if (((entry.DIR_Attr & 0x0F) == 0x00 || entry.DIR_FileSize == 0) && entry.DIR_Name[0] != 0xE5 && entry.DIR_Name[0] != 0x00)
        {

            int year = ((entry.DIR_WrtDate >> 9) & 0x7F) + 1980; // extract the year
            int month = (entry.DIR_WrtDate >> 5) & 0x0F;         // extracts the month
            int day = entry.DIR_WrtDate & 0x1F;                  // extracts the day

            int hour = (entry.DIR_WrtTime >> 11) & 0x1F;  // extracts the hour
            int minute = (entry.DIR_WrtTime >> 5) & 0x3F; // extracts the minutes
            int second = (entry.DIR_WrtTime & 0x1F) * 2;  // extracts the seconds

            // attributes is an array to hold the file attribute characters
            char attributeLetters[] = "ADVSHR";
            char attributes[7];

            // Interpret attributes based on bit positions
            // the loop processes each attribute and assigns the appropriate character
            // The loop iterates six times because there are six relevant file attributes to check
            // (1 << (5 - i))  shifts the value 1 to the left by (5 - i) positions
            for (int i = 0; i < 6; i++)
            {
                // if the attribute is a non zero value e.g 1 then assign a letter
                // left shift operation It takes the value 1 and shifts its binary representation to the left by (5 - i) positions
                // else assign a - which is an unset flag represented by 0
                if (entry.DIR_Attr & (1 << (5 - i)))
                {
                    attributes[i] = attributeLetters[i];
                }
                else
                {
                    attributes[i] = '-';
                }
            }

            printf(" %-16u \t %d-%02d-%02d %02d:%02d:%02d          %-9u  %-10s \t  %.11s \t\n",
                   entry.DIR_FstClusLO, year, month, day, hour, minute, second,
                   entry.DIR_FileSize, attributes, entry.DIR_Name);
        }
    }

    close(fd);
}

int main()
{
    BootSector bootSector;

    openAndReadBootSector("fat16.img", &bootSector);

    uint16_t *fat;
    loadFAT(&bootSector, &fat);

    // output Boot Sector information
    printBootSector(&bootSector);

    // to store the starting cluster number entered by the user
    uint16_t start_cluster;
    // Displays a message prompting the user to input the starting cluster number
    printf("Enter the starting cluster: ");
    // Reads the user input and stores it in the start_cluster
    scanf("%hu", &start_cluster);
    printFileClusters(fat, start_cluster);

    // Process the root directory
    processRootDirectory(&bootSector);

    size_t bytes_to_read = bootSector.BPB_SecPerClus * bootSector.BPB_BytsPerSec; // Modify this based on your requirements
    int nth_cluster;
    printf("Enter the cluster to read: ");
    scanf("%d", &nth_cluster);

    // Allocate memory for buffer
    uint8_t *buffer = (uint8_t *)malloc(bytes_to_read);
    // Call the function to read the nth cluster
    printNCluster(&bootSector, fat, nth_cluster, buffer, bytes_to_read);

    // free the allocated memory
    free(buffer);
    free(fat);
}