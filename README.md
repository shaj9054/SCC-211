# FAT16 File System Inspection Utility

A C command-line utility for exploring the relationship between FAT16 disk metadata, directory entries and stored file content. Developed as operating-systems coursework for SCC-211.

## Features

- Reads boot-sector fields such as bytes per sector, sectors per cluster and FAT size.
- Loads the file allocation table into memory.
- Follows a file's cluster chain from a user-supplied starting cluster.
- Lists root-directory metadata, including filenames, starting clusters, sizes, modification timestamps and attributes.
- Reads and displays the contents of a selected data cluster.
- Prints diagnostics for opening, seeking and reading failures in the cluster-reading routine.

## Requirements and running

Use a C compiler in a POSIX-style environment. Keep the supplied disk image in the working directory:

```bash
git clone https://github.com/shaj9054/SCC-211.git\ncd SCC-211\ngcc -Wall -Wextra OpSys.c -o fat16_inspector\n./fat16_inspector
```

The utility reads the hard-coded filename `fat16.img`. It asks for a file's starting cluster and then a cluster to inspect. Choose values that are valid for the supplied image.

## Main files

| File | Purpose |
| --- | --- |
| `OpSys.c` | FAT16 structures, metadata parsing, cluster traversal and interactive driver. |
| `fat16.img` | Supplied FAT16 image used by the program. |

## Learning focus

Binary file access, C structures, bitwise metadata decoding, disk offsets, memory allocation and the organisation of a simple file system.

## Implementation notes

This is an educational inspector, not a recovery or repair tool. It makes assumptions about structure layout and byte order. Several calls pass a character literal to `open` instead of the usual POSIX flag, and file-operation checks are incomplete. Cluster inputs and chain traversal are not fully validated, so malformed images or invalid values can cause incorrect output, a crash or an endless traversal.

Use the supplied image for experiments; output should not be treated as validated forensic evidence. The code does not include a general file-system integrity check.

## Project context

University coursework for **SCC-211** at Lancaster University. Language: **C**. Repository owner: **Mohammed Shajalal Sarwar**. Some repositories include supplied coursework support code; original source attributions are retained.
