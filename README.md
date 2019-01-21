# custom-filesystem

This is a simple experimental project I made to try out how hard it would be to make a basic, but functional file system for removable devices.

The file system can be accessed through an FTP interface.

## Installation

Clone the repository and use the build command below.

## Build command

```
go build main.go
```

## Preparation

Before you can use the program, you have to edit the flash memory with a Hex editor.

Change the first 6 bytes of the flash memory content to 'CUSTOM'. This indicates to the program, that it can safely access and modify the device's memory.

## Capabilities

* 1 GB of usable space (with default settings)
* Only supports files (you can't create folders)
* Filenames are limited to 255 character (including extension)
* Benchmarking write speed

## FTP Interface

The FTP server is running on port **3000**. **Any username and password** pair will grant access to the file system.

## Implementation

The program uses only the most basic system calls, namely `syscall.Open`, `syscall.Seek`, `syscall.Read` and `syscall.Write`.

This means that we can access the removable device on the lowest possible level, in raw mode. The operating system won't recognize a device created with this program.

In raw mode, the concept of files and folders doesn't exist. We can only see and edit the device's flash memory as an array of bytes.

It is up to the implementation, what it considers a file or a folder and in what format it stores the data and the metadata structure.

**File table structure**

<p align="center">
  <img width="518" height="106" src="https://github.com/Hiroko103/custom-filesystem/blob/master/file-structure.png">
</p>

According to the structure, the minimum metadata size for one file is at least 13 bytes (8 + 1 + 4).

The maximum file table size is 2048 bytes, which is located at the very start of the flash memory. Assuming an average of 10 character long filenames, the current implementation can store around 80 files.

This is not much by no means, but it can be increased by changing `FILE_TABLE_SIZE` and `FS_START` constants. `FS_START` should always be `>= (FILE_TABLE_SIZE / SECTOR)`. Otherwise, actual file data may overwrite part of the table.

`FS_START` is the sector from which file data area stored.

`FS_END` is the end of the file system in bytes. File data after this point cannot be stored, but this value can also be increased.

## Benchmarking

If you create a file called 'benchmark' through the FTP interface, it will create a file with the size of around 6,5 MB. During the operation, it will print log messages about how much data was transferred in a given time. At the end of the operation, the benchmark file is automatically removed.

## License

This software is released under the MIT license.

>  A short and simple permissive license with conditions only requiring preservation of copyright and license notices. Licensed works, modifications, and larger works may be distributed under different terms and without source code.

Refer to the [LICENSE](https://github.com/Hiroko103/game-of-life-simulation/blob/master/LICENSE) file for the complete text.
