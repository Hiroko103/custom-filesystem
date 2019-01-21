package main

import (
    "syscall"
    "encoding/binary"
    "fmt"
    "sort"
    "io"
    "github.com/koofr/graval"
    "os"
    "time"
    "errors"
    "sync"
    "bytes"
    "github.com/fatih/color"
    "strconv"
    "github.com/StackExchange/wmi"
    "bufio"
    "strings"
)

const MAGIC = "CUSTOM"  // FileSystem identifier
                        // A disk with custom filesystem should start with this string
const SECTOR = 512      // Sector size in bytes
const FILE_TABLE_SIZE = 2048 // Maximum size of the file table in bytes
const FS_START = 8      // Files are stored from this sector
const FS_END = 1 * 1024 * 1024 // 1 GB
var fs *FileSystem

//////////////////////////////////////////////////////////////////////////////////
///                                 FTP                                        ///
//////////////////////////////////////////////////////////////////////////////////

type fileServer struct {

}

type Driver struct {

}

type File struct {
    filename string
    size int64
}

func (f *File) Name() string {
    return f.filename
}

func (f *File) Size() int64 {
    return f.size
}

func (f *File) Mode() os.FileMode {
    return 0777
}

func (f *File) ModTime() time.Time {
    return time.Now()
}

func (f *File) IsDir() bool {
    return false
}

func (f *File) Sys() interface{} {
    return nil
}

func (d *Driver) Authenticate(username string, password string) bool {
    return true
}

func (d *Driver) Bytes(path string) int64 {
    return 0
}

func (d *Driver) ModifiedTime(path string) (time.Time, bool) {
    return time.Now(), false
}

func (d *Driver) ChangeDir(path string) bool {
    return true
}

func (d *Driver) DirContents(path string) ([]os.FileInfo, bool) {
    files := make([]os.FileInfo, 0)
    for _, file := range fs.fileList {
        f := File{}
        f.filename = file.filename
        f.size = int64(file.size)
        files = append(files, &f)
    }
    return files, true
}

func (d *Driver) DeleteDir(path string) bool {
    return false
}

func (d *Driver) DeleteFile(path string) bool {
    fs.DeleteFile(path[1:])
    return true
}

func (d *Driver) Rename(fromPath string, toPath string) bool {
    fs.RenameFile(fromPath[1:], toPath[1:])
    return true
}

func (d *Driver) MakeDir(path string) bool {
    return false
}

func (d *Driver) GetFile(path string, position int64) (io.ReadCloser, bool) {
    file, err := fs.GetFile(path[1:])
    if err != nil {
        return &FileEntryReader{file: &file}, false
    }
    return &FileEntryReader{file: &file}, true
}

func (d *Driver) PutFile(path string, reader io.Reader) bool {
    fs.WriteLock.Lock()
    defer fs.WriteLock.Unlock()

    newFile := &FileEntry{
        sector: fs.getFreeSpace(0),
        filenameLength: byte(len(path[1:])),
        filename: path[1:],
    }

    buff := make([]byte, 64 * 1024)
    var writeBuffer []byte

    if path[1:] == "benchmark" {
        fs.Benchmark(newFile, 64 * 1024)
        return true
    }

    for {
        n, err := reader.Read(buff)
        if err != nil {
            if err == io.EOF {
                fs.RegisterFile(newFile)
                return true
            }
        }
        writeBuffer = buff[:n]
        fs.FastAppend(newFile, &writeBuffer)
    }
    return true
}

func (s *fileServer) NewDriver() (_driver graval.FTPDriver, err error) {
    d := &Driver{}
    return d, nil
}

//////////////////////////////////////////////////////////////////////////////////
///                          FileSystem                                        ///
//////////////////////////////////////////////////////////////////////////////////

type FileEntry struct {
    filename string
    filenameLength byte
    sector uint64 // Sector Index
    size uint32   // Size in bytes
}

type FileEntryReader struct {
    file *FileEntry
    read uint
}

type FileSystem struct {
    fileList []FileEntry
    handle syscall.Handle
    size uint64
    WriteLock *sync.Mutex
}

type Range struct {
    start uint64
    end uint64
}

func (r *Range) Valid() bool {
    if r.end >= r.start {
        return true
    }
    return false
}

func SectorFit(offset, size uint64) (uint64, uint64){
    start := offset / SECTOR * SECTOR
    end := (offset + size) / SECTOR * SECTOR
    if end != offset + size {
        end += SECTOR
    }
    return start, end
}

func (f *FileEntryReader) NewReader(file *FileEntry) (*FileEntryReader) {
    return &FileEntryReader{file: file}
}

func (f *FileEntryReader) Read(p []byte) (int, error) {
    remaining := uint(uint(f.file.size) - f.read)
    size := uint(len(p))
    var read uint
    if remaining > size {
        read = size
    } else {
        read = remaining
    }
    buf, n, err := fs.Read(fs.handle, int64(f.file.sector) * int64(SECTOR) + int64(f.read), read)
    f.read += uint(n)
    if err != nil {
        return 0, err
    }
    copy(p, *buf)
    if uint(f.file.size) == f.read {
        return n, io.EOF
    }
    return n, nil
}

func (f *FileEntryReader) Close() error {
    return nil
}

func (f *FileEntry) Serialize() *[]byte {
    entry := make([]byte, 8 + 1 + len(f.filename) + 4)
    binary.BigEndian.PutUint64(entry[:8], f.sector)
    entry[8] = f.filenameLength
    copy(entry[9:], []byte(f.filename))
    binary.BigEndian.PutUint32(entry[len(entry)-4:], f.size)
    return &entry
}

func (f *FileEntry) LastSector() uint64 {
    sector := f.sector + uint64(f.size / SECTOR) // Inclusive
    if f.size > 0 && f.size % SECTOR == 0 {
        sector -= 1
    }
    return sector
}

func (fs *FileSystem) New(disk string) (*FileSystem, error) {
    var err error = nil
    fs.WriteLock = &sync.Mutex{}
    fs.handle, err = fs.OpenDisk(disk)
    if err != nil {
        fmt.Fprintf(color.Output, color.HiRedString("The program doesn't have administrator access\n"))
        return fs, err
    }
    start, _, err := fs.Read(fs.handle, 0, uint(len(MAGIC)))
    if err != nil {
        return fs, errors.New("cant read from disk")
    }
    if !bytes.Equal(*start, []byte(MAGIC)) {
        return fs, errors.New("not a custom filesystem")
    }
    fs.fileList = fs.ReadFileList()
    return fs, nil
}

func (fs *FileSystem) initFileSystem() bool {
    b := make([]byte, FILE_TABLE_SIZE)
    copy(b, []byte(MAGIC))
    _, err := fs.Write(fs.handle, 0, &b)
    if err != nil {
        return false
    }
    return true
}

func (fs *FileSystem) initFileSystemToBuffer(b *[]byte) {
    copy(*b, []byte(MAGIC))
}

func (fs *FileSystem) ReadFileList() []FileEntry {
    filelist := make([]FileEntry, 0)
    table, _, _ := fs.Read(fs.handle, 0, FILE_TABLE_SIZE)
    file := FileEntry{}

    c := len(MAGIC)

    for {
        file.sector = binary.BigEndian.Uint64((*table)[c:c+8])

        if file.sector != 0 {
            c += 8
            file.filenameLength = (*table)[c]
            c += 1
            file.filename = string((*table)[c:c+int(file.filenameLength)])
            c += int(file.filenameLength)
            file.size = binary.BigEndian.Uint32((*table)[c:c+4])
            c += 4
            filelist = append(filelist, file)
        } else {
            break
        }
    }
    return filelist
}

func (fs *FileSystem) GetFile(filename string) (FileEntry, error) {
    for _, file := range fs.fileList {
        if file.filename == filename {
            return file, nil
        }
    }
    return FileEntry{}, errors.New("file doesn't exist")
}

func (fs *FileSystem) RegisterFile(file *FileEntry) error {
    fs.DeleteFile(file.filename)
    fs.fileList = append(fs.fileList, *file)
    err := fs.WriteTable(&fs.fileList)
    if err != nil {
        fs.DeleteFile(file.filename)
        return err
    }
    return nil
}

func (fs *FileSystem) PutFile(file *FileEntry, data *[]byte){
    fs.DeleteFile(file.filename)
    file.sector = fs.getFreeSpace(uint64(file.size))
    fs.Write(fs.handle, int64(file.sector) * SECTOR, data)
    fs.fileList = append(fs.fileList, *file)
    fs.WriteTable(&fs.fileList)
}

func (fs *FileSystem) FastAppend(file *FileEntry, data *[]byte) {
    benchmark := time.Now()
    fs.Write(fs.handle, int64(file.sector) * SECTOR + int64(file.size), data)
    file.size += uint32(len(*data))
    elapsed := time.Since(benchmark)
    fmt.Fprintf(color.Output, "%s\n", "Appended " + color.GreenString(strconv.Itoa(len(*data))) + " bytes to " + color.GreenString(file.filename) +
        " in " + color.GreenString(elapsed.String()) + " (size: " + color.YellowString(strconv.Itoa(int(file.size))) + ")")
}

func (fs *FileSystem) clearTable() {
    fs.initFileSystem()
}

func (fs *FileSystem) WriteTable(fileTable *[]FileEntry) error {
    buff := make([]byte, FILE_TABLE_SIZE)
    fs.initFileSystemToBuffer(&buff)

    c := int64(6)

    for _, file := range *fileTable {
        entryBinary := file.Serialize()
        if c + int64(len(*entryBinary)) <= FILE_TABLE_SIZE {
            copy(buff[c:], *entryBinary)
            c += int64(len(*entryBinary))
        } else {
            err := errors.New("not enough space for filetable")
            fmt.Fprintf(color.Output, color.HiRedString(err.Error()) + "\n")
            return err
        }
    }

    fs.Write(fs.handle, 0, &buff)
    return nil
}

func (fs *FileSystem) DeleteFile(filename string){
    var file *FileEntry

    rewrite := false

    for i := 0; i < len(fs.fileList); i++ {
        file = &fs.fileList[i]
        if file.filename == filename {
            rewrite = true
            copy(fs.fileList[i:], fs.fileList[i+1:])
            fs.fileList[len(fs.fileList)-1] = FileEntry{} // or the zero value of T
            fs.fileList = fs.fileList[:len(fs.fileList)-1]
            i--
        }
    }
    if rewrite {
        fs.WriteTable(&fs.fileList)
    }
}

func (fs *FileSystem) RenameFile(from, to string) {
    rewrite := false

    for i, _ := range fs.fileList {
        file := &fs.fileList[i]
        if file.filename == from {
            rewrite = true
            file.filename = to
            file.filenameLength = byte(len(to))
        }
    }
    if rewrite {
        fs.WriteTable(&fs.fileList)
    }
}

func (fs *FileSystem) getFreeSpace(size uint64) uint64 {
    usedSpaces := make([]Range, len(fs.fileList))
    freeSpaces := make([]Range, 0)
    var r *Range

    i := 0

    for _, file := range fs.fileList {
        usedSpaces[i].start = file.sector
        usedSpaces[i].end = file.LastSector()
        i++
    }

    sort.Slice(usedSpaces, func(i, j int) bool {return usedSpaces[i].start < usedSpaces[j].start})

    if len(fs.fileList) == 0 {
        return FS_START
    }

    if len(fs.fileList) == 1 {
        r = &Range{FS_START, fs.fileList[0].sector - 1}
        if r.Valid() {
            freeSpaces = append(freeSpaces, *r)
        }
        r = &Range{fs.fileList[0].LastSector() + 1, FS_END}
        if r.Valid() {
            freeSpaces = append(freeSpaces, *r)
        }
    } else {
        i = FS_START

        r = &Range{FS_START, fs.fileList[0].sector - 1}
        if r.Valid() {
            freeSpaces = append(freeSpaces, *r)
        }

        for k := 0; k < len(fs.fileList) - 1; k++ {
            file := &fs.fileList[k]
            next := &fs.fileList[k+1]
            r = &Range{file.LastSector() + 1, next.sector - 1}
            if r.Valid() {
                freeSpaces = append(freeSpaces, *r)
            }
        }

        last := &fs.fileList[len(fs.fileList) - 1]
        r = &Range{last.LastSector() + 1, FS_END}
        if r.Valid() {
            freeSpaces = append(freeSpaces, *r)
        }
    }

    sort.Slice(freeSpaces, func(i, j int) bool {return freeSpaces[i].end - freeSpaces[i].start + 1 > freeSpaces[j].end - freeSpaces[j].start + 1})

    return freeSpaces[0].start
}

func (fs *FileSystem) OpenDisk(disk string) (syscall.Handle, error) {
    fd, err := syscall.Open(disk, syscall.O_RDWR, 0777)
    if err != nil {
        return fd, err
    }
    return fd, nil
}

func (fs *FileSystem) Read(fd syscall.Handle, offset int64, n uint) (*[]byte, int, error) {
    start, end := SectorFit(uint64(offset), uint64(n))
    buff := make([]byte, end-start)
    syscall.Seek(fd, int64(start), 0)
    _, err := syscall.Read(fd, buff)
    if err != nil {
        return &[]byte{}, 0, err
    }
    buff = buff[uint64(offset)-start:uint64(offset)-start+uint64(n)]
    return &buff, int(n), err
}

func (fs *FileSystem) Write(fd syscall.Handle, offset int64, data *[]byte) (int, error) {
    start, end := SectorFit(uint64(offset), uint64(len(*data)))
    b := make([]byte, end - start)
    buff := &b
    if len(*data) > 2 * SECTOR {
        overlapBuffer, _, _ := fs.Read(fs.handle, int64(start), SECTOR)
        copy(*buff, *overlapBuffer)
        overlapBuffer, _, _ = fs.Read(fs.handle, int64(end) - SECTOR, SECTOR)
        copy((*buff)[end-start-SECTOR:], *overlapBuffer)
    } else {
        buff, _, _ = fs.Read(fs.handle, int64(start), uint(end - start))
    }
    copy((*buff)[uint64(offset) - start:], *data)
    syscall.Seek(fd, int64(start), 0)
    n, err := syscall.Write(fd, *buff)
    return n, err
}

func (fs *FileSystem) Benchmark(file *FileEntry, size uint) {
    buff := make([]byte, size)
    for i := 0; i < 100; i++ {
        fs.FastAppend(file, &buff)
    }
}

type Win32_DiskDrive struct {
    Name string
    Model string
    Size uint64
}

func selectDevice() (string, error) {
    var err error = nil
    var devices []Win32_DiskDrive
    reader := bufio.NewReader(os.Stdin)

    fmt.Println("Select the disk with the custom filesystem:")
    q := wmi.CreateQuery(&devices, "")
    err = wmi.Query(q, &devices)
    if err != nil {
        fmt.Println(err)
        return "", errors.New("WMI query failed")
    }
    for i, device := range devices {
        fmt.Print(strconv.Itoa(i) + ": ")
        fmt.Println(device.Model, device.Size / 1000 / 1000 / 1000, "GB")
    }

    fmt.Print("Enter the device index: ")
    text, _ := reader.ReadString('\n')
    text = strings.TrimSuffix(text, "\n")
    text = strings.TrimSuffix(text, "\r")
    index, err := strconv.Atoi(text)
    if err != nil {
        fmt.Println(err)
        return "", errors.New("invalid index")
    }
    if index < 0 && index >= len(devices) {
        return "", errors.New("selected index is out of range")
    }
    return devices[index].Name, nil
}

func main() {
    var err error = nil

    disk, err := selectDevice()
    if err != nil {
        fmt.Println(err)
        return
    }
    fs, err = (&FileSystem{}).New(disk)
    if err != nil {
        fmt.Fprintf(color.Output, color.HiRedString(err.Error()))
        return
    }
    fmt.Fprintf(color.Output, color.HiGreenString("FileSystem initialized\n"))
    options := graval.FTPServerOpts{
        ServerName: "Custom filesystem",
        Factory: &fileServer{},
        PassiveOpts: &graval.PassiveOpts{
            PassivePorts: &graval.PassivePorts{
                Low: 49152,
                High: 65535,
            },
        },
    }
    ftp := graval.NewFTPServer(&options)
    fmt.Fprintf(color.Output, color.HiGreenString("FTP interface started\n"))
    ftp.ListenAndServe()
}