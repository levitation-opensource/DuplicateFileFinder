## Duplicate file finder and de-duplicator

Usage: 
<br>`DuplicateFileFinder.exe <minSizeBytes> <directoryToScan> <sharedDirectory> [<hashCacheRoot>] [try-run]`

Example: 
<br>`DuplicateFileFinder.exe 1000000 D:\\ D:\\___SharedDuplicates D:\\ try-run`

When `hashCacheRoot` argument is omitted then hash cache is disabled.

In `try-run` mode no files will be moved or symlinked, duplicates are only reported in the console.


### State
Ready to use. Maintained and in active use.


### Installation

    * Build the project
    * In the build folder launch DuplicateFileFinder.exe


[![Analytics](https://ga-beacon.appspot.com/UA-351728-28/DuplicateFileFinder/README.md?pixel)](https://github.com/igrigorik/ga-beacon)    
