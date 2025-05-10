//
// Copyright (c) Roland Pihlakas 2025
// roland@simplify.ee
//
// Roland Pihlakas licenses this file to you under the GNU Lesser General Public License, ver 2.1.
// See the LICENSE file for more information.
//

using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Collections;
using System.Threading;
using System.Diagnostics;
using System.Security.AccessControl;

namespace DuplicateFileFinder
{
    class Program
    {
        const int SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE = 0x2;

        private const FileAttributes SkipFilesWithAttributes = (
                                                            FileAttributes.ReparsePoint
                                                            | FileAttributes.Offline
                                                            | FileAttributes.Encrypted
                                                            //| FileAttributes.Temporary    //TODO: option to skip these files
                                                        );

        //P/Invoke for creating symbolic links on Windows
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateSymbolicLink(string lpFileName, string lpExistingFileName, int flags);

        private class AllFileAttributes
        {
            public FileAttributes? Attributes;
            public DateTime? CreationTime;
            public DateTime? ModificationTime;
            public DateTime? AccessTime;
            public FileSecurity AccessControl;
        }

        private static void Main(string[] args)
        {
            int deletionRetryCount = 10;        //TODO: parse from command line or from config file

            //Basic argument parsing

            //TODO implement logging to file not just to console
            //TODO print statistics about freed part size minus shared part size
            //TODO implment option to provide arguments via config file

            //An optional fourth argument: "try-run" which will skip the actual moving/linking steps.
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: DuplicateFileFinder.exe <minSizeBytes> <directoryToScan> <sharedDirectory> [<hashCacheRoot>] [try-run]");
                Console.WriteLine("Example: DuplicateFileFinder.exe 1000000 C:\\ C:\\___SharedDuplicates C:\\ try-run");
                Console.WriteLine("When hashCacheRoot argument is omitted then hash cache is disabled.");
                Console.WriteLine("In try-run mode no files will be moved or symlinked, duplicates are only reported in the console.");

                return;
            }

            //Required arguments
            if (
                !long.TryParse(args[0], out long minSizeBytes)
                || minSizeBytes < 1024  //deduplicating smaller files is meaningless since there will be symbolic link + hash cache file, which each consume at least 512 bytes
            )
            {
                Console.WriteLine("Error: Invalid minimum size (must be at least 1024).");
                return;
            }

            string directoryToScan = Path.GetDirectoryName(args[1]) ?? Directory.GetDirectoryRoot(args[1]);  //GetDirectoryName: normalize the path. GetDirectoryRoot: If the path is root folder then GetDirectoryName returns null for some reason.
            if (!Directory.Exists(directoryToScan))
            {
                Console.WriteLine($"Error: Directory '{directoryToScan}' does not exist.");
                return;
            }

            string sharedDirectory = Path.GetDirectoryName(args[2]);  //GetDirectoryName: normalize the path  
            if (sharedDirectory == null)
            {
                //TODO: allow root folder in case the shared directory is in a different drive than the source drive
                //TODO: alternatively check that the shared directory is in a same drive than source directory root
                Console.WriteLine($"Error: Shared directory should not be root folder: '{sharedDirectory}'");
                return;
            }
            else if (sharedDirectory.ToUpperInvariant() == directoryToScan.ToUpperInvariant())
            {
                Console.WriteLine($"Shared directory should not be same as directory to scan");
                return;
            }
            else if (!Directory.Exists(sharedDirectory))
            {
                Console.WriteLine($"Shared directory '{sharedDirectory}' does not exist. Creating it...");
                Directory.CreateDirectory(sharedDirectory);
            }

            string hashCacheRoot = null;
            if (args.Length >= 4 && args[3] != "")
            {
                hashCacheRoot = Path.GetDirectoryName(args[3]) ?? Directory.GetDirectoryRoot(args[3]);  //GetDirectoryName: normalize the path. GetDirectoryRoot: If the path is root folder then GetDirectoryName returns null for some reason.
                if (!Directory.Exists(hashCacheRoot))
                {
                    Console.WriteLine($"Hash cache directory '{hashCacheRoot}' does not exist. Creating it...");
                    Directory.CreateDirectory(hashCacheRoot);
                }
            }


            //make the dir name case-insensitive
            //some characters are available only in the upper case
            var sharedDirectoryCaseInsensitive = sharedDirectory.ToUpperInvariant();
            var hashCacheRootCaseInsensitive = hashCacheRoot?.ToUpperInvariant();
            bool hashCacheIsInSameFolderAsFileRoot = (directoryToScan.ToUpperInvariant() == hashCacheRoot?.ToUpperInvariant());


            //Optional argument for try-run
            bool tryRun = false;
            if (args.Length >= 5 && args[4].Equals("try-run", StringComparison.OrdinalIgnoreCase))
            {
                tryRun = true;
                Console.WriteLine("Running in TRY-RUN mode. No files will be moved or symlinked.");
            }

            Console.WriteLine("Scanning files...");
            var files = GetAllFiles(directoryToScan, sharedDirectoryCaseInsensitive, hashCacheRootCaseInsensitive);


            Console.WriteLine("Indexing potential duplicates...");
            //Data structure:
            //filename -> (size -> (hash -> List of file paths))
            //var duplicatesIndex = new Dictionary<string, Dictionary<long, Dictionary<string, List<string>>>>(/*StringComparer.OrdinalIgnoreCase*/);
            var duplicatesIndex = GetAllExistingSharedFiles(sharedDirectory, minSizeBytes);
            long fileIndex = 0;
            foreach (var filePath in files)
            {
                try
                {
                    if (fileIndex % 10000 == 0)
                        Console.WriteLine($"{fileIndex} files scanned...");
                    fileIndex++;


                    FileInfo fi = new FileInfo(filePath);
                    //Filter by size
                    if (fi.Length < minSizeBytes)
                        continue;

                    string filename = fi.Name;
                    long size = fi.Length;

                    //We will lazily compute the hash later (only if we see more than one file with the same name+size).

                    //TODO: Automatically turn off case insensitivity under Linux
                    //TODO: command line option to turn off or on case insensitivity manually
                    var caseInsensitiveFilename = filename.ToUpperInvariant();

                    //Insert a placeholder in dictionary
                    if (!duplicatesIndex.TryGetValue(caseInsensitiveFilename, out var sizeDict))   
                    {
                        sizeDict = new Dictionary<long, Dictionary<string, List<string>>>();        //TODO: Use OrderedDictionary to make hashing and content scanning progress logs more deterministic
                        duplicatesIndex[caseInsensitiveFilename] = sizeDict;
                    }

                    if (!sizeDict.TryGetValue(size, out var hashDict))
                    {
                        hashDict = new Dictionary<string, List<string>>();        //TODO: Use OrderedDictionary to make hashing and content scanning progress logs more deterministic
                        sizeDict[size] = hashDict;
                    }

                    string fileHash = ""; //calculate hashes later only for potentially duplicate files

                    //Insert a placeholder in dictionary
                    if (!hashDict.TryGetValue(fileHash, out var pathList))
                    {
                        pathList = new List<string>();
                        hashDict[fileHash] = pathList;
                    }

                    pathList.Add(filePath);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error accessing file '{filePath}': {ex.Message}");
                }
            }   //foreach (var targetFilePath in files)


            long fileCount = 0;
            long totalBytes = 0;
            Console.WriteLine("Counting potential duplicates...");
            foreach (var filenameEntry in duplicatesIndex)
            {
                foreach (var sizeEntry in filenameEntry.Value)
                {
                    var hashDict = sizeEntry.Value;
                    if (!hashDict.TryGetValue("", out var unhashedFileList))     //it might be that hashdict contains only hash of an earlier file in the shared folder
                    {
                        hashDict.Clear();       //free a bit of memory: remove hashes of earlier files in the shared dir
                        continue;
                    }

                    //if there is a deduplicated file from an earlier run with same name and size then do not require hash count to be >= 2
                    //.Count == 1 means the only entry is the uncomputed hash placeholder value of ""
                    bool haveEarlierSharedFilesWithSameNameAndSize = hashDict.Count > 1;
                    if (!haveEarlierSharedFilesWithSameNameAndSize)
                    {
                        if (unhashedFileList.Count < 2)
                        {
                            hashDict.Clear();    //free a bit of memory: remove the "" entry
                            continue; //not a duplicate set
                        }
                    }
                    else
                    {
                        bool qqq = true;        //for debugging
                    }

                    fileCount += unhashedFileList.Count;
                    totalBytes += unhashedFileList.Count * sizeEntry.Key;
                }
            }

            Console.WriteLine($"Found {fileCount} potential duplicate files, total {totalBytes} bytes");


            var unwritableFolders = new HashSet<string>();
            var delayedDeletions = new HashSet<string>();

            Console.WriteLine("Computing hashes of potential duplicates...");
            fileIndex = 0;
            long processedBytes = 0;
            long lastProcessedBytes = 0;
            foreach (var filenameEntry in duplicatesIndex)
            {
                foreach (var sizeEntry in filenameEntry.Value)
                {
                    var hashDict = sizeEntry.Value;
                    if (!hashDict.TryGetValue("", out var unhashedFileList))    //"" entry is removed by above loop when unhashedFileList.Count < 2
                        continue;
                    
                    try
                    {
                        foreach (var filePath in unhashedFileList)
                        {
                            if (fileIndex % 100 == 0)
                                Console.WriteLine($"{fileIndex} / {fileCount} files hashed...");

                            if (
                                processedBytes / ((long)10 * 1000 * 1000 * 1000)
                                > lastProcessedBytes / ((long)10 * 1000 * 1000 * 1000)
                            )    //bytes will not be exactly divisible in the current loop, therefore cannot use % here
                            {
                                lastProcessedBytes = processedBytes;
                                Console.WriteLine($"{processedBytes} / {totalBytes} bytes hashed...");
                            }

                            fileIndex++;
                            processedBytes += sizeEntry.Key;


                            Console.WriteLine($"Hashing {filePath}");


                            //Compute hash
                            string fileHash = CheckFolderWritabilityAndGetFileHash
                            (
                                hashCacheIsInSameFolderAsFileRoot, 
                                filePath, 
                                hashCacheRoot, 
                                unwritableFolders, 
                                delayedDeletions
                            );
                            if (fileHash == null)   //folder is not writable, therefore no point in processing this file further
                                continue;

                            //Insert into the dictionary
                            if (!hashDict.TryGetValue(fileHash, out var pathList))
                            {
                                pathList = new List<string>();
                                hashDict[fileHash] = pathList;
                            }
                            pathList.Add(filePath);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error accessing file group '{filenameEntry.Key}': {ex.Message}");

                        unhashedFileList.Clear();
                    }

                    hashDict.Remove("");    //free a bit of memory

                }   //foreach (var sizeEntry in filenameEntry.Value)
            }   //foreach (var filenameEntry in duplicatesIndex)


            long fileGroupCount = 0;
            fileCount = 0;
            totalBytes = 0;
            Console.WriteLine("Counting potential duplicates...");
            foreach (var filenameEntry in duplicatesIndex)
            {
                foreach (var sizeEntry in filenameEntry.Value)
                {
                    foreach (var hashEntry in sizeEntry.Value)
                    {
                        var fileList = hashEntry.Value;
                        if (fileList.Count < 2)
                        {
                            fileList.Clear();   //free a bit of memory
                            continue; //not a duplicate set
                        }

                        fileGroupCount++;
                        fileCount += fileList.Count;
                        totalBytes += fileList.Count * sizeEntry.Key;
                    }
                }
            }

            Console.WriteLine($"Found {fileCount} potential duplicate files (with same hash) in {fileGroupCount} file groups, total {totalBytes} bytes");


            //Now we have a structure of all files grouped by (filename + size + hash).
            //For each group with more than 1 file, we consider them POTENTIAL duplicates.
            //Lets verify the potential duplicates by reading their content.

            Console.WriteLine("Comparing file content of potential duplicates...");
            long lastLoggedFileIndex = 0;
            long fileGroupIndex = 0;
            fileIndex = 0;
            processedBytes = 0;
            lastProcessedBytes = 0;
            foreach (var filenameEntry in duplicatesIndex)
            {
                foreach (var sizeEntry in filenameEntry.Value)
                {
                    foreach (var hashEntry in sizeEntry.Value)
                    {
                        var fileList = hashEntry.Value;
                        if (fileList.Count < 2)
                            continue; //not a duplicate set


                        if (fileGroupIndex % 10 == 0)
                            Console.WriteLine($"{fileGroupIndex} / {fileGroupCount} file groups compared...");
                        
                        if (fileIndex / 100 > lastLoggedFileIndex / 100)    //file indexes will not be exactly divisible in the current loop, therefore cannot use % here
                        {
                            lastLoggedFileIndex = fileIndex;
                            Console.WriteLine($"{fileIndex} / {fileCount} files compared...");
                        }

                        if (
                            processedBytes / ((long)10 * 1000 * 1000 * 1000) 
                            > lastProcessedBytes / ((long)10 * 1000 * 1000 * 1000)
                        )    //bytes will not be exactly divisible in the current loop, therefore cannot use % here
                        {
                            lastProcessedBytes = processedBytes;
                            Console.WriteLine($"{processedBytes} / {totalBytes} bytes compared...");
                        }

                        fileGroupIndex++;
                        fileIndex += fileList.Count;
                        processedBytes += fileList.Count * sizeEntry.Key;


                        Console.WriteLine($"Comparing group {filenameEntry.Key}");


                        //We have a set of duplicates: same name, same size, same hash
                        //Lets check the file content

                        bool equal = true;
                        List<Tuple<byte[], FileStream>> chunksAndReaders = new List<Tuple<byte[], FileStream>>();
                        try
                        {
                            foreach (var filePath in fileList)
                            {
                                var buffer = new byte[1024 * 1024];

                                FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);

                                chunksAndReaders.Add(new Tuple<byte[], FileStream>(buffer, fileStream));
                            }

                            FileStream reader0 = chunksAndReaders[0].Item2;

                            while (
                                equal
                                && reader0.Position < reader0.Length
                            )
                            {
                                for (int i = 0; i < fileList.Count; i++)
                                {
                                    var buffer = chunksAndReaders[i].Item1;
                                    var fileStream = chunksAndReaders[i].Item2;

                                    int maxBytesToRead = (int)Math.Min(1024 * 1024, sizeEntry.Key - fileStream.Position);
                                    fileStream.Read(buffer, 0/*this is array offset, not file offset*/, maxBytesToRead);  //it is okay if the remaining bytes in the buffer are not overwritten, then they will just contain equal bytes from earlier read
                                }

                                for (int i = 1; i < fileList.Count; i++)
                                {
                                    var filePath = fileList[i];

                                    var buffer0 = chunksAndReaders[0].Item1;
                                    var buffer = chunksAndReaders[i].Item1;

                                    if (!buffer0.SequenceEqual(buffer))
                                    {
                                        equal = false;
                                        break;
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            //TODO: exclude only the file that cannot be read from the deduplication

                            Console.WriteLine($"Error accessing file group '{filenameEntry.Key}': {ex.Message}");

                            equal = false;
                        }

                        foreach (var chunkAndReader in chunksAndReaders)
                        {
                            var fileStream = chunkAndReader.Item2;
                            fileStream.Close();
                        }

                        if (!equal)
                        {
                            Console.WriteLine("Non-equal files with colliding hashes found!");

                            fileList.Clear();
                        }
                    }   //foreach (var hashEntry in sizeEntry.Value)
                }   //foreach (var sizeEntry in filenameEntry.Value)
            }   //foreach (var filenameEntry in duplicatesIndex)


            fileGroupCount = 0;
            fileCount = 0;
            totalBytes = 0;
            Console.WriteLine("Counting duplicates...");
            foreach (var filenameEntry in duplicatesIndex)
            {
                foreach (var sizeEntry in filenameEntry.Value)
                {
                    foreach (var hashEntry in sizeEntry.Value)
                    {
                        var fileList = hashEntry.Value;
                        if (fileList.Count < 2)
                            continue; //not a duplicate set

                        fileGroupCount++;
                        fileCount += fileList.Count;
                        totalBytes += fileList.Count * sizeEntry.Key;
                    }
                }
            }

            Console.WriteLine($"Found {fileCount} duplicate files in {fileGroupCount} file groups, total {totalBytes} bytes");


            //Now we have a structure of all files grouped by (filename + size + hash + content).
            //For each group with more than 1 file, we consider them duplicates.
            //If tryRun = false, we'll:
            // 1) Move the first encountered file to the shared directory -> create a symlink in original location.
            // 2) For the rest, replace them with a symlink to that same file in the shared directory.
            //If tryRun = true, we only print what we WOULD do.

            Console.WriteLine("Processing duplicates...");
            lastLoggedFileIndex = 0;
            fileGroupIndex = 0;
            fileIndex = 0;
            processedBytes = 0;
            lastProcessedBytes = 0;
            foreach (var filenameEntry in duplicatesIndex)     //TODO: First count number of files to be processed
            {
                foreach (var sizeEntry in filenameEntry.Value)
                {
                    foreach (var hashEntry in sizeEntry.Value)
                    {
                        var hash = hashEntry.Key;

                        var fileList = hashEntry.Value;
                        if (fileList.Count < 2)
                            continue; //not a duplicate set


                        if (fileGroupIndex % 100 == 0)
                            Console.WriteLine($"{fileGroupIndex} / {fileGroupCount} file groups symlinked...");

                        if (fileIndex / 1000 > lastLoggedFileIndex / 1000)    //file indexes will not be exactly divisible in the current loop, therefore cannot use % here
                        {
                            lastLoggedFileIndex = fileIndex;
                            Console.WriteLine($"{fileIndex} / {fileCount} files symlinked...");
                        }

                        if (
                            processedBytes / ((long)100 * 1000 * 1000 * 1000)
                            > lastProcessedBytes / ((long)100 * 1000 * 1000 * 1000)
                        )    //bytes will not be exactly divisible in the current loop, therefore cannot use % here
                        {
                            lastProcessedBytes = processedBytes;
                            Console.WriteLine($"{processedBytes} / {totalBytes} bytes symlinked...");
                        }

                        fileGroupIndex++;
                        fileIndex += fileList.Count;
                        processedBytes += fileList.Count * sizeEntry.Key;


                        //We have a set of duplicates: same name, same size, same hash, same content.
                        //The first becomes the "canonical" copy in the shared folder.
                        //A symlink will be placed to its original location.
                        //The rest get replaced with a symlink as well.

                        string groupName = filenameEntry.Key.ToLowerInvariant();
                        string canonicalFilename = 
                            Path.GetFileNameWithoutExtension(groupName) 
                            //NB! do not use dot for separating the metadata since that would make extensionless file handling difficult
                            + "-" + sizeEntry.Key.ToString()    //size in file name is needed to avoid filename collisions
                            + "-" + hash 
                            + Path.GetExtension(groupName);

                        string newSharedPath = Path.Combine(sharedDirectory, canonicalFilename);


                        Console.WriteLine($"Symlinking group {filenameEntry.Key} to {canonicalFilename}");


                        //If we're in tryRun mode, just show the grouping.
#if !READONLY
                        if (tryRun)
#else 
                        if (true)
#endif
                        {
                            string sourceFile0 = fileList[0];

                            Console.WriteLine();
                            Console.WriteLine($"[TRY-RUN] Duplicates found (filename='{sourceFile0}', size={sizeEntry.Key}, hash={hashEntry.Key}):");
                            foreach (var dupPath in fileList)
                            {
                                Console.WriteLine($"   - {dupPath}");
                            }
                        }
                        else
                        {
                            //Normal mode: Move and link

#if !READONLY
                            //Move the first canonical file if necessary and create links for the rest
                            for (int i = 0; i < fileList.Count; i++)
                            {
                                var duplicatePath = fileList[i];

                                //TODO: use case-sensitive comparison in Linux and Mac
                                if (Path.GetDirectoryName(duplicatePath).ToUpperInvariant() == sharedDirectoryCaseInsensitive)
                                {
                                    Debug.Assert(newSharedPath == duplicatePath);
                                    Debug.Assert(File.Exists(newSharedPath));

                                    //shared file from an earlier run
                                    continue;
                                }

                                var allFileAttributes = GetAllFileAttributes(duplicatePath);

                                //Move canonical file to shared dir if not already moved.
                                //Has the canonical file been created during earlier runs of the program?
                                //or during earlier loops of the current file group processing?
                                if (!File.Exists(newSharedPath))
                                {
                                    if (i == fileList.Count - 1)
                                    {
                                        //skip further processing in this group if there is only one file left
                                        //to process and we were not able to create the canonical until now
                                        break;
                                    }

                                    try
                                    {
                                        //readonly attribute is not a concern here - moving a readonly file works without issues
                                        File.Move(duplicatePath, newSharedPath);
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine($"Failed to move file from '{duplicatePath}' to '{newSharedPath}': {ex.Message}");

                                        //NB! we will still try creating canonical from the other duplicates if there are at least two more remaining.
                                        continue;
                                    }

                                    try
                                    {
                                        //TODO: create symbolic links with same attributes and permissions as the original file

                                        CreateSymbolicLinkOrThrow(duplicatePath, newSharedPath);
                                        Console.WriteLine($"[CANONICAL] {duplicatePath} -> {newSharedPath}");
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine($"Failed to move/create link for '{duplicatePath}': {ex.Message}");

                                        try
                                        {
                                            //restore file at the original location
                                            //readonly attribute is not a concern here - moving a readonly file works without issues
                                            File.Move(newSharedPath, duplicatePath);

                                            //NB! we will still try creating canonical from the other duplicates if there are at least two more remaining.
                                            continue;
                                        }
                                        catch (Exception ex2)
                                        {
                                            Console.WriteLine($"Major Error: Failed to move file back from '{newSharedPath}' to '{duplicatePath}': {ex2.Message}");

                                            //NB! since the canonical file was created then we can proceed handling the other files
                                            continue;
                                        }
                                    }

                                    //set symbolic link attributes
                                    CopyFileAttributes(duplicatePath, allFileAttributes);

                                    //set shared file attributes
                                    SetSharedFileAttributes(newSharedPath, allFileAttributes.Attributes);

                                }   //if (!File.Exists(newSharedPath))
                                else  //Create links for the rest
                                {
                                    if (File.Exists(duplicatePath))     //check that the file was not removed during disk scan
                                    {
                                        var tempPath = duplicatePath + "." + Guid.NewGuid().ToString() + ".deduplicator-tmp";

                                        try
                                        {
                                            if (File.Exists(tempPath))
                                            {
                                                Console.WriteLine($"File already exists '{tempPath}'");
                                                continue;
                                            }
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"Failed to test temporary backup file existence '{tempPath}': {ex.Message}");
                                            continue;
                                        }

                                        try
                                        {
                                            //keep the original file around until the symbolic link creation has succeeded
                                            //readonly attribute is not a concern here - moving a readonly file works without issues
                                            File.Move(duplicatePath, tempPath);
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"Failed to rename file from '{duplicatePath}' to '{tempPath}': {ex.Message}");
                                            continue;
                                        }

                                        try
                                        {
                                            CreateSymbolicLinkOrThrow(duplicatePath, newSharedPath);
                                            Console.WriteLine($"[DUPLICATE] {duplicatePath} linked -> {newSharedPath}");
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"Failed to replace '{duplicatePath}' with symlink: {ex.Message}");

                                            try
                                            {
                                                //restore file at the original location
                                                File.Move(tempPath, duplicatePath);
                                            }
                                            catch (Exception ex2)
                                            {
                                                Console.WriteLine($"Major Error: Failed to rename file back from '{tempPath}' to '{duplicatePath}': {ex2.Message}");
                                            }

                                            continue;
                                        }

                                        //set symbolic link attributes
                                        CopyFileAttributes(duplicatePath, allFileAttributes);

                                        //remove read-only attribute from the temp file, else deletion will fail
                                        //this is documented - https://learn.microsoft.com/en-us/dotnet/api/system.io.file.delete
                                        if (
                                            allFileAttributes.Attributes.HasValue
                                            && (allFileAttributes.Attributes.Value & FileAttributes.ReadOnly) != 0
                                        )
                                        {
                                            FileAttributes attributes = allFileAttributes.Attributes.Value & ~FileAttributes.ReadOnly;
                                            File.SetAttributes(tempPath, attributes);
                                        }

                                        //try deletion n times, if it still fails then queue for retry after main deduplication loop ends
                                        bool deletionSuccess = false;
                                        for (int deletionRetryIndex = 0; deletionRetryIndex < deletionRetryCount; deletionRetryIndex++)
                                        {
                                            if (deletionRetryIndex > 0)
                                                Thread.Sleep(/*millisecondsTimeout*/1000);

                                            try
                                            {
                                                //remove the original's backup after symbolic link creation succeeded
                                                File.Delete(tempPath);
                                                deletionSuccess = true;
                                                break;
                                            }
                                            catch (Exception ex)
                                            {
                                                Console.WriteLine($"Failed to delete temporary backup file, will retry immediately: '{tempPath}': {ex.Message}");
                                            }
                                        }

                                        if (!deletionSuccess)
                                        {
                                            Console.WriteLine($"Failed to delete temporary backup file, will retry later: '{tempPath}'");

                                            delayedDeletions.Add(tempPath);
                                        }
                                    }   //if (File.Exists(targetFilePath))
                                }   //if (!File.Exists(newSharedPath))
                            }   //for (int i = 1; i < unhashedFileList.Count; i++)
#endif
                        }   //if (tryRun)
                    }   //foreach (var hashEntry in sizeEntry.Value)
                }   //foreach (var sizeEntry in filenameEntry.Value)
            }   //foreach (var filenameEntry in duplicatesIndex)  

            Console.WriteLine("Retrying deletion of temporary backup files...");
            foreach (var tempPath in delayedDeletions)
            {
                try
                {
                    //remove the original's backup after symbolic link creation succeeded
                    File.Delete(tempPath);
                }
                catch (Exception ex)
                {
                    //TODO option to queue for deletion during reboot

                    Console.WriteLine($"Failed to delete temporary file '{tempPath}': {ex.Message}");
                }
            }

            Console.WriteLine("Duplicate processing complete. Press any key to quit.");
            Console.ReadKey();

        }   //static void Main(string[] args)

        ///<summary>
        ///Gets all files in a directory (recursively), handling exceptions (e.g., unauthorized folders).
        ///</summary>
        private static IEnumerable<string> GetAllFiles(string root, string sharedDirectoryCaseInsensitive, string hashCacheRootCaseInsensitive)
        {
            var comparer = new CaseInsensitiveComparer();

            Queue<string> dirs = new Queue<string>();
            dirs.Enqueue(root);

            long dirIndex = 0;
            while (dirs.Count > 0)
            {
                string currentDir = dirs.Dequeue();
                string[] subDirs = null;
                string[] files = null;

                try
                {
                    if (dirIndex % 10000 == 0)
                        Console.WriteLine($"{dirIndex} dirs scanned...");
                    dirIndex++;

                    //do not return files that are already symlinks or other special files (OneDrive placeholders, etc.)
                    var attributes = File.GetAttributes(currentDir);      //this method works on directories as well
                    if ((attributes & SkipFilesWithAttributes) != 0)
                    {
                        if ((attributes & FileAttributes.ReparsePoint) != 0)
                        {
                            Console.WriteLine($"Skipping directory that is reparse point {currentDir}");
                        }
                        else if ((attributes & FileAttributes.Offline) != 0)
                        {
                            Console.WriteLine($"Skipping directory that is offline {currentDir}");
                        }
                        else if ((attributes & FileAttributes.Encrypted) != 0)
                        {
                            Console.WriteLine($"Skipping directory that is encrypted {currentDir}");
                        }
                        else if ((attributes & FileAttributes.Temporary) != 0)
                        {
                            Console.WriteLine($"Skipping directory that is temporary {currentDir}");
                        }
                        else
                        {
                            Debug.Assert(false);    //skipping a directory for undocumented reason
                            Console.WriteLine($"Skipping directory {currentDir}");
                        }

                        continue;
                    }

                    //TODO: implement a method that skips inaccessible entries and still returns the rest of the entries in the same folder
                    subDirs = Directory.GetDirectories(currentDir);
                    files = Directory.GetFiles(currentDir); 

                    //TODO: this sorting is not sufficient in the sense that the dirs queue scans breadth-first
                    Array.Sort(subDirs, comparer);
                    Array.Sort(files, comparer);
                }
                catch
                {
                    //Skip folder if we can't access it
                    Console.WriteLine($"Error accessing directory {currentDir}");
                    continue;
                }

                //this code block needs to be outside of try-catch because yield return is not allowed inside try-catch
                foreach (string file in files)
                {
                    //TODO option to add folder exclusions which will not be de-duplicated

                    var extension = Path.GetExtension(file);
                    if (extension == ".deduplicator-hash")
                        continue;
                    else if (extension == ".deduplicator-tmp")
                        continue;

                    try
                    {
                        //do not return files that are already symlinks or other special files (OneDrive placeholders, etc.)
                        var attributes = File.GetAttributes(file);
                        if ((attributes & SkipFilesWithAttributes) != 0)
                        {
                            //TODO if the reparse point refers to the deduplication folder,
                            //then maybe do not skip it so that it can be considered in deduplication logic for the purposs of REMOVING deduplicated files that DO NOT have more than one reference to them?
                                        
                            //TODO: refactor this code into a shared method
                            if ((attributes & FileAttributes.ReparsePoint) != 0)    //a reparse point => possibly a symlink
                            {
                                Console.WriteLine($"Skipping file that is reparse point {file}");
                            }
                            else if ((attributes & FileAttributes.Offline) != 0)
                            {
                                Console.WriteLine($"Skipping file that is offline {file}");
                            }
                            else if ((attributes & FileAttributes.Encrypted) != 0)
                            {
                                Console.WriteLine($"Skipping file that is encrypted {file}");
                            }
                            else if ((attributes & FileAttributes.Temporary) != 0)
                            {
                                Console.WriteLine($"Skipping file that is temporary {file}");
                            }
                            else
                            {
                                Debug.Assert(false);    //skipping a file for undocumented reason
                                Console.WriteLine($"Skipping file {file}");
                            }

                            continue;
                        }
                    }
                    catch
                    {
                        //skip file if we can't access it
                        Console.WriteLine($"Error accessing file {file}");
                        continue;
                    }

                    //this needs to be outside of try-catch
                    yield return file;
                }   //foreach (string file in files)

                foreach (string subDir in subDirs)
                {
                    var subDirCaseInsensitive = subDir.ToUpperInvariant();

                    //TODO: use case-sensitive comparison in Linux and Mac
                    if (subDirCaseInsensitive == sharedDirectoryCaseInsensitive)
                    {
                        //files in the shared dir will be processed separately
                        continue;
                    }
                    else if (subDirCaseInsensitive == hashCacheRootCaseInsensitive)
                    {
                        //NB! If hash cache root is same as deduplication root then it is not skipped
                        continue;
                    }
                    else
                    {
                        dirs.Enqueue(subDir);
                    }
                }
            }   //while (dirs.Count > 0)

        }   //static IEnumerable<string> GetAllFiles(string root, string sharedDirectoryCaseInsensitive, string hashCacheRootCaseInsensitive)

        ///<summary>
        ///Gets all files in the shared directory, handling exceptions (e.g., unauthorized files) and skipping subfolders.
        ///</summary>
        private static Dictionary<string, Dictionary<long, Dictionary<string, List<string>>>> GetAllExistingSharedFiles(string sharedDirectory, long minSizeBytes)
        {
            Console.WriteLine($"Processing earlier files in the shared directory {sharedDirectory}");

            var hashTemplate = GetHashTemplate();

            //Data structure:
            //filename -> (size -> (hash -> List of file paths))
            var sharedFilesIndex = new Dictionary<string, Dictionary<long, Dictionary<string, List<string>>>>(/*StringComparer.OrdinalIgnoreCase*/);

            string[] files = Directory.GetFiles(sharedDirectory);

            //this code block needs to be outside of try-catch because yield return is not allowed inside try-catch
            foreach (string file in files)
            {
                try
                {
                    //do not return files that are symlinks or other special files (OneDrive placeholders, etc.)
                    //normally, shared files folder should not contain them,
                    //but if any such file ends up there then it is definitely not a deduplicated file
                    var attributes = File.GetAttributes(file);
                    if ((attributes & SkipFilesWithAttributes) != 0)
                    {                        
                        //TODO: refactor this code into a shared method
                        if ((attributes & FileAttributes.ReparsePoint) != 0)
                        {
                            Console.WriteLine($"Skipping file that is reparse point {file}");
                        }
                        else if ((attributes & FileAttributes.Offline) != 0)
                        {
                            Console.WriteLine($"Skipping file that is offline {file}");
                        }
                        else if ((attributes & FileAttributes.Encrypted) != 0)
                        {
                            Console.WriteLine($"Skipping file that is encrypted {file}");
                        }
                        else if ((attributes & FileAttributes.Temporary) != 0)
                        {
                            Console.WriteLine($"Skipping file that is temporary {file}");
                        }
                        else
                        {
                            Debug.Assert(false);    //skipping a file for undocumented reason
                            Console.WriteLine($"Skipping file {file}");
                        }

                        continue;
                    }


                    var filename = Path.GetFileNameWithoutExtension(file);
                    var extension = Path.GetExtension(file);

                    var parts = new List<string>(filename.Split('-'));
                    if (parts.Count >= 3)   //TODO: add some special extension to the shared folder files so that they can be distinguished from other filenames containing dashes?
                    {
                        if (!long.TryParse(parts[parts.Count - 2], out long size))
                        {
                            Console.WriteLine($"Skipping file with invalid size part in the shared folder {file}");
                        }
                        else if (size < minSizeBytes)
                        {
                            Console.WriteLine($"Skipping shared file smaller than minSizeBytes: {file}");
                        }
                        else
                        {
                            var fileHash = parts[parts.Count - 1];
                            if (fileHash.Length != hashTemplate.Length)
                            {
                                Console.WriteLine($"Skipping file with invalid hash part in the shared folder {file}");
                            }
                            else
                            {
                                //sanity check
                                FileInfo fi = new FileInfo(file);
                                if (fi.Length != size)
                                {
                                    Console.WriteLine($"Skipping file with invalid size part in the shared folder {file}");
                                    continue;
                                }


                                parts.RemoveAt(parts.Count - 1);        //remove hash
                                parts.RemoveAt(parts.Count - 1);        //remove length

                                var partsWithoutLengthAndHash = string.Join("-", parts);

                                var filenameWithoutLengthAndHash = partsWithoutLengthAndHash + extension;

                                //TODO: Automatically turn off case insensitivity under Linux
                                //TODO: command line option to turn off or on case insensitivity manually
                                var caseInsensitiveFilename = filenameWithoutLengthAndHash.ToUpperInvariant();

                                //Insert a placeholder in dictionary
                                if (!sharedFilesIndex.TryGetValue(caseInsensitiveFilename, out var sizeDict))
                                {
                                    sizeDict = new Dictionary<long, Dictionary<string, List<string>>>();
                                    sharedFilesIndex[caseInsensitiveFilename] = sizeDict;
                                }

                                if (!sizeDict.TryGetValue(size, out var hashDict))
                                {
                                    hashDict = new Dictionary<string, List<string>>();
                                    sizeDict[size] = hashDict;
                                }

                                if (!hashDict.TryGetValue(fileHash, out var pathList))
                                {
                                    pathList = new List<string>();
                                    hashDict[fileHash] = pathList;
                                }

                                pathList.Add(file);

                            }   //if (fileHash.Length != hashTemplate.Length)
                        }   //if (!long.TryParse(parts[parts.Count - 2], out long size))
                    }
                    else    //if (parts.Count >= 3)
                    {
                        Console.WriteLine($"Skipping file with invalid metadata in the shared folder {file}");
                        continue;
                    }
                }
                catch
                {
                    //skip file if we can't access it
                    Console.WriteLine($"Error accessing file {file}");
                    continue;
                }
            }   //foreach (string file in files)

            return sharedFilesIndex;

        }   //static Dictionary<string, Dictionary<long, Dictionary<string, List<string>>>> GetAllExistingSharedFiles(string sharedDirectory)

        ///<summary>
        ///Computes a hash for the file (using SHA256 here).
        ///For large files, you might consider partial file hashing.
        ///</summary>
        private static string GetHashTemplate()
        {
            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(new byte[0]);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        ///<summary>
        ///Checks folder writability and computes a hash for the file (using SHA256 here).
        ///For large files, you might consider partial file hashing.
        ///</summary>
        private static string CheckFolderWritabilityAndGetFileHash
        (
            bool hashCacheIsInSameFolderAsFileRoot, 
            string filePath, 
            string hashCacheRoot, 
            HashSet<string> unwritableFolders, 
            HashSet<string> delayedDeletions
        )
        {
            string directoryPath = Path.GetDirectoryName(filePath);
            if (unwritableFolders.Contains(directoryPath))
            {
                Console.WriteLine($"Skipping hashing of file in an unwritable folder: '{filePath}'");
                return null;
            }
                        

            FileStream hashCacheStream = null;
            string hashFileName = null;

            var allFileAttributes = GetAllFileAttributes(filePath, skipCreationAndAccessTime: true);

            if (hashCacheRoot != null)
            {
                try
                {
                    //save hash to cache file
                    var fileRoot = Directory.GetDirectoryRoot(filePath);
                    var relativeFilePath = filePath.Substring(fileRoot.Length);
                    hashFileName = Path.Combine(hashCacheRoot, relativeFilePath + ".deduplicator-hash");

                    if (File.Exists(hashFileName))
                    {
                        if (allFileAttributes.ModificationTime.HasValue)    //else we cannot verify the hash validity
                        {
                            try
                            {
                                DateTime hashCreationTime = File.GetCreationTimeUtc(hashFileName);
                                //DateTime hashCreationTime = File.GetLastWriteTimeUtc(hashFileName);
                                if (allFileAttributes.ModificationTime.Value <= hashCreationTime)
                                {
                                    var hash = File.ReadAllBytes(hashFileName);
                                    if (hash.Length == 32)
                                    {
                                        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                                    }
                                    else
                                    {
                                        Console.WriteLine($"Encountered corrupted hash cache file for '{filePath}'");
                                    }
                                }
                                else
                                {
                                    Console.WriteLine($"File is newer than hash file '{filePath}'");
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"Failed to read hash cache file for '{filePath}': {ex.Message}");
                            }
                        }

                        try
                        {
                            var hashFileAttributes = File.GetAttributes(hashFileName);
                            if ((hashFileAttributes & FileAttributes.ReadOnly) != 0)    //else opening the file for writing will fail
                            {
                                FileAttributes updatedAttributes = hashFileAttributes & ~FileAttributes.ReadOnly;
                                File.SetAttributes(hashFileName, updatedAttributes);
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Failed to adjust attributes of hash cache file for '{filePath}': {ex.Message}");
                        }
                    }   //if (File.Exists(hashFileName))

                    hashCacheStream = File.Create(hashFileName);  //creates, or truncates and overwrites, a file in the specified path
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to create hash cache file for '{filePath}': {ex.Message}");

                    if (hashCacheIsInSameFolderAsFileRoot)     //if hash cache is stored in the same folder as hash cache and hash file creation fails then symlink creation would fail too
                    {
                        unwritableFolders.Add(directoryPath);
                        return null;    //TODO: if opening hash cache file failed due to readonly attribute, then do not return here?
                    }
                }
            }   //if (hashCacheRoot != null)


            if (
                !hashCacheIsInSameFolderAsFileRoot
                || hashCacheRoot == null
            )
            {
                //Create test file. If the file creation fails then the folder is not writable
                //and symlink creation would also fail. That would be a problem because by then
                //the original file would have been moved to the shared folder, but now it cannot
                //be moved back. Somehow moving the original file to shared folder is allowed 
                //even when creating new files in the source folder is not allowed.
                var testFileName = Path.Combine(directoryPath, ".deduplicator-tmp");
                try
                {
                    using (var stream = File.Create(testFileName))
                    {
                        //do nothing here
                    }

                    try
                    {
                        File.Delete(testFileName);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to delete test file, will retry later: '{testFileName}': {ex.Message}");

                        delayedDeletions.Add(testFileName);
                    }
                }
                catch (Exception ex)
                {
                    unwritableFolders.Add(directoryPath);

                    Console.WriteLine($"Failed to create test file, probably the folder is not writable, skipping hashing of file '{filePath}': {ex.Message}");

                    if (hashCacheRoot != null)
                    {
                        hashCacheStream.Close();
                        hashCacheStream.Dispose();
                    }

                    return null;
                }
            }   //if (!hashCacheIsInSameFolderAsFile)


            try
            {
                using (var sha256 = SHA256.Create())
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    var hash = sha256.ComputeHash(fs);

                    if (hashCacheRoot != null)
                    {
                        try
                        {
                            hashCacheStream.Write(hash, 0, hash.Length);
                            hashCacheStream.Flush();
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Failed to write to cache file for '{filePath}': {ex.Message}");
                        }

                        //NB! need to close the file first before applying the attributes, therefore cannot use try-finally here
                        hashCacheStream.Close();
                        hashCacheStream.Dispose();
                        hashCacheStream = null;

                        try
                        {
                            if (allFileAttributes.ModificationTime.HasValue)  //if the hash file existed before, update its creation time
                                File.SetCreationTimeUtc(hashFileName, allFileAttributes.ModificationTime.Value);

                            CopyFileAttributes(hashFileName, allFileAttributes, skipTimes: true);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Failed to set hash cache attributes '{hashFileName}': {ex.Message}");
                        }
                    }   //if (hashCacheRoot != null)

                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to read file for hashing purposes, skipping hashing of file '{filePath}': {ex.Message}");

                if (hashCacheStream != null)
                {
                    hashCacheStream.Close();
                    hashCacheStream.Dispose();
                }

                return null;
            }
        }   //private static string CheckFolderWritabilityAndGetFileHash()

#if !READONLY
        ///<summary>
        ///Creates a symbolic link or throws an exception if it fails.
        ///</summary>
        private static void CreateSymbolicLinkOrThrow(string linkPath, string existingPath)
        {
            int flags = 0x0    //the link target is a file.
                        //Specify this flag to allow creation of symbolic links when the process is not elevated.
                        //TODO: Though this flag does not seem to help and running in elevated mode is still needed.
                        | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;     
            bool success = CreateSymbolicLink(linkPath, existingPath, flags);
            if (!success)
            {
                //Attempt to retrieve an error code
                int errorCode = Marshal.GetLastWin32Error();
                throw new IOException($"CreateSymbolicLink failed with error code: {errorCode}");
            }
            //check that the symbolic link was actually created
            //see also https://developercommunity.visualstudio.com/t/systemiodirectorycreatesymboliclink-f/1623428?space=62&q=permissive-+sfinae&entry=myfeedback
            else if (!File.Exists(linkPath))     
            {
                throw new Exception($"Symbolic link file not found after symbolic link creation success: {linkPath}");
            }
        }

        private static AllFileAttributes GetAllFileAttributes(string duplicatePath, bool skipCreationAndAccessTime = false)
        {
            //Get file attributes, creation, modification, and last access dates
            //TODO: do not call these functions in case of creating hardlinks:
            //Any changes made to a hard-linked file are instantly visible to applications that access it
            //through the links that reference it. The attributes on the file are reflected in every hard
            //link to that file, and changes to that file's attributes propagate to all the hard links.
            //https://learn.microsoft.com/en-us/windows/win32/fileio/hard-links-and-junctions
            var allFileAttributes = new AllFileAttributes();
            try
            {
                FileInfo fi = new FileInfo(duplicatePath);

                allFileAttributes.Attributes = fi.Attributes;
                allFileAttributes.ModificationTime = fi.LastWriteTimeUtc;
                if (!skipCreationAndAccessTime)
                {
                    allFileAttributes.CreationTime = fi.CreationTimeUtc;
                    allFileAttributes.AccessTime = fi.LastAccessTimeUtc;
                }
                allFileAttributes.AccessControl = fi.GetAccessControl();  //TODO: Skip this in non-Windows systems where this is not supported
                                                                          //TODO: copy file mas in case of Linux OS
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to get attributes of file '{duplicatePath}': {ex.Message}");

                //NB! this error is only logged and has no effect otherwise
            }

            return allFileAttributes;
        }

        private static void SetSharedFileAttributes(string newSharedPath, FileAttributes? attributes)
        {
            //clear some attributes from the shared file
            //set archive and non-content indexing attribute
            try
            {
                if (attributes.HasValue)
                {
                    attributes &= ~FileAttributes.ReadOnly;
                    attributes &= ~FileAttributes.Hidden;
                    attributes &= ~FileAttributes.System;

                    //TODO: option to ignore temporary files during filesystem scan
                    attributes &= ~FileAttributes.Temporary;

                    attributes |= FileAttributes.Archive;
                    attributes |= FileAttributes.NotContentIndexed;

                    File.SetAttributes(newSharedPath, attributes.Value);
                }

                FileSecurity newAccessControl = new FileSecurity();
                File.SetAccessControl(newSharedPath, newAccessControl); //this call succeeds even when File.SetAttributes has set readonly attribute
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to set attributes on shared file '{newSharedPath}'': {ex.Message}");

                //NB! this error is only logged and has no effect otherwise
            }
        }

        //TODO: do not call this function in case of creating hardlinks:
        //Any changes made to a hard-linked file are instantly visible to applications that access it
        //through the links that reference it. The attributes on the file are reflected in every hard
        //link to that file, and changes to that file's attributes propagate to all the hard links.
        //https://learn.microsoft.com/en-us/windows/win32/fileio/hard-links-and-junctions
        private static void CopyFileAttributes(string targetFilePath, AllFileAttributes allFileAttributes, bool skipTimes = false)
        {
            try
            {
                if (!skipTimes)
                {
                    //these calls need to be made before File.SetAttributes sets readonly attribute

                    if (allFileAttributes.CreationTime.HasValue)
                        File.SetCreationTimeUtc(targetFilePath, allFileAttributes.CreationTime.Value);

                    if (allFileAttributes.ModificationTime.HasValue)
                        File.SetLastWriteTimeUtc(targetFilePath, allFileAttributes.ModificationTime.Value);

                    if (allFileAttributes.AccessTime.HasValue)
                        File.SetLastAccessTimeUtc(targetFilePath, allFileAttributes.AccessTime.Value);
                }

                if (allFileAttributes.Attributes.HasValue)
                    File.SetAttributes(targetFilePath, allFileAttributes.Attributes.Value);

                if (allFileAttributes.AccessControl != null)  //TODO: Skip this in non-Windows systems where this is not supported
                {
                    var accessRules = allFileAttributes.AccessControl.GetAccessRules
                    (
                        /*includeExplicit*/true, 
                        /*includeInherited*/false,  //NB! skip inherited rules
                        typeof(System.Security.Principal.SecurityIdentifier)
                    );

                    FileSecurity copiedAccessControl = new FileSecurity();
                    foreach (var rule in accessRules.Cast<FileSystemAccessRule>())
                    {
                        Debug.Assert(!rule.IsInherited);
                        copiedAccessControl.AddAccessRule(rule);
                    }

                    //this call succeeds even when File.SetAttributes has set readonly attribute
                    File.SetAccessControl(targetFilePath, copiedAccessControl);
                }

                //TODO: copy file mask in case of Linux OS
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to set attributes on symbolic link '{targetFilePath}': {ex.Message}");

                //NB! this error is only logged and has no effect otherwise
            }
        }
#endif
    }
}
