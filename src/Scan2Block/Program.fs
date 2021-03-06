﻿
open System
open System.IO
open System.Text
open System.Threading

let mutable debugging = false

let readTail (path : string) (numberOfTokens : int64) (encoding : Encoding) (tokenSeparator : string) =
    
    let sizeOfChar = encoding.GetByteCount("\n") |> int64
    let buffer = encoding.GetBytes(tokenSeparator)
    use fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)
    let mutable tokenCount = 0L
    let endPosition = fs.Length / int64(sizeOfChar)

    let rec loop position =
      if position > endPosition then None
      else
        fs.Seek(-position, SeekOrigin.End) |> ignore
        fs.Read(buffer, 0, buffer.Length)  |> ignore
        let str = encoding.GetString(buffer)
        if (str = tokenSeparator) then
            tokenCount <- tokenCount + 1L
            if (tokenCount = numberOfTokens) then
                let returnBuffer = Array.zeroCreate<byte> <| int(fs.Length - int64(fs.Position))
                fs.Read(returnBuffer, 0, returnBuffer.Length) |> ignore
                encoding.GetString(returnBuffer) |> Some
            else loop (position + 1L)
        else
          loop (position + 1L)

    match loop sizeOfChar with
    | Some str ->
      str
    | None ->
      // handle case where number of tokens in file is less than numberOfTokens
      fs.Seek(0L, SeekOrigin.Begin) |> ignore
      let buffer = Array.zeroCreate<byte> <| int fs.Length
      fs.Read(buffer, 0, buffer.Length) |> ignore
      encoding.GetString(buffer)

open System.Diagnostics

let execute cmd args =
    
    let proc = new Process();

    proc.StartInfo.FileName         <- cmd
    proc.StartInfo.CreateNoWindow   <- true
    proc.StartInfo.RedirectStandardOutput <- true
    proc.StartInfo.UseShellExecute  <- false
    proc.StartInfo.Arguments        <- args
    proc.StartInfo.CreateNoWindow   <- true

    let r = proc.Start()
    proc.WaitForExit()   
    proc.StandardOutput.ReadToEnd()

open System.Collections.Generic
open System.Text.RegularExpressions

let inline debug (str : string) = 
  if debugging then Console.WriteLine ("DEBUG: " + str)

let processFile offending extractIpAddress block n fileName =
  try
      printfn "processFile: %s" fileName
      let tail = readTail fileName 100L Encoding.UTF8 "\r\n"

      let lines = tail.Split([|"\r\n"|], StringSplitOptions.None)

      let dictionary = Dictionary<string,int>()

      for line in lines do
        debug line
        if offending line then
          let ipAddress = extractIpAddress line
          match dictionary.TryGetValue ipAddress with
          | true, v ->
            dictionary.[ipAddress] <- v + 1
          | _ ->
            dictionary.Add(ipAddress, 0)

      printfn "Analizing collected IP addresses."
      // scan dictionary, ipAddress with more than N infractions will be blocked.
      for ipAddress in dictionary.Keys do
        printfn "ip: %s, %d" ipAddress (dictionary.[ipAddress])
        if dictionary.[ipAddress] > n then
          printfn "Blocking %s" ipAddress
          block ipAddress
    with ex ->
      printfn "processFile FAILED with: %A" ex

let extractIpAddress (line : string) = 
  let ip = new Regex(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
  let matches = ip.Matches(line)
  // we want the second IP address
  matches.[1].Value

let offending (line: string) = 
  line.Contains("POST /wp-login.php") || line.Contains("POST /xmlrpc.php")

let block isWhitelisted ipAddress =
  if not (isWhitelisted ipAddress) then
    printfn "Checking if already blocked."
    let out = execute "netsh" (sprintf "advfirewall firewall show rule name=\"Blackhole %s\"" ipAddress)
    Console.WriteLine out
    if out.Contains("No rules match the specified criteria.") then
      printfn "Block %s" ipAddress
      let out = execute "netsh" (sprintf "advfirewall firewall add rule name=\"Blackhole %s\" dir=in protocol=any action=block remoteip=%s" ipAddress ipAddress)
      Console.WriteLine out
    else
      Console.WriteLine "Already blocked."
  else
    printfn "Whitelisted: %s" ipAddress

let scan whitelisted (rootDir: string) =

  let isWhitelisted ipAddress =
    Array.contains ipAddress whitelisted
  
  // enumerate folders, there is one for each website
  for dir in Directory.EnumerateDirectories(rootDir) do

    printfn "Directory: %s" dir

    let files = 
      Directory.EnumerateFiles(dir,"*.log")
      |> Seq.map (fun x -> FileInfo x)
      |> Seq.sortByDescending(fun x -> x.LastWriteTime)
    
    if Seq.length files > 1 then
      let fileName = (Seq.head files).FullName
      processFile offending extractIpAddress (block isWhitelisted) 4 fileName

let whitelistedFilename = "whitelisted.txt"

let loadWhitelisted _ =
  if File.Exists whitelistedFilename then
    File.ReadAllLines whitelistedFilename
  else
    Array.empty

[<EntryPoint>]
let main argv =

  argv |> Array.iter( fun arg -> if arg = "debug" then debugging <- true)

  let whitelisted = loadWhitelisted ()

  let rootDir = @"D:\LogFiles"
  let sleepTime = 300000 // 5 minutes
  
  while true do
    printfn "Scanning %s .." rootDir
    scan whitelisted rootDir
    printfn "Sleeping .."
    Thread.Sleep sleepTime
  0 // exit
