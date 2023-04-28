#!/usr/bin/php
<?php
// Edit this
$basedir = "/var/lib/xmail";
$logdir = "$basedir/logs";
//$domaindir = "$basedir/domains";
//$spooldir = "$basedir/spool";
$vacationdir = "$basedir/vacation/";
$autoreplydir = "$basedir/autoreply/";


//*** EDIT NOTHING BELOW THIS LINE ***
$file = $argv[1];
$from = $argv[2];
$rcpt = $argv[3];
$log_file = "$logdir/autoresend_".date("Ymd").".log";

if (File_Exists("$vacationdir$rcpt.res") and $from<>"" and $rcpt<>"") {   // overeni existence souboru autoodpovedi nesmi byt stejne aby se nezacyklily


$f=fopen("$vacationdir$rcpt.res","r");  // přidat cestu  
$vacafile = '';while(!feof($f)){$vacafile .= fread($f, 1024);}fclose($f);  // nacteni souboru

if (!strpos($vacafile,$rcpt)){

  include "class.phpmailer.php";
  $mail = new PHPMailer();
  $mail->IsSMTP();  // k odeslání e-mailu pouzijeme SMTP server
  $mail->Host = "95.140.242.149";  // zadáme adresu SMTP serveru
  $mail->SMTPAuth = true;               // nastavíme true v případě, ze server vyzaduje SMTP autentizaci
  $mail->Username = "";   // uzivatelské jméno pro SMTP autentizaci
  $mail->Password = "";            // heslo pro SMTP autentizaci
  $mail->From = $from;   // adresa odesílatele skriptu
  $mail->FromName = ""; // jméno odesílatele skriptu (zobrazí se vedle adresy odesílatele)

$casti = explode(";",$vacafile);@$cykl=0;
while ($casti[@$cykl]):
$mail->AddAddress($casti[@$cykl],"");@$cykl++;
endwhile;

$casti = explode("/",$file);
$cesta=$casti[0]."/".$casti[1]."/".$casti[2]."/".$casti[3]."/".$casti[4]."/".$casti[5]."/".$casti[6]."/".$casti[7]."/";$soubor=$casti[8];

  $mail->Subject = "Preposlany Email";    // nastavíme předmět e-mailu
  $mail->Body ="V priloze mate preposlany email puvodne urceny: ".$rcpt;
  $mail->AddAttachment ($file,"Puvodni Email.eml"); 
  $mail->WordWrap = 350;   // je vhodné taky nastavit zalomení (po 50 znacích)
  $mail->CharSet = "utf-8";   // nastavíme kódování, ve kterém odesíláme e-mail
  $mail->Send();

}

//   zaznamenavat do logu
//$log_handle = fopen($log_file, "a");
//fputs($log_handle, "from:$from to:$rcpt vacafile:$vacafile file:$file \n");
//fclose($log_handle);
}



?>
