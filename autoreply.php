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
$log_file = "$logdir/autoreply_".date("Ymd").".log";

if (File_Exists("$vacationdir$rcpt") and $from <> $rcpt and $from<>"" and $rcpt<>"") {   // overeni existence souboru autoodpovedi nesmi byt stejne aby se nezacyklily


$f=fopen("$vacationdir$rcpt","r");  // přidat cestu  
$vacfile = '';while(!feof($f)){$vacfile .= fread($f, 1024);}fclose($f);  // nacteni souboru


  include "class.phpmailer.php";
  $mail = new PHPMailer();
  $mail->IsSMTP();  // k odeslání e-mailu pouzijeme SMTP server
  $mail->Host = "95.140.242.149";  // zadáme adresu SMTP serveru
  $mail->SMTPAuth = true;               // nastavíme true v případě, ze server vyzaduje SMTP autentizaci
  $mail->Username = "";   // uzivatelské jméno pro SMTP autentizaci
  $mail->Password = "";            // heslo pro SMTP autentizaci
  $mail->From = $rcpt;   // adresa odesílatele skriptu
  $mail->FromName = $rcpt; // jméno odesílatele skriptu (zobrazí se vedle adresy odesílatele)
  $mail->AddAddress($from,"");
//  $mail->AddAddress("608412699@sms.t-zones.cz","Mobil");
//  $mail->AddAddress("724986873@sms.cz.o2.com","Mobil");
  $mail->Subject = "Automatická Odpověď / Auto-Answer";    // nastavíme předmět e-mailu
  $mail->Body =$vacfile;

  $mail->WordWrap = 350;   // je vhodné taky nastavit zalomení (po 50 znacích)
  $mail->CharSet = "utf-8";   // nastavíme kódování, ve kterém odesíláme e-mail
  $mail->Send();



//   zaznamenavat do logu
//$log_handle = fopen($log_file, "a");
//fputs($log_handle, "from:$from to:$rcpt \n");
//fclose($log_handle);
}



?>
