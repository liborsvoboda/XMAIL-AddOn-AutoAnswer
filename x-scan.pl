#!/usr/bin/perl

##
### Smtp server address (this address must but in amtprelay.tab)
##
$ServerName                     = '127.0.0.1';

##
### Root directory of xmail (MailRoot)
##
$Mail_Root                      = '/var/lib/xmail';

##
### 1 = Enable, 0 = Disable 
### (if you Disable one of these you don't need to set thier settings)
##
# 1 = Yes , 0 = No
$Virus_scan                     = 1;
# 1 = Yes , 0 = No
$Spam_scan                      = 0;

##
###
##
# 1 = yes, 0 = no
# Blocking works both ways, Send and reciving.
# Meaning what ever you don't want to recive you can't sent !!!!!
$Attachment_block               = 1;
# Heres you'll list all the disallowed attchemnts
# That you don't want your server / users to deal with.
$Attachments                    = 'exe.zip,vbs';
## Send the sender of the disallowed file type an Alert 
# 1 = yes , 0 = no
$Send_attachment_policy         = 1;
## subject on policly email;
$Attachments_subject            = '[ Rejected ] Email ';

##
### Virus Settings
##
# 1 = Yes , 0 = No
$Virus_logging                  = 1;
# -1 = Disables notifing of anyone and just deletes the email.
#  1 = Send alert of infected email being deleted to sender and reciver.
#  0 = Send alert of infected email being deleted to reciver only.
$Send_virus_alert               = 1;

# 1 = Send alert of infected local user only 
#     (weather they where the send or reciver, this is to help reduce bandwith usage)
#     only works it Send_virus_alert is set to 0 OR 1 
# 0 = Disable this option and use setting from Send_virus_alert
$Send_virus_alert_local_only    = 1;

$Subject                        = '[ VIRUS ] Found in email';
# These must be in the same directory as x-scan.pl
$From_content                   = 'from_message.txt';
$To_content                     = 'to_message.txt';
# this is a secret code to taht tells X-Scan not to scan 
#  the auto reply to a Virus infected email. (it will be md5'ed later)
#  if left blank '' then even the generated replies will be scanned.
$Xcode                          = 'Your code here';


##
### Spam Settings (only set these if you've set $Spam_scan to 1)
##
# 1 = Yes , 0 = No
$Spam_logging                   = 0;
$Spam_score_log                 = 0;
# This option allows to log what the socre of a outoing email
#  would be had i have to pass though spamc.
# This option can be used to make sure none of your users are
#  using there accounts to send out lots of spam.
$Spam_logging_outgoing          = 0;
# What is the lowest spamassassin  needed for us to delete the email
#  Setting this to 0 will disable the Deleting of any email becuase 
#  of spam (Setting this to greater then 0 will also set Spam_score_log to 1)
$Delete_spam_score              = 0;
# This is th same as the above except it's used for outgoing emails
#  Most people won't use this, But it's heres.
$Delete_outgoing_spam_score     = 0;

##
### Program Locations (if it's a global program you don't need the path)
###  example: grep = 'grep';
##
## $Awk                            = '/bin/awk';
## $Cat                            = '/bin/cat';
$ClamScan                       = '/usr/bin/clamscan';
## $Grep                           = '/bin/grep';
## $Head                           = '/usr/bin/head';
## $Spamc                          = '/usr/bin/spamc';
## $Tail                           = '/usr/bin/tail';
## $Wc                             = '/usr/bin/wc';




#                                    #
##                                  ##
###   Nothing to Edit Below this   ###
##                                  ##
#                                    #


# Path to file w/ filename
$File  = $ARGV[0];
# Message going to
$To    = $ARGV[1];
# message coming from
$From  = $ARGV[2];
# Email inbound or outbound
$Bound = $ARGV[3];


##
### My Functions (aka subs)
##
sub xscan_smtp {
 $smtp = Net::SMTP->new($ServerName);
 $smtp->mail( $_[0] );
 $smtp->to( $_[1] );
 $smtp->data();
 $smtp->datasend("To:  ".$_[1]."\n");
 $smtp->datasend("From:  ".$_[0]."\n");
 $smtp->datasend("Subject: ".$_[2]."\n");
 if ($_[3]) {
  $smtp->datasend("X-Scanned-Code: ".$_[3]."\n");
 }
 $smtp->datasend("\n");
 $smtp->datasend($content."\n\n");
 $smtp->dataend();
 $smtp->quit();
}


if ($Spam_logging == 0) { 
 $Spam_logging_outgoing = 0;
}

# Setup date/tome format for log file names
($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime(time);
my $DateTime = sprintf "%4d-%02d-%02d %02d:%02d:%02d",$year+1900,$mon+1,$mday,$hour,$min,$sec;


##
### Attachment Block
##

if ($Attachment_block == 1) {
 $XMail_lines = `$Cat $File | $Grep "<<MAIL-DATA>>" -n -a -m1 | $Awk -F: '{print \$1}'`;
 $Total_lines = `$Cat $File | $Wc -l | $Awk '{print \$1}'`;

 $XMail_lines =~ s/\n//;
 $Total_lines =~ s/\n//;

 $Real_lines  = $Total_lines-$XMail_lines;

 $Xmail_data  = `$Head -n $XMail_lines $File`;
 $Real_data   = `$Tail -n $Real_lines  $File`;

 @Block = split(/,/,$Attachments);
 
 foreach $Attachment(@Block) {
  if ($Real_data =~ /filename=".*.\.$Attachment"/) {
   if ($Send_attachment_policy == 1) {
    $Txt = $Mail_Root.'/filters/extention_blocked.txt'; 

    open INPUT, "< $Txt";
     undef $/;
     $content = <INPUT>;
    close INPUT;
 
    $content =~ s/%TO%/$To/g;
    $content =~ s/%FROM%/$From/g;
    $content =~ s/%TYPES%/$Attachments/g;
    $content =~ s/%TYPE%/$Attachment/g;
    $content =~ s/\r\n/\n/g;
    $content =~ s/\r/\n/g;
    $content =~ s/\n/\r\n/g;
 
    &xscan_smtp($From,$To,$Attachments_subject,'',$content); 
   }
   exit 20;
  }
 }
}



##
### AntiVirus Stuff
##
if ($Virus_scan == 1 && -e $ClamScan ) {

 use Net::SMTP;

 if ($Xcode) {
  use Digest::MD5 qw(md5_hex);
  $Xcode = md5_hex($Xcode);
  $Run = `$Grep -a -n -m1 "X-Scanned-Code: $Xcode" $File`;
 }

 if ($Run == '') {
  $Command = "$ClamScan --scan-mail --infected --no-summary --stdout $File ";
  $Run = `$Command`;
  $Run =~ s/\n//;

  if ($Run) {
   $Virus = $Run;

  if ( $Send_virus_alert_local_only == 1 && ( $Send_virus_alert == 1 || $Send_virus_alert == 0) ) {
   if ($Bound eq '-I') {
    $Start = 0;
    $Send_virus_alert = 0;
   }
   if ($Bound eq '-O') {
    $Start = 1;
    $Send_virus_alert = 1;
   }   
  } else {
   $Start = 0;  
  }

     
   for ($loop=$Start;$loop<=$Send_virus_alert;$loop++) {
  
    if ($loop == 0) {
     $To_tmp   = $To;
     $From_tmp = $From;
     $Txt      = $Mail_Root.'/filters/to_message.txt';
    } else {
     $To_tmp   = $From;
     $From_tmp = $To;
     $Txt  = $Mail_Root.'/filters/from_message.txt';
    }
  
    open INPUT, "< $Txt";
     undef $/;
     $content = <INPUT>;
    close INPUT;
   
    $content =~ s/%VIRUS%/$Virus/g;
    $content =~ s/%TO%/$To/g; 
    $content =~ s/%FROM%/$From/g;
    $content =~ s/\r\n/\n/g;
    $content =~ s/\r/\n/g;
    $content =~ s/\n/\r\n/g;

    &xscan_smtp($From_tmp,$To_tmp,$Subject,$Xcode,$content)

   }
  
   $Virus_found = 'Virus : Yes';

  }

  ##
  ### Virus Loggin Stuff
  ##
 
  if ( $Virus_logging == 1) {
   $Log_file = $Mail_Root.'/logs/antivirus-'.sprintf "%4d%02d%02d000",$year+1900,$mon+1,$mday,$hour,$min,$sec;

   $Log  = '"'.$DateTime.'"'."\t";
   $Log .= '"'.$Virus_found.'"'."\t";
   $Log .= '"'.$Virus.'"'."\t";
   $Log .= '"'.$To.'"'."\t";
   $Log .= '"'.$From.'"'."\t";

   open(LOG,">> $Log_file");
    print LOG "$Log\n";
   close(LOG);
  } 
 
 
  if ($Virus_found eq 'Virus : Yes') {
   exit 20;
  }

 }

} ## End if ($Virus_scan == 1 OR $ClamScan != '') {




##
### SPAM Stuff
##

if ( $Spam_scan == 1 ) {

 if ($Attachment_block == 0 || ( !$Real_data && !$Xmail_data ) ) {
  $XMail_lines = `$Cat $File | $Grep -a -n -m1 "<<MAIL-DATA>>" | $Awk -F: '{print \$1}'`;
  $Total_lines = `$Cat $File | $Wc -l | $Awk '{print \$1}'`;

  $XMail_lines =~ s/\n//;
  $Total_lines =~ s/\n//;

  $Real_lines  = $Total_lines-$XMail_lines;
 
  $Real_data   = `$Tail -n $Real_lines  $File`;
  $Xmail_data  = `$Head -n $XMail_lines $File`;
 }

 open(FILE,"> $File");
  print FILE $Real_data;
 close(FILE);
  
 if ($Bound eq "-I") {

  $Spamc = `$Spamc -f < $File`;

  $Spamc   =~ s/\r\n/\n/g;
  $Spamc   =~ s/\r/\n/g;
  $Spamc   =~ s/\n/\r\n/g;

  open(FILE,"> $File");
   print FILE $Xmail_data;
   print FILE $Spamc;
  close(FILE);

  print $Xmail_data;
  print $Spamc;
 
  if ( $Spamc =~ /X-Spam-Flag: YES/ ) {
   $Spam_found = 'SPAM';
  } else {
   $Spam_found = 'NOT SPAM';
  }

  if ($Delete_spam_score >= 1 || $Spam_score_log == 1) {
   $Spam_score = `$Grep "X-Spam-Level:" $File | $Awk '{print \$2}'`;
   $Spam_score =~ s/\s//g;
   $Spam_score =~ s/\n//;
   $Spam_score = length($Spam_score);

   if ( $Spam_score >= $Delete_spam_score && Delete_spam_score != 0) {
    $exit = 20;
    $Spam_deleted = 'Yes';
   } else {
    $Spam_deleted = 'No';
   }
  } else {
   $Spam_deleted = 'No';
  }

 } ## if ($Bound eq "-I") { 
 
 if ( $Bound eq "-O" && $Spam_logging_outgoing == 1 ) {

  $Spamc = `$Spamc -c < $File `;
  $Spamc =~ s/\n//;

  open(FILE,"> $File");
   print FILE $Xmail_data;
   print FILE $Real_data;
  close(FILE);

  @Spam_scores = split(/\//,$Spamc); 
  $Spam_score  = $Spam_scores[0];
 
  if ($Spam_scores[0] > $Spam_scores[1]) {
   $Spam_found = 'SPAM';
  } else {
   $Spam_found = 'NOT SPAM';
  }
   
  if ( $Delete_outgoing_spam_score >= 1 ) {
   if ( $Spam_score >= $Delete_outgoing_spam_score && $Delete_outgoing_spam_score != 0) {
    $exit = 20;
    $Spam_deleted = 'Yes';
   } else {
    $Spam_deleted = 'No';
   }
  } else {
   $Spam_deleted = 'No';
  }

 } ## if ( $Bound eq "-O" && $Spam_logging_outgoing == 1 ) {
  
  ##
  ### Spam Log File Stuff
  ##
 
 if ( $Spam_logging == 1 ) {
  
  $Log_file = $Mail_Root.'/logs/spam-'.sprintf "%4d%02d%02d000",$year+1900,$mon+1,$mday,$hour,$min,$sec;
 
  $Log  = '"'.$DateTime.'"'."\t";
  $Log .= '"'.$Spam_found.'"'."\t";
  $Log .= '"'.$To.'"'."\t" ;
  $Log .= '"'.$From.'"'."\t" ;
  $Log .= '"'.$Spam_score.'"'."\t" ;
  $Log .= '"'.$Spam_deleted.'"'."\t" ;
  $Log .= '"'.$Bound.'"'."\t" ;
 
 
  open(LOG,">> $Log_file");
   print LOG "$Log\n";
  close(LOG);
 }

} ## if ( $Spam_scan == 1 ) {

## exit code
if (!$exit) {
 $exit = 7;
}
exit $exit;
