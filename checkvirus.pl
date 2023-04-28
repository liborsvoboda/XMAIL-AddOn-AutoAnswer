#!/usr/bin/perl -w

# version 1.9 - see whatsnew.txt for revision update

use Mail::Sendmail;
use Digest::MD5 qw(md5_hex);
use FindBin qw($Bin);
use Switch;
use strict;

my $cfgfile = "$Bin/checkvirus.cfg";
my $MailToOriginator = "$Bin/mailto_originator.txt";
my $MailToReceiver = "$Bin/mailto_receiver.txt";
my $MailToPostmaster = "$Bin/mailto_postmaster.txt";

require("$cfgfile");

our $name_postmaster;
our $postmaster;
our $mail_host;
our $send_to_sender;
our $send_to_sender_template;
our $send_to_rcpt;
our $send_to_rcpt_template;
our $send_to_postmaster;
our $send_to_postmaster_template;
our $filter_dir;
our $fprot_dir;
our $enable_fprot_scan;
our $antivir_dir;
our $enable_antivir_scan;
our $clamav_dir;
our $enable_clamav_scan;
our $clamav_unrar_param;
our $clamav_unzip_param;
our $clamav_unace_param;
our $clamav_arj_param;
our $clamav_unzoo_param;
our $clamav_lha_param;
our $clamav_jar_param;
our $clamav_tar_param;
our $clamav_deb_param;
our $clamav_tgz_param;
our $enable_mcafee_scan;
our $mcafee_dir;


our $tmpdir;
our $secret_code;
our $exitmethod;
our $subject;
our $errorsubject;
our $scanner_error_template;
our $enableLogging;
our $XMAIL_LOG_PATH;
our $xmail_version;

my $version = "1.9";
my $versionstring = "\n--- AV Filter $version for XMail (http://www.lindeman.org/filters.html)\n";
my $headerstring = "X-AV-Scanned: yes  ";

my $debug = 0;	# this flag enables debugmode of the script. Do not set to 1 if you do not know why or if did not ask you so!

sub logit($$$$);
sub openLog($);
sub closeLog($);

if ($xmail_version ne "115" && $xmail_version != "116") {
	print "Wrong version of XMail set in configuration file.\n";
	print "Set \$xmail_version to 115 if you run XMail 1.15 or older.\n";
	print "Set \$xmail_version to 116 if you run XMail 1.16 or newer.\n";
	exit 0;
}

# Set a default exitcode 
my $exitcode = 97;

if ($xmail_version == 115) {
	if ($exitmethod eq 'reject_freeze') {
		$exitcode = 98;
	}
	if ($exitmethod eq 'reject_no_freeze') {
		$exitcode = 97;
	}
}

if ($xmail_version == 116) {
	if ($exitmethod eq 'reject_freeze') {
		$exitcode = 21;
	}
	if ($exitmethod eq 'reject_no_freeze') {
		$exitcode = 20;
	}
}

my $virus_found = 0;
my $virusname = "";
my $retCode = 0;

# Check if the correct number of arguments we're given. If not exit with code 0. 
# Mail is not scanned and there was not an error given to XMail
if ($#ARGV + 1 != 4) {	
	print "Invalid nr of arguments given.\x0a";
	exit 0;
}

my $fileName = $ARGV[0];
my $sender = $ARGV[1];
my $rcpt = $ARGV[2];
my $msgid = $ARGV[3];

my $crlf = "\x0d\x0a";

# Check if mail was scanned before, this can happen when a message that is in the spool
#my $MailScan = ;
switch (CheckIfMailAllreadyIsScanned()) {
	case 1 {
		# Mail was allready scanned so we exit with a 0 value so XMail can continue
		print "Mail was allready scanned.\x0a";
		exit 0;
	}
	case 2 {
		# Mailfile could not be scanned correctly, a read faillure occured, exit 0 to XMail because we can not scan this file.
		print "Mailfile is corrupt. Not possible to correctly scan this file !\x0a";
		exit 0;
	}
}

my $dirName = $tmpdir . substr(md5_hex(time().rand()),0,16) . ".scan";

my $logHandle = openLog($XMAIL_LOG_PATH);

# Create a temp dir for the files
my $dircreated = mkdir($dirName, 0777);

$dirName = "$dirName/";

# Unpack the mail in the temp dir.
system("$filter_dir"."reformime -x$dirName < $fileName");

# Only if McAfee is enabled.
if ($enable_mcafee_scan == 1 && $virus_found == 0) {
	$retCode = system("$mcafee_dir"."uvscan --secure -r --program --summary $dirName/* > $fileName".".report") >> 8;

	if ($retCode == 2 || $retCode == 6 || $retCode == 8 || $retCode == 12 || $retCode == 15) {
		# serious troubles, scanning could not be performed so write postmaster an email

		my $check = CheckHeader("X-errormail");
		if ($check == 0) {
			$check = CheckTime("$filter_dir"."mcafee.error");
			if ($check != 0) { # Last error mail is longer then 1 hour ago
				my $errortext = "Unknown error";
				if ($retCode == 2) {
					$errortext = "Integrity check on a DAT file failed.";
				}
				if ($retCode == 6) {
					$errortext = "A general problem occurred.";
				}
				if ($retCode == 8) {
					$errortext = "The scanner could not find a DAT file.";
				}
				if ($retCode == 12) {
					$errortext = "The scanner tried to clean a file, and that attempt failed for some reason, and the file is still infected.";
				}
				if ($retCode == 15) { 
					$errortext = "The scanner’s self-check failed; it may be infected or damaged.";
				}

				$errorsubject =~ s/%scanner%/McAfee/g;

				my $template = $filter_dir . $scanner_error_template;
				open(MESSAGEFILE, "$template") || die("Could not open file!");
				my @message = <MESSAGEFILE>;
				close(MESSAGEFILE);

				my $message = join "", @message;

				$message =~ s/%scanner%/McAfee/g;
				$message =~ s/%errorcode%/$retCode/g;
				$message =~ s/%errortext%/$errortext/g;

				$message .= $versionstring;

				my %mail = ('Smtp'	=>	$mail_host,
								'X-Mailer'	=>	"AV-Filter " . $version,
								'X-errormail' => "AntiVir error",
								'To'		=>	$postmaster,
								'From'	=>	$postmaster,
								'Date'	=>	Mail::Sendmail::time_to_date(time()),
								'Subject'=>	$errorsubject,
								'Body'	=> $message);
							
				if (!sendmail %mail) {
					print $Mail::Sendmail::error;
				}
			}
		}

	}

	if ($retCode == 13) {	# McAfee found a virus !!
		$virus_found = 1;
		my $line = "";
		my $dataindex;
		my $quit = 0;
		
		open(IN, "$fileName".".report");
		$line = <IN> || ($quit = 1);
		
		while ($line && $quit == 0) {
			if ($line) {
				
				# Find the virus name in the report lines
				$dataindex = index($line, "Found the ");
				if ($dataindex > 0) {
					$line = substr($line, $dataindex + 10);
					$line =~ s/ virus !!!//;
					$virusname = $line;
					$quit = 1;
				}

				# for some odd reason McAfee's line for the eicar test virus is different
				$dataindex = index($line, "Found: ");
				if ($dataindex > 0) {
					$virusname = substr($line, $dataindex + 7);
					$virusname =~ s/ NOT a virus.//;
					$quit = 1;
				}
				
			$line = <IN> || ($quit = 1);
			}
		}

		close(IN);
	}
}


# If F-Prot scan is enabled scan now.
if ($enable_fprot_scan == 1 && $virus_found == 0) {
	$retCode = system("$fprot_dir"."f-prot --archive $dirName/* > $fileName".".report") >> 8;
	if ($retCode == 1 || $retCode == 2 || $retCode == 5 || $retCode == 7) {
		# serious troubles, scanning could not be performed so write postmaster an email
		# Only 1 error mail per hour is allowed so we're gonna write the current systemtime in a logfile

		my $check = CheckTime("$filter_dir"."fprot.error");
		if ($check != 0) {  # Last error mail is longer then 1 hour ago
			my $errortext = "Unknown error";
			if ($retCode == 1) {
				$errortext = "Unrecoverable error (for example, missing SIGN.DEF).";
			}
			if ($retCode == 2) {
				$errortext = "Selftest failed (program has been modified).";
			}
			if ($retCode == 5) {
				$errortext = "Abnormal termination (scanning did not finish).";
			}
			if ($retCode == 7) {
				$errortext = "Error, out of memory";
			}
			
			$errorsubject =~ s/%scanner%/F-Prot/g;
			
			my $template = $filter_dir . $scanner_error_template;
			open(MESSAGEFILE, "$template") || die("Could not open file!");
			my @message = <MESSAGEFILE>;
			close(MESSAGEFILE);
		
			my $message = join "", @message;
			
			$message =~ s/%scanner%/F-Prot/g;
			$message =~ s/%errorcode%/$retCode/g;
			$message =~ s/%errortext%/$errortext/g;
				
			$message .= $versionstring;
			
			my %mail = ('Smtp'	=>	$mail_host,
							'X-Mailer'	=>	"AV-Filter " . $version,
							'X-errormail' => "F-Prot error",
							'To'		=>	$postmaster,
							'From'	=>	$postmaster,
							'Date'	=>	Mail::Sendmail::time_to_date(time()),
							'Subject'=>	$errorsubject,
							'Body'	=> $message);

			if(!sendmail %mail) {
				print $Mail::Sendmail::error;
			}
		}

	}

	if ($retCode == 3) { # Virus was found by Fprot !
		$virus_found = 1;
		my $line = "";
		my $dataindex;
		my $quit = 0;
		
		open(IN, "$fileName".".report");
		$line = <IN> || ($quit = 1);
		
		while ($line && $quit == 0) {
			if ($line) {
				$dataindex = index($line, "Infection: ");
				if ($dataindex > 0) {
					$virusname = substr($line, $dataindex + 11);
					$quit = 1;
				}
			$line = <IN> || ($quit = 1);
			}
		}
		close(IN);
	}
}

# Only if AntiVir is enabled.
if ($enable_antivir_scan == 1 && $virus_found == 0) {
	$retCode = system("$antivir_dir"."antivir --allfiles -z -s $dirName/* > $fileName".".report") >> 8;
	if ($retCode == 200 || $retCode == 201 || $retCode == 202 || $retCode == 203 || $retCode == 204 || $retCode == 205 || $retCode == 210 || $retCode == 211 || $retCode == 212 || $retCode == 213) {
		# serious troubles, scanning could not be performed so write postmaster an email

		my $check = CheckHeader("X-errormail");
		if ($check == 0) {
			$check = CheckTime("$filter_dir"."antivir.error");
			if ($check != 0) { # Last error mail is longer then 1 hour ago
				my $errortext = "Unknown error";
				if ($retCode == 200) {
					$errortext = "Program aborted, not enough memory available";
				}
				if ($retCode == 201) {
					$errortext = "The given response file could not be found";
				}
				if ($retCode == 202) {
					$errortext = "Within a response file another @<rsp> directive was found";
				}
				if ($retCode == 203) {
					$errortext = "Invalid option";
				}
				if ($retCode == 204) {
					$errortext = "Invalid (non-existent) directory given at command line";
				}
				if ($retCode == 205) { 
					$errortext = "The log file could not be created";
				}
				if ($retCode == 210) {
					$errortext = "AntiVir could not find a necessary dll file";
				}
				if ($retCode == 211) {
					$errortext = "Programm aborted, because the self check failed";
				}
				if ($retCode == 212) {
					$errortext = "The file antivir.vdf could not be read";
				}
				if ($retCode == 213) {
					$errortext = "An error occured during initialisation";
				}

				$errorsubject =~ s/%scanner%/AntiVir/g;

				my $template = $filter_dir . $scanner_error_template;
				open(MESSAGEFILE, "$template") || die("Could not open file!");
				my @message = <MESSAGEFILE>;
				close(MESSAGEFILE);

				my $message = join "", @message;

				$message =~ s/%scanner%/AntiVir/g;
				$message =~ s/%errorcode%/$retCode/g;
				$message =~ s/%errortext%/$errortext/g;

				$message .= $versionstring;

				my %mail = ('Smtp'	=>	$mail_host,
								'X-Mailer'	=>	"AV-Filter " . $version,
								'X-errormail' => "AntiVir error",
								'To'		=>	$postmaster,
								'From'	=>	$postmaster,
								'Date'	=>	Mail::Sendmail::time_to_date(time()),
								'Subject'=>	$errorsubject,
								'Body'	=> $message);
							
				if (!sendmail %mail) {
					print $Mail::Sendmail::error;
				}
			}
		}

	}

	if ($retCode == 1) {	# AntiVir found a virus !!
		$virus_found = 1;
		my $line = "";
		my $dataindex;
		my $quit = 0;
		my $token = "\[";
		
		open(IN, "$fileName".".report");
		$line = <IN> || ($quit = 1);
		
		while ($line && $quit == 0) {
			if ($line) {
				$dataindex = index($line, $token);
				if ($dataindex > 0) {
					$line =~ /^(.*)\[(.*)\](.*)$/;
					$line = $2;
					$line =~ s/ virus//;
					$virusname = $line;
					$quit = 1;
				}
			$line = <IN> || ($quit = 1);
			}
		}
		close(IN);
	}
}


# If ClamAV scan is enabled scan now.
if ($enable_clamav_scan == 1 && $virus_found == 0) {
	system('rm', '-r', $fileName.".report");
	$retCode = system("$clamav_dir"."clamscan $clamav_unrar_param $clamav_unzip_param $clamav_unace_param $clamav_arj_param $clamav_unzoo_param $clamav_lha_param $clamav_jar_param $clamav_tar_param $clamav_deb_param $clamav_tgz_param --quiet -r -l $fileName".".report $dirName") >> 8;
	if ($retCode == 40 || $retCode == 50 || $retCode == 51 || $retCode == 52 || $retCode == 53 || $retCode == 54 || $retCode == 55 || $retCode == 56 || $retCode == 57 || $retCode == 58 || $retCode == 59 || $retCode == 60 || $retCode == 61 || $retCode == 63 || $retCode == 64 || $retCode == 70 || $retCode == 71) {
		# serious troubles, scanning could not be performed so write postmaster an email
		# Only 1 error mail per hour is allowed so we're gonna write the current systemtime in a logfile

		my $check = CheckTime("$filter_dir"."clamav.error");
		if ($check != 0) {  # Last error mail is longer then 1 hour ago
			my $errortext = "Unknown error";
			if ($retCode == 40) {
				$errortext = "Unknown option was passed to clamscan. Please check clamscan --help or manual page for available options";
			}
			if ($retCode == 50) {
				$errortext = "Problem with initialization of virus database. Probably it doesn't exist in the default place or wrong file was passed to -database";
			}
			if ($retCode == 51) {
				$errortext = "Wrong nr of threads was passed to -threads. It must be a natural number >= 0";
			}
			if ($retCode == 52) {
				$errortext = "Not supported file type. Scanner supports regular files, directories and symlinks";
			}
			if ($retCode == 53) {
				$errortext = "Can't open directory";
			}
			if ($retCode == 54) {
				$errortext = "Can't open file";
			}
			if ($retCode == 55) {
				$errortext = "Error reading file. Probably the medium you are reading is broken.";
			}
			if ($retCode == 56) {
				$errortext = "Can't stat input file or directory. File/Directory you want to scan does not exist";
			}
			if ($retCode == 57) {
				$errortext = "Can't getabsolute pathname of current working directory. Your current pathname is longer then 200 characters. When clamscan is started wihtout an input file/directory it scans the current directory. For some reason it needs absolute pathnames, the buffer is hardcoded to 200 characters and that should be sufficient.";
			}
			if ($retCode == 58) {
				$errortext = "IO error, please check the filesystem";
			}
			if ($retCode == 59) {
				$errortext = "Can't get information about current user (running clamscan)";
			}
			if ($retCode == 60) {
				$errortext = "Can't get information about user clamscan, user clamscan (default unprivileged user) doesn't exist in /etc/passwd";
			}
			if ($retCode == 61) {
				$errortext = "Can't fork. Can't create new process, please check your limits";
			}
			if ($retCode == 63) {
				$errortext = "Can't create temporary file or directory. Please check permissions";
			}
			if ($retCode == 64) {
				$errortext = "Can't write to temporary directory. Please specify another one";
			}
			if ($retCode == 70) {
				$errortext = "Can't allocate and clear memory. This is a critical error, please check your system";
			}
			if ($retCode == 71) {
				$errortext = "Can't allocate memory. This is a critical error, please check your system";
			}
			
			$errorsubject =~ s/%scanner%/ClamAV/g;
			
			my $template = $filter_dir . $scanner_error_template;
			open(MESSAGEFILE, "$template") || die("Could not open file!");
			my @message = <MESSAGEFILE>;
			close(MESSAGEFILE);
		
			my $message = join "", @message;
			
			$message =~ s/%scanner%/ClamAV/g;
			$message =~ s/%errorcode%/$retCode/g;
			$message =~ s/%errortext%/$errortext/g;
				
			$message .= $versionstring;
			
			my %mail = ('Smtp'	=>	$mail_host,
							'X-Mailer'	=>	"AV-Filter " . $version,
							'X-errormail' => "ClamAV error",
							'To'		=>	$postmaster,
							'From'	=>	$postmaster,
							'Date'	=>	Mail::Sendmail::time_to_date(time()),
							'Subject'=>	$errorsubject,
							'Body'	=> $message);

			if(!sendmail %mail) {
				print $Mail::Sendmail::error;
			}
		}

	}

	if ($retCode == 1) { # Virus was found by ClamAV !
		$virus_found = 1;
		my $line = "";
		my $dataindex1;
		my $dataindex2;
		my $quit = 0;
		
		open(IN, "$fileName".".report");
		$line = <IN> || ($quit = 1);
		
		while ($line && $quit == 0) {
			if ($line) {
				$dataindex1 = index($line, ": ") + 2;
				$dataindex2 = index($line, " FOUND");
				if ($dataindex1 > 0 && $dataindex2 > 0) {
					$virusname = substr($line, $dataindex1, $dataindex2 - $dataindex1);
					$quit = 1;
				}
			$line = <IN> || ($quit = 1);
			}
		}
		close(IN);
	}
}

system('rm', '-r', $dirName);

if ($virus_found == 1) { # A virus was found !!!
	my $msgout = GetHeaders();
	open(IN, "$fileName".".report");
	my @report = <IN>;
	close(IN);
	
	my $report = join "", @report;
	
	system('rm', "$fileName".".report");

	my %mail = ('Smtp'	=>	$mail_host,
					'X-Mailer'	=>	"AV-Filter " . $version,
					'To'		=>	$sender,
					'From'	=>	$postmaster,
					'Date'	=>	Mail::Sendmail::time_to_date(time),
					'Subject'=>	$subject );

	logit($logHandle, "Virus : $virusname", $sender, $rcpt);

	if ($send_to_sender == 1) {
		# Send an email to the sender of the virus
		my $template = $filter_dir . $send_to_sender_template;
		open(MESSAGEFILE, "$template") || die("Could not open file!");
		my @message = <MESSAGEFILE>;
		close(MESSAGEFILE);
		
		my $message = join "", @message;
	
		$message =~ s/%sender%/$sender/g;
		$message =~ s/%recipient%/$rcpt/g;
		$message =~ s/%name_postmaster%/$name_postmaster/g;
		$message =~ s/%email_postmaster%/$postmaster/g;
		$message =~ s/%headers%/$msgout/g;
		$message =~ s/%report%/$report/g;
		$message =~ s/%virus%/$virusname/g;

		$message .= $versionstring;

		$mail{Body} = $message;

		if(!sendmail %mail) {
			print $Mail::Sendmail::error;
		}
	}


	if ($send_to_rcpt == 1) { # Send an email to the recipient of the virus

		$mail{To} = $rcpt;
		
		my $template = $filter_dir . $send_to_rcpt_template;
		open(MESSAGEFILE, "$template") || die("Could not open file!");
		my @message = <MESSAGEFILE>;
		close(MESSAGEFILE);
		
		my $message = join "", @message;
	
		$message =~ s/%sender%/$sender/g;
		$message =~ s/%recipient%/$rcpt/g;
		$message =~ s/%name_postmaster%/$name_postmaster/g;
		$message =~ s/%email_postmaster%/$postmaster/g;
		$message =~ s/%headers%/$msgout/g;
		$message =~ s/%report%/$report/g;
		$message =~ s/%virus%/$virusname/g;

		$message .= $versionstring;
		

		$mail{Body} = $message;

		if(!sendmail %mail) {
			print $Mail::Sendmail::error;
		}
	}


	if ($send_to_postmaster eq 1) {
		# Send an email to the recipient of the virus

		$mail{To} = $postmaster;

		my $template = $filter_dir . $send_to_postmaster_template;
		open(MESSAGEFILE, "$template") || die("Could not open file!");
		my @message = <MESSAGEFILE>;
		close(MESSAGEFILE);
		
		
		my $message = join "", @message;
	
		$message =~ s/%sender%/$sender/g;
		$message =~ s/%recipient%/$rcpt/g;
		$message =~ s/%name_postmaster%/$name_postmaster/g;
		$message =~ s/%email_postmaster%/$postmaster/g;
		$message =~ s/%headers%/$msgout/g;
		$message =~ s/%report%/$report/g;
		$message =~ s/%virus%/$virusname/g;
		
  		$message .= $versionstring;

		$mail{Body} = $message;

		if(!sendmail %mail) {
			print $Mail::Sendmail::error;
		}
	}
	
	closeLog($logHandle);
	exit $exitcode;
}

system('rm', "$fileName".".report");

# If there was no virus found then add a header that this message was scanned.
if ($retCode == 0 && $virus_found == 0) {
	AddHeader();
	if ($xmail_version == 115) {
		$exitcode = 100;
	}

	if ($xmail_version == 116) {
		$exitcode = 7;
	}
}

closeLog($logHandle);
exit $exitcode;


sub GetHeaders {
	open(MAILFILE, $fileName) || die("Could not open file!");
	my $line = "";
	my $maildatastring = "<<MAIL-DATA>>";
	my $headerstart = 0;
	my $location = -1;
	my $foundmaildata = 0;
	my $msgout = "";
	my $quit = 0;

	while ($line ne "$crlf" && $quit == 0)
	{
		$line = <MAILFILE> || ($quit = 1);

		if ($foundmaildata == 1) {
			$headerstart = 1;
			$foundmaildata = 0;
		}

		$location = index($line, $maildatastring);
		if ($location >= 0) {
			$foundmaildata = 1;
		}

		if ($headerstart == 1) {
			$msgout .= $line;
		}
	}

	close(MAILFILE);

	return $msgout;
}


sub CheckHeader {
	my $findheader = shift;
	my $line = "";

	open(MAILFILE, $fileName) || die("Could not open file!");
	my $headerfound = 0;
	my $quit = 0;

	while ($line ne "$crlf" && $headerfound == 0 && $quit == 0)
	{
		$line = <MAILFILE> || ($quit = 1);
		if (index($line, $findheader) >= 0) {
			$headerfound = 1;
		}
	}

	close(MAILFILE);

	return $headerfound;

}

sub CheckTime {
	my $checkfile = shift;
	my $returnvalue = 0;

	open(CHECKFILE, $checkfile);

	my $line = "";

	$line = <CHECKFILE>;
	close(CHECKFILE);

	my $checktime = $line + 3600;

	if ($checktime < time())			# longer then 1 hour ago
	{
		# Older then 1 hour so we write a new timestamp
		$returnvalue = 1;
		open(CHECKFILE, ">" . $checkfile);
		my $lineout = time();
		print CHECKFILE $lineout;

		close(CHECKFILE);
	}

	return $returnvalue;
}

sub CalculateMD5Key {
	
	my $md5key = md5_hex($secret_code . $msgid);
	
	return $md5key;
}

sub AddHeader {
	open(MAILFILE, $fileName) || die("Could not open file!");
	my @mail = <MAILFILE>;
	close(MAILFILE);
	
	my $md5key = CalculateMD5Key();
	
	my $mail = join "", @mail;
	
	# Find "crlf<<MAIL-DATA>>crlf" in the message and replace
	# it with "crlf<<MAIL-DATA>>crlf$headerstring$md5key$crlf"
	$mail =~ s/($crlf<<MAIL-DATA>>$crlf)/$1$headerstring$md5key$crlf/;
	
	open(KEEP, ">$fileName");
	print KEEP $mail;
	close(KEEP);
}

sub CheckIfMailAllreadyIsScanned {
	open(MAILFILE, $fileName) || die("Could not open file!");
	my $line = "";
	my $headerstart = 0;
	my $location = -1;
	my $foundstring = 0;
	my $returnvalue = 0;

	while ($returnvalue == 0 && $line ne "$crlf") {
		$line = <MAILFILE> || return 2;
		
		if ($debug == 1) {
			print $line;
			sleep 1;
		}
		
		$location = index($line, $headerstring);
		
		if ($location == 0) {
			my $md5found = substr($line, length($headerstring));
			$md5found =~ s/\x0d$//;
			$md5found =~ s/\x0a$//;

			my $md5key = CalculateMD5Key();
			
			# Compared the calculated md5 key with the found md5key
			if ($md5key eq $md5found) {
				$returnvalue = 1;
			}
		}
	}

	close(MAILFILE);

	return $returnvalue;	
}


sub openLog($) {
	if ($enableLogging != 1) {
		return 0;
	}

	my ($logPath)=(@_);
	my ($sec,$min,$hour,$dmon,$mon,$year,$wday,$yday,$isdst) = localtime(time());
	$year+=1900;
	$mon++;

	# format the filename similar to other xmail log files.
	my $date = sprintf("%04d%02d%02d",$year,$mon,$dmon );
	
	my $logFile = "$logPath/antivirus-${date}0100";

	open (my $logHandle, ">>$logFile") or die("Can't open log file $logFile");
	return $logHandle;
}

sub closeLog($) {
	if ($enableLogging != 1) {
		return 0;
	}

	my ($logHandle)=@_;
	close($logHandle);
}

sub logit($$$$) {
	if ($enableLogging != 1) {
		return 0;
	}

	my ($logHandle, $virus, $sender, $rcpt) = @_;
	
	#Strip any new lines.
	$virus=~s/\n|\r//g;
	my ($sec,$min,$hour,$dmon,$mon,$year,$wday,$yday,$isdst) = localtime(time());
	$year+=1900;
	$mon++;

	my $dateTime = sprintf("\"%04d-%02d-%02d %02d:%02d:%02d\"",$year,$mon,$dmon,$hour,$min,$sec);
	$virus="\"$virus\"";
	$sender="\"$sender\"";
	$rcpt="\"$rcpt\"";
	print $logHandle "$dateTime\t$virus\t$sender\t$rcpt\n";
}
