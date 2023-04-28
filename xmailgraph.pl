#!/usr/bin/perl

#-----------------------------------------------------
# Configuration / Paths / Binaries
my ($hostname) = "Poskytovatel KlikneteZde.Cz";		# Hostname used inside graphs
my ($dir_of_pngs) = "/var/www/https/phpxmail/xmailgraph/";	# Where to put the graphs

my ($path_to_xmail_logs) = "/var/log/xmail/";	# Where are the xmail-Logs
my ($path_to_rrd) = "/var/log/xmail/";		# Where are the RRDs located


my ($bin_grep) = "/bin/grep";
my ($bin_wc) = "/usr/bin/wc";
my ($bin_rrdtool) = "/usr/bin/rrdtool";
my ($path_of_devnull) = "/dev/null";

$DEBUG=0; # Set DEBUG to 1 if you want to see what is going on

#--------------------------------------------------------
# Functions / Initialisierungen

sub trim {
    my @out = @_;
    for (@out) {
        s/^\s+//;
        s/\s+$//;
    }
    return wantarray ? @out : $out[0];
}

# time-600 = 10 minutes ago
my ($se, $mi, $st, $mo, $mt, $ja, $wt, $jt, $sz) = localtime(time - 600);
$mt+=1; $ja+=1900; $jt+=1;
$mt = $mt < 10 ? $mt = "0".$mt : $mt; $mo = $mo < 10 ? $mo = "0".$mo : $mo;
$st = $st < 10 ? $st = "0".$st : $st; $mi = $mi < 10 ? $mi = "0".$mi : $mi;
my($km) = substr($mi,0,1);

# time-string used for grep
# if xmailgraph.pl runs to slow comment out the 3rd $akt_log!

my ($akt_log) = $ja.$mt.$mo."*";   # Date of logfile
$akt_log = $ja.$mt."*";
$akt_log = $ja."*";


my ($akt_time) = $ja."-".$mt."-".$mo." ".$st.":".$km;  # Date/Time for

#--------------------------------------------------------
# Get Values from the logs

my ($b_pop3) = "( ".$bin_grep." \"$akt_time\" ".$path_to_xmail_logs."pop3-".$akt_log." | $bin_wc -l ) 2>".$path_of_devnull;
my ($c_pop3) = trim(`$b_pop3`);
if($DEBUG==1){ print "\n$b_pop3"; }

my ($b_antiv) = "( ".$bin_grep." \"$akt_time\" ".$path_to_xmail_logs."antivirus-".$akt_log." | $bin_grep \"\\\"Virus : \" | $bin_wc -l ) 2>".$path_of_devnull;
my ($c_antiv) = trim(`$b_antiv`);
if($DEBUG==1){ print "\n$b_antiv"; }

my ($b_bounce) = "( ".$bin_grep." \"$akt_time\" ".$path_to_xmail_logs."smtp-".$akt_log." | $bin_grep \"RCPT=EAVAIL\" | $bin_wc -l ) 2>".$path_of_devnull;
my ($c_bounce) = trim( `$b_bounce` );
if($DEBUG==1){ print "\n$b_bounce"; }

my ($b_spam1) = "( ".$bin_grep." \"$akt_time\" ".$path_to_xmail_logs."smtp-".$akt_log." | $bin_grep \"SNDR=ESPAM\" | $bin_wc -l ) 2>".$path_of_devnull;
my ($c_spam1) = trim( `$b_spam1` );
if($DEBUG==1){ print "\n$b_spam1"; }

my ($b_spam2) = "( ".$bin_grep." \"$akt_time\" ".$path_to_xmail_logs."spam-".$akt_log." | $bin_grep \"\\\"SPAM\\\"\" | $bin_wc -l ) 2>".$path_of_devnull;
my ($c_spam2) = trim( `$b_spam2` );
if($DEBUG==1){ print "\n$b_spam2"; }

my ($b_spam3) = "( ".$bin_grep." \"$akt_time\" ".$path_to_xmail_logs."smtp-".$akt_log." | $bin_grep \"SNDRIP=EIPMAP\" | $bin_wc -l ) 2>".$path_of_devnull;
my ($c_spam3) = trim( `$b_spam3` );
if($DEBUG==1){ print "\n$b_spam3"; }

my ($b_sent) = "( ".$bin_grep." \"$akt_time\" ".$path_to_xmail_logs."smail-".$akt_log." | $bin_grep \"\\\"SMTP\\\"\" | $bin_wc -l ) 2>".$path_of_devnull;
my ($c_sent) = trim( `$b_sent` );
if($DEBUG==1){ print "\n$b_sent"; }

my ($b_sent_fwd) = "( ".$bin_grep." \"$akt_time\" ".$path_to_xmail_logs."smail-".$akt_log." | $bin_grep \"\\\"FWD\\\"\" | $bin_wc -l ) 2>".$path_of_devnull;
my ($c_sent_fwd) = trim( `$b_sent_fwd` );
if($DEBUG==1){ print "\n$b_sent_fwd"; }

$c_sent = $c_sent + $c_sent_fwd;

my ($b_recv) = "( ".$bin_grep." \"$akt_time\" ".$path_to_xmail_logs."smtp-".$akt_log." | $bin_grep \"RECV=OK\" | $bin_wc -l ) 2>".$path_of_devnull;
my ($c_recv) = trim( `$b_recv` );
if($DEBUG==1){ print "\n$b_recv"; }

my ($msg_total) = $c_recv + $c_sent + $c_bounce + $c_spam1 + $c_spam3;

if($DEBUG==1){
print "
-----------------------------------
$akt_log / $akt_time:
RECV:\t $c_recv
SENT:\t $c_sent
EAVAIL:\t $c_bounce
SPAM1:\t $c_spam1
SPAM2:\t $c_spam2
SPAM3:\t $c_spam3
POP3:\t $c_pop3
VIRUS:\t $c_antiv

TOTALMSG:\t $msg_total
-----------------------------------
";
}

# Add SNDRIP=EIPMAP AND SNDR=ESPAM
$c_spam1 = $c_spam1 + $c_spam3;

#--------------------------------------------------------
# Write Values to the rrd

my ($timestamp) = time();
my ($rrd_update1) = $bin_rrdtool." update ".$path_to_rrd."WN_xmail_pop3.rrd -t pop3 ".$timestamp.":".$c_pop3;
if($DEBUG==1){ print "$rrd_update1\n"; }
`$rrd_update1`;

my ($rrd_update4) = $bin_rrdtool." update ".$path_to_rrd."WN_xmail_antivirus.rrd -t virus ".$timestamp.":".$c_antiv;
if($DEBUG==1){ print "$rrd_update4\n"; }
`$rrd_update4`;

my ($rrd_update2) = $bin_rrdtool." update ".$path_to_rrd."WN_xmail_spam.rrd -t spam1:spam2 ".$timestamp.":".$c_spam1.":".$c_spam2;
if($DEBUG==1){ print "$rrd_update2\n"; }
`$rrd_update2`;

my ($rrd_update3) = $bin_rrdtool." update ".$path_to_rrd."WN_xmail_smtp.rrd -t sent:recv:bounce ".$timestamp.":".$c_sent.":".$c_recv.":".$c_bounce;
if($DEBUG==1){ print "$rrd_update3\n"; }
`$rrd_update3`;


#--------------------------------------------------------
# Create the Graphs

my ($pop3_daily) = $bin_rrdtool." graph ".$dir_of_pngs."pop3_daily.png \\
--imgformat=PNG --start=-86400 --title=\"$hostname - daily POP3 Usage\" --height=120 --width=540 --vertical-label=\"sessions/min\" \\
DEF:gpop3=\"".$path_to_rrd."WN_xmail_pop3.rrd\":pop3:AVERAGE CDEF:a=gpop3,60,* LINE1:a#000000:\"POP3 Sessions\" GPRINT:a:LAST:\"Current\\:%8.2lf %s\"  \\
GPRINT:a:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:a:MAX:\"Maximum\\:%8.2lf %s\\n\" AREA:a#FF0000:\"POP3 Sessions\" ";
`$pop3_daily`;

my ($virus_daily) = $bin_rrdtool." graph ".$dir_of_pngs."virus_daily.png \\
--imgformat=PNG --start=-86400 --title=\"$hostname - daily VIRUSES\" --height=120 --width=540 --vertical-label=\"viruses/min\" \\
DEF:gvir=\"".$path_to_rrd."WN_xmail_antivirus.rrd\":virus:AVERAGE CDEF:a=gvir,60,* LINE1:a#000000:\"Viruses\" GPRINT:a:LAST:\"Current\\:%8.2lf %s\"  \\
GPRINT:a:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:a:MAX:\"Maximum\\:%8.2lf %s\\n\" AREA:a#FF0000:\"Viruses\" ";
`$virus_daily`;


my ($spam_daily) = $bin_rrdtool." graph ".$dir_of_pngs."spam_daily.png \\
--imgformat=PNG --start=-86400 --title=\"$hostname - daily SPAM Messages\" --height=120 --width=540 --vertical-label=\"Messages/min\" \\
DEF:gspam1=\"".$path_to_rrd."WN_xmail_spam.rrd\":spam1:AVERAGE DEF:gspam2=\"".$path_to_rrd."WN_xmail_spam.rrd\":spam2:AVERAGE CDEF:a=gspam1,60,* CDEF:b=gspam2,60,* CDEF:ab=a,b,+ \\
LINE1:ab#CCCCCC:\"Total Spam    \" GPRINT:ab:LAST:\"Current\\:%8.2lf %s\" GPRINT:ab:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:ab:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
AREA:ab#CCCCCC:\"Total Spam\\n\" \\
LINE2:a#FF0000:\"ESPAM / EIPMAP\" GPRINT:a:LAST:\"Current\\:%8.2lf %s\" GPRINT:a:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:a:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
LINE3:b#0000FF:\"Spamassassin  \" GPRINT:b:LAST:\"Current\\:%8.2lf %s\" GPRINT:b:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:b:MAX:\"Maximum\\:%8.2lf %s\\n\" ";
`$spam_daily`;

my ($bounce_daily) = $bin_rrdtool." graph ".$dir_of_pngs."bounce_daily.png \\
--imgformat=PNG --start=-86400 --title=\"$hostname - daily BOUNCED Messages\" \\
--height=120 --width=540 --vertical-label=\"Messages/min\" \\
DEF:gbounce=\"".$path_to_rrd."WN_xmail_smtp.rrd\":bounce:AVERAGE \\
DEF:grecv=\"".$path_to_rrd."WN_xmail_smtp.rrd\":recv:AVERAGE \\
DEF:gsent=\"".$path_to_rrd."WN_xmail_smtp.rrd\":sent:AVERAGE \\
CDEF:a=gbounce,60,* CDEF:b=grecv,60,* CDEF:c=gsent,60,* CDEF:abc=a,b,c,+,+ \\
LINE1:abc#FF0000:\"Sum of Msgs\" GPRINT:abc:LAST:\"Current\\:%8.2lf %s\" GPRINT:abc:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:abc:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
AREA:abc#FF0000:\"Sum of Msgs\\n\" \\
LINE2:a#000000:\"RCPT=EAVAIL\" GPRINT:a:LAST:\"Current\\:%8.2lf %s\" GPRINT:a:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:a:MAX:\"Maximum\\:%8.2lf %s\\n\"  ";
`$bounce_daily`;

my ($smtp_daily) = $bin_rrdtool." graph ".$dir_of_pngs."smtp_daily.png \\
--imgformat=PNG --start=-86400 --title=\"$hostname - daily SMTP Stats\" --height=120 --width=540 --vertical-label=\"Messages/min\" \\
DEF:gbounce=\"".$path_to_rrd."WN_xmail_smtp.rrd\":bounce:AVERAGE DEF:grecv=\"".$path_to_rrd."WN_xmail_smtp.rrd\":recv:AVERAGE DEF:gsent=\"".$path_to_rrd."WN_xmail_smtp.rrd\":sent:AVERAGE \\
CDEF:a=gbounce,60,* CDEF:b=grecv,60,* CDEF:c=gsent,60,* CDEF:abc=a,b,c,+,+ \\
LINE1:abc#CCCCCC:\"Sum of Msgs\" GPRINT:abc:LAST:\"Current\\:%8.2lf %s\" GPRINT:abc:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:abc:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
AREA:abc#CCCCCC:\"Sum of Msgs\\n\" \\
LINE2:b#FF0000:\"Received   \" GPRINT:b:LAST:\"Current\\:%8.2lf %s\" GPRINT:b:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:b:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
LINE3:c#0000FF:\"Sent Msgs  \" GPRINT:c:LAST:\"Current\\:%8.2lf %s\" GPRINT:c:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:c:MAX:\"Maximum\\:%8.2lf %s\\n\" ";
`$smtp_daily`;


my ($pop3_weekly) = $bin_rrdtool." graph ".$dir_of_pngs."pop3_weekly.png \\
--imgformat=PNG --start=-604800 --title=\"$hostname - weekly POP3 Usage\" --height=120 --width=540 --vertical-label=\"sessions/min\" \\
DEF:gpop3=\"".$path_to_rrd."WN_xmail_pop3.rrd\":pop3:AVERAGE CDEF:a=gpop3,60,* LINE1:a#000000:\"POP3 Sessions\" \\
GPRINT:a:LAST:\"Current\\:%8.2lf %s\" GPRINT:a:AVERAGE:\"Average\\:%8.2lf %s\"  \\
GPRINT:a:MAX:\"Maximum\\:%8.2lf %s\\n\" AREA:a#FF0000:\"POP3 Sessions\" ";
`$pop3_weekly`;

my ($virus_weekly) = $bin_rrdtool." graph ".$dir_of_pngs."virus_weekly.png \\
--imgformat=PNG --start=-604800 --title=\"$hostname - weekly VIRUSES\" --height=120 --width=540 --vertical-label=\"viruses/min\" \\
DEF:gvir=\"".$path_to_rrd."WN_xmail_antivirus.rrd\":virus:AVERAGE CDEF:a=gvir,60,* LINE1:a#000000:\"Viruses\" GPRINT:a:LAST:\"Current\\:%8.2lf %s\"  \\
GPRINT:a:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:a:MAX:\"Maximum\\:%8.2lf %s\\n\" AREA:a#FF0000:\"Viruses\" ";
`$virus_weekly`;


my ($spam_weekly) = $bin_rrdtool." graph ".$dir_of_pngs."spam_weekly.png \\
--imgformat=PNG --start=-604800 --title=\"$hostname - weekly SPAM Messages\" --height=120 --width=540 --vertical-label=\"Messages/min\" \\
DEF:gspam1=\"".$path_to_rrd."WN_xmail_spam.rrd\":spam1:AVERAGE DEF:gspam2=\"".$path_to_rrd."WN_xmail_spam.rrd\":spam2:AVERAGE CDEF:a=gspam1,60,* CDEF:b=gspam2,60,* CDEF:ab=a,b,+ \\
LINE1:ab#CCCCCC:\"Total Spam    \" GPRINT:ab:LAST:\"Current\\:%8.2lf %s\" GPRINT:ab:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:ab:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
AREA:ab#CCCCCC:\"Total Spam\\n\" \\
LINE2:a#FF0000:\"ESPAM / EIPMAP\" GPRINT:a:LAST:\"Current\\:%8.2lf %s\" GPRINT:a:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:a:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
LINE3:b#0000FF:\"Spamassassin  \" GPRINT:b:LAST:\"Current\\:%8.2lf %s\" GPRINT:b:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:b:MAX:\"Maximum\\:%8.2lf %s\\n\" ";
`$spam_weekly`;

my ($bounce_weekly) = $bin_rrdtool." graph ".$dir_of_pngs."bounce_weekly.png \\
--imgformat=PNG --start=-604800 --title=\"$hostname - weekly BOUNCED Messages\" --height=120 --width=540 --vertical-label=\"Messages/min\" \\
DEF:gbounce=\"".$path_to_rrd."WN_xmail_smtp.rrd\":bounce:AVERAGE \\
DEF:grecv=\"".$path_to_rrd."WN_xmail_smtp.rrd\":recv:AVERAGE \\
DEF:gsent=\"".$path_to_rrd."WN_xmail_smtp.rrd\":sent:AVERAGE \\
CDEF:a=gbounce,60,* CDEF:b=grecv,60,* CDEF:c=gsent,60,* CDEF:abc=a,b,c,+,+ \\
LINE1:abc#FF0000:\"Sum of Msgs\" GPRINT:abc:LAST:\"Current\\:%8.2lf %s\" GPRINT:abc:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:abc:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
AREA:abc#FF0000:\"Sum of Msgs\\n\" \\
LINE2:a#000000:\"RCPT=EAVAIL\" GPRINT:a:LAST:\"Current\\:%8.2lf %s\" GPRINT:a:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:a:MAX:\"Maximum\\:%8.2lf %s\\n\" ";
`$bounce_weekly`;

my ($smtp_weekly) = $bin_rrdtool." graph ".$dir_of_pngs."smtp_weekly.png \\
--imgformat=PNG --start=-604800 --title=\"$hostname - weekly SMTP Stats\" \\
--height=120 --width=540 --vertical-label=\"Messages/min\" \\
DEF:gbounce=\"".$path_to_rrd."WN_xmail_smtp.rrd\":bounce:AVERAGE \\
DEF:grecv=\"".$path_to_rrd."WN_xmail_smtp.rrd\":recv:AVERAGE \\
DEF:gsent=\"".$path_to_rrd."WN_xmail_smtp.rrd\":sent:AVERAGE \\
CDEF:a=gbounce,60,* CDEF:b=grecv,60,* CDEF:c=gsent,60,* CDEF:abc=a,b,c,+,+ \\
LINE1:abc#CCCCCC:\"Sum of Msgs\" GPRINT:abc:LAST:\"Current\\:%8.2lf %s\" GPRINT:abc:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:abc:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
AREA:abc#CCCCCC:\"Sum of Msgs\\n\" \\
LINE2:b#FF0000:\"Received   \" GPRINT:b:LAST:\"Current\\:%8.2lf %s\" GPRINT:b:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:b:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
LINE3:c#0000FF:\"Sent Msgs  \" GPRINT:c:LAST:\"Current\\:%8.2lf %s\" GPRINT:c:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:c:MAX:\"Maximum\\:%8.2lf %s\\n\" ";
`$smtp_weekly`;


my ($pop3_monthly) = $bin_rrdtool." graph ".$dir_of_pngs."pop3_monthly.png \\
--imgformat=PNG --start=-2678400 --title=\"$hostname - monthly POP3 Usage\" \\
--height=120 --width=540 --vertical-label=\"sessions/min\" \\
DEF:gpop3=\"".$path_to_rrd."WN_xmail_pop3.rrd\":pop3:AVERAGE \\
CDEF:a=gpop3,60,* LINE1:a#000000:\"POP3 Sessions\"  \\
GPRINT:a:LAST:\"Current\\:%8.2lf %s\" GPRINT:a:AVERAGE:\"Average\\:%8.2lf %s\"  \\
GPRINT:a:MAX:\"Maximum\\:%8.2lf %s\\n\" AREA:a#FF0000:\"POP3 Sessions\" ";
`$pop3_monthly`;

my ($virus_monthly) = $bin_rrdtool." graph ".$dir_of_pngs."virus_monthly.png \\
--imgformat=PNG --start=-2678400 --title=\"$hostname - monthly VIRUSES\" --height=120 --width=540 --vertical-label=\"viruses/min\" \\
DEF:gvir=\"".$path_to_rrd."WN_xmail_antivirus.rrd\":virus:AVERAGE CDEF:a=gvir,60,* LINE1:a#000000:\"Viruses\" GPRINT:a:LAST:\"Current\\:%8.2lf %s\"  \\
GPRINT:a:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:a:MAX:\"Maximum\\:%8.2lf %s\\n\" AREA:a#FF0000:\"Viruses\" ";

`$virus_monthly`;


my ($spam_monthly) = $bin_rrdtool." graph ".$dir_of_pngs."spam_monthly.png \\
--imgformat=PNG --start=-2678400 --title=\"$hostname - monthly SPAM Messages\" --height=120 --width=540 --vertical-label=\"Messages/min\" \\
DEF:gspam1=\"".$path_to_rrd."WN_xmail_spam.rrd\":spam1:AVERAGE DEF:gspam2=\"".$path_to_rrd."WN_xmail_spam.rrd\":spam2:AVERAGE CDEF:a=gspam1,60,* CDEF:b=gspam2,60,* CDEF:ab=a,b,+ \\
LINE1:ab#CCCCCC:\"Total Spam    \" GPRINT:ab:LAST:\"Current\\:%8.2lf %s\" GPRINT:ab:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:ab:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
AREA:ab#CCCCCC:\"Total Spam\\n\" \\
LINE2:a#FF0000:\"ESPAM / EIPMAP\" GPRINT:a:LAST:\"Current\\:%8.2lf %s\" GPRINT:a:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:a:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
LINE3:b#0000FF:\"Spamassassin  \" GPRINT:b:LAST:\"Current\\:%8.2lf %s\" GPRINT:b:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:b:MAX:\"Maximum\\:%8.2lf %s\\n\" ";

`$spam_monthly`;
my ($bounce_monthly) = $bin_rrdtool." graph ".$dir_of_pngs."bounce_monthly.png \\
--imgformat=PNG --start=-2678400 --title=\"$hostname - monthly BOUNCED Messages\" --height=120 --width=540 --vertical-label=\"Messages/min\" \\
DEF:gbounce=\"".$path_to_rrd."WN_xmail_smtp.rrd\":bounce:AVERAGE \\
DEF:grecv=\"".$path_to_rrd."WN_xmail_smtp.rrd\":recv:AVERAGE \\
DEF:gsent=\"".$path_to_rrd."WN_xmail_smtp.rrd\":sent:AVERAGE \\
CDEF:a=gbounce,60,* CDEF:b=grecv,60,* CDEF:c=gsent,60,* CDEF:abc=a,b,c,+,+ \\
LINE1:abc#FF0000:\"Sum of Msgs\" GPRINT:abc:LAST:\"Current\\:%8.2lf %s\" GPRINT:abc:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:abc:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
AREA:abc#FF0000:\"Sum of Msgs\\n\" \\
LINE2:a#000000:\"RCPT=EAVAIL\" GPRINT:a:LAST:\"Current\\:%8.2lf %s\" GPRINT:a:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:a:MAX:\"Maximum\\:%8.2lf %s\\n\" ";
`$bounce_monthly`;

my ($smtp_monthly) = $bin_rrdtool." graph ".$dir_of_pngs."smtp_monthly.png \\
--imgformat=PNG --start=-2678400 --title=\"$hostname - monthly SMTP Stats\" \\
--height=120 --width=540 --vertical-label=\"Messages/min\" \\
DEF:gbounce=\"".$path_to_rrd."WN_xmail_smtp.rrd\":bounce:AVERAGE \\
DEF:grecv=\"".$path_to_rrd."WN_xmail_smtp.rrd\":recv:AVERAGE \\
DEF:gsent=\"".$path_to_rrd."WN_xmail_smtp.rrd\":sent:AVERAGE \\
CDEF:a=gbounce,60,* CDEF:b=grecv,60,* CDEF:c=gsent,60,* CDEF:abc=a,b,c,+,+ \\
LINE1:abc#CCCCCC:\"Sum of Msgs\" GPRINT:abc:LAST:\"Current\\:%8.2lf %s\" GPRINT:abc:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:abc:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
AREA:abc#CCCCCC:\"Sum of Msgs\\n\" \\
LINE2:b#FF0000:\"Received   \" GPRINT:b:LAST:\"Current\\:%8.2lf %s\" GPRINT:b:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:b:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
LINE3:c#0000FF:\"Sent Msgs  \" GPRINT:c:LAST:\"Current\\:%8.2lf %s\" GPRINT:c:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:c:MAX:\"Maximum\\:%8.2lf %s\\n\" ";
`$smtp_monthly`;


my ($pop3_yearly) = $bin_rrdtool." graph ".$dir_of_pngs."pop3_yearly.png \\
--imgformat=PNG --start=-33053184 --title=\"$hostname - yearly POP3 Usage\" \\
--height=120 --width=540 --vertical-label=\"sessions/min\" \\
DEF:gpop3=\"".$path_to_rrd."WN_xmail_pop3.rrd\":pop3:AVERAGE \\
CDEF:a=gpop3,60,* LINE1:a#000000:\"POP3 Sessions\"  \\
GPRINT:a:LAST:\"Current\\:%8.2lf %s\" GPRINT:a:AVERAGE:\"Average\\:%8.2lf %s\"  \\
GPRINT:a:MAX:\"Maximum\\:%8.2lf %s\\n\" AREA:a#FF0000:\"POP3 Sessions\" ";
`$pop3_yearly`;

my ($virus_yearly) = $bin_rrdtool." graph ".$dir_of_pngs."virus_yearly.png \\
--imgformat=PNG --start=-33053184 --title=\"$hostname - yearly VIRUSES\" --height=120 --width=540 --vertical-label=\"viruses/min\" \\
DEF:gvir=\"".$path_to_rrd."WN_xmail_antivirus.rrd\":virus:AVERAGE CDEF:a=gvir,60,* LINE1:a#000000:\"Viruses\" GPRINT:a:LAST:\"Current\\:%8.2lf %s\"  \\
GPRINT:a:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:a:MAX:\"Maximum\\:%8.2lf %s\\n\" AREA:a#FF0000:\"Viruses\" ";

`$virus_yearly`;


my ($spam_yearly) = $bin_rrdtool." graph ".$dir_of_pngs."spam_yearly.png \\
--imgformat=PNG --start=-33053184 --title=\"$hostname - yearly SPAM Messages\" --height=120 --width=540 --vertical-label=\"Messages/min\" \\
DEF:gspam1=\"".$path_to_rrd."WN_xmail_spam.rrd\":spam1:AVERAGE DEF:gspam2=\"".$path_to_rrd."WN_xmail_spam.rrd\":spam2:AVERAGE CDEF:a=gspam1,60,* CDEF:b=gspam2,60,* CDEF:ab=a,b,+ \\
LINE1:ab#CCCCCC:\"Total Spam    \" GPRINT:ab:LAST:\"Current\\:%8.2lf %s\" GPRINT:ab:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:ab:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
AREA:ab#CCCCCC:\"Total Spam\\n\" \\
LINE2:a#FF0000:\"ESPAM / EIPMAP\" GPRINT:a:LAST:\"Current\\:%8.2lf %s\" GPRINT:a:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:a:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
LINE3:b#0000FF:\"Spamassassin  \" GPRINT:b:LAST:\"Current\\:%8.2lf %s\" GPRINT:b:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:b:MAX:\"Maximum\\:%8.2lf %s\\n\" ";
`$spam_yearly`;
my ($bounce_yearly) = $bin_rrdtool." graph ".$dir_of_pngs."bounce_yearly.png \\
--imgformat=PNG --start=-33053184 --title=\"$hostname - yearly BOUNCED Messages\" --height=120 --width=540 --vertical-label=\"Messages/min\" \\
DEF:gbounce=\"".$path_to_rrd."WN_xmail_smtp.rrd\":bounce:AVERAGE \\
DEF:grecv=\"".$path_to_rrd."WN_xmail_smtp.rrd\":recv:AVERAGE \\
DEF:gsent=\"".$path_to_rrd."WN_xmail_smtp.rrd\":sent:AVERAGE \\
CDEF:a=gbounce,60,* CDEF:b=grecv,60,* CDEF:c=gsent,60,* CDEF:abc=a,b,c,+,+ \\
LINE1:abc#FF0000:\"Sum of Msgs\" GPRINT:abc:LAST:\"Current\\:%8.2lf %s\" GPRINT:abc:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:abc:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
AREA:abc#FF0000:\"Sum of Msgs\\n\" \\
LINE2:a#000000:\"RCPT=EAVAIL\" GPRINT:a:LAST:\"Current\\:%8.2lf %s\" GPRINT:a:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:a:MAX:\"Maximum\\:%8.2lf %s\\n\" ";
`$bounce_yearly`;
my ($smtp_yearly) = $bin_rrdtool." graph ".$dir_of_pngs."smtp_yearly.png \\
--imgformat=PNG --start=-33053184 --title=\"$hostname - yearly SMTP Stats\" \\
--height=120 --width=540 --vertical-label=\"Messages/min\" \\
DEF:gbounce=\"".$path_to_rrd."WN_xmail_smtp.rrd\":bounce:AVERAGE \\
DEF:grecv=\"".$path_to_rrd."WN_xmail_smtp.rrd\":recv:AVERAGE \\
DEF:gsent=\"".$path_to_rrd."WN_xmail_smtp.rrd\":sent:AVERAGE \\
CDEF:a=gbounce,60,* CDEF:b=grecv,60,* CDEF:c=gsent,60,* CDEF:abc=a,b,c,+,+ \\
LINE1:abc#CCCCCC:\"Sum of Msgs\" GPRINT:abc:LAST:\"Current\\:%8.2lf %s\" GPRINT:abc:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:abc:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
AREA:abc#CCCCCC:\"Sum of Msgs\\n\" \\
LINE2:b#FF0000:\"Received   \" GPRINT:b:LAST:\"Current\\:%8.2lf %s\" GPRINT:b:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:b:MAX:\"Maximum\\:%8.2lf %s\\n\"  \\
LINE3:c#0000FF:\"Sent Msgs  \" GPRINT:c:LAST:\"Current\\:%8.2lf %s\" GPRINT:c:AVERAGE:\"Average\\:%8.2lf %s\" GPRINT:c:MAX:\"Maximum\\:%8.2lf %s\\n\" ";
`$smtp_yearly`;

