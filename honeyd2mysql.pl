#!/usr/bin/perl -w
#
# Honeyd2MySQL v0.3
#
# A simple script to populate a MySQL database
# with data extracted from honeyd honeypot's log.
#
# A web interface for the results will be published soon
# on the website mentioned below.
#
# Please leave feedback at: bruteforce.gr/honeyd2mysql
#
# This file is a modified version of "honeyd_importer" perl script originally
# writen by Joshua Gimer and shared through "honeypots" mailing list.
#  
# This file is distributed under the terms of GPLv3.
#

use strict;
use warnings;
use DBI;

#The path to honeyd's log file - change accordingly!
my $logfile='/var/log/honeypot/honeyd.log';

#MySQL server values - change accordingly!
my $mysql_user = 'username';
my $mysql_password = 'password';
my $mysql_database = 'honeyd';
my $mysql_ip = '127.0.0.1';
my $mysql_port = '3306';

open(FILE, "$logfile");

#Connect to the MySQL database
my $dbh = DBI->connect("dbi:mysql:database=$mysql_database;host=$mysql_ip;port=$mysql_port", $mysql_user, $mysql_password);

#Create the required database table
my $SQL = "DROP TABLE IF EXISTS connections";
my $dropTable = $dbh->do($SQL);
my $SQL = "CREATE TABLE connections(id integer primary key auto_increment not null, date_time datetime not null, proto varchar(4) not null, source_ip varchar(15) not null," .
	"source_port integer not null, dest_ip varchar(15) not null, dest_port integer not null)";
my $createTable = $dbh->do($SQL);

print "\n Honeyd2MySQL: a simple script to populate a MySQL database with data from honeyd log files.\n";
print "\n Depending on the size of your logfile this operation might take some minutes,\n seat back and relax, don't worry if your terminal seems idle for a long time.\n\n";
sleep(3);

#Start parsing honeyd logfile...
while (<FILE>) {

print "\nChecking logfile line: $_";
if (!($_ =~ /honeyd log started/)) {
print "Check passed - OK\n";

	my ($date_time, $proto, $start_end,
        $src_ip, $src_port, $dest_ip, $dest_port);

	if ( (/icmp/) || (/dsr/) || (/gre/) ) {

	($date_time, $proto, $start_end, 
        $src_ip, $dest_ip, $dest_port) = split(/ /, "$_");

	$dest_port =~ s/\(\d+\):?//;
	$src_port = '00';

	} else {

	($date_time, $proto, $start_end, 
	$src_ip, $src_port, $dest_ip, $dest_port) = split(/ /, "$_"); 

	}

	$date_time =~ s/-(\d\d):/ $1:/;
	$date_time =~ s/\.\d.*$//;

	$proto =~ s/\(\d\)//;
	$proto =~ s/\s/udp/;
	$proto =~ s/\(\d+\)//;
	$dest_port =~ s/://;

	unless ($start_end eq "E") {
		print "Inserting Values:\nDate-Time: $date_time\nProtocol: $proto\nSource IP and Port: $src_ip:$src_port\nDestination IP and Port: $dest_ip:$dest_port\n";
		$dbh->do("INSERT INTO connections (id, date_time, proto, source_ip, source_port, dest_ip, dest_port) 
		VALUES('', \'$date_time\', \'$proto\', \'$src_ip\', \'$src_port\', \'$dest_ip\', \'$dest_port\');");
	}
} #if

} #while

#Fix protocol column (if any) and remove trailing ':' from dest_ip for icmp connections
$dbh->do("UPDATE connections SET proto = 'udp' WHERE proto='';");
$dbh->do("UPDATE connections SET dest_ip = SUBSTRING(dest_ip, 1, LENGTH(dest_ip)-1) WHERE proto='icmp';");

close(FILE);

#End
