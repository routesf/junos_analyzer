#!/usr/bin/perl -w

##-----------------------------------------------------------------------
##
## Author: Michael Zhou, routesf@gmail.com 11/10/2012
##
##-----------------------------------------------------------------------

use 5.10.1;
use strict;
use File::Basename;
use lib qw(/home/mzhou/analyze_cfg/lib);
use Getopt::Long;
use Cwd;
use Benchmark;
use AnalysisCommon;
use Security;
use Routing;
use RoutingInstances;
use LogicalSystems;
use Group;
use Applications;
use Firewall;
use Misc;

my ($help,$cfg,$verbose);
GetOptions (
		"help" => \$help,
		"cfg=s" => \$cfg,
		"verbose" => \$verbose,
);

my $usage = <<EOU;
NAME
	analyze_cfg.pl - Analyze the configuration file to summarize it as a human-readable summary

SYNOPSIS
	analyze_cfg.pl [ -- script-args ]

OPTIONS
	-h, --help         Prints this message.
	-c, --cfg          Configuration file name.
	-v, --verbose      Show more detailed information like resource name list
EOU

if ($help) {
		print $usage;
		exit 0;
}

## specify the log directory
my $cfg_name;
if (defined $cfg) {
	$cfg_name = basename($cfg);
} else {
	print $usage;
	exit 0;
}
#my $script_dir = dirname($0);
my $log_dir = "results/$cfg_name" . "d";

## remove old files if they are already there
if (-e $log_dir) {
		unlink (grep {-T} glob "$log_dir/*");
} else {
		unless (-e "results") {
			mkdir("results");
		}
		mkdir("$log_dir");
}

my $t1 = Benchmark->new;
my $now = localtime(time());
print "Start at $now\n";

## Save config file to a hash with each first level keyword as keys, the related content are values as a scalar
print "Analyze $cfg_name... ","\n";
open(IN,'<',"$cfg") or die "Can't open src file: $cfg\n";
my ($cfg_ref,$rest) = split_file0(fh=>*IN, dir=>$log_dir,save=>1);
close IN;

my $first_level_num = my @first_level_items = keys %{$cfg_ref};

if ($first_level_num == 0 ) {
		print "Unsupported or broken format, only JUNOS hierarchy are accepted!\n";
		exit 0;
}

print "$first_level_num first level items found, saved in $log_dir\n";
print join(", ",@first_level_items),"\n";

## Basic summary, including chassis, interfaces, system
print "== summary ==\n","="x100,"\n";
analyze_basic(cfg=>$cfg_ref,rest=>$rest,layer=>1,verbose=>$verbose);

## security 
if (defined($cfg_ref->{'security'})) {
		print "== security ==\n","="x100,"\n";
		my $dir_security = "$log_dir/security";
		my $security_ref = split_file(data=>$cfg_ref->{'security'}, dir=>$dir_security);
		analyze_security(security=>$security_ref,layer=>1,verbose=>$verbose);
}

## applications
if (defined($cfg_ref->{'applications'})) {
		print "== applications ==\n","="x100,"\n";
		analyze_applications(applications=>$cfg_ref->{'applications'},verbose=>$verbose,layer=>1);
}

## firewall 
if (defined($cfg_ref->{'firewall'})) {
		print "== firewall ==\n","="x100,"\n";
		analyze_firewall(firewall=>$cfg_ref->{'firewall'},verbose=>$verbose,layer=>1);
}

## groups 
if (defined($cfg_ref->{'groups'})) {
		print "== groups ==\n","="x100,"\n";
		my $dir_groups = "$log_dir/groups";
		my $groups_ref = split_file(data=>$cfg_ref->{'groups'},dir=>$dir_groups);
		analyze_group(groups=>$groups_ref,verbose=>$verbose,layer=>1);
}

## protocols & routing-options 
if (defined($cfg_ref->{'protocols'}) || defined($cfg_ref->{'routing-options'})) {
		print "== protocols & routing-options ==\n","="x100,"\n";
		my $dir_protocols = "$log_dir/protocols";
		my $dir_routingoptions = "$log_dir/routing-options";

		my ($protocols_ref,$routingoptions_ref);
		if (defined($cfg_ref->{'protocols'})) {
			$protocols_ref = split_file(data=>$cfg_ref->{'protocols'}, dir=>$dir_protocols);
		} else {
			$protocols_ref = {};
		}
		if (defined($cfg_ref->{'routing-options'})) {
			$routingoptions_ref = split_file(data=>$cfg_ref->{'routing-options'}, dir=>$dir_routingoptions);
		} else {
			$routingoptions_ref = {};
		}

		## Start routing protocols analysis 
		analyze_routing(protocols=>$protocols_ref,rtoptions=>$routingoptions_ref,layer=>1,verbose=>$verbose);

}

## routing-instances
if (defined($cfg_ref->{'routing-instances'})) {
		print "== routing-instances ==\n","="x100,"\n";
		my $dir_routinginstances = "$log_dir/routing-instances";
		my $routinginstances_ref = split_file(data=>$cfg_ref->{'routing-instances'},dir=>$dir_routinginstances);
		
		analyze_routinginstances(ri=>$routinginstances_ref,verbose=>$verbose,layer=>1);
}

## logical-systems
if (defined($cfg_ref->{'logical-systems'})) {
		print "== logical-systems ==\n","="x100,"\n";
		my $dir_lsys = "$log_dir/logical-systems";
		my $lsys_ref = split_file(data=>$cfg_ref->{'logical-systems'},dir=>$dir_lsys);
		
		analyze_lsys(lsys=>$lsys_ref,verbose=>$verbose,layer=>1);
}


my $after = localtime(time());
print "Finish at $after\n";
my $t2 = Benchmark->new;
my $td = timediff($t2,$t1);
print "Total spent:", timestr($td),"\n";

=pod

=head1 NAME

 analyze_cfg.pl - Analyze the JUNOS configuration file to summarize it as a human-readable summary

=head1 SYNOPSIS

 Run this script on Linux with Perl5.10+
 
 [mzhou@ipg-lnx-shell1 ~]$ ~mzhou/analyze_cfg.pl -h
 NAME
 	analyze_cfg.pl - Analyze the configuration file to summarize it as a human-readable summary
 
 SYNOPSIS
 	analyze_cfg.pl [ -- script-args ]
 
 OPTIONS
 	-h, --help         Prints this message.
 	-c, --cfg          Configuration file name.
 	-v, --verbose      Show more detailed information like resource name list.
 
 without -v option, the script only prints a summary of resource number, such as, policy number, VPN number, etc.
 with -v option, the script will print more detailed info, such as, resource name list, be careful to use this 
 option if there are too many resources configured in config file, that will lead to flood of output.
 the script will create a directory named results to put all separated pieces of configs

=head1 DESCRIPTION

 In current stage the input files must be the JUNOS hierarchy format. Firstly analyze_cfg.pl separate the 
 source cofig file based on first level keywords in JUNOS config (for example, security, applications, 
 firewall, routing-instances, logical-systems,...) and create a directory for each keyword, then save the
 extracted configs to related directory with the keyword as the file name. After extracting configs based 
 on the first level keywords, the script analyze them with the below analyze_xxx subroutines.
 
 There are two ways to extract stuffs in recursive curly brackets, one is to use a stack to push/pop the 
 open/close curly bracket, the other is to use the regular expression extended patterns to make recursive
 matching, this must need the Perl5.10 or later. When handling a huge data, regular expression might have
 low efficiency, and if there is any unmatched curly brackets in double quotes, that will lead to a matching
 error, but this is possible in JUNOS config (for example,in services hierarchy). So the former way is used
 in split_file() which is a subroutine to split the JUNOS hierarchy config, the regular expressions are used 
 in most of analyze_xxx subs.
 
 This is one extended patterns which can extract multiple layer curly brackets with one keyword outside
 $ptn = qr/(         # paren group 1
 	([\S]+)\s       # paren group 2
 		(           # paren group 3
 			\{
 				(
 					(?:              # only for clustering, not capturing
 						(?> [^{}]+)  # non curly brackets without backtracking
 						|
 						(?3)         # recurse to start of paren group 3
 					)*
 				)
 			\}
 		)
 )
 /x;
 it can extract most of JUNOS hierarchy like below.
 security {
 	zones {
 		...
 	}
 	nat {
 		...
 	}
 	...
 }
 but fail if there is any unmatched curly bracket in double quotes
 services {
 	...
 	signature {
 		dfa-pattern "xxx\}yyy";
 	}
	regexp "(?i:url)\s*=\s*[\"']?[^'\"\s]{512}";
 	...
 }
 to resolve this issue, use another algorithm which act as a stack to push/pop for those curly brackets
 
 ...
 open(SRC,'<',\$content) or die "Cannot open the variable:$!"; # read it line by line
 my %results;
 my $tag;
 my $text;
 my $keyword;
 my $rest;
 while(<SRC>){
	if(/\s*(\S+)\s+\{\s*$/){
		$tag = 1;
 		$text = $_;       
 		$keyword = $1;
 		while(<SRC>){
			$tag += /\S+\s+\{\s*$/ ? 1 :
				 /^\s*\}\s*$/ ? -1 : 0;
 			$text .= $_;
 			last if ! $tag;
 		}
 		$results{$keyword} = $text;
 		...
 	} else {
 			$rest .= $_;
 	}
 
 }
 
 Here is the flow of analyzing scripts.
 
 ## open the source config file 
 open(IN,'<',"$cfg") or die "Can't open src file: $cfg\n";
 
 ## extract each config block from the opened handle, save them to a hash with the keyword
 ## as the key($cfg_ref is the hash reference), save the rest stuff to another variable $rest, 
 my ($cfg_ref,$rest) = split_file0(fh=>*IN, dir=>$log_dir,save=>1);

 ## close the file handle
 close IN;
 
 ## analyze each feature set step by step
 analyze_basic;      # basic summary, including chassis, interfaces, system
 analyze_security;   #  security, it will call the below items
 analyze_policy_zone
 analyze_ipsecvpn
 analyze_nat
 analyze_idp
 analyze_screen
 analyze_applications
 analyze_firewall
 analyze_group
 analyze_routing;            # protocols and routing-options
 analyze_routinginstances;   # routing-instances 
 analyze_lsys;               # logical-systems
 
 In each analyze_xxx sub, the related config is summarized and printed with a fixed format, these APIs can be
 expanded, more analyze_xxx subs can be added based on requirements in the future.	

=head1 EXAMPLE 

=head2 Example 1, without -v option

 [mzhou@ipg-lnx-shell1 ~]$ ~mzhou/analyze_cfg.pl -c ~mzhou/cfg_example/junos_1.cfg
 Start at Tue Oct 29 01:25:38 2013
 Analyze junos_1.cfg... 
 12 first level items found, saved in results/junos_1.cfgd
 routing-instances, event-options, system, applications, snmp, interfaces, routing-options, policy-options, firewall, security, groups, chassis
 == summary ==
 ====================================================================================================
 Summary {
 	Device info: ndc1p03natfw03-node0:ndc1p03natfw03-node1 HA-Active/Passive 10.4R3.4
 	system login user number: 3
 	reth interface number: 3
 	GE interface number: 2
 	XE interface number: 16
 	sub interface number: 5
 }
 == security ==
 ====================================================================================================
 PolicyZone {
 	policy context number: 1
 	policy number: 16
 	inter-zone policy number: 16
 	intra-zone policy number: 0
 	zone number: 3
 	address number: 18
 	address-set number: 4
 	zone interfaces number: 3
 }
 NAT {
 	source pool number: 3
 	source rule number: 9
 	source ruleset number: 1
 }
 Screen {
 	ids-option number: 2
 	ids-option name: L3-BASE-SCREEN L3-DIRTY-ICMP
 	zone with screen number: 1
 	NDC1-ZONEC-UNTRUST: L3-BASE-SCREEN
 }
 == applications ==
 ====================================================================================================
 Applications {
 	application number: 15
 	application udp number: 7
 	application tcp number: 8
 	application-set number: 1
 }
 == firewall ==
 ====================================================================================================
 Firewall {
 	IPv4 filter number: 1
 }
 == groups ==
 ====================================================================================================
 Groups {
 	group number: 2
 }
 == protocols & routing-options ==
 ====================================================================================================
 Routing {
 	static route number: 1
 }
 == routing-instances ==
 ====================================================================================================
 routing-instances {
 	virtual-router number: 2
 }
 Finish at Tue Oct 29 01:25:38 2013
 Total spent: 0 wallclock secs ( 0.02 usr +  0.00 sys =  0.02 CPU)
 
 The separated configs have been saved on below directory
 [mzhou@ipg-lnx-shell1 ~]$ ls results/
 junos_1.cfgd
 [mzhou@ipg-lnx-shell1 ~]$ ll results/junos_1.cfgd/
 total 48
 drwxr-xr-x    2 mzhou    test-tech1     4096 Oct 30 23:46 applications
 drwxr-xr-x    2 mzhou    test-tech1     4096 Oct 30 23:46 chassis
 drwxr-xr-x    2 mzhou    test-tech1     4096 Oct 30 23:46 event-options
 drwxr-xr-x    2 mzhou    test-tech1     4096 Oct 30 23:46 firewall
 drwxr-xr-x    2 mzhou    test-tech1     4096 Oct 30 23:46 groups
 drwxr-xr-x    2 mzhou    test-tech1     4096 Oct 30 23:46 interfaces
 drwxr-xr-x    2 mzhou    test-tech1     4096 Oct 30 23:46 policy-options
 drwxr-xr-x    2 mzhou    test-tech1     4096 Oct 30 23:46 routing-instances
 drwxr-xr-x    2 mzhou    test-tech1     4096 Oct 30 23:46 routing-options
 drwxr-xr-x    2 mzhou    test-tech1     4096 Oct 30 23:46 security
 drwxr-xr-x    2 mzhou    test-tech1     4096 Oct 30 23:46 snmp
 drwxr-xr-x    2 mzhou    test-tech1     4096 Oct 30 23:46 system
 [mzhou@ipg-lnx-shell1 ~]$ ll results/junos_1.cfgd/routing-instances/
 total 12
 -rw-r--r--    1 mzhou    test-tech1      654 Oct 30 23:46 DMZ-VR
 -rw-r--r--    1 mzhou    test-tech1      416 Oct 30 23:46 MOBILE-VR
 -rw-r--r--    1 mzhou    test-tech1     1094 Oct 30 23:46 routing-instances

=head2 Example 2, with -v option
 
 [mzhou@ipg-lnx-shell1 ~]$ ~mzhou/analyze_cfg.pl -c ~mzhou/cfg_example/junos_1.cfg -v
 Start at Mon Oct 28 23:57:30 2013
 Analyze junos_1.cfg... 
 12 first level items found, saved in results/junos_1.cfgd
 routing-instances, event-options, system, applications, snmp, interfaces, routing-options, policy-options, firewall, security, groups, chassis
 == summary ==
 ====================================================================================================
 Summary {
 	Device info: ndc1p03natfw03-node0:ndc1p03natfw03-node1 HA-Active/Passive 10.4R3.4
 	system login user number: 3
 	system login user name: nsm phillips ryan
 	reth interface number: 3
 	reth interface name: reth0 reth1 reth2
 	GE interface number: 2
 	GE interface name: ge-12/1/0 ge-0/1/0
 	XE interface number: 16
 	XE interface name: xe-14/1/0 xe-14/2/0 xe-2/0/0 xe-2/2/0 xe-1/2/0 xe-13/0/0 xe-1/1/0 xe-13/1/0 xe-14/3/0 xe-1/0/0 xe-2/1/0 xe-2/3/0 xe-13/2/0 xe-13/3/0 xe-14/0/0 xe-1/3/0
 	sub interface number: 5
 }
 == security ==
 ====================================================================================================
 PolicyZone {
 	policy context number: 1
 	policy context name: from-zone NDC1-ZONEC-TRUST to-zone NDC1-ZONEC-UNTRUST
 	policy number: 16
 	from-zone NDC1-ZONEC-TRUST to-zone NDC1-ZONEC-UNTRUST: 1000 1001 1002 1050 1051 1003 1004 1005 1006 1007 1008 1009 1010 8888 1061 9999
 	inter-zone policy number: 16
 	inter-zone policy name: 1000 1001 1002 1050 1051 1003 1004 1005 1006 1007 1008 1009 1010 8888 1061 9999
 	intra-zone policy number: 0
 	zone number: 3
 	zone name: L3-FWLOG-ZONE NDC1-ZONEC-TRUST NDC1-ZONEC-UNTRUST
 	address number: 18
 	NDC1-ZONEC-UNTRUST: 14
 	NDC1-ZONEC-TRUST: 4
 	address-set number: 4
 	NDC1-ZONEC-UNTRUST: 4
 	zone interfaces number: 3
 	NDC1-ZONEC-UNTRUST: reth1.0
 	NDC1-ZONEC-TRUST: reth0.0
 	L3-FWLOG-ZONE: reth2.0
 }
 NAT {
 	source pool number: 3
 	source pool name: PAT-POOL-PUBLIC PAT-POOL-SPIRENT NAT-POOL-P2P
 	source rule number: 9
 	source rule name: PAT-TO-SPIRENT PAT-MSPTEST-INTERNET NAT-TO-P2P_ID-CommNAT NAT-TO-P2P_ID-CDX NAT-TO-P2P_Data-Exch PAT-TO-Yahoo_Push-01 PAT-TO-Yahoo_Push-02 PAT-TO-Mobile_Me PAT-TO-INTERNET
 	source ruleset number: 1
 	source ruleset name: PAT-NAT-POLICY
 }
 Screen {
 	ids-option number: 2
 	ids-option name: L3-BASE-SCREEN L3-DIRTY-ICMP
 	zone with screen number: 1
 	NDC1-ZONEC-UNTRUST: L3-BASE-SCREEN
 }
 == applications ==
 ====================================================================================================
 Applications {
 	application number: 15
 	application name: P2P_ID-CDX P2P_ID-CommNAT P2P_Data-Exch Yahoo_Push TFTP_UDP DNS_UDP UDP_ALL FTP_300TTL HTTP_300TTL IMAP_300TTL Mobile_Me TCP_ALL RTSP_TCP HTTPS_1800TTL DNS_TCP
 	application udp number: 7
 	application udp name: P2P_ID-CDX P2P_ID-CommNAT P2P_Data-Exch Yahoo_Push TFTP_UDP DNS_UDP UDP_ALL
 	application tcp number: 8
 	application tcp name: FTP_300TTL HTTP_300TTL IMAP_300TTL Mobile_Me TCP_ALL RTSP_TCP HTTPS_1800TTL DNS_TCP
 	application-set number: 1
 	application-set name: DNS_TCP_UDP
 }
 == firewall ==
 ====================================================================================================
 Firewall {
 	IPv4 filter number: 1
 	IPv4 filter name: RE-PROTECT
 }
 == groups ==
 ====================================================================================================
 Groups {
 	group number: 2
 	group name: node0 node1
 }
 == protocols & routing-options ==
 ====================================================================================================
 Routing {
 	static route number: 1
 	static route name: 0.0.0.0/0
 }
 == routing-instances ==
 ====================================================================================================
 routing-instances {
 	virtual-router number: 2
 	virtual-router name: MOBILE-VR DMZ-VR
 	MOBILE-VR: ---------------------------------------------------
 		lo0.0 reth0.0
 		Routing {
 			Protocols number: 1
 			Protocols name: ospf
 			OSPF area number: 1
 			OSPF area name: 0.0.0.0
 			OSPF interfaces number: 2
 			area 0.0.0.0: reth0.0 lo0.0
 		}
 	DMZ-VR: ------------------------------------------------------
 		lo0.1 reth1.0
 		Routing {
 			Protocols number: 1
 			Protocols name: ospf
 			OSPF area number: 1
 			OSPF area name: 0.0.0.0
 			OSPF interfaces number: 2
 			area 0.0.0.0: reth1.0 lo0.1
 			static route number: 4
 			static route name: 155.165.68.0/25 172.20.196.0/23 155.165.38.176/29 155.165.38.216/29
 		}
 }
 Finish at Mon Oct 28 23:57:30 2013
 Total spent: 0 wallclock secs ( 0.01 usr +  0.01 sys =  0.02 CPU)

=head1 DIAGNOSTICS

=head1 AUTHOR

 Michael Zhou (routesf@gmail.com)

=head1 BUGS AND IRRITATIONS

 There are undoubtedly serious bugs lurking somewhere in this code.
 Bug reports and other feedback are most welcome.

=cut



