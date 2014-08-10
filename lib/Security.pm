#!/usr/bin/perl5.12 -w
##-----------------------------------------------------------------------
##
## Author: Michael Zhou, routesf@gmail.com 03/06/2012
##
##-----------------------------------------------------------------------

package Security;
use strict;
use Exporter;
use vars qw(@ISA @EXPORT);
use AnalysisCommon;
use PolicyZone;
use IPsecVPN;
use NAT;
use Screen;
use IDP;

@ISA = qw(Exporter);
@EXPORT = qw(
	analyze_security
);


sub analyze_security {
		my %args = (
				'security' => undef,
				'layer' => 1,
				'verbose' => 0,
				@_,
		);
		my $security_ref = $args{'security'};
		my $layer = $args{'layer'};
		my $verbose = $args{'verbose'};
		my ($zone_with_screen,$policy_with_idp);

		if (defined($security_ref->{'policies'}) || defined($security_ref->{'zones'})) {
				($zone_with_screen,$policy_with_idp) = analyze_policy_zone(security=>$security_ref,layer=>$layer,verbose=>$verbose);
		}

		if (defined($security_ref->{'ike'}) || defined($security_ref->{'ipsec'})) {
				analyze_ipsecvpn(security=>$security_ref,layer=>$layer,verbose=>$verbose);
		}

		if (defined($security_ref->{'nat'})) {
				analyze_nat(nat=>\$security_ref->{'nat'},layer=>$layer,verbose=>$verbose);
		}

		if (defined($security_ref->{'screen'})) {
				analyze_screen(screen=>\$security_ref->{'screen'},zone=>$zone_with_screen,layer=>$layer,verbose=>$verbose);
		}
		if (defined($security_ref->{'idp'})) {
				analyze_idp(idp=>\$security_ref->{'idp'},policy=>$policy_with_idp,layer=>$layer,verbose=>$verbose);
		}
}

1;
