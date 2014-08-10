#!/usr/bin/perl5.12 -w
##-----------------------------------------------------------------------
##
## Author: Michael Zhou, routesf@gmail.com 03/06/2012
##
##-----------------------------------------------------------------------

package IPsecVPN;
use strict;
use Exporter;
use vars qw(@ISA @EXPORT);
use AnalysisCommon;

@ISA = qw(Exporter);
@EXPORT = qw(
	analyze_ipsecvpn
	match_ipsecvpn
);

## output format for VPN summary, use array to ensure the output order
my $vpn_summary = [
		{'summary' => "IKE proposal", 'number' => 0, 'name' => []},
		{'summary' => "IKE policy", 'number' => 0, 'name' => []},
		{'summary' => "IKE gateway", 'number' => 0, 'name' => []},
		{'summary' => "IPsec proposal", 'number' => 0, 'name' => []},
		{'summary' => "IPsec policy", 'number' => 0, 'name' => []},
		{'summary' => "IPsec vpn", 'number' => 0, 'name' => []},
		{'summary' => "Policy-based", 'number' => 0, 'name' => []},
		{'summary' => "Route-based", 'number' => 0, 'name' => []},
];
## summary end

sub show_summary {
		my %args = (
				'summary' => undef,
				'verbose' => 0,
				'layer' => 1,
				@_,
		);
		my $summary_ref = $args{'summary'};
		my $verbose = $args{'verbose'};
		my $layer = $args{'layer'};
		my $encap = $layer - 1;

		print "\t"x$encap,"VPN {\n";
		for (@$summary_ref) {
				print "\t"x$layer,"$_->{'summary'}"." "."number: ", $_->{'number'},"\n";
				print "\t"x$layer,"$_->{'summary'}"." "."name: ", "@{$_->{'name'}}\n" if $verbose && @{$_->{'name'}};

		}
		print "\t"x$encap,"}\n";
}
## IKE and IPsec will be handled as one module

sub analyze_ipsecvpn {
		my %args = (
				'security' => undef,
				'layer' => 1,
				'verbose' => 0,
				@_,
		);

		my $security_ref = $args{'security'};
		my $layer = $args{'layer'};
		my $verbose = $args{'verbose'};

		clear_summary($vpn_summary);

		## Handle IKE 
		if (defined($security_ref->{'ike'})) {
				my ($ptn_ike_proposal,$ptn_ike_policy,$ptn_ike_gateway);
				$ptn_ike_proposal = qr/(
					proposal\s([^\s]+)\s
						(
							\{
								(
									(?:
										(?> [^{}]+)
										|
										(?3)
									)*
								)
							\}
						)
				)
				/x;
				$ptn_ike_policy = qr/(
					policy\s([^\s]+)\s
						(
							\{
								(
									(?:
										(?> [^{}]+)
										|
										(?3)
									)*
								)
							\}
						)
				)
				/x;
				$ptn_ike_gateway = qr/(
					gateway\s([^\s]+)\s
						(
							\{
								(
									(?:
										(?> [^{}]+)
										|
										(?3)
									)*
								)
							\}
						)
				)
				/x;


				## IKE proposal
				my @ary_ike_proposal = ($security_ref->{'ike'} =~ /$ptn_ike_proposal/g); 
				my (@ary_ike_proposal_name,@ary_ike_proposal_context);
				for (my $i = 0; $i < @ary_ike_proposal; $i+=4) {
						push @ary_ike_proposal_context, $ary_ike_proposal[$i];
						push @ary_ike_proposal_name, $ary_ike_proposal[$i+1];
				}
				my $ike_proposal_num = $#ary_ike_proposal_name + 1;
				#print "Total IKE proposal number: $ike_proposal_num\n";
				#print "IKE proposal name list: ",join(" ",@ary_ike_proposal_name),"\n\n" if $verbose;
				$vpn_summary->[0]->{'number'} = $ike_proposal_num;
				@{$vpn_summary->[0]->{'name'}} = @ary_ike_proposal_name;


				## IKE policy 
				my @ary_ike_policy = ($security_ref->{'ike'} =~ /$ptn_ike_policy/g); 
				my (@ary_ike_policy_name,@ary_ike_policy_context);
				for (my $i = 0; $i < @ary_ike_policy; $i+=4) {
						push @ary_ike_policy_context, $ary_ike_policy[$i];
						push @ary_ike_policy_name, $ary_ike_policy[$i+1];
				}
				my $ike_policy_num = $#ary_ike_policy_name + 1;
				#print "Total IKE policy number: $ike_policy_num\n";
				#print "IKE policy name list: ",join(" ",@ary_ike_policy_name),"\n\n" if $verbose;
				$vpn_summary->[1]->{'number'} = $ike_policy_num;
				@{$vpn_summary->[1]->{'name'}} = @ary_ike_policy_name;

				## IKE gateway 
				my @ary_ike_gateway = ($security_ref->{'ike'} =~ /$ptn_ike_gateway/g); 
				my (@ary_ike_gateway_name,@ary_ike_gateway_context);
				for (my $i = 0; $i < @ary_ike_gateway; $i+=4) {
						push @ary_ike_gateway_context, $ary_ike_gateway[$i];
						push @ary_ike_gateway_name, $ary_ike_gateway[$i+1];
				}
				my $ike_gateway_num = $#ary_ike_gateway_name + 1;
				#print "Total IKE gateway number: $ike_gateway_num\n";
				#print "IKE gateway name list: ",join(" ",@ary_ike_gateway_name),"\n\n" if $verbose;
				$vpn_summary->[2]->{'number'} = $ike_gateway_num;
				@{$vpn_summary->[2]->{'name'}} = @ary_ike_gateway_name;

		}

		## Handle IPsec
		if (defined($security_ref->{'ipsec'})) {
				my ($ptn_ipsec_proposal,$ptn_ipsec_policy,$ptn_ipsec_vpn);
				$ptn_ipsec_proposal = qr/(
					proposal\s([^\s]+)\s
						(
							\{
								(
									(?:
										(?> [^{}]+)
										|
										(?3)
									)*
								)
							\}
						)
				)
				/x;
				$ptn_ipsec_policy = qr/(
					policy\s([^\s]+)\s
						(
							\{
								(
									(?:
										(?> [^{}]+)
										|
										(?3)
									)*
								)
							\}
						)
				)
				/x;
				$ptn_ipsec_vpn = qr/(
					vpn\s([^\s]+)\s
						(
							\{
								(
									(?:
										(?> [^{}]+)
										|
										(?3)
									)*
								)
							\}
						)
				)
				/x;


				## IPsec proposal
				my @ary_ipsec_proposal = ($security_ref->{'ipsec'} =~ /$ptn_ipsec_proposal/g); 
				my (@ary_ipsec_proposal_name,@ary_ipsec_proposal_context);
				for (my $i = 0; $i < @ary_ipsec_proposal; $i+=4) {
						push @ary_ipsec_proposal_context, $ary_ipsec_proposal[$i];
						push @ary_ipsec_proposal_name, $ary_ipsec_proposal[$i+1];
				}
				my $ipsec_proposal_num = $#ary_ipsec_proposal_name + 1;
				#print "Total IPsec proposal number: $ipsec_proposal_num\n";
				#print "IPsec proposal name list: ",join(" ",@ary_ipsec_proposal_name),"\n\n" if $verbose;
				$vpn_summary->[3]->{'number'} = $ipsec_proposal_num;
				@{$vpn_summary->[3]->{'name'}} = @ary_ipsec_proposal_name;

				## IPsec policy 
				my @ary_ipsec_policy = ($security_ref->{'ipsec'} =~ /$ptn_ipsec_policy/g); 
				my (@ary_ipsec_policy_name,@ary_ipsec_policy_context);
				for (my $i = 0; $i < @ary_ipsec_policy; $i+=4) {
						push @ary_ipsec_policy_context, $ary_ipsec_policy[$i];
						push @ary_ipsec_policy_name, $ary_ipsec_policy[$i+1];
				}
				my $ipsec_policy_num = $#ary_ipsec_policy_name + 1;
				#print "Total IPsec policy number: $ipsec_policy_num\n";
				#print "IPsec policy name list: ",join(" ",@ary_ipsec_policy_name),"\n\n" if $verbose;
				$vpn_summary->[4]->{'number'} = $ipsec_policy_num;
				@{$vpn_summary->[4]->{'name'}} = @ary_ipsec_policy_name;

				## IPsec vpn 
				my @ary_ipsec_vpn = ($security_ref->{'ipsec'} =~ /$ptn_ipsec_vpn/g); 
				my (@ary_ipsec_vpn_name,@ary_ipsec_vpn_context,@ary_pb_vpn,@ary_rb_vpn);
				for (my $i = 0; $i < @ary_ipsec_vpn; $i+=4) {
						push @ary_ipsec_vpn_context, $ary_ipsec_vpn[$i];
						push @ary_ipsec_vpn_name, $ary_ipsec_vpn[$i+1];
						if ($ary_ipsec_vpn[$i+3] =~ /bind-interface st[\d\.]+/) {
							   push @ary_pb_vpn, $ary_ipsec_vpn[$i+1] 
						} else {
							   push @ary_rb_vpn, $ary_ipsec_vpn[$i+1] 
						}

				}
				my $ipsec_vpn_num = $#ary_ipsec_vpn_name + 1;
				my $pb_vpn_num = $#ary_pb_vpn + 1;
				my $rb_vpn_num = $#ary_rb_vpn + 1;
				#print "Total IPsec vpn number: $ipsec_vpn_num\n";
				#print "\tPolicy-based: $pb_vpn_num\n";
				#print "\tRoute-based: $rb_vpn_num\n";
				#print "IPsec vpn name list: ",join(" ",@ary_ipsec_vpn_name),"\n\n" if $verbose;
				$vpn_summary->[5]->{'number'} = $ipsec_vpn_num;
				@{$vpn_summary->[5]->{'name'}} = @ary_ipsec_vpn_name;
				$vpn_summary->[6]->{'number'} = $pb_vpn_num;
				@{$vpn_summary->[6]->{'name'}} = @ary_pb_vpn;
				$vpn_summary->[7]->{'number'} = $rb_vpn_num;
				@{$vpn_summary->[7]->{'name'}} = @ary_rb_vpn;

		}

		show_summary(summary=>$vpn_summary,verbose=>$verbose,layer=>$layer);
		#get_inactive_item($content1) if (defined($content_ref->{"ike"}));
		#get_inactive_item($content2) if (defined($content_ref->{"ipsec"}));


}

sub match_ipsecvpn {
		my $user = shift;
		my $pdt = shift;
		my (%user_data,%pdt_data,%score);
		my $sum = 0;
		my $percentage;

		my @match_criteria = (
				"Total IKE proposal number:",
				"Total IKE policy number:",
				"Total IKE gateway number:",
				"Total IPsec proposal number:",
				"Total IPsec policy number:",
				"Total IPsec vpn number:",
				"Policy-based:",
				"Route-based:",
		);
		for my $item (@match_criteria) {
				if ($user =~ /$item\s*(\d+)/) {
						$user_data{"$item"} = $1;
				} else {
						$user_data{"$item"} = 0;
				}
				if ($pdt =~ /$item\s*(\d+)/) {
						$pdt_data{"$item"} = $1;
				} else {
						$pdt_data{"$item"} = 0;
				}

				#print ($user_data{"$item"},'-', $pdt_data{"$item"},"\n");

				if ($user_data{"$item"} != 0) {
						if ($pdt_data{"$item"} < $user_data{"$item"}) {
							$score{"$item"} = $pdt_data{"$item"}/$user_data{"$item"};
						} else {
							$score{"$item"} = 1;
						}
				} else {
						$score{"$item"} = 1;
				}
				$sum += $score{"$item"};
		}
		$percentage = int($sum / ($#match_criteria + 1) * 100);
		return ($percentage . "%");


}

1;
