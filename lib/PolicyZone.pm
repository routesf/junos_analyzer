#!/usr/bin/perl5.12 -w
##-----------------------------------------------------------------------
##
## Author: Michael Zhou, routesf@gmail.com 03/06/2012
##
##-----------------------------------------------------------------------

package PolicyZone;
use strict;
use Exporter;
use vars qw(@ISA @EXPORT);
use AnalysisCommon;

@ISA = qw(Exporter);
@EXPORT = qw(
	analyze_policy_zone
	match_policy_zone
);

## output format for Policy and Zone summary, use array to ensure the output order
my $policyzone_summary = [
		{'summary' => "policy context", 'number' => 0, 'name' => []},
		{'summary' => "policy", 'number' => 0, 'name' => {}},
		{'summary' => "inter-zone policy", 'number' => 0, 'name' => []},
		{'summary' => "intra-zone policy", 'number' => 0, 'name' => []},
		{'summary' => "zone", 'number' => 0, 'name' => []},
		{'summary' => "address", 'number' => 0, 'name' => {}},
		{'summary' => "address-set", 'number' => 0, 'name' => {}},
		{'summary' => "zone interfaces", 'number' => 0, 'name' => {}},
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

		print "\t"x$encap,"PolicyZone {\n";
		print "\t"x$layer,"$summary_ref->[0]->{'summary'}"." "."number: ", $summary_ref->[0]->{'number'},"\n";
		print "\t"x$layer,"$summary_ref->[0]->{'summary'}"." "."name: ", "@{$summary_ref->[0]->{'name'}}","\n" if $verbose;
		print "\t"x$layer,"$summary_ref->[1]->{'summary'}"." "."number: ", $summary_ref->[1]->{'number'},"\n";
		if ($verbose) {
				while (my ($key,$value) = each %{$summary_ref->[1]->{'name'}}) {
						print "\t"x$layer,"$key: ",join(' ',@{$value}),"\n";
				}
		}

		for (2..4) {
				print "\t"x$layer,"$summary_ref->[$_]->{'summary'}"." "."number: ", $summary_ref->[$_]->{'number'},"\n";
				if($verbose && @{$summary_ref->[$_]->{'name'}}) {
					print "\t"x$layer,"$summary_ref->[$_]->{'summary'}"." "."name: ", "@{$summary_ref->[$_]->{'name'}}","\n";
				}
		}
		for (5..6) {
				print "\t"x$layer,"$summary_ref->[$_]->{'summary'}"." "."number: ", $summary_ref->[$_]->{'number'},"\n";
				if($verbose && %{$summary_ref->[$_]->{'name'}}) {
						while (my ($key,$value) = each %{$summary_ref->[$_]->{'name'}}) {
								print "\t"x$layer,"$key: ",$value,"\n";
						}
				}
		}
		print "\t"x$layer,"$summary_ref->[7]->{'summary'}"." "."number: ", $summary_ref->[7]->{'number'},"\n";
		if($verbose && %{$summary_ref->[7]->{'name'}}) {
				while (my ($key,$value) = each %{$summary_ref->[7]->{'name'}}) {
						print "\t"x$layer,"$key: ",join(' ',@{$value}),"\n";
				}
		}

		print "\t"x$encap,"}\n";
}


## Policies and Zones will be handled as one module
## Handle policies

sub analyze_policy_zone {
		my %args = (
				'security' => undef,
				'layer' => 1,
				'verbose' => 0,
				@_,
		);

		my $security_ref = $args{'security'};
		my $layer = $args{'layer'};
		my $verbose = $args{'verbose'};

		my %zone_with_screen = ();
		my @policy_with_idp = ();

		clear_summary($policyzone_summary);



		## policies
		if (defined($security_ref->{'policies'})) {
				my ($ptn_policy_context,$ptn_policy_name);
				$ptn_policy_context = qr/(
					from-zone\s([^\s]+)\sto-zone\s([^\s]+)\s
						(
							\{
								(
									(?:
										(?> [^{}]+)
										|
										(?4)
									)*
								)
							\}
						)
				)
				/x;
				$ptn_policy_name = qr/(
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

				my (@ary_pctx,@ary_from_zone,@ary_to_zone);

				## improve the efficiency by reducing the use of RE
#				open(POLICY,'<',\$security_ref->{'policies'}) or die "Cannot open variable of policies:$!";
#				my $tag;
#				my $text;
#				while (<POLICY>) {
#						if (/from-zone\s([^\s]+)\sto-zone\s([^\s]+)\s+{/) {
#								$tag = 1;
#								$text = $_;
#								push @ary_from_zone,$1;
#								push @ary_to_zone,$2;
#								while(<POLICY>) {
#										$tag += /(?<!\\)[{]/ ? 1 :
#												/(?<!\\)[}]/ ? -1 : 0;
#										$text .= $_;
#										last if !$tag;
#								}
#								push @ary_pctx,$text;
#						}
#				}
#				close(POLICY);

				my @ary_policy= ($security_ref->{'policies'} =~ /$ptn_policy_context/g); 
				for (my $i = 0; $i < @ary_policy; $i+=5) {
						push @ary_pctx, $ary_policy[$i];
						push @ary_from_zone, $ary_policy[$i+1];
						push @ary_to_zone, $ary_policy[$i+2];
				}

				my $pctx = $#ary_pctx + 1;

				my $inter_zone_policy = 0;
				my @inter_zone_policy_name = ();
				my $intra_zone_policy = 0;
				my @intra_zone_policy_name = ();
				my @ary_policy_raw;
				my %ctx_policy_map;
				my @ary_policy_context;
				my $ptn_app_service = qr/(application-services\s(\{((?:(?>[^{}]+)|(?2))*)\}))/;
				my @ary_policy_name = ();

				## This loop might cost much time if there are too many policies 
				for (my $i = 0; $i < @ary_pctx; $i++) {
						@ary_policy_raw = ($ary_pctx[$i] =~ /$ptn_policy_name/g);
						my $ct = 0;
						for (my $j = 0; $j < @ary_policy_raw; $j += 4) {
								push @ary_policy_context, $ary_policy_raw[$j];
								push @ary_policy_name, $ary_policy_raw[$j+1];
								## check policy which enable IDP
								if ($ary_policy_raw[$j] =~ /$ptn_app_service/) {
									push(@policy_with_idp,$ary_policy_raw[$j+1]) if $2 =~ /idp/;
								}
								$ct++;
						}
						if ($ary_from_zone[$i] ne $ary_to_zone[$i]) {
								$inter_zone_policy += $ct;
								push(@inter_zone_policy_name,@ary_policy_name);
						} else {
								$intra_zone_policy += $ct;
								push(@intra_zone_policy_name,@ary_policy_name);
						}
						$ctx_policy_map{"from-zone $ary_from_zone[$i] to-zone $ary_to_zone[$i]"} = \@ary_policy_name;
				}

				my $total_policy = $inter_zone_policy + $intra_zone_policy;

				$policyzone_summary->[0]->{'number'} = keys %ctx_policy_map; 
				@{$policyzone_summary->[0]->{'name'}} = keys %ctx_policy_map; 
				$policyzone_summary->[1]->{'number'} = $total_policy; 
				%{$policyzone_summary->[1]->{'name'}} = %ctx_policy_map; 
				$policyzone_summary->[2]->{'number'} = $inter_zone_policy; 
				@{$policyzone_summary->[2]->{'name'}} = @inter_zone_policy_name; 
				$policyzone_summary->[3]->{'number'} = $intra_zone_policy; 
				@{$policyzone_summary->[3]->{'name'}} = @intra_zone_policy_name; 


		}


		## Zones
		if (defined($security_ref->{'zones'})) {
				my ($ptn_zone_name,$ptn_address_book,$ptn_interface,$ptn_interface_name);
				$ptn_zone_name = qr/(
					security-zone\s([^\s]+)\s
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
				$ptn_address_book = qr/(
					address-book\s
						(
							\{
								(
									(?:
										(?> [^{}]+)
										|
										(?2)
									)*
								)
							\}
						)
				)
				/x;
				$ptn_interface = qr/(
					interfaces\s
						(
							\{
								(
									(?:
										(?> [^{}]+)
										|
										(?2)
									)*
								)
							\}
						)
				)
				/x;
				$ptn_interface_name = qr/(
					((?:reth|lo|lt|ge|xe)[^\s]+)\s
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


				my @ary_zone = ($security_ref->{'zones'}=~ /$ptn_zone_name/g); 
				my (@ary_zone_name,@ary_zone_context);
				for (my $i = 0; $i < @ary_zone; $i+=4) {
						push @ary_zone_context, $ary_zone[$i];
						push @ary_zone_name, $ary_zone[$i+1];
				}

				my $zone_num = $#ary_zone_name + 1;
				$policyzone_summary->[4]->{'number'} = $zone_num; 
				@{$policyzone_summary->[4]->{'name'}} = @ary_zone_name; 

				my %zone_int_map;
				my $total_address = 0;
				my %zone_address;
				my $total_address_set = 0;
				my %zone_addressset;
				my $total_interface = 0;
				my %zone_interface;
				for (my $i = 0; $i < @ary_zone_context; $i++) {
						if ($ary_zone_context[$i] =~ /$ptn_address_book/) {
								my $address_info = $1;
								my @address_pair = ($address_info =~ /address ([^\s]+) ([\d]+\.[\d]+\.[\d]+\.[\d]+\/[\d]+)/g);
								my $address_in_zone = ($#address_pair + 1)/2;
								$zone_address{$ary_zone_name[$i]} = $address_in_zone;
								$total_address += $address_in_zone;

								## Hanlde address-set, save address-set info to hash %set_address_map 
								## with key as address-set name and value is a array of all addresses
								if ($address_info =~ /address-set ([^\s]+) \{([^}]+)\}/) {
										my @address_set = ($address_info =~ /address-set\s([^\s]+)\s\{([^}]+)\}/g);
										my %set_address_map;
										for (my $j = 0; $j < @address_set; $j += 2) {
												my @ary_temp = ($address_set[$j+1] =~ /address ([^\s]+);/g);
												$set_address_map{"$address_set[$j]"} = \@ary_temp;
										}
										my $address_set_num = 0;
										while (my ($key,$value) = each %set_address_map) {
												my $address_in_set = $#{$set_address_map{$key}} + 1;
												$address_set_num++;
										}
										$zone_addressset{$ary_zone_name[$i]} = $address_set_num;
										$total_address_set += $address_set_num;
								}
						}
						if ($ary_zone_context[$i] =~ /$ptn_interface/) {
								## use $2 since the keyword 'interfaces' is not needed
								my $interface_info = $2;
								my @interface_context = ($interface_info =~ /$ptn_interface_name/g);
								my @interface_name = ();
								for (my $j = 0; $j < @interface_context; $j += 4) {
										push @interface_name, $interface_context[$j+1];
								}
								## interface name doesn't have a curly brace followed if no 
								## host-inbound-traffic and protocol are configured, such as, reth0.0;
								push(@interface_name,($interface_info =~ /((?:reth|lo|lt|ge|xe)[^\s]+);/g));

								my $int_num_in_zone = $#interface_name + 1;
								$zone_int_map{"$ary_zone_name[$i]"} = \@interface_name;
								$zone_interface{$ary_zone_name[$i]} = \@interface_name;
								$total_interface += $int_num_in_zone;

						}

						## save to hash if this zone is configured screen, assume
						## that one zone can only be configured one screen ids-option
						if ($ary_zone_context[$i] =~ /screen\s([^\s]+);/) {
								$zone_with_screen{"$ary_zone_name[$i]"} = $1;
						}
				}

				$policyzone_summary->[5]->{'number'} = $total_address; 
				%{$policyzone_summary->[5]->{'name'}} = %zone_address; 
				$policyzone_summary->[6]->{'number'} = $total_address_set; 
				%{$policyzone_summary->[6]->{'name'}} = %zone_addressset; 
				$policyzone_summary->[7]->{'number'} = $total_interface; 
				%{$policyzone_summary->[7]->{'name'}} = %zone_interface; 

		}

		show_summary(summary=>$policyzone_summary,verbose=>$verbose,layer=>$layer);
		#get_inactive_item($content1) if (defined($security_ref->{"policies"}));
		#get_inactive_item($content2) if (defined($security_ref->{"zones"}));
		return (\%zone_with_screen,\@policy_with_idp);

}

sub match_policy_zone {
		my $user = shift;
		my $pdt = shift;
		my (%user_data,%pdt_data,%score);
		my $sum = 0;
		my $percentage;

		my @match_criteria = (
				"Total policy context:",
				"Total policy number:",
				"Inter-zone policy:",
				"Intra-zone policy:",
				"Total zone number:",
				"Total address number:",
				"Total address-set number:",
				"Total interface number:",
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
