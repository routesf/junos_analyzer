#!/usr/bin/perl5.12 -w
##-----------------------------------------------------------------------
##
## Author: Michael Zhou, routesf@gmail.com 03/06/2012
##
##-----------------------------------------------------------------------

package IDP;
use strict;
use Exporter;
use vars qw(@ISA @EXPORT);
use AnalysisCommon;

@ISA = qw(Exporter);
@EXPORT = qw(
	analyze_idp
	match_idp
);

## output format for IDP summary, use array to ensure the output order
my $idp_summary = [
		{'summary' => "idp-policy", 'number' => 0, 'name' => []},
		{'summary' => "active-policy", 'name' => ''},
		{'summary' => "security package", 'name' => ''},
		{'summary' => "custom-attack", 'number' => 0, 'name' => []},
		{'summary' => "custom-attack-group", 'number' => 0, 'name' => []},
		{'summary' => "policy with IDP", 'number' => 0, 'name' => []},
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

		print "\t"x$encap,"IDP {\n";
		print "\t"x$layer,"$summary_ref->[0]->{'summary'}"." "."number: ", $summary_ref->[0]->{'number'},"\n";
		print "\t"x$layer,"$summary_ref->[0]->{'summary'}"." "."name: ", "@{$summary_ref->[0]->{'name'}}","\n";

		print "\t"x$layer,"$summary_ref->[1]->{'summary'}"." "."name: ", "$summary_ref->[1]->{'name'}","\n";
		print "\t"x$layer,"$summary_ref->[2]->{'summary'}"." "."name: ", "$summary_ref->[2]->{'name'}","\n";

		for (3..5) {
			if ($summary_ref->[$_]->{'number'}) {
				print "\t"x$layer,"$summary_ref->[$_]->{'summary'}"." "."number: ", $summary_ref->[$_]->{'number'},"\n";
				if($verbose && $summary_ref->[$_]->{'number'} < 50) {
					print "\t"x$layer,"$summary_ref->[$_]->{'summary'}"." "."name: ", "@{$summary_ref->[$_]->{'name'}}","\n";
				}
			}
		}


		print "\t"x$encap,"}\n";
}

sub analyze_idp {
		my %args = (
				'idp' => undef,
				'policy' => undef,
				'layer' => 1,
				'verbose' => 0,
				@_,
		);

		my $idp_ref = $args{'idp'};
		my $layer = $args{'layer'};
		my $verbose = $args{'verbose'};
		my $policy_idp_ref = $args{'policy'};

		clear_summary($idp_summary);

		## Handle idp
				my %ptn_in_idp;
				my @keyword_in_idp = qw(idp-policy custom-attack custom-attack-group);
				for (@keyword_in_idp) {
						$ptn_in_idp{"$_"} = qr/(
							$_\s([^\s]+)\s
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
				}


				## idp-policy
				my @ary_idp_policy = (${$args{'idp'}} =~ /$ptn_in_idp{'idp-policy'}/g); 
				my (@ary_idp_policy_name,@ary_idp_policy_context);
				for (my $i = 0; $i < @ary_idp_policy; $i+=4) {
						push @ary_idp_policy_context, $ary_idp_policy[$i];
						push @ary_idp_policy_name, $ary_idp_policy[$i+1];
				}
				my $idp_policy_num = $#ary_idp_policy_name + 1;
				$idp_summary->[0]->{'number'} = $idp_policy_num;
				@{$idp_summary->[0]->{'name'}} = @ary_idp_policy_name;

				## custom-attack
				my @ary_custom_attack = (${$args{'idp'}} =~ /$ptn_in_idp{'custom-attack'}/g); 
				my (@ary_custom_attack_name,@ary_custom_attack_context);
				for (my $i = 0; $i < @ary_custom_attack; $i+=4) {
						push @ary_custom_attack_context, $ary_custom_attack[$i];
						push @ary_custom_attack_name, $ary_custom_attack[$i+1];
				}
				my $custom_attack_num = $#ary_custom_attack_name + 1;
				$idp_summary->[3]->{'number'} = $custom_attack_num;
				@{$idp_summary->[3]->{'name'}} = @ary_custom_attack_name;

				## custom-attack-group
				my @ary_custom_attack_group = (${$args{'idp'}} =~ /$ptn_in_idp{'custom-attack-group'}/g); 
				my (@ary_custom_attack_group_name,@ary_custom_attack_group_context);
				for (my $i = 0; $i < @ary_custom_attack_group; $i+=4) {
						push @ary_custom_attack_group_context, $ary_custom_attack_group[$i];
						push @ary_custom_attack_group_name, $ary_custom_attack_group[$i+1];
				}
				my $custom_attack_group_num = $#ary_custom_attack_group_name + 1;
				$idp_summary->[4]->{'number'} = $custom_attack_group_num;
				@{$idp_summary->[4]->{'name'}} = @ary_custom_attack_group_name;

				## active-policy 
				my $idp_active_policy;
			    if (${$args{'idp'}} =~ /active-policy\s([^\s]+);/) {
					$idp_active_policy = $1;
				} else {
					$idp_active_policy = ""; 
				}
				$idp_summary->[1]->{'name'} = $idp_active_policy;

				## security-package
				my $idp_security_package = $3 if ${$args{'idp'}} =~ /(security-package\s(\{((?:(?>[^{}]+)|(?2))*)\}))/;
				$idp_security_package =~ s/\A\s+(.*)\s+\z/$1/;
				$idp_summary->[2]->{'name'} = $idp_security_package;

				$idp_summary->[5]->{'number'} = @{$args{'policy'}};
				@{$idp_summary->[5]->{'name'}} = @{$args{'policy'}};

				show_summary(summary=>$idp_summary,verbose=>$verbose,layer=>$layer);
				#get_inactive_item(${$args{'idp'}});

}

sub match_idp {
		my $user = shift;
		my $pdt = shift;
		my (%user_data,%pdt_data,%score);
		my $sum = 0;
		my $percentage;



}

1;
