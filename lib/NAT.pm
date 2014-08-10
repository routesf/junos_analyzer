#!/usr/bin/perl5.12 -w
##-----------------------------------------------------------------------
##
## Author: Michael Zhou, routesf@gmail.com 03/06/2012
##
##-----------------------------------------------------------------------

package NAT;
use strict;
use Exporter;
use vars qw(@ISA @EXPORT);
use AnalysisCommon;

@ISA = qw(Exporter);
@EXPORT = qw(
	analyze_nat
	match_nat
);

## output format for NAT summary, use array to ensure the output order
my $nat_summary = [
		{'summary' => "source pool", 'number' => 0, 'name' => []},
		{'summary' => "source rule", 'number' => 0, 'name' => []},
		{'summary' => "source ruleset", 'number' => 0, 'name' => []},
		{'summary' => "destination pool", 'number' => 0, 'name' => []},
		{'summary' => "destination rule", 'number' => 0, 'name' => []},
		{'summary' => "destination ruleset", 'number' => 0, 'name' => []},
		{'summary' => "static rule", 'number' => 0, 'name' => []},
		{'summary' => "static ruleset", 'number' => 0, 'name' => []},
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

		print "\t"x$encap,"NAT {\n";
		for (@$summary_ref) {
			if ($_->{'number'}) {
				print "\t"x$layer,"$_->{'summary'}"." "."number: ", $_->{'number'},"\n";
				if ($verbose && $_->{'number'} < 50) {
					print "\t"x$layer,"$_->{'summary'}"." "."name: ", "@{$_->{'name'}}\n";
				}
			}

		}
		print "\t"x$encap,"}\n";
}

sub analyze_nat {
		my %args = (
				'nat' => undef,
				'layer' => 1,
				'verbose' => 0,
				@_,
		);

		my $nat_ref = $args{'nat'};
		my $layer = $args{'layer'};
		my $verbose = $args{'verbose'};

		clear_summary($nat_summary);

		## Handle NAT
		my ($ptn_nat_pool,$ptn_nat_rule,$ptn_nat_ruleset);
		$ptn_nat_pool = qr/(
			pool\s([^\s]+)\s
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
		$ptn_nat_rule = qr/(
			rule\s([^\s]+)\s
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
		$ptn_nat_ruleset = qr/(
			rule-set\s([^\s]+)\s
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


		my $nat_sub_ref = split_file(data=>${$args{'nat'}},save=>0);

		## source nat 
		if (defined($nat_sub_ref->{'source'})) {
				## source nat pool
				my @ary_source_pool = ($nat_sub_ref->{'source'} =~ /$ptn_nat_pool/g);
				my (@ary_source_pool_name,@ary_source_pool_context);
				for (my $i = 0; $i < @ary_source_pool; $i+=4) {
					push @ary_source_pool_context, $ary_source_pool[$i];
					push @ary_source_pool_name, $ary_source_pool[$i+1];
				}
				my $source_pool_num = $#ary_source_pool_name + 1;
				$nat_summary->[0]->{'number'} = $source_pool_num;
				@{$nat_summary->[0]->{'name'}} = @ary_source_pool_name;

				## source nat rule-set 
				my @ary_source_ruleset = ($nat_sub_ref->{'source'} =~ /$ptn_nat_ruleset/g);
				my (@ary_source_ruleset_name,@ary_source_ruleset_context);
				for (my $i = 0; $i < @ary_source_ruleset; $i+=4) {
					push @ary_source_ruleset_context, $ary_source_ruleset[$i];
					push @ary_source_ruleset_name, $ary_source_ruleset[$i+1];
				}
				my $source_ruleset_num = $#ary_source_ruleset_name + 1;
				$nat_summary->[2]->{'number'} = $source_ruleset_num;
				@{$nat_summary->[2]->{'name'}} = @ary_source_ruleset_name;

				## source nat rule
				my @ary_source_rule = ($nat_sub_ref->{'source'} =~ /$ptn_nat_rule/g);
				my (@ary_source_rule_name,@ary_source_rule_context);
				for (my $i = 0; $i < @ary_source_rule; $i+=4) {
					push @ary_source_rule_context, $ary_source_rule[$i];
					push @ary_source_rule_name, $ary_source_rule[$i+1];
				}
				my $source_rule_num = $#ary_source_rule_name + 1;
				$nat_summary->[1]->{'number'} = $source_rule_num;
				@{$nat_summary->[1]->{'name'}} = @ary_source_rule_name;
		}

		## destination nat 
		if (defined($nat_sub_ref->{'destination'})) {
				## destination nat pool
				my @ary_destination_pool = ($nat_sub_ref->{'destination'} =~ /$ptn_nat_pool/g);
				my (@ary_destination_pool_name,@ary_destination_pool_context);
				for (my $i = 0; $i < @ary_destination_pool; $i+=4) {
					push @ary_destination_pool_context, $ary_destination_pool[$i];
					push @ary_destination_pool_name, $ary_destination_pool[$i+1];
				}
				my $destination_pool_num = $#ary_destination_pool_name + 1;
				$nat_summary->[3]->{'number'} = $destination_pool_num;
				@{$nat_summary->[3]->{'name'}} = @ary_destination_pool_name;

				## destination nat rule-set 
				my @ary_destination_ruleset = ($nat_sub_ref->{'destination'} =~ /$ptn_nat_ruleset/g);
				my (@ary_destination_ruleset_name,@ary_destination_ruleset_context);
				for (my $i = 0; $i < @ary_destination_ruleset; $i+=4) {
					push @ary_destination_ruleset_context, $ary_destination_ruleset[$i];
					push @ary_destination_ruleset_name, $ary_destination_ruleset[$i+1];
				}
				my $destination_ruleset_num = $#ary_destination_ruleset_name + 1;
				$nat_summary->[5]->{'number'} = $destination_ruleset_num;
				@{$nat_summary->[5]->{'name'}} = @ary_destination_ruleset_name;

				## destination nat rule
				my @ary_destination_rule = ($nat_sub_ref->{'destination'} =~ /$ptn_nat_rule/g);
				my (@ary_destination_rule_name,@ary_destination_rule_context);
				for (my $i = 0; $i < @ary_destination_rule; $i+=4) {
					push @ary_destination_rule_context, $ary_destination_rule[$i];
					push @ary_destination_rule_name, $ary_destination_rule[$i+1];
				}
				my $destination_rule_num = $#ary_destination_rule_name + 1;
				$nat_summary->[4]->{'number'} = $destination_rule_num;
				@{$nat_summary->[4]->{'name'}} = @ary_destination_rule_name;
		}


		## static nat 
		if (defined($nat_sub_ref->{'static'})) {
				## static nat rule-set 
				my @ary_static_ruleset = ($nat_sub_ref->{'static'} =~ /$ptn_nat_ruleset/g);
				my (@ary_static_ruleset_name,@ary_static_ruleset_context);
				for (my $i = 0; $i < @ary_static_ruleset; $i+=4) {
					push @ary_static_ruleset_context, $ary_static_ruleset[$i];
					push @ary_static_ruleset_name, $ary_static_ruleset[$i+1];
				}
				my $static_ruleset_num = $#ary_static_ruleset_name + 1;
				$nat_summary->[7]->{'number'} = $static_ruleset_num;
				@{$nat_summary->[7]->{'name'}} = @ary_static_ruleset_name;

				## static nat rule
				my @ary_static_rule = ($nat_sub_ref->{'static'} =~ /$ptn_nat_rule/g);
				my (@ary_static_rule_name,@ary_static_rule_context);
				for (my $i = 0; $i < @ary_static_rule; $i+=4) {
					push @ary_static_rule_context, $ary_static_rule[$i];
					push @ary_static_rule_name, $ary_static_rule[$i+1];
				}
				my $static_rule_num = $#ary_static_rule_name + 1;
				$nat_summary->[6]->{'number'} = $static_rule_num;
				@{$nat_summary->[6]->{'name'}} = @ary_static_rule_name;
		}

		show_summary(summary=>$nat_summary,verbose=>$verbose,layer=>$layer);

		#get_inactive_item($content) if (defined($content_ref->{"nat"}));

}

sub match_nat {
		my $user = shift;
		my $pdt = shift;
		my (%user_data,%pdt_data,%score);
		my $sum = 0;
		my $percentage;

		my @match_criteria = (
				"Total nat source pool number:",
				"Total nat source ruleset number:",
				"Total nat source rule number:",
				"Total nat destination pool number:",
				"Total nat destination ruleset number:",
				"Total nat destination rule number:",
				"Total nat static ruleset number:",
				"Total nat static rule number:",
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
