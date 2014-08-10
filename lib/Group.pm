#!/usr/bin/perl5.12 -w
##-----------------------------------------------------------------------
##
## Author: Michael Zhou, routesf@gmail.com 03/06/2012
##
##-----------------------------------------------------------------------

package Group;
use strict;
use Exporter;
use vars qw(@ISA @EXPORT);
use AnalysisCommon;

@ISA = qw(Exporter);
@EXPORT = qw(
	analyze_group
	match_group
);

## output format for groups summary, use array to ensure the output order
my $groups_summary = [
		{'summary' => "group", 'number' => 0, 'name' => []},
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

		print "\t"x$encap,"Groups {\n";
		for (@$summary_ref) {
				print "\t"x$layer,"$_->{'summary'}"." "."number: ", $_->{'number'},"\n";
				print "\t"x$layer,"$_->{'summary'}"." "."name: ", join(' ',@{$_->{'name'}}), "\n" if $verbose && @{$_->{'name'}};

		}
		print "\t"x$encap,"}\n";
}


sub analyze_group {
		my %args = (
				'groups' => undef,
				'layer' => 1,
				'verbose' => 0,
				@_,
		);

		my $groups_ref = $args{'groups'};
		my $layer = $args{'layer'};
		my $verbose = $args{'verbose'};

		clear_summary($groups_summary);

		$groups_summary->[0]->{'number'} = @{$groups_summary->[0]->{'name'}} = keys %{$groups_ref};

		show_summary(summary=>$groups_summary,verbose=>$verbose,layer=>$layer);


}

sub match_group {

}

1;
