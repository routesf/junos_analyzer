#!/usr/bin/perl5.12 -w
##-----------------------------------------------------------------------
##
## Author: Michael Zhou, routesf@gmail.com 03/06/2012
##
##-----------------------------------------------------------------------

package Screen;
use strict;
use Exporter;
use vars qw(@ISA @EXPORT);
use AnalysisCommon;

@ISA = qw(Exporter);
@EXPORT = qw(
	analyze_screen
	match_screen
);

## output format for Screen summary, use array to ensure the output order
my $screen_summary = [
		{'summary' => "ids-option", 'number' => 0, 'name' => []},
		{'summary' => "zone with screen", 'number' => 0, 'name' => {}},
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

		print "\t"x$encap,"Screen {\n";
		print "\t"x$layer,"$summary_ref->[0]->{'summary'}"." "."number: ", $summary_ref->[0]->{'number'},"\n";
		print "\t"x$layer,"$summary_ref->[0]->{'summary'}"." "."name: ", "@{$summary_ref->[0]->{'name'}}","\n";

		print "\t"x$layer,"$summary_ref->[1]->{'summary'}"." "."number: ", $summary_ref->[1]->{'number'},"\n";
		if(%{$summary_ref->[1]->{'name'}}) {
				while (my ($key,$value) = each %{$summary_ref->[1]->{'name'}}) {
						print "\t"x$layer,"$key: ",$value,"\n";
				}
		}

		print "\t"x$encap,"}\n";
}
sub analyze_screen {
		my %args = (
				'screen' => undef,
				'zone' => undef,
				'layer' => 1,
				'verbose' => 0,
				@_,
		);

		my $screen_ref = $args{'screen'};
		my $layer = $args{'layer'};
		my $verbose = $args{'verbose'};
		my $zone_screen_ref = $args{'zone'};

		clear_summary($screen_summary);


		## Handle screen
		my $ptn_screen_ids = qr/(
			ids-option\s([^\s]+)\s
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


		my @ary_screen_ids = (${$args{'screen'}} =~ /$ptn_screen_ids/g); 
		my (@ary_screen_ids_name,@ary_screen_ids_context);
		for (my $i = 0; $i < @ary_screen_ids; $i+=4) {
				push @ary_screen_ids_context, $ary_screen_ids[$i];
				push @ary_screen_ids_name, $ary_screen_ids[$i+1];
		}
		my $screen_ids_num = $#ary_screen_ids_name + 1;
		$screen_summary->[0]->{'number'} = $screen_ids_num;
		@{$screen_summary->[0]->{'name'}} = @ary_screen_ids_name;


		$screen_summary->[1]->{'number'} = keys %{$zone_screen_ref};
		%{$screen_summary->[1]->{'name'}} = %{$zone_screen_ref};

		show_summary(summary=>$screen_summary,verbose=>$verbose,layer=>$layer);
		#get_inactive_item($content) if (defined($content_ref->{"screen"}));

}

sub match_screen {

}

1;
