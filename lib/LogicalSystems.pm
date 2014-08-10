#!/usr/bin/perl5.12 -w
##-----------------------------------------------------------------------
##
## Author: Michael Zhou, routesf@gmail.com 03/06/2012
##
##-----------------------------------------------------------------------

package LogicalSystems;
use strict;
use Exporter;
use vars qw(@ISA @EXPORT);
use AnalysisCommon;
use Routing;
use Security;
use RoutingInstances;
use Data::Dumper;

@ISA = qw(Exporter);
@EXPORT = qw(
	analyze_lsys
	match_lsys
);

## output format for lsys 
my $lsys_summary = [
		{'summary' => "logical-systems", 'number' => 0, 'name' => []},
];
## summary end

## show summary result for lsys 
sub show_summary {
		my %args = (
			'summary' => undef,
			'lsys_sub_items' => undef,
			'verbose' => 0,
			'layer' => 1,
			@_,
		);
		my $summary_ref = $args{'summary'};
		my $lsys_sub_items = $args{'lsys_sub_items'};
		my $verbose = $args{'verbose'};
		my $layer = $args{'layer'};
		my $encap = $layer - 1;

		print "\t"x$encap,"lsys {\n";

		for (0..0) {
				if ($summary_ref->[$_]->{'number'}) {
						print "\t"x$layer,"$summary_ref->[$_]->{'summary'}"." "."number: ", $summary_ref->[$_]->{'number'},"\n";
						print "\t"x$layer,"$summary_ref->[$_]->{'summary'}"." "."name: ", "@{$summary_ref->[$_]->{'name'}}", "\n";
				}

		}
		## for each lsys
		my $lsys_layer = $layer + 2;
		while(my($key,$value) = each %{$lsys_sub_items}) {
				my $width = 80 - length($key);
				print "\t"x$layer,"$key: ","-"x$width,"\n";

				## security 
				if (defined($value->{'security'})) {
						my $security_ref = split_file(data=>$value->{'security'}, save=>0);
						analyze_security(security=>$security_ref,layer=>$lsys_layer,verbose=>$verbose);
				}

				## protocols & routing-options 
				if (defined($value->{'protocols'}) || defined($value->{'routing-options'})) {
						my ($protocols_ref,$routingoptions_ref);
						if (defined($value->{'protocols'})) {
							$protocols_ref = split_file(data=>$value->{'protocols'},save=>0);
						} else {
							$protocols_ref = {};
						}
						if (defined($value->{'routing-options'})) {
							$routingoptions_ref = split_file(data=>$value->{'routing-options'},save=>0);
						} else {
							$routingoptions_ref = {};
						}
						analyze_routing(protocols=>$protocols_ref,rtoptions=>$routingoptions_ref,verbose=>$verbose,layer=>$lsys_layer);
				}

				## routing-instances
				if (defined($value->{'routing-instances'})) {
						my $routinginstances_ref = split_file(data=>$value->{'routing-instances'},save=>0);
						analyze_routinginstances(ri=>$routinginstances_ref,verbose=>$verbose,layer=>$lsys_layer);
				}

		}


		print "\t"x$encap,"}\n";
}

sub analyze_lsys {
		my %args = (
				'lsys' => undef,
				'layer' => 1,
				'verbose' => 0,
				@_,
		);

		my $lsys_ref = $args{'lsys'};
		my $verbose = $args{'verbose'};
		my $layer = $args{'layer'};

		my %lsys_sub_items;

		clear_summary($lsys_summary);
		
		while(my($key,$value) = each %{$lsys_ref}) {
			   push(@{$lsys_summary->[0]->{'name'}},$key); 
			   $lsys_sub_items{$key} = split_file(data=>$value,save=>0);

		}
		$lsys_summary->[0]->{'number'} = @{$lsys_summary->[0]->{'name'}};

		show_summary(summary=>$lsys_summary,lsys_sub_items=>\%lsys_sub_items,verbose=>$verbose,layer=>$layer);
		#get_inactive_item($content);



}


sub match_lsys {

}

1;
