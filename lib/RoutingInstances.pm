#!/usr/bin/perl5.12 -w
##-----------------------------------------------------------------------
##
## Author: Michael Zhou, routesf@gmail.com 03/06/2012
##
##-----------------------------------------------------------------------

package RoutingInstances;
use strict;
use Exporter;
use vars qw(@ISA @EXPORT);
use AnalysisCommon;
use Routing;

@ISA = qw(Exporter);
@EXPORT = qw(
	analyze_routinginstances
	match_routinginstances
);

## output format for routing-instances 
my $ri_summary = [
		{'summary' => "virtual-router", 'number' => 0, 'name' => {}},
		{'summary' => "vpls", 'number' => 0, 'name' => {}},
		{'summary' => "forwarding", 'number' => 0, 'name' => {}},
		{'summary' => "no-forwarding", 'number' => 0, 'name' => {}},
		{'summary' => "l2backhaul-vpn", 'number' => 0, 'name' => {}},
];
## summary end

## show summary result for routing-instances 
sub show_summary {
		my %args = (
			'summary' => undef,
			'ri_sub_items' => undef,
			'verbose' => 0,
			'layer' => 1,
			@_,
		);
		my $summary_ref = $args{'summary'};
		my $ri_sub_items = $args{'ri_sub_items'};
		my $verbose = $args{'verbose'};
		my $layer = $args{'layer'};
		my $encap = $layer - 1;

		print "\t"x$encap,"routing-instances {\n";

		for (0..4) {
			if ($summary_ref->[$_]->{'number'}) {
				print "\t"x$layer,"$summary_ref->[$_]->{'summary'}"." "."number: ", $summary_ref->[$_]->{'number'},"\n";
				if ($verbose && $summary_ref->[$_]->{'number'}) {
					print "\t"x$layer,"$summary_ref->[$_]->{'summary'}"." "."name: ", join(' ',(keys %{$summary_ref->[$_]->{'name'}})), "\n";
				}
			}

		}
		## for each routing-instance

		if ($verbose) {
				my $ri_layer = $layer + 2;
				my $int_layer = $layer + 1;
				while(my($key,$value) = each %{$ri_sub_items}) {
						my $width = 60 - length($key);
						print "\t"x$layer,"$key: ","-"x$width,"\n";
						for (0..4) {
							if (exists $ri_summary->[$_]->{'name'}->{$key}) {
									if (@{$ri_summary->[$_]->{'name'}->{$key}}) {
										print "\t"x$int_layer,"@{$ri_summary->[$_]->{'name'}->{$key}}\n";
										last;
									}
								}
						}

						## protocols and routing-options
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
								analyze_routing(protocols=>$protocols_ref,rtoptions=>$routingoptions_ref,verbose=>$verbose,layer=>$ri_layer);
						}

				}
		}


		print "\t"x$encap,"}\n";
}

sub analyze_routinginstances {
		my %args = (
			'ri' => undef,
			'layer' => 1,
			'verbose' => 0,
			@_,
		);

		my $ri_ref = $args{'ri'};
		my $verbose = $args{'verbose'};
		my $layer = $args{'layer'};
		my (%ri_sub_items,$rest);

		clear_summary($ri_summary);
		
		while(my($key,$value) = each %{$ri_ref}) {
			   ($ri_sub_items{$key},$rest) = split_file(data=>$value,save=>0);
			   	my @int = ($rest =~ /interface ([^;]+);/g);
			   if ($rest =~ /instance-type virtual-router/) {
			   		$ri_summary->[0]->{'name'}->{$key} = \@int; 
			   } elsif ($rest =~ /instance-type vpls/) {
			   		$ri_summary->[1]->{'name'}->{$key} = \@int; 
			   } elsif ($rest =~ /instance-type forwarding/) {
			   		$ri_summary->[2]->{'name'}->{$key} = \@int; 
			   } elsif ($rest =~ /instance-type no-forwarding/) {
			   		$ri_summary->[3]->{'name'}->{$key} = \@int; 
			   } elsif ($rest =~ /instance-type l2backhaul-vpn/) {
			   		$ri_summary->[4]->{'name'}->{$key} = \@int; 
			   }

		}
		$ri_summary->[$_]->{'number'} = (keys %{$ri_summary->[$_]->{'name'}}) for(0..4);

		show_summary(summary=>$ri_summary,ri_sub_items=>\%ri_sub_items,verbose=>$verbose,layer=>$layer);
		#get_inactive_item($content);



}

sub match_routinginstances {

}

1;
