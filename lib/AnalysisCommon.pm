#!/usr/bin/perl5.12 -w
##-----------------------------------------------------------------------
##
## Author: Michael Zhou, routesf@gmail.com 03/06/2012
##
##-----------------------------------------------------------------------

package AnalysisCommon;
use 5.10.1;
use strict;
use Exporter;
use vars qw(@ISA @EXPORT);

@ISA = qw(Exporter);
@EXPORT = qw(
		get_inactive_item
		get_module_content
		split_file0
		split_file
		clear_summary
		pickup_item
);

sub get_inactive_item {
		my $data = shift;
		my $ptn_inactive = qr/(inactive:.*?\n)/;
		my @inactive_rt = ($data =~ /$ptn_inactive/g);
		my $inactive_num = $#inactive_rt + 1;
		print "Total inactive items: $inactive_num\n" if $inactive_num;
		print "inactive items: \n @inactive_rt" if $inactive_num;

}



sub get_module_content {
		my $data_src = shift;
		my $match_str = shift;
		
		my $result_summary;
		if ($data_src =~ /$match_str\s+{(.*?)}/s) {
			$result_summary = $1;
		} else {
			$result_summary = "NOT Configured";
		}
		$result_summary =~ s/\n/<br>/g;
		return $result_summary;

}
#######################################################################
## Split the string based on keywords
## split_file1 use the regexp to extract stuffs in {}, it will give an 
## error result when there are unmatched {} in double quotes
## abc {
##      "def\}"
##      }
## it is possible to meet this in services {} hierarchy
#######################################################################
sub split_file1 {
		my %args = (
				'root' => 0,
				'data' => '',
				'dir' => './',
				'save' => 1,
				@_,
		);
		my $content = $args{'data'};
		my %results;
		my $ptn_no_keyword = qr/(([\S]+)\s(\{((?:(?>[^{}]+)|(?3))*)\}))/;
		if (!$args{'root'}) {
			$content = $4 if $args{'data'} =~ /$ptn_no_keyword/;
		}
		while ($content =~ /$ptn_no_keyword/) {
				$results{$2} = $1;
				$content = $`.$';
				if ($args{'save'}) {
						my $dst= "$args{'dir'}/$2";
						if ($args{'root'}) {
								if (-e $dst) {
										unlink (grep {-T} glob "$dst/*");
								} else {
										mkdir($dst);
								}
								$dst = "$args{'dir'}/$2/$2";
						}

						open(OUT,'>',"$dst") or die "Can't open dst file: $dst\n";
						print OUT $1; 
						close OUT;
						#printf "%s found, saved in %s\n",$2,$dst;
				}
		}

		return wantarray ? (\%results,$content) : \%results;
}

#######################################################################
## Split the string based on keywords, to replace the split_file
## split_file use a stack but not a recursive regexp to extract stuffs in {} 
## use stack to avoid the bug of unmatched {} in double quotes
## abc {
##      "def\}"
##      }
## it is possible to meet this in services {} hierarchy
#######################################################################
sub split_file {
        my %args = ( 
                'root' => 0,
                'data' => '', 
                'dir' => './',
                'save' => 1,
                @_, 
		     );  

        my $content = $args{'data'};
		if (!$args{'root'}) {
			$content =~ s/[\S]+\s+\{(.*)\}/$1/s;
		}
        my %results;
		open(SRC,'<',\$content) or die "Cannot open the variable:$!";

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
					if ($args{'save'}) {
						my $dst= "$args{'dir'}/$keyword";
						if ($args{'root'}) {
								if (-e $dst) {
										unlink (grep {-T} glob "$dst/*");
								} else {
										mkdir($dst);
								}   
								$dst = "$args{'dir'}/$keyword/$keyword";
						}   

						open(OUT,'>',"$dst") or die "Can't open dst file: $dst\n";
						print OUT $text; 
						close OUT;
					}   
			} else {
					$rest .= $_;
			}

		}
		close(SRC);

        return wantarray ? (\%results,$rest) : \%results;

}
#######################################################################
## split the source config file
## read the config file line by line in a while loop, but not read them in a slurp mode
## take the file handle as a sub argument, this way can save some memory
#######################################################################
sub split_file0 {
        my %args = ( 
                'fh' => '', 
                'dir' => './',
                'save' => 1,
                @_, 
		     );  

        my $SRC = $args{'fh'};
        my %results;
		my $tag;
		my $text;
		my $keyword;
		my $rest;

		while(<$SRC>){
			if(/\s*(\S+)\s+\{\s*$/){
					$tag = 1;
					$text = $_;       
					$keyword = $1;
					while(<$SRC>){
							$tag += /\S+\s+\{\s*$/ ? 1 :
								 /^\s*\}\s*$/ ? -1 : 0;
							$text .= $_;
							last if ! $tag;
					}
					$results{$keyword} = $text;
					if ($args{'save'}) {
						my $dst= "$args{'dir'}/$keyword";
						if (-e $dst) {
								unlink (grep {-T} glob "$dst/*");
						} else {
								mkdir($dst);
						}   
						$dst = "$args{'dir'}/$keyword/$keyword";

						open(OUT,'>',"$dst") or die "Can't open dst file: $dst\n";
						print OUT $text; 
						close OUT;
					}   
			} else {
					$rest .= $_;
			}

		}

        return wantarray ? (\%results,$rest) : \%results;

}
sub clear_summary {
		my $summary_ref = shift;
		for (@{$summary_ref}) {
				while (my ($key,$value) = each %{$_}) {
						if ($key eq 'summary') {
								next;
						} elsif ($key eq 'number') {
								$_->{'number'} = 0; 
						} elsif ($key eq 'name') {
								if (ref($value) eq 'ARRAY') {
										$_->{'name'} = []; 
								} elsif (ref($value) eq 'HASH') {
										$_->{'name'} = {};
								} else {
										$_->{'name'} = '';
								}
						}
				}
		}
}

sub pickup_item {
		my %args = (
				'array' => undef,
				'step' => 4,
				'indexing' => 1,
				@_,
		);
		my @rt;
		my @array = @{$args{'array'}};
		for (my $i = 0; $i < @array; $i += $args{'step'}) {
				push(@rt,$array[$i+$args{'indexing'}-1]);
		}
		return @rt;	
}


1;
