#!/usr/bin/perl

use warnings;
use strict;

use lib qw(./lib);
use POE;
use POE::Component::Resolver;
use Socket6 qw(AF_INET6);

my $r = POE::Component::Resolver->new();

my @hosts = qw(
	www.nic.cz
);

POE::Session->create(
	inline_states => {
		_start => sub {
			foreach my $host (@hosts) {
				$r->resolve(
					host    => $host,
					service => "http",
					event   => "got_response",
				) or die $!;
			}
		},

		_stop => sub { print "client session stopped\n" },

		got_response => sub {
			my ($error, $addresses, $request) = @_[ARG0..ARG2];
			use YAML; print YAML::Dump(
				{
					error => $error,
					addr => $addresses,
					req => $request,
				}
			);
		},
	}
);

POE::Kernel->run();
