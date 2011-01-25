package POE::Component::Resolver;

use warnings;
use strict;

use POE qw(Wheel::Run Filter::Reference);
use Scalar::Util qw(weaken);
use Carp qw(croak);
use Storable qw(nfreeze thaw);
use Socket::GetAddrInfo qw(:newapi getaddrinfo);
use Time::HiRes qw(time);

# Plain Perl constructor.

sub new {
	my ($class, $args) = @_;

	my $max_resolvers = $args->{max_resolvers} || 8;

	my $self = bless { }, $class;

	POE::Session->create(
		inline_states => {
			_start           => \&_poe_start,
			request          => \&_poe_request,
			shutdown         => \&_poe_shutdown,
			sidecar_closed   => \&_poe_sidecar_closed,
			sidecar_error    => \&_poe_sidecar_error,
			sidecar_response => \&_poe_sidecar_response,
			sidecar_signal   => \&_poe_sidecar_signal,
			sidecar_eject    => \&_poe_sidecar_eject,
			sidecar_attach   => \&_poe_sidecar_attach,
		},
		args => [ "$self", $max_resolvers ],
	);

	return $self;
}

sub DESTROY {
	my $self = shift;
	$poe_kernel->call("$self", "shutdown");
}

# Internal POE event handler to release all resources owned by the
# hidden POE::Session and then shut it down.  It's an event handler so
# that this code can run "within" the POE::Session.

sub _poe_shutdown {
	my ($kernel, $heap) = @_[KERNEL, HEAP];

	$heap->{shutdown} = 1;

	$kernel->alias_clear($heap->{alias});

	_poe_wipe_sidecars($heap);

	foreach my $request (%{$heap->{requests}}) {
		$kernel->post(
			$request->{sender},
			$request->{event},
			'component shut down',
			[ ],
			{ map { $_ => $request->{$_} } qw(host service event misc) },
		);

		$kernel->refcount_decrement($request->{sender}, __PACKAGE__);
	}

	$heap->{requests} = {};
}

# POE event handler to accept a request from some other session.  The
# public Perl resolve() method forwards into this.  This runs "within"
# the session so the resources it creates are properly owned.

sub _poe_request {
	my ($kernel, $heap, $host, $service, $hints, $event, $misc) = @_[
		KERNEL, HEAP, ARG0..ARG4
	];

	return if $heap->{shutdown};

	my $request_id = ++$heap->{last_request_id};
	my $sender_id  = $_[SENDER]->ID();

	$heap->{requests}{$request_id} = {
		begin   => time(),
		host    => $host,
		service => $service,
		hints   => $hints,
		sender  => $sender_id,
		event   => $event,
		misc    => $misc,
	};

	$kernel->refcount_increment($sender_id, __PACKAGE__);

	_poe_setup_sidecar_ring($kernel, $heap);

	my $next_sidecar = pop @{$heap->{sidecar_ring}};
	unshift @{$heap->{sidecar_ring}}, $next_sidecar;

	$next_sidecar->put( [ $request_id, $host, $service, $hints ] );

	return 1;
}

# POE _start handler.  Initialize the session and start sidecar
# processes, which are owned and managed by that session.

sub _poe_start {
	my ($kernel, $heap, $alias, $max_resolvers) = @_[KERNEL, HEAP, ARG0..ARG1];

	$heap->{requests}        = {};
	$heap->{last_reuqest_id} = 0;
	$heap->{alias}           = $alias;
	$heap->{max_resolvers}   = $max_resolvers;

	$kernel->alias_set($alias);

	_poe_setup_sidecar_ring($kernel, $heap);

	undef;
}

# Internal helper sub.  Make sure the apprpriate number of sidecar
# resolvers are running at any given time.

sub _poe_setup_sidecar_ring {
	my ($kernel, $heap) = @_;

	return if $heap->{shutdown};

	while (scalar keys %{$heap->{sidecar}} < $heap->{max_resolvers}) {
		my $sidecar = POE::Wheel::Run->new(
			StdioFilter  => POE::Filter::Reference->new(),
			StdoutEvent  => 'sidecar_response',
			StderrEvent  => 'sidecar_error',
			CloseEvent   => 'sidecar_closed',
			Program      => \&_sidecar_code,
		);

		$heap->{sidecar}{$sidecar->PID}   = $sidecar;
		$heap->{sidecar_id}{$sidecar->ID} = $sidecar;
		push @{$heap->{sidecar_ring}}, $sidecar;

		$kernel->sig_child($sidecar->PID(), "sidecar_signal");
	}
}

# Internal helper sub.  This is the code that will run within each
# sidecar process.  It accepts requests from the main process, runs
# the blocking getaddrinfo() for each request, and returns responses.
#
# TODO - This would be more efficient as a stand-alone Perl program.
# The program at large can be quite... large... and forking it for
# just this snip of code seems inefficient.

sub _sidecar_code {
	my $filter = POE::Filter::Reference->new();
	my $buffer = "";
	my $read_length;

	while (1) {
		if (defined $read_length) {
			if (length($buffer) >= $read_length) {
				my $request = thaw(substr($buffer, 0, $read_length, ""));
				$read_length = undef;

				my ($request_id, $host, $service, $hints) = @$request;
				my ($err, @addrs) = getaddrinfo($host, $service, $hints);

				my $streamable = nfreeze( [ $request_id, $err, \@addrs ] );
				print length($streamable), chr(0), $streamable;

				next;
			}
		}
		elsif ($buffer =~ s/^(\d+)\0//) {
			$read_length = $1;
			next;
		}

		my $octets_read = sysread(STDIN, $buffer, 4096, length($buffer));
		last unless $octets_read;
	}
}

# Internal helper sub to replay pending requests when their associated
# sidecars are destroyed.

sub _poe_replay_pending {
	my ($kernel, $heap) = @_;

	# TODO - Broken implementation.  This worked when we had a single
	# sidecar, but now we have many.  We need to only replay the pending
	# requests that aren't associated with a currently active sidecar.
	#
	# There must be a mapping from requests to sidecars.  We can check
	# whether $request->{sidecar_id} (or such) exists.  If not, we can
	# replay it to a new sidecar.

	# TODO - We should have some sort of retry count.  I can foresee a
	# case where particular input crashes a sidecar process.  Replaying
	# that input indefinitely would just perform a fork/crash thrash.

	while (my ($request_id, $request) = each %{$heap->{requests}}) {
		my $next_sidecar = pop @{$heap->{sidecar_ring}};
		unshift @{$heap->{sidecar_ring}}, $next_sidecar;

		$next_sidecar->put(
			[
				$request_id, $request->{host}, $request->{service}, $request->{hints}
			]
		);
	}
}

# Internal event handler to briefly defer replaying requests until any
# responses in the queue have had time to be delivered.  This prevents
# us from replaying requests that may already have answers.

sub _poe_sidecar_attach {
	my ($kernel, $heap) = @_[KERNEL, HEAP];

	# Nothing to do if we don't have requests.
	return unless scalar keys %{$heap->{reuqests}};

	# Requests exist.
	_poe_setup_sidecar_ring($kernel, $heap);
	_poe_replay_pending($kernel, $heap);
}

# Plain public Perl method.  Begin resolving something.

sub resolve {
	my ($self, @args) = @_;

	croak "resolve() requires an even number of parameters" if @args % 2;
	my %args = @args;

	my $host = delete $args{host};
	croak "resolve() requires a host" unless defined $host and length $host;

	my $service = delete $args{service};
	croak "resolve() requires a service" unless (
		defined $service and length $service
	);

	my $misc = delete $args{misc};
	$misc //= "";

	my $hints = delete $args{hints};
	$hints //= { };

	my $event = delete $args{event};
	$event = "resolver_response" unless defined $event and length $event;

	my @error = sort keys %args;
	croak "unknown resolve() parameter(s): @error" if @error;

	croak "resolve() on shutdown resolver" unless (
		$poe_kernel->call(
			"$self", "request", $host, $service, $hints, $event, $misc
		)
	);
}

# A sidecar process has produced an error or warning.  Pass it
# through to the parent process' console.

sub _poe_sidecar_error {
	warn __PACKAGE__, " error in getaddrinfo subprocess: $_[ARG0]\n";
}

# A sidecar process has closed its standard output.  We will receive
# no more responses from it.  Clean up the sidecar's resources, and
# start new ones if necessary.

sub _poe_sidecar_closed {
	my ($kernel, $heap, $wheel_id) = @_[KERNEL, HEAP, ARG0];

	# Don't bother checking for pending requests if we've shut down.
	return if $heap->{shutdown};

	my $sidecar = delete $heap->{sidecar_id}{$wheel_id};
	if (defined $sidecar) {
		$sidecar->kill(9);
		delete $heap->{sidecar}{$sidecar->PID()};
	}

	# Keep sidecars in order for fairnes.
	# TODO - Does it really matter?
	@{$heap->{sidecar_ring}} = (
		map { $heap->{sidecar_id}{$_} }
		sort { $a <=> $b }
		keys %{$heap->{sidecar_id}}
	);

	_poe_setup_sidecar_ring($kernel, $heap);
	_poe_replay_pending($kernel, $heap) if scalar keys %{$heap->{requests}};
}

# A sidecar has produced a response.  Pass it back to the original
# caller of resolve().  If we've run out of requests, briefly defer a
# partial shutdown.  We don't need all those sidecar processes if we
# might be done.

sub _poe_sidecar_response {
	my ($kernel, $heap, $response_rec) = @_[KERNEL, HEAP, ARG0];
	my ($request_id, $error, $addresses) = @$response_rec;

	my $request_rec = delete $heap->{requests}{$request_id};
	return unless defined $request_rec;

	$kernel->post(
		$request_rec->{sender}, $request_rec->{event},
		$error, $addresses,
		{ map { $_ => $request_rec->{$_} } qw(host service event misc) },
	);

	$kernel->refcount_decrement($request_rec->{sender}, __PACKAGE__);

	# No more requests?  Consder detaching sidecar.
	$kernel->yield("sidecar_eject") unless scalar keys %{$heap->{requests}};
}

# A sidecar process has exited.  Clean up its resources, and attach a
# replacement sidecar if there are requests.

sub _poe_sidecar_signal {
	my ($heap, $pid) = @_[HEAP, ARG1];

	return unless exists $heap->{sidecar}{$pid};
	my $sidecar = delete $heap->{sidecar}{$pid};
	delete $heap->{sidecar_id}{$sidecar->ID()};

	# Keep sidecars in order for fairnes.
	# TODO - Does it really matter?
	@{$heap->{sidecar_ring}} = (
		map { $heap->{sidecar_id}{$_} }
		sort { $a <=> $b }
		keys %{$heap->{sidecar_id}}
	);

	$_[KERNEL]->yield("sidecar_attach") if scalar keys %{$heap->{requests}};

	undef;
}

# Event handler to defer wiping out all sidecars.  This allows for
# lazy cleanup, which may eliminate thrashing in some situations.

sub _poe_sidecar_eject {
	my ($kernel, $heap) = @_[KERNEL, HEAP];
	_poe_wipe_sidecars($heap) unless scalar keys %{$heap->{requests}};
}

# Internal helper sub to synchronously wipe out all sidecars.

sub _poe_wipe_sidecars {
	my $heap = shift;

	if (@{$heap->{sidecar_ring}}) {
		foreach my $sidecar (@{$heap->{sidecar_ring}}) {
			$sidecar->kill(-9);
		}
		delete $heap->{sidecar};
		delete $heap->{sidecar_id};
		delete $heap->{sidecar_ring};
	}
}

1;

__END__

=head1 NAME

POE::Component::Resolver - A non-blocking wrapper for getaddrinfo()

=head1 SYNOPSIS

	use warnings;
	use strict;

	use POE;
	use POE::Component::Resolver;

	my $r = POE::Component::Resolver->new();

	POE::Session->create(
		inline_states => {
			_start => sub {
				$r->resolve(
					host => "www.yahoo.com",
					service => "http",
					event => "got_response"
				) or die $!;
			},

			_stop => sub { print "client session stopped\n" },

			got_response => sub {
				my ($error, $addresses) = @_[ARG0..ARG1];
				use YAML; print YAML::Dump({ error => $error, addr => $addresses });
			},
		}
	);

	POE::Kernel->run();

=head1 DESCRIPTION

POE::Component::Resolver makes Socket::GetAddrInfo::getaddrinfo()
calls in a subprocess, where their blocking nature isn't an issue.

=cut
