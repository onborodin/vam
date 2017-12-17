#!@perl@

package aConfig;

use strict;
use warnings;

sub new {
    my ($class, $file) = @_;
    my $self = {
        file => $file
    };
    bless $self, $class;
    $self;
}

sub file {
    my ($self, $name) = @_;
    return $self->{'file'} unless $name;
    $self->{'file'} = $name;
    $self;
}

sub read {
    my $self = shift;
    return undef unless -r $self->file;
    open my $fh, '<', $self->file;
    my %res;
    while (my $line = readline $fh) {
        chomp $line;
        $line =~ s/^\s+//g;

        next if $line =~ /^#/;
        next if $line =~ /^;/;
        next unless $line =~ /[=:]/;

        $line =~ s/[\"\']//g;
        my ($key, $rawvalue) = split(/==|=>|[=:]/, $line);
        next unless $rawvalue and $key;

        my ($value, $comment) = split(/[#;,]/, $rawvalue);

        $key =~ s/^\s+|\s+$//g;
        $value =~ s/^\s+|\s+$//g;

        $res{$key} = $value;
    }
    close $fh;
    \%res;
}

1;

#----------
#--- DB ---
#----------

package aDB;

use strict;
use warnings;
use DBI;
use DBD::Pg;

sub new {
    my ($class, %args) = @_;
    my $self = {
        host => $args{host} || '',
        login => $args{login} || '',
        password => $args{password} || '',
        database => $args{database} || '',
        engine => $args{engine} || 'SQLite',
        error => ''
    };
    bless $self, $class;
    return $self;
}

sub login {
    my ($self, $login) = @_;
    return $self->{login} unless $login;
    $self->{login} = $login;
    $self;
}

sub password {
    my ($self, $password) = @_;
    return $self->{password} unless $password;
    $self->{password} = $password;
    $self;
}

sub host {
    my ($self, $host) = @_;
    return $self->{host} unless $host;
    $self->{host} = $host;
    $self;
}

sub database {
    my ($self, $database) = @_;
    return $self->{database} unless $database;
    $self->{database} = $database;
    $self;
}

sub error {
    my ($self, $error) = @_;
    return $self->{error} unless $error;
    $self->{error} = $error;
    $self;
}

sub engine {
    my ($self, $engine) = @_;
    return $self->{engine} unless $engine;
    $self->{engine} = $engine;
    $self;
}

sub exec {
    my ($self, $query) = @_;
    return undef unless $query;

    my $dsn = 'dbi:'.$self->engine.
                ':dbname='.$self->database.
                ';host='.$self->host;
    my $dbi;
    eval {
        $dbi = DBI->connect($dsn, $self->login, $self->password, {
            RaiseError => 1,
            PrintError => 0,
            AutoCommit => 1
        });
    };
    $self->error($@);
    return undef if $@;

    my $sth;
    eval {
        $sth = $dbi->prepare($query);
    };
    $self->error($@);
    return undef if $@;

    my $rows = $sth->execute;
    my @list;

    while (my $row = $sth->fetchrow_hashref) {
        push @list, $row;
    }
    $sth->finish;
    $dbi->disconnect;
    \@list;
}

sub exec1 {
    my ($self, $query) = @_;
    return undef unless $query;

    my $dsn = 'dbi:'.$self->engine.
                ':dbname='.$self->database.
                ';host='.$self->host;
    my $dbi;
    eval {
        $dbi = DBI->connect($dsn, $self->login, $self->password, {
            RaiseError => 1,
            PrintError => 0,
            AutoCommit => 1
        });
    };
    $self->error($@);
    return undef if $@;

    my $sth;
    eval {
        $sth = $dbi->prepare($query);
    };
    $self->error($@);
    return undef if $@;

    my $rows = $sth->execute;
    my $row = $sth->fetchrow_hashref;

    $sth->finish;
    $dbi->disconnect;
    $row;
}

sub do {
    my ($self, $query) = @_;
    return undef unless $query;
    my $dsn = 'dbi:'.$self->engine.
                ':dbname='.$self->database.
                ';host='.$self->host;
    my $dbi;
    eval {
        $dbi = DBI->connect($dsn, $self->login, $self->password, {
            RaiseError => 1,
            PrintError => 0,
            AutoCommit => 1
        });
    };
    $self->error($@);
    return undef if $@;
    my $rows;
    eval {
        $rows = $dbi->do($query);
    };
    $self->error($@);
    return undef if $@;

    $dbi->disconnect;
    $rows*1;
}

1;


#------------
#--- USER ---
#------------

package aUser;

use strict;
use warnings;

sub new {
    my ($class, $db) = @_;
    my $self = { 
        db => $db
    };
    bless $self, $class;
    return $self;
}

sub db {
    my ($self, $db) = @_;
    return $self->{db} unless $db;
    $self->{db} = $db;
    $self;
}

# --- USER ---

sub user_exist {
    my ($self, $name) = @_;
    return undef unless $name;
    my $res = $self->db->exec1("select * from users where users.name = '$name' limit 1");
    $res->{id};
}

sub user_profile {
    my ($self, $id) = @_;
    return undef unless $id;
    $self->db->exec1("select * from users where id = $id limit 1");
}

sub user_list {
    my ($self) = @_;
    $self->db->exec('select * from users order by name');
}

1;



#############
#--- MAIN ---
#############

use strict;
use warnings;
use IO::Handle;
use Mojo::Util qw(dumper getopt);

my $appname = 'vam-helper';

STDOUT->autoflush(1);

my %config;
my $config = \%config;

$config->{conffile} = '@app_confdir@/vam.conf';
$config->{dbname} =  '@app_datadir@/vam.db';
$config->{dbhost} =  '';
$config->{dblogin} =  '';
$config->{dbpassword} =  '';
$config->{dbengine} =  'sqlite3';

if (-r $config->{conffile}) {
    my $c = aConfig->new($config->{conffile});
    my $hash = $c->read;
    foreach my $key (keys %$hash) {
        $config->{$key} = $hash->{$key};
    }
}

my $engine = 'SQLite' if $config->{dbengine} =~ /sqlite/i;
$engine = 'Pg' if $config->{dbengine} =~ /postgres/i;

my $dbi = aDB->new(
            database => $config->{dbname},
            host => $config->{dbhost},
            login => $config->{dblogin},
            password => $config->{dbpassword},
            engine => $engine
);

my $u = aUser->new($dbi);

my $user = $ENV{"username"};
my $password = $ENV{"password"};
my $cn = $ENV{"common_name"};

exit 1 unless $user;
exit 1 unless $password;

my $user_id = $u->user_exist($user);
exit 1 unless $user_id ;

my $profile = $u->user_profile($user_id);
exit 1 unless $profile;

my $profile_password = $profile->{password} || '';

if ($profile_password eq $password) {
    exit 0;
} else {
    exit 1;
}
#EOF
