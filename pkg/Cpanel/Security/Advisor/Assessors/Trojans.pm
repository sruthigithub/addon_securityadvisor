package Cpanel::Security::Advisor::Assessors::Trojans;

# Copyright (c) 2016, cPanel, Inc.
# All rights reserved.
# http://cpanel.net
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the owner nor the names of its contributors may
#       be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL  BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use Cpanel::SafeFind ();
use base 'Cpanel::Security::Advisor::Assessors';
use Cpanel::SafeRun::Simple;
use Digest::SHA;

our $LIBKEYUTILS_FILES_REF;
$LIBKEYUTILS_FILES_REF = build_libkeyutils_file_list();
our $IPCS_REF;
$IPCS_REF = get_ipcs_hash();

sub version {
    return '1.04';
}

sub generate_advice {
    my ($self) = @_;
    $self->_check_for_libkeyutils();
    $self->_check_for_UMBREON_rootkit();
    $self->_check_for_NCOM_rootkit();
    $self->_check_for_jynx2_rootkit();
    $self->_check_for_cdorked_A();
    $self->_check_for_cdorked_B();
    $self->_check_for_libkeyutils_filenames();
    $self->_check_sha1_sigs_libkeyutils();
    $self->_check_sha1_sigs_httpd();
    $self->_check_sha1_sigs_named();
    $self->_check_sha1_sigs_ssh();
    $self->_check_sha1_sigs_ssh_add();
    $self->_check_for_ebury_ssh_G();
    $self->_check_for_ebury_ssh_banner();
    $self->_check_for_ebury_ssh_shmem();
    $self->_check_for_ebury_root_file();
    return 1;
}

sub _check_for_libkeyutils {
    my ($self) = @_;

    my @search_dirs = ('/lib');
    push @search_dirs, '/lib64' if -e '/lib64';

    Cpanel::SafeFind::find(
        {
            'wanted' => sub {
                if ( $File::Find::name =~ m/libkeyutils.so/ ) {
                    my $res = Cpanel::SafeRun::Simple::saferun(
                        '/bin/rpm', '-qf',
                        $File::Find::name
                    );
                    chomp($res);

                    if ( $res =~ m/file.*is not owned by any package/ ) {
                        $self->add_bad_advice(
                            'text' => [
                                "Libkeyutils check: “[_1]” is not owned by any system packages. This indicates a possible server compromise. (NOTE: Corrupted RPM databases can report this as a false positive).",
                                $File::Find::name
                            ],
                            'suggestion' => [
                                'Check the following to determine if this server is compromised "[output,url,_1,Determine your Systems Status,_2,_3]"',
                                'https://documentation.cpanel.net/display/CKB/Determine+Your+System%27s+Status',
                                'target',
                                '_blank'
                            ],
                        );
                    }
                }
            },
            'no_chdir' => 1,
        },
        @search_dirs,
    );

    return 1;
}

sub _check_for_UMBREON_rootkit {
    my ($self) = @_;
    my $dir    = '/usr/local/__UMBREON__';
    my $dir2   = '/usr/local/UMBREON';
    if ( -d $dir or -d $dir2 ) {
        $self->add_bad_advice(
            'text'       => ["UMBREON rootkit check: Evidence of the UMBREON rootkit was found."],
            'suggestion' => [
                'Check the following to determine if this server is compromised "[output,url,_1,Determine your Systems Status,_2,_3]"',
                'https://documentation.cpanel.net/display/CKB/Determine+Your+System%27s+Status',
                'target',
                '_blank'
            ],
        );
    }
}

sub _check_for_NCOM_rootkit {
    my ($self) = @_;
    my @bad_libs;
    my @dirs  = qw( /lib /lib64 );
    my @files = qw( libncom.so.4.0.1 libselinux.so.4 );

    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            if ( -f "${dir}/${file}" and !-z "${dir}/${file}" ) {
                push( @bad_libs, "<br>&nbsp;&nbsp; - ${dir}/${file}" );
            }
        }
    }

    if (@bad_libs) {
        $self->add_bad_advice(
            'text' => [
                "NCOM rootkit check: Evidence of the NCOM rootkit was found: [list_and,_1]",
                \@bad_libs
            ],
            'suggestion' => [
                'Check the following for more information "[output,url,_1,We Live Security More Information,_2,_3]"',
                'https://documentation.cpanel.net/display/CKB/Determine+Your+System%27s+Status',
                'target',
                '_blank'
            ],
        );
    }
}

sub _check_for_jynx2_rootkit {
    my ($self) = @_;
    my $dir = '/usr/bin64';
    my @found_jynx2_files = grep { -e } map { "$dir/$_" } qw( 3.so 4.so );
    if ( scalar @found_jynx2_files > 0 ) {
        $self->add_bad_advice(
            'text'       => ["Jynx 2 rootkit check: Evidence of the Jynx 2 rootkit was found."],
            'suggestion' => [
                'Check the following to determine if this server is compromised "[output,url,_1,Determine your Systems Status,_2,_3]"',
                'https://documentation.cpanel.net/display/CKB/Determine+Your+System%27s+Status',
                'target',
                '_blank'
            ],
        );
    }
}

sub _check_for_cdorked_A {
    my ($self)       = @_;
    my $apache_bin   = '/usr/local/apache/bin/httpd';
    my $max_bin_size = 10_485_760;                      # avoid slurping too much mem
    return if ( !-f $apache_bin );
    return if ( ( stat($apache_bin) )[7] > $max_bin_size );

    my $has_cdorked = 0;
    my $signature;
    my @apache_bins = ();
    push @apache_bins, $apache_bin;
    my @PROCESS_LIST;
    for my $process (@PROCESS_LIST) {
        if ( $process =~ m{ \A root \s+ (\d+) [^\d]+ $apache_bin }xmsa ) {
            my $pid          = $1;
            my $proc_pid_exe = "/proc/" . $pid . "/exe";
            if ( -l $proc_pid_exe
                && readlink($proc_pid_exe) =~ m{ \(deleted\) }xms ) {
                next if ( ( stat($proc_pid_exe) )[7] > $max_bin_size );
                push @apache_bins, $proc_pid_exe;
            }
        }
    }

    for my $check_bin (@apache_bins) {
        my $httpd;
        if ( open my $fh, '<', $check_bin ) {
            local $/;
            $httpd = <$fh>;
            close $fh;
        }

        next if !$httpd;

        if ( $httpd =~ /(open_tty|hangout|ptsname|Qkkbal)/ ) {
            $signature   = $check_bin . ": \"" . $1 . "\"";
            $has_cdorked = 1;
            last;
        }
    }
    if ( $has_cdorked == 1 ) {
        $self->add_bad_advice(
            'text'       => ["CDORKED rootkit check: Evidence of the CDORKED A rootkit was found."],
            'suggestion' => [
                'Check the following for more information "[output,url,_1,We Live Security More Information,_2,_3]"',
                'http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf',
                'target',
                '_blank'
            ],
        );
    }
}

sub _check_for_cdorked_B {
    my ($self) = @_;
    my $has_cdorked_b = 0;
    my @files = ( '/usr/sbin/arpd ', '/usr/sbin/tunelp ', '/usr/bin/s2p ' );
    my @cdorked_files;

    for my $file (@files) {
        if ( -e $file ) {
            $has_cdorked_b = 1;
            push( @cdorked_files, "[$file] " );
        }
    }

    if ( $has_cdorked_b == 1 ) {
        $self->add_bad_advice(
            'text' => [
                "CDORKED rootkit check: The following [numerate,_1,file was,files were] found, indicating the possibility of the CDORKED B rootkit: [list_and,_1]",
                \@cdorked_files
            ],
            'suggestion' => [
                'Check the following for more information "[output,url,_1,We Live Security More Information,_2,_3]"',
                'http://www.welivesecurity.com/2013/04/26/linuxcdorked-new-apache-backdoor-in-the-wild-serves-blackhole/',
                'target',
                '_blank'
            ],
        );
    }
}

sub _check_for_libkeyutils_filenames {
    my ($self) = @_;
    my @bad_libs;
    my @dirs  = qw( /lib /lib64 );
    my @files = qw(
      libkeyutils.so.1.9
      libkeyutils-1.2.so.0
      libkeyutils-1.2.so.2
      libkeyutils.so.1.3.0
      libkeyutils.so.1.3.2
      libns2.so
      libns5.so
      libpw3.so
      tls/libkeyutils.so.1
      tls/libkeyutils.so.1.5
    );

    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            if ( -f "${dir}/${file}" and !-z "${dir}/${file}" ) {
                push( @bad_libs, "<br>&nbsp;&nbsp; - ${dir}/${file}" );
            }
        }
    }

    if (@bad_libs) {
        $self->add_bad_advice(
            'text' => [
                "Libkey rootkit check: The following system [numerate,library,libraries] were found which could indicate a root level compromise: [list_and,_1]",
                \@bad_libs
            ],
            'suggestion' => [
                'Check the following for more information "[output,url,_1,We Live Security More Information,_2,_3]"',
                'http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf',
                'target',
                '_blank'
            ],
        );
    }
}

sub build_libkeyutils_file_list {
    my ($self) = @_;
    my @dirs = qw( /lib /lib64 );
    my @libkeyutils_files;

    for my $dir (@dirs) {
        next if !-e $dir;
        opendir( my $dir_fh, $dir );
        while ( my $file = readdir($dir_fh) ) {
            if ( $file =~ /^libkeyutils\.so(?:\.[\.\d]+)?$/ ) {
                if ( $dir eq '/lib' ) {
                    push @libkeyutils_files, "/lib/$file";
                }
                elsif ( $dir eq '/lib64' ) {
                    push @libkeyutils_files, "/lib64/$file";
                }
            }
        }
        closedir $dir_fh;
    }

    return \@libkeyutils_files;
}

sub _check_sha1_sigs_libkeyutils {
    my ($self) = @_;
    return if !$LIBKEYUTILS_FILES_REF;

    my @trojaned_lib;

    # p67 http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf
    my @checksums = qw(
      09c8af3be4327c83d4a7124a678bbc81e12a1de4
      1a9aff1c382a3b139b33eeccae954c2d65b64b90
      267d010201c9ff53f8dc3fb0a48145dc49f9de1e
      2e571993e30742ee04500fbe4a40ee1b14fa64d7
      2fc132440bafdbc72f4d4e8dcb2563cc0a6e096b
      39ec9e03edb25f1c316822605fe4df7a7b1ad94a
      3c5ec2ab2c34ab57cba69bb2dee70c980f26b1bf
      471ee431030332dd636b8af24a428556ee72df37
      58f185c3fe9ce0fb7cac9e433fb881effad31421
      5d3ec6c11c6b5e241df1cc19aa16d50652d6fac0
      74aa801c89d07fa5a9692f8b41cb8dd07e77e407
      7adb38bf14e6bf0d5b24fa3f3c9abed78c061ad1
      899b860ef9d23095edb6b941866ea841d64d1b26
      8daad0a043237c5e3c760133754528b97efad459
      8f75993437c7983ac35759fe9c5245295d411d35
      9bb6a2157c6a3df16c8d2ad107f957153cba4236
      9e2af0910676ec2d92a1cad1ab89029bc036f599
      a7b8d06e2c0124e6a0f9021c911b36166a8b62c5
      adfcd3e591330b8d84ab2ab1f7814d36e7b7e89f
      b8508fc2090ddee19a19659ea794f60f0c2c23ff
      bbce62fb1fc8bbed9b40cfb998822c266b95d148
      bf1466936e3bd882b47210c12bf06cb63f7624c0
      d552cbadee27423772a37c59cb830703b757f35e
      e14da493d70ea4dd43e772117a61f9dbcff2c41c
      e2a204636bda486c43d7929880eba6cb8e9de068
      f1ada064941f77929c49c8d773cbad9c15eba322
    );

    for my $lib (@$LIBKEYUTILS_FILES_REF) {
        next unless my $checksum = _check_sha1sum( $lib, @checksums );
        push( @trojaned_lib, "<br>&nbsp;&nbsp; SHA-1 Checksum $checksum $lib<br>" );
    }

    if (@trojaned_lib) {
        $self->add_bad_advice(
            'text'       => [ "Libkey rootkit check: The following suspicious [numerate,file,files] were found that match a specific SHA-1 checksum which could indicate a root level compromise: [list]", \@trojaned_lib ],
            'suggestion' => [
                'Check the following for more information "[output,url,_1,We Live Security More Information,_2,_3]"',
                'http://www.welivesecurity.com/2014/02/21/an-in-depth-analysis-of-linuxebury/',
                'target',
                '_blank'
            ],
        );
    }
}

sub _check_sha1_sigs_httpd {
    my ($self) = @_;
    my $httpd = '/usr/local/apache/bin/httpd';
    return if !-e $httpd;

    my @infected;

    my @sigs = qw(
      0004b44d110ad9bc48864da3aea9d80edfceed3f
      03592b8147e2c84233da47f6e957acd192b3796a
      0eb1108a9d2c9fe1af4f031c84e30dcb43610302
      10c6ce8ee3e5a7cb5eccf3dffd8f580e4fb49089
      149cf77d2c6db226e172390a9b80bc949149e1dc
      1972616a731c9e8a3dbda8ece1072bd16c44aa35
      24e3ebc0c5a28ba433dfa69c169a8dd90e05c429
      4f40bb464526964ba49ed3a3b2b2b74491ea89a4
      5b87807b4a1796cfb1843df03b3dca7b17995d20
      62c4b65e0c4f52c744b498b555c20f0e76363147
      78c63e9111a6701a8308ad7db193c6abb17c65c4
      858c612fe020fd5089a05a3ec24a6577cbeaf7eb
      9018377c0190392cc95631170efb7d688c4fd393
      a51b1835abee79959e1f8e9293a9dcd8d8e18977
      a53a30f8cdf116de1b41224763c243dae16417e4
      ac96adbe1b4e73c95c28d87fa46dcf55d4f8eea2
      dd7846b3ec2e88083cae353c02c559e79124a745
      ddb9a74cd91217cfcf8d4ecb77ae2ae11b707cd7
      ee679661829405d4a57dbea7f39efeb526681a7f
      fc39009542c62a93d472c32891b3811a4900628a
      fdf91a8c0ff72c9d02467881b7f3c44a8a3c707a
    );

    return unless my $checksum = _check_sha1sum( $httpd, @sigs );
    push( @infected, "<br>&nbsp;&nbsp; SHA-1 checksum: $checksum $httpd" );

    if (@infected) {
        $self->add_bad_advice(
            'text'       => [ "Trojan Apache check: Suspicious checksums/hashes were found that could indicate the existence of the CDORKED rootkit. [list_and,_1]", \@infected ],
            'suggestion' => [
                'Check pages 67-68 from the following for more information "[output,url,_1,We Live Security More Information,_2,_3]"',
                'http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf',
                'target',
                '_blank'
            ],
        );
    }
}

sub _check_sha1_sigs_named {
    my ($self) = @_;
    my $named = '/usr/sbin/named';
    return if !-e $named;

    my $infected;

    my @sigs = qw(
      42123cbf9d51fb3dea312290920b57bd5646cefb
      ebc45dd1723178f50b6d6f1abfb0b5a728c01968
    );

    return unless my $checksum = _check_sha1sum( $named, @sigs );
    $infected = "\t$checksum: $named\n";

    if ($infected) {
        $self->add_bad_advice(
            'text' => [
                "Trojan bind/named check: suspicious checksums/hashes were found [_1] that could indicate the existence of the CDORKED rootkit.",
                $infected
            ],
            'suggestion' => [
                'Check pages 67-68 from the following for more information "[output,url,_1,We Live Security More Information,_2,_3]"',
                'http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf',
                'target',
                '_blank'
            ],
        );
    }
}

sub _check_sha1_sigs_ssh {
    my ($self) = @_;
    my $ssh = '/usr/bin/ssh';
    return if !-e $ssh;

    my $infected;

    my @sigs = qw(
      c4c28d0372aee7001c44a1659097c948df91985d
      fa6707c7ef12ce9b0f7152ca300ebb2bc026ce0b
    );

    return unless my $checksum = _check_sha1sum( $ssh, @sigs );
    $infected = "\t$checksum: $ssh\n";

    if ($infected) {
        $self->add_bad_advice(
            'text' => [
                "Trojan sshd binary check: suspicious checksums/hashes were found [_1] that could indicate the existence of the Ebury rootkit.",
                $infected
            ],
            'suggestion' => [
                'Check pages 67-68 from the following for more information "[output,url,_1,We Live Security More Information,_2,_3]"',
                'http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf',
                'target',
                '_blank'
            ],
        );
    }
}

sub _check_sha1_sigs_ssh_add {
    my ($self) = @_;
    my $ssh_add = '/usr/bin/ssh-add';
    return if !-e $ssh_add;

    my $infected;

    my @sigs = qw(
      575bb6e681b5f1e1b774fee0fa5c4fe538308814
    );

    return unless my $checksum = _check_sha1sum( $ssh_add, @sigs );
    $infected = "\t$checksum: $ssh_add\n";

    if ($infected) {
        $self->add_bad_advice(
            'text' => [
                "Trojan sshd binary check: suspicious checksums/hashes were found [_1] that could indicate the existence of the Ebury rootkit.",
                $infected
            ],
            'suggestion' => [
                'Check pages 67-68 from the following for more information "[output,url,_1,We Live Security More Information,_2,_3]"',
                'http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf',
                'target',
                '_blank'
            ],
        );
    }
}

sub _check_sha1_sigs_sshd {
    my ($self) = @_;
    my $sshd = '/usr/sbin/sshd';
    return if !-e $sshd;

    my $infected;

    my @sigs = qw(
      0daa51519797cefedd52864be0da7fa1a93ca30b
      4d12f98fd49e58e0635c6adce292cc56a31da2a2
      7314eadbdf18da424c4d8510afcc9fe5fcb56b39
      98cdbf1e0d202f5948552cebaa9f0315b7a3731d
    );

    return unless my $checksum = _check_sha1sum( $sshd, @sigs );
    $infected = "\t$checksum: $sshd\n";

    if ($infected) {
        $self->add_bad_advice(
            'text' => [
                "Trojan sshd binary check: suspicious checksums/hashes were found [_1] that could indicate the existence of the Ebury rootkit.",
                $infected
            ],
            'suggestion' => [
                'Check pages 67-68 from the following for more information "[output,url,_1,We Live Security More Information,_2,_3]"',
                'http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf',
                'target',
                '_blank'
            ],
        );
    }
}

sub _check_for_ebury_ssh_G {
    my ($self) = @_;
    my $ssh = '/usr/bin/ssh';
    return if !-e $ssh;
    return if !-f _;
    return if !-x _;
    return if -z _;

    my $ssh_version = Cpanel::SafeRun::Timed::timedsaferun( 0, $ssh, '-V' );
    return if $ssh_version !~ m{ \A OpenSSH_5 }xms;

    my $ssh_G = Cpanel::SafeRun::Timed::timedsaferun( 0, $ssh, '-G' );
    if ( $ssh_G !~ /illegal|unknown/ ) {
        $self->add_bad_advice(
            'text'       => ["Trojan sshd binary check: ssh -G failed to return illegal/unknown indicating the possibility of the Ebury rootkit."],
            'suggestion' => [
                'Check page 57 from the following for more information "[output,url,_1,We Live Security More Information,_2,_3]"',
                'http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf',
                'target',
                '_blank'
            ],
        );
    }
}

sub _check_for_ebury_ssh_banner {
    my ($self) = @_;
    my ( $host, $port, $ssh_banner );
    my $ssh_connection = $ENV{'SSH_CONNECTION'};
    return if !$ssh_connection;

    if ( $ssh_connection =~ m{ \s (\d+\.\d+\.\d+\.\d+) \s (\d+) \z }xms ) {
        ( $host, $port ) = ( $1, $2 );
    }

    return if !$host;
    return if !$port;

    my $sock = IO::Socket::INET->new(
        PeerAddr => $host,
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or return;

    $ssh_banner = readline $sock;
    close $sock;
    return if !$ssh_banner;
    chomp $ssh_banner;

    if ( $ssh_banner =~ m{ \A SSH-2\.0-[0-9a-f]{22,46} }xms ) {
        $self->add_bad_advice(
            'text'       => ["Trojan sshd binary check: The sshd banner matches known signatures from Ebury machines, indicating the existence of the Ebury rootkit."],
            'suggestion' => [
                'Check the following for more information "[output,url,_1,We Live Security More Information,_2,_3]"',
                'http://www.welivesecurity.com/2014/02/21/an-in-depth-analysis-of-linuxebury/',
                'target',
                '_blank'
            ],
        );
    }
}

sub _check_for_ebury_ssh_shmem {
    my ($self) = @_;

    # As far as we know, sshd sholudn't be using shared memory at all, so any usage is a strong
    # sign of ebury.
    return if !defined( $IPCS_REF->{root}{mp} );
    my $PROCESS_REF;
    for my $href ( @{ $IPCS_REF->{root}{mp} } ) {
        my $shmid = $href->{shmid};
        my $cpid  = $href->{cpid};
        if (   $PROCESS_REF->{$cpid}{CMD}
            && $PROCESS_REF->{$cpid}{CMD} =~ m{ \A /usr/sbin/sshd \b }x ) {
            $self->add_bad_advice(
                'text'       => ["sshd shared memory check: A shared memory segment created by sshd process exists."],
                'suggestion' => [
                    'Check pages 33-34 from the following for more information "[output,url,_1,We Live Security More Information,_2,_3]"',
                    'http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf',
                    'target',
                    '_blank'
                ],
            );
        }
    }
}

sub get_ipcs_hash {
    my %hash;
    my $header = 0;
    my @res = Cpanel::SafeRun::Simple::saferun( 'ipcs', '-m', '-p' );
    chomp(@res);
    my $line;
    foreach $line (@res) {
        chomp($line);
        if ( $header == 0 ) {
            $header = 1
              if ( $line =~ m/^ shmid \s+ owner \s+ cpid \s+ lpid \s* $/ix );
            next;
        }
        my @ipcs = split( /\s+/, $line, 5 );
        push @{ $hash{ $ipcs[1] }{mp} },
          {
            'shmid' => $ipcs[0],
            'cpid'  => $ipcs[2],
            'lpid'  => $ipcs[3]
          };
    }
    return \%hash;
}

sub _check_sha1sum {
    my ( $file, @checksums ) = @_;
    my $fh;
    open $fh, $file;
    my $sha = Digest::SHA->new;
    $sha->addfile($fh);
    close $fh;
    my $digest = $sha->hexdigest;
    for my $checklib (@checksums) {

        if ( grep { $digest eq $_ } @checksums ) {
            return $digest;
        }
    }
    return 0;
}

1;
