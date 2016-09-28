package Cpanel::Security::Advisor::Assessors::Scgiwrap;

# Copyright (c) 2015, cPanel, Inc.
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
use base 'Cpanel::Security::Advisor::Assessors';
use Cpanel::Config::Httpd ();

sub generate_advice {
    my ($self) = @_;
    $self->_check_scgiwrap;

    return 1;
}

sub _binary_has_setuid {
    my ($binary) = @_;
    return ( ( stat $binary )[2] || 0 ) & 04000;
}

sub _check_scgiwrap {
    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    # In ea3 these are always the same, in ea4 they are determined by the RPM in question.
    my $httpd  = "/usr/local/apache/bin/httpd";
    my $suexec = "/usr/local/apache/bin/suexec";

    #check for sticky bit on file to see if it is enabled or not.
    my $suenabled = _binary_has_setuid($suexec);

    if ( defined &Cpanel::Config::Httpd::is_ea4 ) {
        if ( Cpanel::Config::Httpd::is_ea4() ) {
            require Cpanel::ConfigFiles::Apache;
            my $apacheconf = Cpanel::ConfigFiles::Apache->new();
            $suexec = $apacheconf->bin_suexec();
            $httpd  = $apacheconf->bin_httpd();
            if ( -f $suexec ) {

                # patches welcome for more a robust way to do this besides matching getcap output!
                my $gc = `getcap $suexec`;    # the RPM in ea4 uses capabilities for setuid, not setuid bit
                $suenabled = $gc =~ m/cap_setgid/ && $gc =~ m/cap_setuid/;

                # CloudLinux's EA 4 RPM uses setuid.
                $suenabled ||= _binary_has_setuid($suexec);
            }
        }
    }

    # DEPRECATED_1158
    my $scgiwrap = '/usr/local/cpanel/cgi-sys/scgiwrap';
    $scgiwrap .= '_deprecated' if $Cpanel::Version::MAJORVERSION > 11.57;

    #check for sticky bit on file to see if it is enabled or not.
    my $scgienabled = ( ( stat $scgiwrap )[2] || 0 ) & 04000;

    my ($ruid) = ( grep { /ruid2_module/ } split( /\n/, Cpanel::SafeRun::Simple::saferun( $httpd, '-M' ) ) );

    if ( $suenabled && !$scgienabled ) {
        $security_advisor_obj->add_advice(
            {
                'key'  => 'Scgiwrap_SCGI_is_disabled',
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => $self->_lh->maketext('SCGI is disabled, currently using the recommended suEXEC.'),
            }
        );
    }
    elsif ( $suenabled && $scgienabled ) {
        if ( !$ruid ) {
            $security_advisor_obj->add_advice(
                {
                    'key'        => 'Scgiwrap_SCGI_AND_suEXEC_are_enabled',
                    'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                    'text'       => $self->_lh->maketext('Both SCGI and suEXEC are enabled.'),
                    'suggestion' => $self->_lh->maketext(
                        'On the “[output,url,_1,Configure PHP and suEXEC,_2,_3]” page toggle “Apache suEXEC” off then back on to disable SCGI.',
                        $self->base_path('scripts2/phpandsuexecconf'),
                        'target',
                        '_blank'
                    ),
                }
            );
        }
        else {
            $security_advisor_obj->add_advice(
                {
                    'key'  => 'Scgiwrap_SCGI_suEXEC_and_mod_ruid2_are_enabled',
                    'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                    'text' => $self->_lh->maketext('SCGI, suEXEC, and mod_ruid2 are enabled.'),
                }
            );
        }
    }
    elsif ( !$suenabled || -f "$suexec.disable" ) {
        if ( !$ruid ) {
            $security_advisor_obj->add_advice(
                {
                    'key'        => 'Scgiwrap_suEXEC_is_disabled',
                    'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                    'text'       => $self->_lh->maketext('suEXEC is disabled.'),
                    'suggestion' => $self->_lh->maketext(
                        'Enable suEXEC on the “[output,url,_1,Configure PHP and suEXEC,_2,_3]” page.',
                        $self->base_path('scripts2/phpandsuexecconf'),
                        'target',
                        '_blank'
                    ),
                }
            );
        }
        else {
            $security_advisor_obj->add_advice(
                {
                    'key'  => 'Scgiwrap_suEXEC_is_disabled_mod_ruid2_is_installed',
                    'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                    'text' => $self->_lh->maketext('suEXEC is disabled; however mod_ruid2 is installed.'),
                }
            );
        }
    }
    else {
        $security_advisor_obj->add_advice(
            {
                'key'        => 'Scgiwrap_SCGI_is_enabled',
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => $self->_lh->maketext('SCGI is enabled.'),
                'suggestion' => $self->_lh->maketext(
                    'Turn off SCGI and enable the more secure suEXEC in the “[output,url,_1,Configure PHP and suEXEC,_2,_3]” page.',
                    $self->base_path('scripts2/phpandsuexecconf'),
                    'target',
                    '_blank'
                ),
            }
        );

    }

    return 1;
}
1;
