package Cpanel::Security::Advisor::Assessors::Brute;

# Copyright (c) 2013, cPanel, Inc.
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
use Cpanel::Config::Hulk ();
use Cpanel::PsParser     ();
use Cpanel::LoadFile     ();

use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advice {
    my ($self) = @_;
    $self->_check_for_brute_force_protection();

    return 1;
}

sub _check_for_brute_force_protection {
    my ($self) = @_;

    my $cphulk_enabled = Cpanel::Config::Hulk::is_enabled();

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    if ($cphulk_enabled) {
        $security_advisor_obj->add_advice(
            {
                'key'  => 'Brute_protection_enabled',
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => $self->_lh->maketext('cPHulk Brute Force Protection is enabled.'),
            }
        );

    }
    elsif ( -e "/etc/csf" ) {
        if ( -e "/etc/csf/csf.disable" ) {
            if ( -e "/usr/local/cpanel/whostmgr/docroot/cgi/configserver/csf" ) {
                $security_advisor_obj->add_advice(
                    {
                        'key'        => 'Brute_csf_installed_but_disabled_1',
                        'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                        'text'       => $self->_lh->maketext('CSF is installed, but appears to be disabled.'),
                        'suggestion' => $self->_lh->maketext(
                            'Click “Firewall Enable“ in the “[output,url,_1,ConfigServer Security & Firewall,_2,_3]” area. Alternately, run “csf -e“ from the command line.',
                            $self->base_path('cgi/configserver/csf.cgi'),
                            'target',
                            '_blank'
                        ),
                    }
                );
            }
            else {
                $security_advisor_obj->add_advice(
                    {
                        'key'        => 'Brute_csf_installed_but_disabled_2',
                        'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                        'text'       => $self->_lh->maketext('CSF is installed, but appears to be disabled.'),
                        'suggestion' => $self->_lh->maketext('Run “csf -e“ from the command line.'),
                    }
                );
            }
        }
        elsif ( check_lfd_running() ) {
            $security_advisor_obj->add_advice(
                {
                    'key'  => 'Brute_csf_installed_lfd_running',
                    'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                    'text' => $self->_lh->maketext('CSF is installed, and LFD is running.'),
                }
            );
        }
        else {
            if ( -e "/usr/local/cpanel/whostmgr/docroot/cgi/configserver/csf" ) {
                $security_advisor_obj->add_advice(
                    {
                        'key'        => 'Brute_csf_installed_lfd_not_running_1',
                        'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                        'text'       => $self->_lh->maketext('CSF is installed, but LFD is not running.'),
                        'suggestion' => $self->_lh->maketext(
                            'Click “lfd Restart“ in the “[output,url,_1,ConfigServer Security & Firewall,_2,_3]” area. Alternately, run “csf --lfd restart“ from the command line.',
                            $self->base_path('cgi/configserver/csf.cgi'),
                            'target',
                            '_blank'
                        ),
                    }
                );
            }
            else {
                $security_advisor_obj->add_advice(
                    {
                        'key'        => 'Brute_csf_installed_lfd_not_running_2',
                        'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                        'text'       => $self->_lh->maketext('CSF is installed, but LFD is not running.'),
                        'suggestion' => $self->_lh->maketext('Run “csf --lfd restart“ from the command line.'),
                    }
                );
            }
        }
    }
    else {
        $security_advisor_obj->add_advice(
            {
                'key'        => 'Brute_force_protection_not_enabled',
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => $self->_lh->maketext('No brute force protection detected'),
                'suggestion' => $self->_lh->maketext(
                    'Enable cPHulk Brute Force Protection in the “[output,url,_1,cPHulk Brute Force Protection,_2,_3]” area.',
                    $self->base_path('cgi/tweakcphulk.cgi'),
                    'target',
                    '_blank'

                ),
            }
        );
    }

    return 1;
}

sub check_lfd_running {
    my $v_pid = Cpanel::LoadFile::load_if_exists("/var/run/lfd.pid");
    if ( $v_pid && $v_pid =~ m/^[0-9]+$/ ) {
        chomp($v_pid);
        my $parsed_ps = Cpanel::PsParser::fast_parse_ps( 'want_pid' => $v_pid );
        if ( $parsed_ps && $parsed_ps->[0]->{'command'} =~ m{^lfd\b} ) {
            return 1;
        }
    }
    return 0;
}

1;
