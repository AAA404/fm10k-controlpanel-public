"""Execute the actual generated TestPoint Perl against a register fixture."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

import pytest

spec = importlib.util.spec_from_file_location("legacy_survey", Path(__file__).resolve().parents[1] / "scripts/legacy_survey.py")
survey = importlib.util.module_from_spec(spec)
spec.loader.exec_module(survey)

PREAMBLE = r'''
use JSON::PP;
our ($mux, $writes, $read_failed, @events) = (2, 0, 0);
our %page = (1 => 5, 2 => 5);
our %lm = (0xfe => 1, 0xff => 0x49, 0x4a => INITIAL_MODE, 0x4c => 64,
           0x4d => 8, 0x45 => 0x13, 0x03 => 6);
sub tp { return; }
sub Chip::fmI2cWriteRead {
    my ($self, $sw, $addr, $bytes, $nw, $nr) = @_;
    my $reg = $bytes->[0];
    if ($addr == 0x58) {
        if ($nr) { @$bytes = ($mux | 0x30); }
        else { $mux = $bytes->[0]; }
        return 0;
    }
    if ($nr) {
        if ($addr == 0x4c) {
            die "incorrect LM96163 mux" if $mux != 8;
            return 1 if FAIL_READ && $writes == 2 && $reg == 0x4c && !$read_failed++;
            @$bytes = map { $reg + $_ == 0x4c && !($lm{0x4a} & 0x20) ? 128 : ($lm{$reg + $_} // 0) } (0 .. $nr - 1);
        } elsif ($addr == 0x59) {
            @$bytes = (255) x $nr;
        } elsif ($addr == 0x50) {
            die "incorrect OBT mux" unless $mux == 1 || $mux == 2;
            @$bytes = $reg == 0x7f ? ($page{$mux}) : (0) x $nr;
        } else { die "unexpected address"; }
        return 0;
    }
    if ($addr == 0x4c) {
        die "unexpected fan register write" if $reg != 0x4a && $reg != 0x4c;
        $lm{$reg} = $bytes->[1];
        push @events, [$reg, $bytes->[1]];
        ++$writes;
        return 1 if FAIL_WRITE == $writes;
    } elsif ($addr == 0x50 && $reg == 0x7f) {
        $page{$mux} = $bytes->[1];
    } else { die "unexpected hardware write"; }
    return 0;
}
my $self = {FT => {CHIP => bless({}, 'Chip')}};
eval {
'''


@pytest.mark.parametrize("mode,seconds,failure,read_failure", [
    (0x10, 0, 0, 0), (0x10, 1, 0, 0), (0x30, 1, 0, 0),
    (0x10, 1, 1, 0), (0x10, 1, 2, 0), (0x10, 1, 0, 1), (0x10, 1, 3, 0),
])
def test_survey_restores_selectors_and_fan_or_retains_full_speed(tmp_path, mode, seconds, failure, read_failure):
    perl = shutil.which("perl")
    if not perl:
        pytest.skip("Perl is required for the legacy TestPoint diagnostic fixture")
    preamble = PREAMBLE.replace("INITIAL_MODE", str(mode)).replace("FAIL_WRITE", str(failure)).replace("FAIL_READ", str(read_failure))
    script = survey.survey_script("FM10K_SURVEY_" + "a" * 32, seconds)
    # Suppress only the time delay; every generated read/write/recovery branch
    # runs in the actual Perl interpreter, with failures after register mutation.
    script = script.replace("select(undef, undef, undef, 1.0);", "")
    script = script.replace("select(undef, undef, undef, 0.035) if $offset == 0x7f;", "")
    program = tmp_path / "survey-fixture.pl"
    program.write_text(preamble + script + r'''
};
print "FIXTURE_RESULT ", encode_json({error => "$@", mux => $mux, pages => \%page,
    mode => $lm{0x4a}, pwm => $lm{0x4c}, writes => \@events}), "\n";
''')
    result = subprocess.run([perl, str(program)], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr + result.stdout
    state = json.loads(result.stdout.split("FIXTURE_RESULT ", 1)[1])
    assert state["mux"] == 2 and state["pages"] == {"1": 5, "2": 5}
    assert bool(state["error"]) == bool(failure or read_failure)
    if failure == 3:  # failed LUT restore is compensated to full, never to off
        assert state["mode"] == 0x30 and state["pwm"] == 255
    else:
        assert state["mode"] == mode
        if mode == 0x30:
            assert state["pwm"] == 64
    if not seconds:
        assert state["writes"] == []
    else:
        assert all(register in (0x4a, 0x4c) for register, _ in state["writes"])
        assert all(value > 0 for register, value in state["writes"] if register == 0x4c)


def test_survey_rejects_unbounded_or_injected_parameters():
    with pytest.raises(ValueError):
        survey.survey_script('FM10K_SURVEY_"; exit; #')
    for value in (-1, 6, "3", True):
        with pytest.raises(ValueError):
            survey.fan_diagnostic_script(value)
