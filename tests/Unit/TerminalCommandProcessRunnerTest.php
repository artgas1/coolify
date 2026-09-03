<?php

use App\Services\Terminal\TerminalCommandProcessRunner;
use Tests\TestCase;

uses(TestCase::class);

test('terminal process runner sends the script over stdin and reports output', function () {
    $result = resolve(TerminalCommandProcessRunner::class)->run(
        ['sh', '-s'],
        "printf 'hello'; printf 'warning' >&2\n",
        2,
    );

    expect($result)
        ->exit_code->toBe(0)
        ->stdout->toBe('hello')
        ->stderr->toBe('warning')
        ->stdout_bytes->toBe(5)
        ->stderr_bytes->toBe(7)
        ->stdout_truncated->toBeFalse()
        ->stderr_truncated->toBeFalse()
        ->timed_out->toBeFalse();
});

test('terminal process runner bounds each output stream while continuing to completion', function () {
    $result = resolve(TerminalCommandProcessRunner::class)->run(
        ['sh', '-s'],
        "head -c 70000 /dev/zero | tr '\\0' a; head -c 70000 /dev/zero | tr '\\0' b >&2\n",
        3,
    );

    expect($result)
        ->exit_code->toBe(0)
        ->stdout_bytes->toBe(70_000)
        ->stderr_bytes->toBe(70_000)
        ->stdout_truncated->toBeTrue()
        ->stderr_truncated->toBeTrue()
        ->and(strlen($result['stdout']))->toBe(TerminalCommandProcessRunner::OUTPUT_LIMIT_BYTES)
        ->and(strlen($result['stderr']))->toBe(TerminalCommandProcessRunner::OUTPUT_LIMIT_BYTES)
        ->and($result['stdout'])->toEndWith('[... Output truncated at 65536 bytes ...]')
        ->and($result['stderr'])->toEndWith('[... Output truncated at 65536 bytes ...]');
});

test('terminal process runner sanitizes invalid utf8', function () {
    $result = resolve(TerminalCommandProcessRunner::class)->run(
        ['sh', '-s'],
        "printf '\\377'\n",
        2,
    );

    expect(mb_check_encoding($result['stdout'], 'UTF-8'))->toBeTrue();
});

test('terminal process runner truncates multibyte output on a valid utf8 boundary', function () {
    $result = resolve(TerminalCommandProcessRunner::class)->run(
        [PHP_BINARY, '-r', 'echo str_repeat("Ж", 40000);'],
        '',
        2,
    );

    expect($result)
        ->exit_code->toBe(0)
        ->stdout_bytes->toBe(80_000)
        ->stdout_truncated->toBeTrue()
        ->and(strlen($result['stdout']))->toBe(TerminalCommandProcessRunner::OUTPUT_LIMIT_BYTES)
        ->and(mb_check_encoding($result['stdout'], 'UTF-8'))->toBeTrue()
        ->and($result['stdout'])->toEndWith('[... Output truncated at 65536 bytes ...]');
});

test('terminal process runner watchdog includes connection remote kill and emergency budgets', function () {
    expect(TerminalCommandProcessRunner::localProcessTimeoutSeconds(1, 0))->toBe(4)
        ->and(TerminalCommandProcessRunner::maximumSupervisionSeconds(1, 0))->toBe(4)
        ->and(TerminalCommandProcessRunner::localProcessTimeoutSeconds(4, 10))->toBe(17);

    $result = resolve(TerminalCommandProcessRunner::class)->run(
        ['sh', '-s'],
        "sleep 5\n",
        1,
    );

    expect($result)
        ->exit_code->toBe(124)
        ->timed_out->toBeTrue()
        ->stderr->toContain('timed out after 1 seconds')
        ->duration_ms->toBeGreaterThanOrEqual(4_000)
        ->duration_ms->toBeLessThan(5_000);
});

test('missing remote timeout fails before the stdin shell script starts', function () {
    $frame = '__COOLIFY_TERMINAL_FRAME_'.str_repeat('a', 64).'__';
    $marker = $frame.':timeout';
    $startMarker = $frame.':start';
    $wrapper = 'IFS= read -r frame || exit 125; printf "\\n%s:start\\n" "$frame" >&2; '
        .'script=$(cat; printf x); script=${script%x}; PATH=/definitely-missing; '
        .'printf "%s" "$script" | timeout --preserve-status -k 1s 1s sh -s';
    $result = resolve(TerminalCommandProcessRunner::class)->run(
        ['/bin/sh', '-c', $wrapper],
        $frame."\nprintf 'payload-must-not-run'\n",
        1,
        0,
        $marker,
        $startMarker,
    );

    expect($result)
        ->exit_code->toBe(127)
        ->timed_out->toBeFalse()
        ->stdout->not->toContain('payload-must-not-run');
});

test('terminal process runner sends only the frame until it observes the remote start marker', function () {
    $frame = '__COOLIFY_TERMINAL_FRAME_'.str_repeat('b', 64).'__';
    $startMarker = $frame.':start';
    $script = '$frame = fgets(STDIN); stream_set_blocking(STDIN, false); '
        .'$premature = stream_get_contents(STDIN); '
        .'fwrite(STDERR, '.var_export("\n{$startMarker}\n", true).'); fflush(STDERR); '
        .'stream_set_blocking(STDIN, true); $payload = stream_get_contents(STDIN); '
        .'fwrite(STDOUT, ($premature === "" ? "staged:" : "premature:").$payload);';
    $result = resolve(TerminalCommandProcessRunner::class)->run(
        [PHP_BINARY, '-r', $script],
        $frame."\npayload-after-start\n",
        1,
        1,
        $frame.':timeout',
        $startMarker,
    );

    expect($result)
        ->exit_code->toBe(0)
        ->timed_out->toBeFalse()
        ->stdout->toBe("staged:payload-after-start\n")
        ->stderr->not->toContain($startMarker);
});

test('ordinary terminal exit statuses are not identified as timeouts before the deadline', function (int $status) {
    $frame = '__COOLIFY_TERMINAL_FRAME_'.str_repeat('c', 64).'__';
    $marker = $frame.':timeout';
    $startMarker = $frame.':start';
    $framedMarkers = "\n{$startMarker}\n".(in_array($status, [137, 143], true) ? "\n{$marker}\n" : '');
    $script = 'fgets(STDIN); fwrite(STDERR, '.var_export($framedMarkers, true).'); fflush(STDERR); '
        .'stream_get_contents(STDIN); exit('.$status.');';
    $result = resolve(TerminalCommandProcessRunner::class)->run(
        [PHP_BINARY, '-r', $script],
        $frame."\nexit {$status}\n",
        1,
        1,
        $marker,
        $startMarker,
    );

    expect($result)
        ->exit_code->toBe($status)
        ->timed_out->toBeFalse()
        ->stderr->not->toContain($marker, $startMarker);
})->with([124, 137, 143]);

test('remote timeout marker after the supervised deadline normalizes term and kill statuses', function (int $status) {
    $frame = '__COOLIFY_TERMINAL_FRAME_'.str_repeat('d', 64).'__';
    $marker = $frame.':timeout';
    $startMarker = $frame.':start';
    $script = 'fgets(STDIN); fwrite(STDERR, '.var_export("\n{$startMarker}\n", true).'); fflush(STDERR); '
        .'stream_get_contents(STDIN); usleep(1100000); '
        .'fwrite(STDERR, '.var_export("\n{$marker}\n", true).'); exit('.$status.');';
    $result = resolve(TerminalCommandProcessRunner::class)->run(
        [PHP_BINARY, '-r', $script],
        $frame."\nsleep beyond deadline\n",
        1,
        1,
        $marker,
        $startMarker,
    );

    expect($result)
        ->exit_code->toBe(124)
        ->timed_out->toBeTrue()
        ->stderr->not->toContain($marker, $startMarker);
})->with([137, 143]);

test('remote start and timeout markers are detected across stream chunks beyond the stderr cap', function () {
    $frame = '__COOLIFY_TERMINAL_FRAME_'.str_repeat('e', 64).'__';
    $marker = $frame.':timeout';
    $startMarker = $frame.':start';
    $framedMarker = "\n{$marker}\n";
    $firstHalf = substr($framedMarker, 0, 40);
    $secondHalf = substr($framedMarker, 40);
    $script = 'fgets(STDIN); fwrite(STDERR, '.var_export("\n{$startMarker}\n", true).'); fflush(STDERR); '
        .'stream_get_contents(STDIN); fwrite(STDERR, str_repeat("x", 70000)); usleep(1050000); '
        .'fwrite(STDERR, '.var_export($firstHalf, true).'); usleep(50000); '
        .'fwrite(STDERR, '.var_export($secondHalf, true).'); exit(143);';
    $result = resolve(TerminalCommandProcessRunner::class)->run(
        [PHP_BINARY, '-r', $script],
        $frame."\nlarge timeout output\n",
        1,
        1,
        $marker,
        $startMarker,
    );

    expect($result)
        ->exit_code->toBe(124)
        ->timed_out->toBeTrue()
        ->stderr_bytes->toBe(70_000)
        ->stderr_truncated->toBeTrue()
        ->and(strlen($result['stderr']))->toBe(TerminalCommandProcessRunner::OUTPUT_LIMIT_BYTES)
        ->and($result['stderr'])->not->toContain($marker, $startMarker);
});

test('an early timeout marker cannot become a timeout because process teardown crosses the deadline', function () {
    $frame = '__COOLIFY_TERMINAL_FRAME_'.str_repeat('f', 64).'__';
    $marker = $frame.':timeout';
    $startMarker = $frame.':start';
    $script = 'fgets(STDIN); fwrite(STDERR, '.var_export("\n{$startMarker}\n", true).'); fflush(STDERR); '
        .'stream_get_contents(STDIN); fwrite(STDERR, '.var_export("\n{$marker}\n", true).'); fflush(STDERR); '
        .'usleep(1100000); exit(137);';
    $result = resolve(TerminalCommandProcessRunner::class)->run(
        [PHP_BINARY, '-r', $script],
        $frame."\nearly marker then slow teardown\n",
        1,
        1,
        $marker,
        $startMarker,
    );

    expect($result)
        ->exit_code->toBe(137)
        ->timed_out->toBeFalse()
        ->duration_ms->toBeGreaterThanOrEqual(1_000)
        ->stderr->not->toContain($marker, $startMarker);
});

test('a later qualifying timeout marker wins over an earlier forged marker', function () {
    $frame = '__COOLIFY_TERMINAL_FRAME_'.str_repeat('1', 64).'__';
    $marker = $frame.':timeout';
    $startMarker = $frame.':start';
    $script = 'fgets(STDIN); fwrite(STDERR, '.var_export("\n{$startMarker}\n", true).'); fflush(STDERR); '
        .'stream_get_contents(STDIN); fwrite(STDERR, '.var_export("\n{$marker}\n", true).'); fflush(STDERR); '
        .'usleep(1100000); fwrite(STDERR, '.var_export("\n{$marker}\n", true).'); fflush(STDERR); exit(137);';
    $result = resolve(TerminalCommandProcessRunner::class)->run(
        [PHP_BINARY, '-r', $script],
        $frame."\nearly and late markers\n",
        1,
        1,
        $marker,
        $startMarker,
    );

    expect($result)
        ->exit_code->toBe(124)
        ->timed_out->toBeTrue()
        ->stderr->not->toContain($marker, $startMarker);
});

test('coalesced start and timeout markers cannot claim a deadline that did not elapse', function () {
    $frame = '__COOLIFY_TERMINAL_FRAME_'.str_repeat('2', 64).'__';
    $marker = $frame.':timeout';
    $startMarker = $frame.':start';
    $script = 'fgets(STDIN); fwrite(STDERR, '.var_export("\n{$startMarker}\n\n{$marker}\n", true).'); '
        .'fflush(STDERR); stream_get_contents(STDIN); exit(143);';
    $result = resolve(TerminalCommandProcessRunner::class)->run(
        [PHP_BINARY, '-r', $script],
        $frame."\ncoalesced markers\n",
        1,
        1,
        $marker,
        $startMarker,
    );

    expect($result)
        ->exit_code->toBe(143)
        ->timed_out->toBeFalse()
        ->stderr->not->toContain($marker, $startMarker);
});
