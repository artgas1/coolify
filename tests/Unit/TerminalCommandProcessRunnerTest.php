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
    $marker = '__COOLIFY_TERMINAL_TIMEOUT_'.str_repeat('a', 64).'__';
    $completionMarker = '__COOLIFY_TERMINAL_COMPLETE_'.str_repeat('a', 64).'__';
    $controlledShell = 'sh -s; status=$?; printf "\\n%s\\n" "'.$completionMarker.'" >&2; exit "$status"';
    $wrapper = 'PATH=/definitely-missing; timeout --preserve-status -k 1s 1s sh -c '
        .escapeshellarg($controlledShell).'; status=$?; '
        .'case "$status" in 137|143) printf "\\n%s\\n" "'.$marker.'" >&2;; esac; exit "$status"';
    $result = resolve(TerminalCommandProcessRunner::class)->run(
        ['/bin/sh', '-c', $wrapper],
        "printf 'payload-must-not-run'\n",
        1,
        0,
        $marker,
        $completionMarker,
    );

    expect($result)
        ->exit_code->toBe(127)
        ->timed_out->toBeFalse()
        ->stdout->not->toContain('payload-must-not-run');
});

test('ordinary terminal exit statuses are not identified as timeouts when completion is observed', function (int $status) {
    $marker = '__COOLIFY_TERMINAL_TIMEOUT_'.str_repeat('b', 64).'__';
    $completionMarker = '__COOLIFY_TERMINAL_COMPLETE_'.str_repeat('b', 64).'__';
    $framedCompletionMarker = "\n{$completionMarker}\n";
    $framedTimeoutMarker = in_array($status, [137, 143], true) ? "\n{$marker}\n" : '';
    $script = 'fwrite(STDERR, '.var_export($framedCompletionMarker.$framedTimeoutMarker, true).'); exit('.$status.');';
    $result = resolve(TerminalCommandProcessRunner::class)->run(
        [PHP_BINARY, '-r', $script],
        '',
        1,
        1,
        $marker,
        $completionMarker,
    );

    expect($result)
        ->exit_code->toBe($status)
        ->timed_out->toBeFalse()
        ->stderr->not->toContain($marker, $completionMarker);
})->with([124, 137, 143]);

test('remote supervisor marker identifies term and kill statuses and is stripped', function (int $status) {
    $marker = '__COOLIFY_TERMINAL_TIMEOUT_'.str_repeat('c', 64).'__';
    $completionMarker = '__COOLIFY_TERMINAL_COMPLETE_'.str_repeat('c', 64).'__';
    $framedMarker = "\n{$marker}\n";
    $script = 'fwrite(STDERR, '.var_export($framedMarker, true).'); exit('.$status.');';
    $result = resolve(TerminalCommandProcessRunner::class)->run(
        [PHP_BINARY, '-r', $script],
        '',
        1,
        1,
        $marker,
        $completionMarker,
    );

    expect($result)
        ->exit_code->toBe(124)
        ->timed_out->toBeTrue()
        ->stderr->not->toContain($marker);
})->with([137, 143]);

test('remote timeout marker is detected across stream chunks beyond the stderr cap', function () {
    $marker = '__COOLIFY_TERMINAL_TIMEOUT_'.str_repeat('d', 64).'__';
    $completionMarker = '__COOLIFY_TERMINAL_COMPLETE_'.str_repeat('d', 64).'__';
    $framedMarker = "\n{$marker}\n";
    $firstHalf = substr($framedMarker, 0, 40);
    $secondHalf = substr($framedMarker, 40);
    $script = 'fwrite(STDERR, str_repeat("x", 70000)); '
        .'fwrite(STDERR, '.var_export($firstHalf, true).'); usleep(50000); '
        .'fwrite(STDERR, '.var_export($secondHalf, true).'); exit(143);';
    $result = resolve(TerminalCommandProcessRunner::class)->run(
        [PHP_BINARY, '-r', $script],
        '',
        1,
        1,
        $marker,
        $completionMarker,
    );

    expect($result)
        ->exit_code->toBe(124)
        ->timed_out->toBeTrue()
        ->stderr_bytes->toBe(70_000)
        ->stderr_truncated->toBeTrue()
        ->and(strlen($result['stderr']))->toBe(TerminalCommandProcessRunner::OUTPUT_LIMIT_BYTES)
        ->and($result['stderr'])->not->toContain($marker);
});

test('split completion marker beyond the stderr cap prevents an ordinary 143 exit from becoming a timeout', function () {
    $marker = '__COOLIFY_TERMINAL_TIMEOUT_'.str_repeat('e', 64).'__';
    $completionMarker = '__COOLIFY_TERMINAL_COMPLETE_'.str_repeat('e', 64).'__';
    $framedCompletionMarker = "\n{$completionMarker}\n";
    $firstHalf = substr($framedCompletionMarker, 0, 40);
    $secondHalf = substr($framedCompletionMarker, 40);
    $framedTimeoutMarker = "\n{$marker}\n";
    $script = 'fwrite(STDERR, str_repeat("x", 70000)); '
        .'fwrite(STDERR, '.var_export($firstHalf, true).'); usleep(50000); '
        .'fwrite(STDERR, '.var_export($secondHalf.$framedTimeoutMarker, true).'); exit(143);';
    $result = resolve(TerminalCommandProcessRunner::class)->run(
        [PHP_BINARY, '-r', $script],
        '',
        1,
        1,
        $marker,
        $completionMarker,
    );

    expect($result)
        ->exit_code->toBe(143)
        ->timed_out->toBeFalse()
        ->stderr_bytes->toBe(70_000)
        ->stderr_truncated->toBeTrue()
        ->and($result['stderr'])->not->toContain($marker, $completionMarker);
});
