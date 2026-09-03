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
        ->stderr_truncated->toBeFalse();
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

test('terminal process runner converts timeouts to exit code 124', function () {
    $result = resolve(TerminalCommandProcessRunner::class)->run(
        ['sh', '-s'],
        "sleep 2\n",
        1,
    );

    expect($result)
        ->exit_code->toBe(124)
        ->stderr->toContain('timed out after 1 seconds');
});
