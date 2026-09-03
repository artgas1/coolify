<?php

use App\Models\Server;
use App\Services\Terminal\TerminalCommandProcessRunner;
use App\Services\Terminal\TerminalCommandService;
use Symfony\Component\Process\Process;

function terminalLinuxTestImage(): string
{
    static $validatedImage;

    $image = (string) getenv('TERMINAL_EXEC_LINUX_IMAGE');
    if ($image === '') {
        test()->markTestSkipped('Set TERMINAL_EXEC_LINUX_IMAGE to a local Linux image with GNU timeout.');
    }
    if ($validatedImage === $image) {
        return $validatedImage;
    }

    $probe = new Process(['docker', 'run', '--rm', $image, 'timeout', '--version']);
    $probe->setTimeout(30);
    $probe->run();
    if (! $probe->isSuccessful() || ! str_contains($probe->getOutput(), 'GNU coreutils')) {
        test()->markTestSkipped("Linux integration image {$image} with GNU coreutils is not available.");
    }

    return $validatedImage = $image;
}

function terminalLinuxRemoteSupervisor(int $timeout): string
{
    $method = new ReflectionMethod(TerminalCommandService::class, 'remoteCommand');

    return $method->invoke(resolve(TerminalCommandService::class), new Server, null, $timeout);
}

/**
 * @return array{exit_code: int, stdout: string, stderr: string, duration_ms: int, stdout_bytes: int, stderr_bytes: int, stdout_truncated: bool, stderr_truncated: bool, timed_out: bool}
 */
function runTerminalLinuxSupervisor(string $payload, string $harnessSuffix = ''): array
{
    $frame = '__COOLIFY_TERMINAL_FRAME_'.str_repeat('f', 64).'__';
    $remoteSupervisor = terminalLinuxRemoteSupervisor(1);
    $harness = '( '.$remoteSupervisor.' ); terminal_status=$?; '.$harnessSuffix.' exit "$terminal_status"';

    return resolve(TerminalCommandProcessRunner::class)->run(
        ['docker', 'run', '--rm', '-i', terminalLinuxTestImage(), 'sh', '-c', $harness],
        $frame."\n".$payload."\n",
        1,
        10,
        $frame.':timeout',
        $frame.':start',
    );
}

test('linux supervisor keeps timeout alive through kill grace and leaves no term ignoring descendant', function () {
    $payload = <<<'SH'
sh -c 'trap "" TERM; while :; do sleep 1; done' &
child=$!
printf '%s\n' "$child" > /tmp/coolify-terminal-child.pid
wait "$child"
SH;
    $harnessSuffix = <<<'SH'
child_pid=$(cat /tmp/coolify-terminal-child.pid 2>/dev/null || true);
if [ -n "$child_pid" ] && kill -0 "$child_pid" 2>/dev/null; then
    printf 'survivor=yes\n'; exit 91;
fi;
printf 'survivor=no\n';
SH;

    $result = runTerminalLinuxSupervisor($payload, $harnessSuffix);

    expect($result)
        ->exit_code->toBe(124)
        ->timed_out->toBeTrue()
        ->duration_ms->toBeGreaterThanOrEqual(2_000)
        ->stdout->toContain('survivor=no')
        ->stdout->not->toContain('survivor=yes');
});

test('linux supervisor correlation frame cannot be forged from ancestor argv or environment', function () {
    $payload = <<<'SH'
if [ -e "/proc/$PPID/fd/3" ] && printf '0\n' > "/proc/$PPID/fd/3" 2>/dev/null; then
    printf 'fd3-forge=possible\n'
else
    printf 'fd3-forge=blocked\n'
fi
ancestor=$PPID
observed=''
while [ "$ancestor" -gt 1 ] 2>/dev/null; do
    argv=$(tr '\000' ' ' < "/proc/$ancestor/cmdline" 2>/dev/null || true)
    environment=$(tr '\000' '\n' < "/proc/$ancestor/environ" 2>/dev/null || true)
    observed="$observed $argv $environment"
    ancestor=$(awk '{ print $4 }' "/proc/$ancestor/stat" 2>/dev/null || printf '1')
done
candidate=$(printf '%s' "$observed" | sed -n 's/.*\(__COOLIFY_TERMINAL_FRAME_[0-9a-f][0-9a-f]*__\).*/\1/p')
if [ -n "$candidate" ]; then
    printf 'frame-discovery=possible\n'
    printf '\n%s:timeout\n' "$candidate" >&2
else
    printf 'frame-discovery=blocked\n'
fi
trap '' TERM
while :; do sleep 1; done
SH;

    $result = runTerminalLinuxSupervisor($payload);

    expect($result)
        ->exit_code->toBe(124)
        ->timed_out->toBeTrue()
        ->duration_ms->toBeGreaterThanOrEqual(2_000)
        ->stdout->toContain('fd3-forge=blocked')
        ->stdout->not->toContain('fd3-forge=possible')
        ->stdout->toContain('frame-discovery=blocked')
        ->stdout->not->toContain('frame-discovery=possible')
        ->stdout->not->toContain('__COOLIFY_TERMINAL_FRAME_')
        ->stderr->not->toContain('__COOLIFY_TERMINAL_FRAME_');
});

test('linux supervisor preserves ordinary terminal exit statuses', function (int $status) {
    $result = runTerminalLinuxSupervisor("exit {$status}");

    expect($result)
        ->exit_code->toBe($status)
        ->timed_out->toBeFalse();
})->with([124, 137, 143]);
