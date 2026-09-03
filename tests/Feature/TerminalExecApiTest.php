<?php

use App\Models\Application;
use App\Models\AuditEvent;
use App\Models\Environment;
use App\Models\InstanceSettings;
use App\Models\PrivateKey;
use App\Models\Project;
use App\Models\Server;
use App\Models\StandaloneDocker;
use App\Models\Team;
use App\Models\User;
use App\Services\Terminal\TerminalCommandProcessRunner;
use App\Services\Terminal\TerminalCommandService;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

uses(RefreshDatabase::class);

class CapturingTerminalCommandProcessRunner extends TerminalCommandProcessRunner
{
    /** @var array<int, array{argv: array<int, string>, stdin: string, timeout: int, connectionTimeout: int, timeoutMarker: string, startMarker: string}> */
    public array $calls = [];

    /** @var array{exit_code: int, stdout: string, stderr: string, duration_ms: int, stdout_bytes: int, stderr_bytes: int, stdout_truncated: bool, stderr_truncated: bool, timed_out: bool} */
    public array $result = [
        'exit_code' => 0,
        'stdout' => "ok\n",
        'stderr' => '',
        'duration_ms' => 12,
        'stdout_bytes' => 3,
        'stderr_bytes' => 0,
        'stdout_truncated' => false,
        'stderr_truncated' => false,
        'timed_out' => false,
    ];

    public ?string $exceptionMessage = null;

    public function run(
        array $argv,
        string $stdin,
        int $timeout,
        int $connectionTimeout = 0,
        string $timeoutMarker = '',
        string $startMarker = '',
    ): array {
        $this->calls[] = compact('argv', 'stdin', 'timeout', 'connectionTimeout', 'timeoutMarker', 'startMarker');
        if (! is_null($this->exceptionMessage)) {
            throw new RuntimeException($this->exceptionMessage);
        }

        return $this->result;
    }
}

beforeEach(function () {
    config([
        'api.rate_limit' => 1000,
        'app.key' => '12345678901234567890123456789012',
    ]);
    RateLimiter::for('api', fn (Request $request) => Limit::perMinute(1000)->by($request->user()?->id ?: $request->ip()));
    Cache::flush();

    InstanceSettings::forceCreate(['id' => 0, 'is_api_enabled' => true]);
    $this->team = Team::factory()->create(['is_terminal_api_enabled' => true]);
    $this->user = User::factory()->create();
    $this->team->members()->attach($this->user->id, ['role' => 'owner']);
    [$this->bearerToken, $this->accessToken] = createAuditedExecToken($this->user, $this->team);

    $this->privateKey = PrivateKey::create([
        'name' => 'Terminal API test key',
        'private_key' => <<<'KEY'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBbhpqHhqv6aI67Mj9abM3DVbmcfYhZAhC7ca4d9UCevAAAAJi/QySHv0Mk
hwAAAAtzc2gtZWQyNTUxOQAAACBbhpqHhqv6aI67Mj9abM3DVbmcfYhZAhC7ca4d9UCevA
AAAECBQw4jg1WRT2IGHMncCiZhURCts2s24HoDS0thHnnRKVuGmoeGq/pojrsyP1pszcNV
uZx9iFkCELtxrh31QJ68AAAAEXNhaWxANzZmZjY2ZDJlMmRkAQIDBA==
-----END OPENSSH PRIVATE KEY-----
KEY,
        'team_id' => $this->team->id,
    ]);
    $this->server = Server::factory()->create([
        'team_id' => $this->team->id,
        'private_key_id' => $this->privateKey->id,
        'ip' => 'coolify-testing-host',
        'user' => 'root',
    ]);
    $this->server->settings()->update([
        'is_terminal_enabled' => true,
        'force_disabled' => false,
    ]);

    $destination = StandaloneDocker::where('server_id', $this->server->id)->first()
        ?? StandaloneDocker::factory()->create(['server_id' => $this->server->id, 'network' => 'terminal-api-test']);
    $project = Project::factory()->create(['team_id' => $this->team->id]);
    $environment = Environment::factory()->create(['project_id' => $project->id]);
    $this->application = Application::factory()->create([
        'environment_id' => $environment->id,
        'destination_id' => $destination->id,
        'destination_type' => $destination->getMorphClass(),
    ]);

    $this->runner = new CapturingTerminalCommandProcessRunner;
    app()->instance(TerminalCommandProcessRunner::class, $this->runner);
});

function createAuditedExecToken(
    User $user,
    Team $team,
    array $abilities = ['terminal'],
    ?DateTimeInterface $expiresAt = null,
): array {
    $plainTextToken = Str::random(40);
    $token = $user->tokens()->create([
        'name' => 'audited-terminal-token',
        'token' => hash('sha256', $plainTextToken),
        'abilities' => $abilities,
        'team_id' => $team->id,
        'expires_at' => $expiresAt ?? now()->addDays(30),
    ]);

    return [$token->getKey().'|'.$plainTextToken, $token];
}

function insertInvalidAuditedExecToken(
    User $user,
    Team $team,
    ?DateTimeInterface $expiresAt,
    ?DateTimeInterface $createdAt = null,
): string {
    $plainTextToken = Str::random(40);
    $createdAt ??= now();
    $id = DB::table('personal_access_tokens')->insertGetId([
        'tokenable_type' => User::class,
        'tokenable_id' => $user->id,
        'name' => 'invalid-terminal-token',
        'token' => hash('sha256', $plainTextToken),
        'abilities' => json_encode(['terminal'], JSON_THROW_ON_ERROR),
        'team_id' => $team->id,
        'expires_at' => $expiresAt,
        'created_at' => $createdAt,
        'updated_at' => $createdAt,
    ]);

    return $id.'|'.$plainTextToken;
}

function auditedExecHeaders(string $bearerToken): array
{
    return [
        'Authorization' => 'Bearer '.$bearerToken,
        'Content-Type' => 'application/json',
    ];
}

function auditedApplicationContainer(string $name = 'app-container', string $state = 'running', ?int $pullRequestId = null): string
{
    $labels = ['coolify.applicationId='.test()->application->id];
    if (! is_null($pullRequestId)) {
        $labels[] = "coolify.pullRequestId={$pullRequestId}";
    }

    return json_encode([
        'Names' => $name,
        'State' => $state,
        'Labels' => implode(',', $labels),
    ], JSON_THROW_ON_ERROR)."\n";
}

test('server exec uses static ssh argv stdin and persists a redacted correlated audit event', function () {
    $command = 'TOKEN=super-secret printf done';
    $this->server->settings()->update(['connection_timeout' => 45]);
    $this->runner->result['stdout'] = "super-secret output\n";
    $this->runner->result['stdout_bytes'] = 20;

    $response = $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/servers/{$this->server->uuid}/exec", [
            'command' => $command,
            'timeout' => 4,
        ]);

    $response->assertOk()->assertJson([
        'exit_code' => 0,
        'stdout' => "super-secret output\n",
        'stderr' => '',
        'duration_ms' => 12,
        'stdout_truncated' => false,
        'stderr_truncated' => false,
        'timed_out' => false,
    ])->assertJsonStructure(['audit_event_id']);

    expect($this->runner->calls)->toHaveCount(1);
    $call = $this->runner->calls[0];
    [$timeoutFrame, $script] = explode("\n", $call['stdin'], 2);
    expect($call['argv'])->toContain('ConnectTimeout=10')
        ->and($call['argv'][array_key_last($call['argv'])])->toContain('timeout --preserve-status -k 1s 4s sh -c')
        ->and($call['argv'][array_key_last($call['argv'])])->toContain('terminal_timed_out=0', 'terminal_script=$(cat; printf x)', '3>&- 4>&- 5>&- 6>&-', 'while :; do sleep 1; done')
        ->and(implode(' ', $call['argv']))->not->toContain($command)
        ->and($timeoutFrame)->toMatch('/^__COOLIFY_TERMINAL_FRAME_[0-9a-f]{64}__$/')
        ->and($script)->toBe($command."\n")
        ->and($call['timeout'])->toBe(4)
        ->and($call['connectionTimeout'])->toBe(10)
        ->and($call['timeoutMarker'])->toBe($timeoutFrame.':timeout')
        ->and($call['startMarker'])->toBe($timeoutFrame.':start')
        ->and(implode(' ', $call['argv']))->not->toContain($timeoutFrame)
        ->and(TerminalCommandProcessRunner::localProcessTimeoutSeconds(4, 10))->toBe(17);

    $leaseMethod = new ReflectionMethod(TerminalCommandService::class, 'concurrencyLeaseSeconds');
    expect($leaseMethod->invoke(resolve(TerminalCommandService::class), 4, 10))->toBe(18);

    $audit = AuditEvent::query()->findOrFail($response->json('audit_event_id'));
    $metadata = $audit->metadata;
    expect($audit)
        ->team_id->toBe($this->team->id)
        ->event->toBe('api.server.command.executed')
        ->source->toBe('api')
        ->action->toBe('executed')
        ->actor_id->toBe($this->user->id)
        ->actor_token_id->toBe($this->accessToken->id)
        ->resource_type->toBe('server')
        ->resource_uuid->toBe($this->server->uuid)
        ->and($metadata['outcome'])->toBe('success')
        ->and($metadata['command_redacted'])->toBe('TOKEN=[REDACTED] printf done')
        ->and($metadata['command_hmac_sha256'])->toBe(hash_hmac('sha256', $command, config('app.key')))
        ->and($metadata['server_uuid'])->toBe($this->server->uuid)
        ->and($metadata['timed_out'])->toBeFalse()
        ->and(array_key_exists('stdout', $metadata))->toBeFalse()
        ->and(array_key_exists('stderr', $metadata))->toBeFalse()
        ->and(json_encode($audit->toArray(), JSON_THROW_ON_ERROR))->not->toContain('super-secret output')
        ->not->toContain($this->privateKey->private_key);
});

test('existing sensitive audit API returns correlated terminal metadata without command output', function () {
    [$token] = createAuditedExecToken($this->user, $this->team, ['terminal', 'read', 'read:sensitive']);
    $command = 'PASSWORD=audit-api-secret printf command-result';
    $this->runner->result['stdout'] = "runtime-only-output\n";
    $this->runner->result['stdout_bytes'] = 20;

    $this->withHeaders(auditedExecHeaders($token))
        ->postJson("/api/v1/servers/{$this->server->uuid}/exec", ['command' => $command])
        ->assertOk();

    $response = $this->withHeaders(auditedExecHeaders($token))
        ->getJson('/api/v1/audit-events?source=api&action=executed')
        ->assertOk()
        ->assertJsonCount(1, 'data')
        ->assertJsonPath('data.0.event', 'api.server.command.executed')
        ->assertJsonPath('data.0.metadata.command_redacted', 'PASSWORD=[REDACTED] printf command-result')
        ->assertJsonPath('data.0.metadata.outcome', 'success');

    $serialized = json_encode($response->json('data.0'), JSON_THROW_ON_ERROR);
    expect($serialized)
        ->not->toContain('audit-api-secret')
        ->not->toContain('runtime-only-output')
        ->not->toContain($this->privateKey->private_key);
});

test('root ability does not bypass the literal terminal ability', function () {
    [$rootToken] = createAuditedExecToken($this->user, $this->team, ['root']);

    $this->withHeaders(auditedExecHeaders($rootToken))
        ->postJson("/api/v1/servers/{$this->server->uuid}/exec", ['command' => 'whoami'])
        ->assertForbidden();

    expect($this->runner->calls)->toBeEmpty();
});

test('terminal endpoints require an authenticated unexpired token', function (string $case) {
    $token = $case === 'missing'
        ? null
        : insertInvalidAuditedExecToken($this->user, $this->team, now()->subSecond(), now()->subDay());

    $request = $this;
    if (! is_null($token)) {
        $request = $this->withHeaders(auditedExecHeaders($token));
    }

    $request->postJson("/api/v1/servers/{$this->server->uuid}/exec", ['command' => 'whoami'])
        ->assertUnauthorized();

    expect($this->runner->calls)->toBeEmpty();
})->with(['missing', 'expired']);

test('terminal endpoint rejects missing and overlong token expirations', function (?DateTimeInterface $expiresAt) {
    $createdAt = now();
    $token = insertInvalidAuditedExecToken($this->user, $this->team, $expiresAt, $createdAt);

    $this->withHeaders(auditedExecHeaders($token))
        ->postJson("/api/v1/servers/{$this->server->uuid}/exec", ['command' => 'whoami'])
        ->assertForbidden()
        ->assertJsonPath('message', 'Terminal API token lifetime is invalid.');

    expect($this->runner->calls)->toBeEmpty();
})->with([
    'no expiration' => null,
    'more than 90 days from creation' => fn () => now()->addDays(91),
]);

test('terminal token issuance rejects team members and lifetimes over 90 days', function () {
    $member = User::factory()->create();
    $this->team->members()->attach($member->id, ['role' => 'member']);

    expect(fn () => createAuditedExecToken($member, $this->team))
        ->toThrow(AuthorizationException::class)
        ->and(fn () => createAuditedExecToken($this->user, $this->team, expiresAt: now()->addDays(91)))
        ->toThrow(ValidationException::class);
});

test('terminal token security fields cannot be updated beyond the lifetime policy', function () {
    $this->accessToken->expires_at = $this->accessToken->created_at->addDays(91);

    expect(fn () => $this->accessToken->save())
        ->toThrow(ValidationException::class);

    expect($this->accessToken->fresh()->expires_at->lessThanOrEqualTo(
        $this->accessToken->created_at->addDays(90)
    ))->toBeTrue();
});

test('terminal endpoint denies member tokens created outside the issuance guard', function () {
    $member = User::factory()->create();
    $this->team->members()->attach($member->id, ['role' => 'member']);
    $token = insertInvalidAuditedExecToken($member, $this->team, now()->addDays(30));

    $this->withHeaders(auditedExecHeaders($token))
        ->postJson("/api/v1/servers/{$this->server->uuid}/exec", ['command' => 'whoami'])
        ->assertForbidden();

    expect($this->runner->calls)->toBeEmpty();
});

test('server exec enforces team opt in server gates team isolation and strict request fields', function (string $case) {
    if ($case === 'team-disabled') {
        $this->team->update(['is_terminal_api_enabled' => false]);
        $path = "/api/v1/servers/{$this->server->uuid}/exec";
        $payload = ['command' => 'whoami'];
        $expectedStatus = 403;
    } elseif ($case === 'terminal-disabled') {
        $this->server->settings()->update(['is_terminal_enabled' => false]);
        $path = "/api/v1/servers/{$this->server->uuid}/exec";
        $payload = ['command' => 'whoami'];
        $expectedStatus = 403;
    } elseif ($case === 'force-disabled') {
        $this->server->settings()->update(['force_disabled' => true]);
        $path = "/api/v1/servers/{$this->server->uuid}/exec";
        $payload = ['command' => 'whoami'];
        $expectedStatus = 403;
    } elseif ($case === 'foreign-server') {
        $foreignTeam = Team::factory()->create();
        $foreignServer = Server::factory()->create([
            'team_id' => $foreignTeam->id,
            'private_key_id' => $this->privateKey->id,
        ]);
        $path = "/api/v1/servers/{$foreignServer->uuid}/exec";
        $payload = ['command' => 'whoami'];
        $expectedStatus = 404;
    } else {
        $path = "/api/v1/servers/{$this->server->uuid}/exec";
        $payload = ['command' => 'whoami', 'use_sudo' => true];
        $expectedStatus = 422;
    }

    $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson($path, $payload)
        ->assertStatus($expectedStatus);

    expect($this->runner->calls)->toBeEmpty();
})->with(['team-disabled', 'terminal-disabled', 'force-disabled', 'foreign-server', 'unknown-field']);

test('server exec validates command and timeout bounds before execution', function (array $payload) {
    $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/servers/{$this->server->uuid}/exec", $payload)
        ->assertUnprocessable();

    expect($this->runner->calls)->toBeEmpty()
        ->and(AuditEvent::query()->count())->toBe(0);
})->with([
    'blank command' => [['command' => " \t\n"]],
    'overlong command' => [['command' => str_repeat('x', 20_001)]],
    'timeout below minimum' => [['command' => 'whoami', 'timeout' => 0]],
    'timeout above maximum' => [['command' => 'whoami', 'timeout' => 11]],
]);

test('server exec accepts timeout boundaries', function (int $timeout) {
    $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/servers/{$this->server->uuid}/exec", [
            'command' => 'whoami',
            'timeout' => $timeout,
        ])
        ->assertOk();

    expect($this->runner->calls)->toHaveCount(1)
        ->and($this->runner->calls[0]['timeout'])->toBe($timeout);
})->with([1, 10]);

test('initial audit failure is fail closed and does not start the command', function () {
    AuditEvent::creating(fn () => throw new RuntimeException('database unavailable'));

    $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/servers/{$this->server->uuid}/exec", ['command' => 'whoami'])
        ->assertStatus(503)
        ->assertJsonPath('message', 'Command audit is unavailable. No command was started.');

    expect($this->runner->calls)->toBeEmpty();
});

test('failed final audit update does not rerun the command and falls back to unknown', function () {
    AuditEvent::updating(fn () => throw new RuntimeException('database unavailable'));

    $response = $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/servers/{$this->server->uuid}/exec", ['command' => 'whoami'])
        ->assertOk();

    expect($this->runner->calls)->toHaveCount(1)
        ->and(AuditEvent::query()->findOrFail($response->json('audit_event_id'))->metadata['outcome'])->toBe('unknown');
});

test('runner exceptions return a generic result without logging or auditing the raw command', function () {
    $command = 'TOKEN=runner-exception-secret false';
    $this->runner->exceptionMessage = 'runner leaked: '.$command;
    Log::spy();

    $response = $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/servers/{$this->server->uuid}/exec", ['command' => $command])
        ->assertOk()
        ->assertJson([
            'exit_code' => 1,
            'stdout' => '',
            'stderr' => "Command execution failed.\n",
        ]);

    expect($this->runner->calls)->toHaveCount(1)
        ->and(json_encode($response->json(), JSON_THROW_ON_ERROR))->not->toContain($command)
        ->and(json_encode(AuditEvent::query()->findOrFail($response->json('audit_event_id'))->toArray(), JSON_THROW_ON_ERROR))->not->toContain($command);
    Log::shouldNotHaveReceived('warning');
    Log::shouldNotHaveReceived('error');
});

test('server exec enforces the shared token and concurrency limits before audit and process', function (string $limit) {
    $locks = collect();
    if ($limit === 'token') {
        $key = "terminal-api-exec:token:{$this->team->id}:{$this->accessToken->id}";
        foreach (range(1, 30) as $_) {
            RateLimiter::hit($key, 60);
        }
    } else {
        foreach (range(1, 3) as $slot) {
            $lock = Cache::lock("terminal-api-exec:concurrent:team:{$this->team->id}:server:{$this->server->uuid}:{$slot}", 20);
            expect($lock->get())->toBeTrue();
            $locks->push($lock);
        }
    }

    try {
        $this->withHeaders(auditedExecHeaders($this->bearerToken))
            ->postJson("/api/v1/servers/{$this->server->uuid}/exec", ['command' => 'whoami'])
            ->assertStatus(429)
            ->assertHeader('Retry-After')
            ->assertJsonStructure(['retry_after']);
    } finally {
        $locks->each->release();
    }

    expect($this->runner->calls)->toBeEmpty()
        ->and(AuditEvent::query()->count())->toBe(0);
})->with(['token', 'concurrency']);

test('server exec atomically increments and admits only through each rate threshold', function (string $limit) {
    $key = $limit === 'token'
        ? "terminal-api-exec:token:{$this->team->id}:{$this->accessToken->id}"
        : "terminal-api-exec:server:{$this->team->id}:{$this->server->uuid}";
    $threshold = $limit === 'token' ? 30 : 60;

    foreach (range(1, $threshold - 1) as $_) {
        RateLimiter::increment($key, 60);
    }

    $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/servers/{$this->server->uuid}/exec", ['command' => 'whoami'])
        ->assertOk();

    expect(RateLimiter::attempts($key))->toBe($threshold)
        ->and($this->runner->calls)->toHaveCount(1);

    $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/servers/{$this->server->uuid}/exec", ['command' => 'whoami'])
        ->assertStatus(429);

    expect(RateLimiter::attempts($key))->toBe($threshold + 1)
        ->and($this->runner->calls)->toHaveCount(1)
        ->and(AuditEvent::query()->count())->toBe(1);
})->with(['token', 'server']);

test('server exec does not start the runner after losing its distributed concurrency slot', function () {
    $lockKey = "terminal-api-exec:concurrent:team:{$this->team->id}:server:{$this->server->uuid}:1";
    AuditEvent::created(function () use ($lockKey): void {
        Cache::lock($lockKey, 20)->forceRelease();
    });

    $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/servers/{$this->server->uuid}/exec", ['command' => 'whoami'])
        ->assertStatus(429)
        ->assertHeader('Retry-After', '1');

    expect($this->runner->calls)->toBeEmpty();
    $metadata = AuditEvent::query()->sole()->metadata;
    expect($metadata['outcome'])->toBe('unknown')
        ->and($metadata['exit_code'])->toBeNull()
        ->and($metadata['remote_process_started'])->toBeFalse()
        ->and($metadata['not_started_reason'])->toBe('concurrency_lock_lost');
});

test('application exec resolves a running container and shares the stdin execution and audit service', function () {
    Process::fake(['*' => Process::result(output: auditedApplicationContainer())]);
    $command = 'PASSWORD=application-secret php artisan about';

    $response = $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/applications/{$this->application->uuid}/exec", ['command' => $command])
        ->assertOk();

    $call = $this->runner->calls[0];
    [$timeoutFrame, $script] = explode("\n", $call['stdin'], 2);
    expect($call['argv'][array_key_last($call['argv'])])
        ->toContain("docker exec -i 'app-container' sh -c", 'timeout --preserve-status -k 1s 10s sh -c')
        ->and(implode(' ', $call['argv']))->not->toContain($command)
        ->and(implode(' ', $call['argv']))->not->toContain($timeoutFrame)
        ->and($timeoutFrame)->toMatch('/^__COOLIFY_TERMINAL_FRAME_[0-9a-f]{64}__$/')
        ->and($script)->toBe($command."\n");

    $audit = AuditEvent::query()->findOrFail($response->json('audit_event_id'));
    expect($audit)
        ->resource_type->toBe('application')
        ->resource_uuid->toBe($this->application->uuid)
        ->and($audit->metadata['container'])->toBe('app-container')
        ->and($audit->metadata['command_redacted'])->not->toContain('application-secret');
});

test('application and server routes share the server rate bucket', function () {
    Process::fake(['*' => Process::result(output: auditedApplicationContainer())]);
    $serverKey = "terminal-api-exec:server:{$this->team->id}:{$this->server->uuid}";
    foreach (range(1, 60) as $_) {
        RateLimiter::hit($serverKey, 60);
    }

    $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/applications/{$this->application->uuid}/exec", ['command' => 'whoami'])
        ->assertStatus(429);

    expect($this->runner->calls)->toBeEmpty();
});

test('application exec returns choices for ambiguous containers without starting a command', function () {
    Process::fake(['*' => Process::result(output: auditedApplicationContainer('web').auditedApplicationContainer('worker'))]);

    $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/applications/{$this->application->uuid}/exec", ['command' => 'whoami'])
        ->assertStatus(422)
        ->assertJsonPath('message', 'Multiple running containers found. Specify a container.')
        ->assertJsonCount(2, 'containers');

    expect($this->runner->calls)->toBeEmpty();
});

test('application exec requires a server selector when the same container exists on multiple servers', function () {
    $additionalServer = Server::factory()->create([
        'team_id' => $this->team->id,
        'private_key_id' => $this->privateKey->id,
        'user' => 'root',
    ]);
    $additionalServer->settings()->update([
        'is_terminal_enabled' => true,
        'force_disabled' => false,
    ]);
    $additionalDestination = StandaloneDocker::where('server_id', $additionalServer->id)->first()
        ?? StandaloneDocker::factory()->create([
            'server_id' => $additionalServer->id,
            'network' => 'terminal-api-additional-test',
        ]);
    $this->application->additional_servers()->attach($additionalServer->id, [
        'standalone_docker_id' => $additionalDestination->id,
    ]);
    Process::fake(['*' => Process::result(output: auditedApplicationContainer())]);

    $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/applications/{$this->application->uuid}/exec", [
            'command' => 'whoami',
            'container' => 'app-container',
        ])
        ->assertUnprocessable()
        ->assertJsonPath('message', 'Multiple servers contain this container. Specify a server_uuid.')
        ->assertJsonCount(2, 'containers');

    expect($this->runner->calls)->toBeEmpty();

    $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/applications/{$this->application->uuid}/exec", [
            'command' => 'whoami',
            'container' => 'app-container',
            'server_uuid' => $additionalServer->uuid,
        ])
        ->assertOk();

    expect($this->runner->calls)->toHaveCount(1)
        ->and($this->runner->calls[0]['argv'])->toContain('root@'.$additionalServer->ip);
});

test('application exec rejects stopped and foreign application targets', function (string $case) {
    if ($case === 'stopped') {
        Process::fake(['*' => Process::result(output: auditedApplicationContainer(state: 'exited'))]);
        $uuid = $this->application->uuid;
    } else {
        $foreignTeam = Team::factory()->create();
        $foreignProject = Project::factory()->create(['team_id' => $foreignTeam->id]);
        $foreignEnvironment = Environment::factory()->create(['project_id' => $foreignProject->id]);
        $foreignApplication = Application::factory()->create(['environment_id' => $foreignEnvironment->id]);
        $uuid = $foreignApplication->uuid;
    }

    $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/applications/{$uuid}/exec", ['command' => 'whoami'])
        ->assertNotFound();

    expect($this->runner->calls)->toBeEmpty();
})->with(['stopped', 'foreign']);

test('application exec rejects Swarm targets until a running task container can be resolved', function () {
    $this->server->settings()->update(['is_swarm_manager' => true]);
    Process::fake(['*' => Process::result(output: auditedApplicationContainer())]);

    $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/applications/{$this->application->uuid}/exec", ['command' => 'whoami'])
        ->assertUnprocessable()
        ->assertJsonPath('message', 'Application exec on Swarm targets is not supported.');

    expect($this->runner->calls)->toBeEmpty();
    Process::assertNothingRan();
});

test('application exec treats pull request id zero as the base deployment', function () {
    Process::fake(['*' => Process::result(output: auditedApplicationContainer('base').auditedApplicationContainer('preview-12', pullRequestId: 12))]);

    $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/applications/{$this->application->uuid}/exec", [
            'command' => 'whoami',
            'pull_request_id' => 0,
        ])
        ->assertOk();

    expect($this->runner->calls[0]['argv'][array_key_last($this->runner->calls[0]['argv'])])
        ->toContain("docker exec -i 'base' sh -c", 'timeout --preserve-status -k 1s 10s sh -c');
});

test('application exec selects only the requested pull request container', function () {
    Process::fake(['*' => Process::result(output: auditedApplicationContainer('base').auditedApplicationContainer('preview-12', pullRequestId: 12).auditedApplicationContainer('preview-34', pullRequestId: 34))]);

    $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/applications/{$this->application->uuid}/exec", [
            'command' => 'whoami',
            'pull_request_id' => 12,
        ])
        ->assertOk();

    expect($this->runner->calls[0]['argv'][array_key_last($this->runner->calls[0]['argv'])])
        ->toContain("docker exec -i 'preview-12' sh -c", 'timeout --preserve-status -k 1s 10s sh -c');
});

test('application exec pull request selector never substring matches another PR label', function () {
    Process::fake(['*' => Process::result(output: auditedApplicationContainer('preview-12', pullRequestId: 12))]);

    $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/applications/{$this->application->uuid}/exec", [
            'command' => 'whoami',
            'pull_request_id' => 1,
        ])
        ->assertNotFound();

    expect($this->runner->calls)->toBeEmpty();
});

test('application exec uses sudo only for docker on a non-root managed server', function () {
    $this->server->update(['user' => 'deploy']);
    Process::fake(['*' => Process::result(output: auditedApplicationContainer())]);

    $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/applications/{$this->application->uuid}/exec", ['command' => 'whoami'])
        ->assertOk();

    expect($this->runner->calls[0]['argv'][array_key_last($this->runner->calls[0]['argv'])])
        ->toContain("sudo docker exec -i 'app-container' sh -c", 'timeout --preserve-status -k 1s 10s sh -c')
        ->and($this->runner->calls[0]['argv'])->toContain('deploy@'.$this->server->ip);
});

test('timeout result is returned normally and audited as timed out', function () {
    $this->runner->result = [
        'exit_code' => 124,
        'stdout' => '',
        'stderr' => "Command timed out after 2 seconds.\n",
        'duration_ms' => 2000,
        'stdout_bytes' => 0,
        'stderr_bytes' => 35,
        'stdout_truncated' => false,
        'stderr_truncated' => false,
        'timed_out' => true,
    ];

    $response = $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/servers/{$this->server->uuid}/exec", [
            'command' => 'sleep 30',
            'timeout' => 2,
        ])
        ->assertOk()
        ->assertJsonPath('exit_code', 124)
        ->assertJsonPath('timed_out', true);

    $metadata = AuditEvent::query()->findOrFail($response->json('audit_event_id'))->metadata;
    expect($metadata['outcome'])->toBe('timed_out')
        ->and($metadata['timed_out'])->toBeTrue();
});

test('ordinary terminal exit status is not misclassified as a timeout', function (int $status) {
    $this->runner->result['exit_code'] = $status;
    $this->runner->result['timed_out'] = false;

    $response = $this->withHeaders(auditedExecHeaders($this->bearerToken))
        ->postJson("/api/v1/servers/{$this->server->uuid}/exec", ['command' => "exit {$status}"])
        ->assertOk()
        ->assertJsonPath('exit_code', $status)
        ->assertJsonPath('timed_out', false);

    $metadata = AuditEvent::query()->findOrFail($response->json('audit_event_id'))->metadata;
    expect($metadata['outcome'])->toBe('failed')
        ->and($metadata['timed_out'])->toBeFalse();
})->with([124, 137, 143]);
