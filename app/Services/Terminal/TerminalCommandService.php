<?php

namespace App\Services\Terminal;

use App\Exceptions\TerminalAuditUnavailableException;
use App\Exceptions\TerminalCommandLimitException;
use App\Helpers\SshMultiplexingHelper;
use App\Models\Application;
use App\Models\AuditEvent;
use App\Models\PersonalAccessToken;
use App\Models\Server;
use App\Models\Team;
use App\Models\User;
use Illuminate\Cache\Lock as CacheLock;
use Illuminate\Contracts\Cache\Lock as LockContract;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use OpenApi\Attributes as OA;
use Throwable;

#[OA\Schema(
    schema: 'TerminalCommandResult',
    type: 'object',
    required: ['exit_code', 'stdout', 'stderr', 'duration_ms', 'audit_event_id', 'stdout_truncated', 'stderr_truncated', 'timed_out'],
    properties: [
        new OA\Property(property: 'exit_code', type: 'integer'),
        new OA\Property(property: 'stdout', type: 'string'),
        new OA\Property(property: 'stderr', type: 'string'),
        new OA\Property(property: 'duration_ms', type: 'integer', minimum: 0),
        new OA\Property(property: 'audit_event_id', type: 'integer'),
        new OA\Property(property: 'stdout_truncated', type: 'boolean'),
        new OA\Property(property: 'stderr_truncated', type: 'boolean'),
        new OA\Property(property: 'timed_out', description: 'True only when a remote timeout supervisor marker was observed without controlled-shell completion, or the bounded local SSH watchdog expired.', type: 'boolean'),
    ],
)]
class TerminalCommandService
{
    public const DEFAULT_TIMEOUT_SECONDS = 10;

    public const MAX_TIMEOUT_SECONDS = 10;

    public const MAX_CONNECTION_TIMEOUT_SECONDS = 10;

    private const TOKEN_RATE_LIMIT_PER_MINUTE = 30;

    private const SERVER_RATE_LIMIT_PER_MINUTE = 60;

    private const SERVER_CONCURRENCY_LIMIT = 3;

    private const LOCK_LEASE_BUFFER_SECONDS = 1;

    public function __construct(
        private readonly TerminalCommandProcessRunner $processRunner,
        private readonly TerminalCommandRedactor $redactor,
    ) {}

    /**
     * @return array{exit_code: int, stdout: string, stderr: string, duration_ms: int, audit_event_id: int, stdout_truncated: bool, stderr_truncated: bool, timed_out: bool}
     */
    public function executeOnServer(
        Server $server,
        User $actor,
        PersonalAccessToken $token,
        string $command,
        int $timeout,
    ): array {
        return $this->execute(
            server: $server,
            resource: $server,
            actor: $actor,
            token: $token,
            command: $command,
            timeout: $timeout,
            container: null,
        );
    }

    /**
     * @return array{exit_code: int, stdout: string, stderr: string, duration_ms: int, audit_event_id: int, stdout_truncated: bool, stderr_truncated: bool, timed_out: bool}
     */
    public function executeInApplication(
        Application $application,
        Server $server,
        User $actor,
        PersonalAccessToken $token,
        string $container,
        string $command,
        int $timeout,
    ): array {
        return $this->execute(
            server: $server,
            resource: $application,
            actor: $actor,
            token: $token,
            command: $command,
            timeout: $timeout,
            container: $container,
        );
    }

    /**
     * @return array{exit_code: int, stdout: string, stderr: string, duration_ms: int, audit_event_id: int, stdout_truncated: bool, stderr_truncated: bool, timed_out: bool}
     */
    private function execute(
        Server $server,
        Model $resource,
        User $actor,
        PersonalAccessToken $token,
        string $command,
        int $timeout,
        ?string $container,
    ): array {
        $teamId = (int) $server->team_id;
        $connectionTimeout = $this->connectionTimeoutSeconds($server);
        $this->enforceRateLimits($teamId, $server, $token);
        $lock = $this->acquireConcurrencySlot($teamId, $server, $timeout, $connectionTimeout);

        try {
            $auditEvent = $this->beginAuditEvent(
                teamId: $teamId,
                server: $server,
                resource: $resource,
                actor: $actor,
                token: $token,
                command: $command,
                timeout: $timeout,
                container: $container,
            );

            try {
                [$timeoutMarker, $completionMarker] = $this->timeoutMarkers();
                $this->refreshConcurrencySlot($lock, $auditEvent, $timeout, $connectionTimeout);
                $remoteCommand = $this->remoteCommand(
                    server: $server,
                    container: $container,
                    timeout: $timeout,
                    timeoutMarker: $timeoutMarker,
                    completionMarker: $completionMarker,
                );
                $argv = SshMultiplexingHelper::generateSshStdinCommand($server, $remoteCommand, $connectionTimeout);
                $this->refreshConcurrencySlot($lock, $auditEvent, $timeout, $connectionTimeout);
                $result = $this->processRunner->run(
                    argv: $argv,
                    stdin: $command."\n",
                    timeout: $timeout,
                    connectionTimeout: $connectionTimeout,
                    timeoutMarker: $timeoutMarker,
                    completionMarker: $completionMarker,
                );
                $outcome = match (true) {
                    $result['timed_out'] => 'timed_out',
                    $result['exit_code'] === 0 => 'success',
                    default => 'failed',
                };
            } catch (TerminalCommandLimitException $exception) {
                throw $exception;
            } catch (Throwable) {
                $result = [
                    'exit_code' => 1,
                    'stdout' => '',
                    'stderr' => "Command execution failed.\n",
                    'duration_ms' => 0,
                    'stdout_bytes' => 0,
                    'stderr_bytes' => strlen("Command execution failed.\n"),
                    'stdout_truncated' => false,
                    'stderr_truncated' => false,
                    'timed_out' => false,
                ];
                $outcome = 'unknown';
            }

            $this->finishAuditEvent($auditEvent, $result, $outcome);

            return [
                'exit_code' => $result['exit_code'],
                'stdout' => $result['stdout'],
                'stderr' => $result['stderr'],
                'duration_ms' => $result['duration_ms'],
                'audit_event_id' => $auditEvent->id,
                'stdout_truncated' => $result['stdout_truncated'],
                'stderr_truncated' => $result['stderr_truncated'],
                'timed_out' => $result['timed_out'],
            ];
        } finally {
            try {
                $lock->release();
            } catch (Throwable $exception) {
                Log::warning('Terminal command concurrency lock release failed', [
                    'server_uuid' => $server->uuid,
                    'exception' => $exception::class,
                ]);
            }
        }
    }

    private function enforceRateLimits(int $teamId, Server $server, PersonalAccessToken $token): void
    {
        $tokenKey = "terminal-api-exec:token:{$teamId}:{$token->id}";
        $tokenAttempts = RateLimiter::increment($tokenKey, 60);
        if ($tokenAttempts > self::TOKEN_RATE_LIMIT_PER_MINUTE) {
            $retryAfter = max(1, RateLimiter::availableIn($tokenKey));
            throw new TerminalCommandLimitException(
                "Too many terminal command requests. Please retry in {$retryAfter} seconds.",
                $retryAfter,
            );
        }

        $serverKey = "terminal-api-exec:server:{$teamId}:{$server->uuid}";
        $serverAttempts = RateLimiter::increment($serverKey, 60);
        if ($serverAttempts > self::SERVER_RATE_LIMIT_PER_MINUTE) {
            $retryAfter = max(1, RateLimiter::availableIn($serverKey));
            throw new TerminalCommandLimitException(
                "Too many terminal commands for this server. Please retry in {$retryAfter} seconds.",
                $retryAfter,
            );
        }
    }

    private function acquireConcurrencySlot(int $teamId, Server $server, int $timeout, int $connectionTimeout): LockContract
    {
        foreach (range(1, self::SERVER_CONCURRENCY_LIMIT) as $slot) {
            $lock = Cache::lock(
                "terminal-api-exec:concurrent:team:{$teamId}:server:{$server->uuid}:{$slot}",
                $this->concurrencyLeaseSeconds($timeout, $connectionTimeout),
            );

            if ($lock->get()) {
                return $lock;
            }
        }

        throw new TerminalCommandLimitException(
            'Too many terminal commands are already running on this server. Please retry shortly.',
            1,
        );
    }

    private function refreshConcurrencySlot(
        LockContract $lock,
        AuditEvent $auditEvent,
        int $timeout,
        int $connectionTimeout,
    ): void {
        try {
            $isOwned = $lock instanceof CacheLock && $lock->isOwnedByCurrentProcess();
            $refreshed = $isOwned && $lock->refresh($this->concurrencyLeaseSeconds($timeout, $connectionTimeout));
        } catch (Throwable $exception) {
            $isOwned = false;
            $refreshed = false;
            Log::warning('Terminal command concurrency lock refresh failed', [
                'audit_event_id' => $auditEvent->id,
                'exception' => $exception::class,
            ]);
        }

        if ($isOwned && $refreshed) {
            return;
        }

        $this->finishAuditEvent($auditEvent, [
            'exit_code' => null,
            'duration_ms' => 0,
            'stdout_bytes' => 0,
            'stderr_bytes' => 0,
            'stdout_truncated' => false,
            'stderr_truncated' => false,
            'timed_out' => false,
        ], 'unknown', [
            'remote_process_started' => false,
            'not_started_reason' => 'concurrency_lock_lost',
        ]);

        throw new TerminalCommandLimitException(
            'Terminal command concurrency slot was lost before execution. Please retry shortly.',
            1,
        );
    }

    private function concurrencyLeaseSeconds(int $timeout, int $connectionTimeout): int
    {
        return TerminalCommandProcessRunner::maximumSupervisionSeconds($timeout, $connectionTimeout)
            + self::LOCK_LEASE_BUFFER_SECONDS;
    }

    private function connectionTimeoutSeconds(Server $server): int
    {
        return min(
            self::MAX_CONNECTION_TIMEOUT_SECONDS,
            max(1, SshMultiplexingHelper::getConnectionTimeout($server)),
        );
    }

    /**
     * @return array{string, string}
     */
    private function timeoutMarkers(): array
    {
        return [
            '__COOLIFY_TERMINAL_TIMEOUT_'.bin2hex(random_bytes(32)).'__',
            '__COOLIFY_TERMINAL_COMPLETE_'.bin2hex(random_bytes(32)).'__',
        ];
    }

    private function remoteCommand(
        Server $server,
        ?string $container,
        int $timeout,
        string $timeoutMarker,
        string $completionMarker,
    ): string {
        $killGrace = TerminalCommandProcessRunner::REMOTE_KILL_GRACE_SECONDS;
        $controlledShell = 'sh -s; status=$?; printf "\\n%s\\n" "'.$completionMarker.'" >&2; exit "$status"';
        $supervisedShell = 'timeout --preserve-status -k '.$killGrace.'s '.$timeout.'s sh -c '
            .escapeshellarg($controlledShell).'; status=$?; '
            .'case "$status" in 137|143) printf "\\n%s\\n" "'.$timeoutMarker.'" >&2;; esac; '
            .'exit "$status"';
        if (is_null($container)) {
            return $supervisedShell;
        }

        return ($server->isNonRoot() ? 'sudo ' : '')
            .'docker exec -i '.escapeshellarg($container).' sh -c '.escapeshellarg($supervisedShell);
    }

    private function beginAuditEvent(
        int $teamId,
        Server $server,
        Model $resource,
        User $actor,
        PersonalAccessToken $token,
        string $command,
        int $timeout,
        ?string $container,
    ): AuditEvent {
        $appKey = (string) config('app.key');
        if ($appKey === '') {
            throw new TerminalAuditUnavailableException('Command audit is unavailable.');
        }

        $resourceType = $resource instanceof Application ? 'application' : 'server';
        $startedAt = now();

        try {
            return AuditEvent::query()->create([
                'team_id' => $teamId,
                'event' => "api.{$resourceType}.command.executed",
                'source' => 'api',
                'action' => 'executed',
                'actor_type' => 'api_token',
                'actor_id' => $actor->id,
                'actor_name' => $actor->name,
                'actor_email' => $actor->email,
                'actor_token_id' => $token->id,
                'actor_token_name' => $token->name,
                'resource_type' => $resourceType,
                'resource_uuid' => $resource->uuid,
                'resource_name' => $resource->name,
                'description' => ucfirst($resourceType).' command execution',
                'metadata' => [
                    'outcome' => 'running',
                    'server_uuid' => $server->uuid,
                    'container' => $container,
                    'command_redacted' => $this->redactor->redact($command, $this->knownSecrets($resource, $server)),
                    'command_hmac_sha256' => hash_hmac('sha256', $command, $appKey),
                    'requested_timeout_seconds' => $timeout,
                    'started_at' => $startedAt->toIso8601String(),
                ],
                'ip_address' => request()->ip(),
                'user_agent' => str((string) request()->userAgent())->limit(200, '')->value(),
                'created_at' => $startedAt,
            ]);
        } catch (TerminalAuditUnavailableException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            Log::warning('Terminal command initial audit persistence failed', [
                'resource_type' => $resourceType,
                'resource_uuid' => $resource->uuid,
                'exception' => $exception::class,
            ]);

            throw new TerminalAuditUnavailableException('Command audit is unavailable.');
        }
    }

    /**
     * @param  array{exit_code: int|null, duration_ms: int, stdout_bytes: int, stderr_bytes: int, stdout_truncated: bool, stderr_truncated: bool, timed_out: bool}  $result
     * @param  array<string, mixed>  $additionalMetadata
     */
    private function finishAuditEvent(AuditEvent $auditEvent, array $result, string $outcome, array $additionalMetadata = []): void
    {
        $finalMetadata = array_merge($auditEvent->metadata ?? [], [
            'outcome' => $outcome,
            'exit_code' => $result['exit_code'],
            'duration_ms' => $result['duration_ms'],
            'stdout_bytes' => $result['stdout_bytes'],
            'stderr_bytes' => $result['stderr_bytes'],
            'stdout_truncated' => $result['stdout_truncated'],
            'stderr_truncated' => $result['stderr_truncated'],
            'timed_out' => $result['timed_out'],
            'finished_at' => now()->toIso8601String(),
        ], $additionalMetadata);

        try {
            $auditEvent->metadata = $finalMetadata;
            $auditEvent->save();

            return;
        } catch (Throwable $exception) {
            Log::warning('Terminal command final audit update failed', [
                'audit_event_id' => $auditEvent->id,
                'exception' => $exception::class,
            ]);
        }

        try {
            AuditEvent::query()->whereKey($auditEvent->id)->update([
                'metadata' => json_encode(array_merge($auditEvent->metadata ?? [], [
                    'outcome' => 'unknown',
                    'finished_at' => now()->toIso8601String(),
                ]), JSON_THROW_ON_ERROR),
            ]);
        } catch (Throwable $exception) {
            Log::warning('Terminal command audit outcome remains running', [
                'audit_event_id' => $auditEvent->id,
                'exception' => $exception::class,
            ]);
        }
    }

    /**
     * @return array<int, mixed>
     */
    private function knownSecrets(Model $resource, Server $server): array
    {
        $secrets = [$server->privateKey?->private_key];

        try {
            $team = Team::query()->find($server->team_id);
            $secrets = array_merge(
                $secrets,
                $team?->environment_variables()->get()->pluck('value')->all() ?? [],
                $server->environment_variables()->get()->pluck('value')->all(),
            );

            if ($resource instanceof Application) {
                $variables = $resource->environment_variables()->get()
                    ->merge($resource->environment_variables_preview()->get());
                $secrets = array_merge(
                    $secrets,
                    $variables->pluck('value')->all(),
                    $variables->pluck('real_value')->all(),
                );
            }
        } catch (Throwable) {
        }

        return $secrets;
    }
}
