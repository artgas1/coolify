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
use Illuminate\Contracts\Cache\Lock;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use OpenApi\Attributes as OA;
use Throwable;

#[OA\Schema(
    schema: 'TerminalCommandResult',
    type: 'object',
    required: ['exit_code', 'stdout', 'stderr', 'duration_ms', 'audit_event_id', 'stdout_truncated', 'stderr_truncated'],
    properties: [
        new OA\Property(property: 'exit_code', type: 'integer'),
        new OA\Property(property: 'stdout', type: 'string'),
        new OA\Property(property: 'stderr', type: 'string'),
        new OA\Property(property: 'duration_ms', type: 'integer', minimum: 0),
        new OA\Property(property: 'audit_event_id', type: 'integer'),
        new OA\Property(property: 'stdout_truncated', type: 'boolean'),
        new OA\Property(property: 'stderr_truncated', type: 'boolean'),
    ],
)]
class TerminalCommandService
{
    public const DEFAULT_TIMEOUT_SECONDS = 10;

    public const MAX_TIMEOUT_SECONDS = 10;

    private const TOKEN_RATE_LIMIT_PER_MINUTE = 30;

    private const SERVER_RATE_LIMIT_PER_MINUTE = 60;

    private const SERVER_CONCURRENCY_LIMIT = 3;

    private const LOCK_GRACE_SECONDS = 2;

    public function __construct(
        private readonly TerminalCommandProcessRunner $processRunner,
        private readonly TerminalCommandRedactor $redactor,
    ) {}

    /**
     * @return array{exit_code: int, stdout: string, stderr: string, duration_ms: int, audit_event_id: int, stdout_truncated: bool, stderr_truncated: bool}
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
     * @return array{exit_code: int, stdout: string, stderr: string, duration_ms: int, audit_event_id: int, stdout_truncated: bool, stderr_truncated: bool}
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
     * @return array{exit_code: int, stdout: string, stderr: string, duration_ms: int, audit_event_id: int, stdout_truncated: bool, stderr_truncated: bool}
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
        $this->enforceRateLimits($teamId, $server, $token);
        $lock = $this->acquireConcurrencySlot($teamId, $server, $timeout);

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
                $remoteCommand = is_null($container)
                    ? 'sh -s'
                    : ($server->isNonRoot() ? 'sudo ' : '').'docker exec -i '.escapeshellarg($container).' sh -s';
                $argv = SshMultiplexingHelper::generateSshStdinCommand($server, $remoteCommand);
                $result = $this->processRunner->run($argv, $command."\n", $timeout);
                $outcome = match (true) {
                    $result['exit_code'] === 124 => 'timed_out',
                    $result['exit_code'] === 0 => 'success',
                    default => 'failed',
                };
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
        if (RateLimiter::tooManyAttempts($tokenKey, self::TOKEN_RATE_LIMIT_PER_MINUTE)) {
            $retryAfter = max(1, RateLimiter::availableIn($tokenKey));
            throw new TerminalCommandLimitException(
                "Too many terminal command requests. Please retry in {$retryAfter} seconds.",
                $retryAfter,
            );
        }

        $serverKey = "terminal-api-exec:server:{$teamId}:{$server->uuid}";
        if (RateLimiter::tooManyAttempts($serverKey, self::SERVER_RATE_LIMIT_PER_MINUTE)) {
            $retryAfter = max(1, RateLimiter::availableIn($serverKey));
            throw new TerminalCommandLimitException(
                "Too many terminal commands for this server. Please retry in {$retryAfter} seconds.",
                $retryAfter,
            );
        }

        RateLimiter::hit($tokenKey, 60);
        RateLimiter::hit($serverKey, 60);
    }

    private function acquireConcurrencySlot(int $teamId, Server $server, int $timeout): Lock
    {
        foreach (range(1, self::SERVER_CONCURRENCY_LIMIT) as $slot) {
            $lock = Cache::lock(
                "terminal-api-exec:concurrent:team:{$teamId}:server:{$server->uuid}:{$slot}",
                $timeout + self::LOCK_GRACE_SECONDS,
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
     * @param  array{exit_code: int, duration_ms: int, stdout_bytes: int, stderr_bytes: int, stdout_truncated: bool, stderr_truncated: bool}  $result
     */
    private function finishAuditEvent(AuditEvent $auditEvent, array $result, string $outcome): void
    {
        $finalMetadata = array_merge($auditEvent->metadata ?? [], [
            'outcome' => $outcome,
            'exit_code' => $result['exit_code'],
            'duration_ms' => $result['duration_ms'],
            'stdout_bytes' => $result['stdout_bytes'],
            'stderr_bytes' => $result['stderr_bytes'],
            'stdout_truncated' => $result['stdout_truncated'],
            'stderr_truncated' => $result['stderr_truncated'],
            'finished_at' => now()->toIso8601String(),
        ]);

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
