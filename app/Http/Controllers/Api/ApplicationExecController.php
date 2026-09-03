<?php

namespace App\Http\Controllers\Api;

use App\Exceptions\TerminalAuditUnavailableException;
use App\Exceptions\TerminalCommandLimitException;
use App\Http\Controllers\Controller;
use App\Models\Application;
use App\Models\Server;
use App\Services\Terminal\TerminalCommandService;
use App\Support\ValidationPatterns;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Validator;
use OpenApi\Attributes as OA;

class ApplicationExecController extends Controller
{
    #[OA\Post(
        summary: 'Execute command',
        description: 'Execute a bounded non-interactive shell command in a running application container. Requires a literal terminal token ability with a lifetime of at most 90 days and team opt-in. Swarm application targets are not supported. The timeout supervises the ordinary command tree but this arbitrary-code-execution API is not a sandbox and cannot universally stop deliberately detached processes. A compatible timeout executable must exist in the target container; otherwise the shell script is not started.',
        path: '/applications/{uuid}/exec',
        operationId: 'execute-command-in-application',
        security: [['bearerAuth' => []]],
        tags: ['Applications'],
        parameters: [
            new OA\Parameter(name: 'uuid', in: 'path', required: true, description: 'Application UUID', schema: new OA\Schema(type: 'string')),
        ],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['command'],
                properties: [
                    new OA\Property(property: 'command', description: 'Shell script. Prefer reading secrets from the target environment instead of passing literal secret values.', type: 'string', maxLength: 20000, minLength: 1),
                    new OA\Property(property: 'timeout', type: 'integer', maximum: 10, minimum: 1, default: 10),
                    new OA\Property(property: 'container', type: 'string', maxLength: 255),
                    new OA\Property(property: 'server_uuid', type: 'string', maxLength: 255),
                    new OA\Property(property: 'pull_request_id', type: 'integer', minimum: 0),
                ],
                additionalProperties: false,
            ),
        ),
        responses: [
            new OA\Response(response: 200, description: 'Command finished, including non-zero exits and timeouts.', content: new OA\JsonContent(ref: '#/components/schemas/TerminalCommandResult')),
            new OA\Response(response: 401, ref: '#/components/responses/401'),
            new OA\Response(response: 403, description: 'Terminal access denied.', content: new OA\JsonContent(
                required: ['message'],
                properties: [new OA\Property(property: 'message', type: 'string')],
            )),
            new OA\Response(response: 404, ref: '#/components/responses/404'),
            new OA\Response(response: 422, description: 'Validation or target ambiguity error. Swarm application targets are not supported.', content: new OA\JsonContent(
                required: ['message'],
                properties: [new OA\Property(property: 'message', type: 'string')],
            )),
            new OA\Response(response: 429, description: 'Terminal command rate or concurrency limit exceeded.', content: new OA\JsonContent(
                required: ['message', 'retry_after'],
                properties: [
                    new OA\Property(property: 'message', type: 'string'),
                    new OA\Property(property: 'retry_after', type: 'integer', minimum: 1),
                ],
            )),
            new OA\Response(response: 503, description: 'The initial audit record could not be persisted; no command was started.', content: new OA\JsonContent(
                required: ['message'],
                properties: [new OA\Property(property: 'message', type: 'string')],
            )),
        ],
    )]
    public function __invoke(Request $request, string $uuid, TerminalCommandService $commandService): JsonResponse
    {
        $validated = $this->validateRequest($request);
        if ($validated instanceof JsonResponse) {
            return $validated;
        }

        $teamId = getTeamIdFromToken();
        if (is_null($teamId)) {
            return response()->json(['message' => 'Invalid token.'], 401);
        }

        $application = Application::ownedByCurrentTeamAPI((int) $teamId)->where('uuid', $uuid)->first();
        if (! $application) {
            return response()->json(['message' => 'Application not found.'], 404);
        }

        $target = $this->resolveTarget($application, (int) $teamId, $validated);
        if ($target instanceof JsonResponse) {
            return $target;
        }

        try {
            $result = $commandService->executeInApplication(
                application: $application,
                server: $target['server'],
                actor: $request->user(),
                token: $request->user()->currentAccessToken(),
                container: $target['container'],
                command: (string) $validated['command'],
                timeout: (int) ($validated['timeout'] ?? TerminalCommandService::DEFAULT_TIMEOUT_SECONDS),
            );
        } catch (TerminalCommandLimitException $exception) {
            return response()->json([
                'message' => $exception->getMessage(),
                'retry_after' => $exception->retryAfter,
            ], 429, ['Retry-After' => (string) $exception->retryAfter]);
        } catch (TerminalAuditUnavailableException) {
            return response()->json(['message' => 'Command audit is unavailable. No command was started.'], 503);
        }

        return response()->json($result);
    }

    /**
     * @return array<string, mixed>|JsonResponse
     */
    private function validateRequest(Request $request): array|JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'command' => [
                'required',
                'string',
                'max:20000',
                fn (string $attribute, mixed $value, \Closure $fail) => trim((string) $value) === '' ? $fail('The command field must not be blank.') : null,
            ],
            'timeout' => ['sometimes', 'integer', 'min:1', 'max:'.TerminalCommandService::MAX_TIMEOUT_SECONDS],
            'container' => ['sometimes', 'string', 'max:255'],
            'server_uuid' => ['sometimes', 'string', 'max:255'],
            'pull_request_id' => ['sometimes', 'integer', 'min:0'],
        ]);

        $validator->fails();
        foreach (array_diff(array_keys($request->all()), ['command', 'timeout', 'container', 'server_uuid', 'pull_request_id']) as $field) {
            $validator->errors()->add($field, 'This field is not allowed.');
        }

        if ($request->filled('container') && ! ValidationPatterns::isValidContainerName((string) $request->input('container'))) {
            $validator->errors()->add('container', 'The container field has an invalid format.');
        }

        if ($validator->errors()->isNotEmpty()) {
            return response()->json([
                'message' => 'Validation failed.',
                'errors' => $validator->errors(),
            ], 422);
        }

        return $validator->validated();
    }

    /**
     * @param  array<string, mixed>  $validated
     * @return array{server: Server, container: string}|JsonResponse
     */
    private function resolveTarget(Application $application, int $teamId, array $validated): array|JsonResponse
    {
        $requestedServerUuid = (string) ($validated['server_uuid'] ?? '');
        $requestedContainer = (string) ($validated['container'] ?? '');
        $pullRequestId = array_key_exists('pull_request_id', $validated) ? (int) $validated['pull_request_id'] : null;

        $application->loadMissing(['destination.server', 'additional_servers']);
        $servers = collect([$application->destination?->server])
            ->merge($application->additional_servers)
            ->filter(fn (?Server $server): bool => $server !== null && (int) $server->team_id === $teamId)
            ->unique('id')
            ->values();

        if ($requestedServerUuid !== '') {
            $servers = $servers->where('uuid', $requestedServerUuid)->values();
            if ($servers->isEmpty()) {
                return response()->json(['message' => 'Server not found for this application.'], 404);
            }
        }

        if ($servers->contains(fn (Server $server): bool => $server->isSwarm())) {
            return response()->json([
                'message' => 'Application exec on Swarm targets is not supported.',
            ], 422);
        }

        $runningContainers = collect();
        $disabledServers = collect();

        foreach ($servers as $server) {
            if (! $server->isTerminalEnabled() || $server->isForceDisabled()) {
                $disabledServers->push($server);

                continue;
            }

            $containers = getCurrentApplicationContainerStatus(
                $server,
                $application->id,
                $pullRequestId,
                includePullrequests: is_null($pullRequestId),
            );

            $containers
                ->filter(fn (mixed $container): bool => data_get($container, 'State') === 'running')
                ->each(function (mixed $container) use ($runningContainers, $server): void {
                    $runningContainers->push([
                        'server' => $server,
                        'container' => (string) data_get($container, 'Names'),
                    ]);
                });
        }

        if ($runningContainers->isEmpty()) {
            if ($servers->isNotEmpty() && $disabledServers->count() === $servers->count()) {
                return response()->json(['message' => 'Terminal access is disabled on this server.'], 403);
            }

            return response()->json(['message' => 'No running application containers found.'], 404);
        }

        if ($requestedContainer !== '') {
            $matchingTargets = $runningContainers->where('container', $requestedContainer)->values();
            if ($matchingTargets->isEmpty()) {
                return response()->json(['message' => 'Container not found for this application.'], 404);
            }

            if ($matchingTargets->count() > 1) {
                return $this->ambiguousTargetResponse(
                    'Multiple servers contain this container. Specify a server_uuid.',
                    $matchingTargets,
                );
            }

            return $matchingTargets->first();
        }

        if ($runningContainers->count() > 1) {
            return $this->ambiguousTargetResponse(
                'Multiple running containers found. Specify a container.',
                $runningContainers,
            );
        }

        return $runningContainers->first();
    }

    private function ambiguousTargetResponse(string $message, Collection $targets): JsonResponse
    {
        return response()->json([
            'message' => $message,
            'containers' => $targets->map(fn (array $target): array => [
                'server_uuid' => $target['server']->uuid,
                'container' => $target['container'],
            ])->values(),
        ], 422);
    }
}
