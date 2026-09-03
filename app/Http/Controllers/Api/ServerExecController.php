<?php

namespace App\Http\Controllers\Api;

use App\Exceptions\TerminalAuditUnavailableException;
use App\Exceptions\TerminalCommandLimitException;
use App\Http\Controllers\Controller;
use App\Models\Server;
use App\Services\Terminal\TerminalCommandService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use OpenApi\Attributes as OA;

class ServerExecController extends Controller
{
    #[OA\Post(
        summary: 'Execute command',
        description: 'Execute a bounded non-interactive shell command on a managed server. Requires a literal terminal token ability with a lifetime of at most 90 days and team opt-in.',
        path: '/servers/{uuid}/exec',
        operationId: 'execute-command-on-server',
        security: [['bearerAuth' => []]],
        tags: ['Servers'],
        parameters: [
            new OA\Parameter(name: 'uuid', in: 'path', required: true, description: 'Server UUID', schema: new OA\Schema(type: 'string')),
        ],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['command'],
                properties: [
                    new OA\Property(property: 'command', description: 'Shell script. Prefer reading secrets from the target environment instead of passing literal secret values.', type: 'string', maxLength: 20000, minLength: 1),
                    new OA\Property(property: 'timeout', type: 'integer', maximum: 10, minimum: 1, default: 10),
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
            new OA\Response(response: 422, ref: '#/components/responses/422'),
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
        $validationResponse = $this->validateRequest($request);
        if ($validationResponse instanceof JsonResponse) {
            return $validationResponse;
        }

        $teamId = getTeamIdFromToken();
        if (is_null($teamId)) {
            return response()->json(['message' => 'Invalid token.'], 401);
        }

        $server = Server::query()->where('team_id', $teamId)->where('uuid', $uuid)->first();
        if (! $server) {
            return response()->json(['message' => 'Server not found.'], 404);
        }

        if (! $server->isTerminalEnabled() || $server->isForceDisabled()) {
            return response()->json(['message' => 'Terminal access is disabled on this server.'], 403);
        }

        try {
            $result = $commandService->executeOnServer(
                server: $server,
                actor: $request->user(),
                token: $request->user()->currentAccessToken(),
                command: (string) $validationResponse['command'],
                timeout: (int) ($validationResponse['timeout'] ?? TerminalCommandService::DEFAULT_TIMEOUT_SECONDS),
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
        ]);

        $validator->fails();
        foreach (array_diff(array_keys($request->all()), ['command', 'timeout']) as $field) {
            $validator->errors()->add($field, 'This field is not allowed.');
        }

        if ($validator->errors()->isNotEmpty()) {
            return response()->json([
                'message' => 'Validation failed.',
                'errors' => $validator->errors(),
            ], 422);
        }

        return $validator->validated();
    }
}
