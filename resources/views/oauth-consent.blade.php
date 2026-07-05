{{-- MCP OAuth consent — ALWAYS shown (no auto-approve). Client registration is
     public + dynamic, so this explicit, human confirmation is the guard against a
     phished operator silently authorizing an attacker's claude.ai client. The
     warning + the shown client/redirect let the operator spot a connection they did
     not start themselves. Publish to override:
     `php artisan vendor:publish --tag=mcp-oauth-views`. --}}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>MCP authorization — {{ config('app.name') }}</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem; }
        .card { border: 1px solid #e2e2e2; border-radius: .75rem; padding: 1.5rem; }
        h1 { font-size: 1.25rem; margin: 0 0 .75rem; }
        p { color: #444; line-height: 1.5; }
        .actions { display: flex; gap: .75rem; margin-top: 1.5rem; }
        button { padding: .6rem 1.1rem; border-radius: .5rem; border: 0; font-weight: 600; cursor: pointer; }
        .approve { background: #16a34a; color: #fff; }
        .deny { background: #ef4444; color: #fff; }
        .warn { background: #fff7ed; border: 1px solid #fdba74; color: #9a3412; border-radius: .5rem; padding: .75rem 1rem; margin: 1rem 0; font-size: .92rem; }
        .meta { font-size: .85rem; color: #666; word-break: break-all; }
        code { background: #f3f3f3; padding: .1rem .3rem; border-radius: .25rem; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Authorize diagnostic access</h1>
        <p>
            <strong>{{ $client->name }}</strong> is requesting <em>read-only</em>
            access (masked data) to {{ config('app.name') }} diagnostics, scope
            <code>{{ implode(', ', collect($scopes)->pluck('id')->all()) }}</code>.
        </p>
        <p class="meta">Redirect after approval: <code>{{ $request->redirect_uri }}</code></p>

        <div class="warn">
            ⚠️ Approve <strong>only</strong> if <strong>you</strong> are starting this
            connection in claude.ai right now. Approval grants an external AI
            <strong>read-only access to production data</strong>. If you did not initiate
            this connection — deny.
        </div>

        <div class="actions">
            <form method="post" action="{{ route('passport.authorizations.approve') }}">
                @csrf
                <input type="hidden" name="state" value="{{ $request->state }}">
                <input type="hidden" name="client_id" value="{{ $client->getKey() }}">
                <input type="hidden" name="auth_token" value="{{ $authToken }}">
                <button type="submit" class="approve">Allow</button>
            </form>

            <form method="post" action="{{ route('passport.authorizations.deny') }}">
                @csrf
                @method('delete')
                <input type="hidden" name="state" value="{{ $request->state }}">
                <input type="hidden" name="client_id" value="{{ $client->getKey() }}">
                <input type="hidden" name="auth_token" value="{{ $authToken }}">
                <button type="submit" class="deny">Deny</button>
            </form>
        </div>
    </div>
</body>
</html>
