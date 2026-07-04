<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::connection($this->connection())->create('mcp_audit_log', function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('account_id')->nullable();
            $table->string('channel');            // query | tool | command
            $table->string('name');
            $table->json('parameters')->nullable();
            $table->json('result_summary')->nullable();
            $table->unsignedInteger('row_count')->nullable();
            $table->integer('exit_code')->nullable();
            $table->string('ip', 45)->nullable();
            $table->timestamp('created_at')->nullable();

            $table->index(['channel', 'name']);
            $table->index('account_id');
        });
    }

    public function down(): void
    {
        Schema::connection($this->connection())->dropIfExists('mcp_audit_log');
    }

    private function connection(): ?string
    {
        return config('mcp.migration_connection');
    }
};
