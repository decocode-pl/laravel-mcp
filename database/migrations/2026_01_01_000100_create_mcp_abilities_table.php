<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::connection($this->connection())->create('mcp_abilities', function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('account_id');
            $table->string('capability');
            $table->json('scope')->nullable();
            $table->timestamps();

            $table->unique(['account_id', 'capability']);
        });
    }

    public function down(): void
    {
        Schema::connection($this->connection())->dropIfExists('mcp_abilities');
    }

    private function connection(): ?string
    {
        return config('mcp.migration_connection');
    }
};
