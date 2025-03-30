<?php

namespace Paperscissorsandglue\EncryptionAtRest\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;

class EncryptEmails extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'encryption:encrypt-emails 
                           {model : The model class to process (e.g. "App\\Models\\User")}
                           {--chunk=100 : Process records in chunks of the specified size}
                           {--dry-run : Run without making changes}
                           {--backup=true : Create a database backup before processing}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Encrypt emails for existing records and populate email_index for searching';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $modelClass = $this->argument('model');
        $chunkSize = $this->option('chunk');
        $dryRun = $this->option('dry-run');
        $shouldBackup = $this->option('backup') === 'true';
        
        // Verify the model exists
        if (!class_exists($modelClass)) {
            $this->error("Model class {$modelClass} not found.");
            return 1;
        }
        
        // Check if the model has the HasEncryptedEmail trait
        $model = new $modelClass;
        
        // Check if the class or its parents/traits have the handleEmailEncryption method
        try {
            $reflection = new \ReflectionClass($modelClass);
            $hasTraitMethod = $reflection->hasMethod('handleEmailEncryption');
            
            if (!$hasTraitMethod) {
                $this->error("Model {$modelClass} does not use the HasEncryptedEmail trait.");
                return 1;
            }
        } catch (\Exception $e) {
            $this->error("Error checking model traits: " . $e->getMessage());
            return 1;
        }
        
        // Check if the required email_index column exists
        if (!Schema::hasColumn($model->getTable(), 'email_index')) {
            $this->error("The email_index column does not exist in the {$model->getTable()} table.");
            $this->info("Run the migration first: php artisan vendor:publish --tag=encryption-at-rest-migrations");
            return 1;
        }
        
        // Backup confirmation
        if ($shouldBackup) {
            if ($this->confirm('This will create a database backup before processing. Continue?', true)) {
                $this->backup();
            } else {
                if (!$this->confirm('Proceeding without backup. Are you sure you want to continue?', false)) {
                    $this->info('Operation cancelled by user.');
                    return 0;
                }
            }
        }

        $this->info("Encrypting emails for {$modelClass}...");
        
        $count = 0;
        $recordsProcessed = 0;
        
        // Process in chunks to avoid memory issues
        $modelClass::chunk($chunkSize, function ($records) use (&$count, &$recordsProcessed, $dryRun) {
            foreach ($records as $record) {
                $recordsProcessed++;
                
                // Skip if email_index is already set and email is encrypted
                try {
                    // Attempt to decrypt - if it works, it means the email is already encrypted
                    // This will cause an exception for plaintext emails
                    $decrypted = $record->attributes['email'];
                    
                    if (!empty($record->email_index)) {
                        $this->line("Skipping ID {$record->id} - already processed.");
                        continue;
                    }
                } catch (\Exception $e) {
                    // Email is not encrypted yet, proceed
                }

                $originalEmail = $record->email;
                
                // Apply the encryption and hashing
                if (!$dryRun) {
                    DB::beginTransaction();
                    
                    try {
                        // Store original email
                        $originalEmail = $record->email;
                        
                        // Use reflection to access the protected method to create email_index
                        $reflection = new \ReflectionMethod(get_class($record), 'handleEmailEncryption');
                        $reflection->setAccessible(true);
                        $reflection->invoke($record);
                        
                        // Force email update to trigger encryption
                        $record->email = $originalEmail;
                        
                        // Check if encrypted value would exceed database limit before saving
                        $encryptionService = app()->make(\Paperscissorsandglue\EncryptionAtRest\EncryptionService::class);
                        
                        // Try standard encryption first
                        $standardEncryptedEmail = $encryptionService->encrypt($originalEmail, false);
                        
                        if (strlen($standardEncryptedEmail) > 255 && DB::connection()->getDriverName() === 'pgsql') {
                            // For PostgreSQL with strict character limits, try compact encryption
                            $compactEncryptedEmail = $encryptionService->encrypt($originalEmail, true);
                            
                            if (strlen($compactEncryptedEmail) <= 255) {
                                // Use compact encryption if it fits
                                $this->line("Using compact encryption for email ID {$record->id} (reduced from " . 
                                    strlen($standardEncryptedEmail) . " to " . strlen($compactEncryptedEmail) . " chars)");
                                
                                // Apply the compact encryption directly (no need to set email again since we're just using a different format)
                                $record->attributes['email'] = $compactEncryptedEmail;
                            } else {
                                // Even compact encryption is too long
                                $this->warn("Email for ID {$record->id} is too long even with compact encryption (" . 
                                    strlen($compactEncryptedEmail) . " chars)");
                                    
                                // Options:
                                // 1. Store a shortened email (last part omitted)
                                // 2. Store just the email_index and a note
                            
                            if ($this->confirm("Would you like to store a truncated version of this email?", true)) {
                                // Truncate email to fit in the database while keeping domain
                                $parts = explode('@', $originalEmail);
                                if (count($parts) === 2) {
                                    $username = $parts[0];
                                    $domain = $parts[1];
                                    
                                    // Keep shortening username until it fits
                                    $maxTries = 10;
                                    $tries = 0;
                                    
                                    while ($tries < $maxTries) {
                                        $truncatedUsername = substr($username, 0, max(1, strlen($username) - $tries * 5));
                                        $truncatedEmail = $truncatedUsername . '@' . $domain;
                                        $encryptedTruncated = $encryptionService->encrypt($truncatedEmail);
                                        
                                        if (strlen($encryptedTruncated) <= 255) {
                                            $record->email = $truncatedEmail;
                                            $this->line("Email shortened from {$originalEmail} to {$truncatedEmail}");
                                            break;
                                        }
                                        
                                        $tries++;
                                    }
                                }
                            } else {
                                // Skip this record
                                $this->info("Skipping encryption for email ID {$record->id}");
                                DB::rollBack();
                                continue;
                            }
                        }
                        
                        $record->save();
                        DB::commit();
                        $count++;
                    } catch (\Exception $e) {
                        DB::rollBack();
                        $this->error("Error processing ID {$record->id}: " . $e->getMessage());
                    }
                } else {
                    $this->info("Would encrypt email for ID {$record->id}: {$originalEmail}");
                    $count++;
                }
                
                // Show progress 
                if ($recordsProcessed % 10 === 0) {
                    $this->output->write(".");
                }
            }
        });
        
        $this->newLine();
        
        if ($dryRun) {
            $this->info("Dry run completed. {$count} records would be updated.");
        } else {
            $this->info("Encryption completed. {$count} records updated.");
        }
        
        return 0;
    }
    
    /**
     * Create a database backup.
     */
    protected function backup()
    {
        $connection = config('database.default');
        $driver = config("database.connections.{$connection}.driver");
        
        $backupPath = storage_path('app/backups');
        if (!file_exists($backupPath)) {
            mkdir($backupPath, 0755, true);
        }
        
        $db = config("database.connections.{$connection}.database");
        $user = config("database.connections.{$connection}.username");
        $password = config("database.connections.{$connection}.password");
        $host = config("database.connections.{$connection}.host");
        $port = config("database.connections.{$connection}.port");
        
        $timestamp = date('Y-m-d-H-i-s');
        $filename = $backupPath . '/' . $db . '-' . $timestamp . '.sql';
        
        if ($driver === 'mysql') {
            $this->info('Creating MySQL backup...');
            
            // Handle password with special characters
            $passwordParam = !empty($password) ? "--password='{$password}'" : '';
            $portParam = !empty($port) ? "--port={$port}" : '';
            
            $command = "mysqldump --user='{$user}' {$passwordParam} --host='{$host}' {$portParam} {$db} > \"{$filename}\"";
            exec($command, $output, $returnVar);
            
        } elseif ($driver === 'pgsql') {
            $this->info('Creating PostgreSQL backup...');
            
            // Change file extension for PostgreSQL dumps
            $filename = str_replace('.sql', '.dump', $filename);
            
            // Add debug information
            $this->line("Database: {$db}");
            $this->line("Host: {$host}");
            
            // Check if pg_dump is available
            exec('which pg_dump', $pgDumpOutput, $pgDumpReturnVar);
            
            if ($pgDumpReturnVar !== 0) {
                $this->error("pg_dump command not found. Please ensure PostgreSQL client tools are installed.");
                if (!$this->confirm('Proceed without backup?', false)) {
                    $this->info('Operation cancelled by user.');
                    exit;
                }
                return;
            }
            
            // Create backup command using Laravel's .env/config values
            // First prepare connection string with credentials
            $connectionString = "postgresql://";
            
            // Add credentials if they exist
            if (!empty($user)) {
                $connectionString .= urlencode($user);
                if (!empty($password)) {
                    $connectionString .= ":" . urlencode($password);
                }
                $connectionString .= "@";
            }
            
            // Add host and port
            $connectionString .= urlencode($host);
            if (!empty($port)) {
                $connectionString .= ":" . $port;
            }
            
            // Add database name
            $connectionString .= "/" . urlencode($db);
            
            // Build the pg_dump command with the connection string
            $command = "pg_dump \"{$connectionString}\" -f \"{$filename}\"";
            
            // Execute the command
            $this->line("Running backup...");
            exec($command, $output, $returnVar);
            
            // Check for errors
            if ($returnVar !== 0) {
                $this->error("PostgreSQL backup failed. If you're using a password, make sure pg_dump can access it properly.");
                $this->line("You can try running the backup manually with: pg_dump -h {$host} -U {$user} -f {$filename} {$db}");
                
                if (!$this->confirm('Proceed without backup?', false)) {
                    $this->info('Operation cancelled by user.');
                    exit;
                }
                return;
            }
            
        } else {
            $this->warn("Automatic backup not supported for {$driver} database. Please backup your database manually before proceeding.");
            if (!$this->confirm('Continue without backup?', false)) {
                $this->info('Operation cancelled by user.');
                exit;
            }
            
            return;
        }
        
        // Check if backup was successful
        if ($returnVar === 0) {
            $this->info("Database backup created at {$filename}");
        } else {
            $this->error("Database backup failed. Continue with caution.");
            if (!$this->confirm('Proceed without backup?', false)) {
                $this->info('Operation cancelled by user.');
                exit;
            }
        }
    }
}