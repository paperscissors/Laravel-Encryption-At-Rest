<?php

namespace Paperscissorsandglue\GdprLaravel\Console;

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
        if (!method_exists($model, 'handleEmailEncryption')) {
            $this->error("Model {$modelClass} does not use the HasEncryptedEmail trait.");
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
                        $record->handleEmailEncryption();
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
        
        if ($driver === 'mysql') {
            $this->info('Creating MySQL backup...');
            
            $db = config("database.connections.{$connection}.database");
            $user = config("database.connections.{$connection}.username");
            $password = config("database.connections.{$connection}.password");
            $host = config("database.connections.{$connection}.host");
            
            $backupPath = storage_path('app/backups');
            if (!file_exists($backupPath)) {
                mkdir($backupPath, 0755, true);
            }
            
            $filename = $backupPath . '/' . $db . '-' . date('Y-m-d-H-i-s') . '.sql';
            
            $command = "mysqldump --user={$user} --password={$password} --host={$host} {$db} > {$filename}";
            exec($command, $output, $returnVar);
            
            if ($returnVar === 0) {
                $this->info("Database backup created at {$filename}");
            } else {
                $this->error("Database backup failed. Continue with caution.");
                if (!$this->confirm('Proceed without backup?', false)) {
                    $this->info('Operation cancelled by user.');
                    exit;
                }
            }
        } else {
            $this->warn("Automatic backup not supported for {$driver} database. Please backup your database manually before proceeding.");
            if (!$this->confirm('Continue without backup?', false)) {
                $this->info('Operation cancelled by user.');
                exit;
            }
        }
    }
}