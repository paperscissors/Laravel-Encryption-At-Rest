<?php

namespace Paperscissorsandglue\EncryptionAtRest\Console;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use ReflectionClass;

class EncryptModelData extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'encryption:encrypt-model
                            {model : The model class to process (e.g. "App\\Models\\User")}
                            {--chunk=100 : Process records in chunks of the specified size}
                            {--dry-run : Run without making changes}
                            {--backup=true : Create a database backup before processing}
                            {--filter= : Only process records matching a where clause (e.g. "id > 100")}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Encrypt existing data for models using Encryptable or EncryptableJson traits';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $modelClass = $this->argument('model');
        $chunkSize = $this->option('chunk');
        $dryRun = $this->option('dry-run');
        $shouldBackup = $this->option('backup') === 'true';
        $filter = $this->option('filter');
        
        // Verify the model exists
        if (!class_exists($modelClass)) {
            $this->error("Model class {$modelClass} not found.");
            return 1;
        }
        
        // Create an instance of the model to check its traits
        $model = new $modelClass;
        $traits = $this->getTraits($model);
        
        $hasEncryptable = in_array('Paperscissorsandglue\EncryptionAtRest\Encryptable', $traits);
        $hasEncryptableJson = in_array('Paperscissorsandglue\EncryptionAtRest\EncryptableJson', $traits);
        $hasEncryptedEmail = in_array('Paperscissorsandglue\EncryptionAtRest\HasEncryptedEmail', $traits);
        
        if (!$hasEncryptable && !$hasEncryptableJson && !$hasEncryptedEmail) {
            $this->error("Model {$modelClass} does not use any encryption traits (Encryptable, EncryptableJson, or HasEncryptedEmail).");
            return 1;
        }
        
        // Check if we have fields to encrypt
        $fieldsToEncrypt = [];
        
        if ($hasEncryptable && property_exists($model, 'encryptable')) {
            $fieldsToEncrypt = array_merge($fieldsToEncrypt, $model->encryptable);
        }
        
        if ($hasEncryptableJson && property_exists($model, 'encryptableJson')) {
            $this->info("Found JSON fields to encrypt: " . implode(', ', array_keys($model->encryptableJson)));
        }
        
        if ($hasEncryptedEmail) {
            $this->info("Found HasEncryptedEmail trait. Will process email encryption and hashing.");
            
            // Check if email_index column exists
            if (!Schema::hasColumn($model->getTable(), 'email_index')) {
                $this->error("The email_index column doesn't exist in the {$model->getTable()} table. Run the migration first.");
                return 1;
            }
        }
        
        if (empty($fieldsToEncrypt) && !$hasEncryptableJson && !$hasEncryptedEmail) {
            $this->error("No fields to encrypt found in the model.");
            return 1;
        }
        
        if ($hasEncryptable) {
            $this->info("Found fields to encrypt: " . implode(', ', $fieldsToEncrypt));
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
        
        // Show what's about to happen
        $this->info("Processing model: {$modelClass}");
        $this->info("Chunk size: {$chunkSize}");
        if ($filter) {
            $this->info("Filter: {$filter}");
        }
        if ($dryRun) {
            $this->info("DRY RUN: No changes will be made to the database.");
        }
        
        if (!$this->confirm('Ready to begin encryption. Continue?', true)) {
            $this->info('Operation cancelled by user.');
            return 0;
        }
        
        // Process in chunks
        $count = 0;
        $total = 0;
        $query = $modelClass::query();
        
        // Apply filter if provided
        if ($filter) {
            $query->whereRaw($filter);
        }
        
        $total = $query->count();
        $this->info("Found {$total} records to process.");
        
        if ($total === 0) {
            $this->info("No records to process. Exiting.");
            return 0;
        }
        
        $bar = $this->output->createProgressBar($total);
        $bar->start();
        
        $query->chunk($chunkSize, function ($records) use (&$count, $dryRun, $bar, $hasEncryptedEmail) {
            foreach ($records as $record) {
                // For email encryption, we need to trigger the email encryption
                if ($hasEncryptedEmail && !empty($record->email) && empty($record->email_index)) {
                    if (!$dryRun) {
                        DB::beginTransaction();
                        try {
                            if (method_exists($record, 'handleEmailEncryption')) {
                                $record->handleEmailEncryption();
                                $record->save();
                            }
                            DB::commit();
                            $count++;
                        } catch (\Exception $e) {
                            DB::rollBack();
                            $this->error("Error processing ID {$record->id}: " . $e->getMessage());
                        }
                    } else {
                        $count++;
                    }
                } 
                // For regular model updates, just save which will trigger the encrypt attributes
                else if (!$dryRun) {
                    DB::beginTransaction();
                    try {
                        $record->save();
                        DB::commit();
                        $count++;
                    } catch (\Exception $e) {
                        DB::rollBack();
                        $this->error("Error processing ID {$record->id}: " . $e->getMessage());
                    }
                } else {
                    $count++;
                }
                
                $bar->advance();
            }
        });
        
        $bar->finish();
        $this->newLine();
        
        if ($dryRun) {
            $this->info("Dry run completed. {$count} records would be processed.");
        } else {
            $this->info("Encryption completed. {$count} records updated.");
        }
        
        return 0;
    }
    
    /**
     * Get all traits used by a model and its parent classes.
     *
     * @param  Model  $model
     * @return array
     */
    protected function getTraits($model)
    {
        $traits = [];
        $class = get_class($model);
        
        do {
            $traits = array_merge($traits, class_uses($class));
            $class = get_parent_class($class);
        } while ($class);
        
        // Get traits of traits
        foreach ($traits as $trait) {
            $traits = array_merge($traits, class_uses($trait));
        }
        
        return array_unique($traits);
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